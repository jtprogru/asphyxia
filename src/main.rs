use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{Duration, Instant};

use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory, FromArgMatches};
use owo_colors::OwoColorize;
use rayon::prelude::*;

use asphyxia::cli::{Args, ScanMode, Unavailable};
use asphyxia::config::Config;
use asphyxia::output::{OutputFormat, ScanRecord, emit};
use asphyxia::rate;
use asphyxia::resume::{ScanState, StateFinding};
use asphyxia::scanner::exclude::ExcludeSet;
use asphyxia::scanner::well_known::{named_port_set, top_ports};
use asphyxia::scanner::{address, nmap, port, service, syn};
use asphyxia::timing;
use asphyxia::utils::{
    init_scan_pool, parse_ip, parse_ports, parse_subnet, progress_bar, read_targets_from_file,
    read_targets_from_stdin,
};

/// One reportable port result, normalized across TCP, UDP and the raw scan
/// modes so the output path does not care which probe produced it.
struct Finding {
    port: u16,
    latency: Duration,
    /// The observed state: `"open"` (TCP, or a UDP port that replied),
    /// `"open|filtered"` (a silent UDP port), or `"unfiltered"`/`"filtered"`
    /// from an ACK scan, which reports what a firewall let through rather than
    /// whether anything is listening.
    status: &'static str,
    /// The probe that produced this result: `"connect"`, `"syn"` or `"ack"`.
    /// Recorded per finding, not per scan, because a raw mode falls back to a
    /// connect probe for individual targets (IPv6) and ports (lost replies).
    scan: &'static str,
    /// Detected service, when `--sV` is on and identification succeeded.
    service: Option<String>,
    /// Raw service banner, when `--sV` is on and one was grabbed.
    banner: Option<String>,
}

/// Mark every address as up without probing, for `-Pn` (skip discovery). The
/// latency is zero since no probe was sent.
fn all_up(addrs: Vec<IpAddr>) -> Vec<address::HostHit> {
    addrs
        .into_iter()
        .map(|ip| address::HostHit {
            ip,
            latency: Duration::ZERO,
        })
        .collect()
}

/// Build the address exclusion set from the `--exclude` specs and an optional
/// `--exclude-file`. Blank lines and `#` comments in the file are ignored.
fn build_exclude_set(specs: &[String], file: Option<&Path>) -> Result<ExcludeSet, String> {
    let mut all: Vec<String> = specs.to_vec();
    if let Some(path) = file {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Could not read exclude file {}: {}", path.display(), e))?;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            all.push(line.to_string());
        }
    }
    ExcludeSet::parse(all)
}

/// Hand each scanned host's open ports off to nmap, grouping the flat
/// `(host_index, hit)` list by host. Nothing runs for hosts with no open ports.
///
/// A missing nmap binary is reported once with an install hint rather than
/// failing per host; any other spawn error is surfaced per host.
fn run_nmap_handoff(resolved: &[(String, String)], opened: &[(usize, Finding)], extra: &[String]) {
    use std::io::ErrorKind;

    // `opened` is already sorted by (host index, port), so consecutive runs of
    // the same index group a host's ports together.
    let mut idx = 0;
    while idx < opened.len() {
        let host_i = opened[idx].0;
        let mut ports = Vec::new();
        while idx < opened.len() && opened[idx].0 == host_i {
            ports.push(opened[idx].1.port);
            idx += 1;
        }

        let host = &resolved[host_i].0;
        println!(
            "\n##### {} nmap on {} #####\n",
            "Handing off to".bright_blue(),
            host.bright_green()
        );
        match nmap::run_nmap(host, &ports, extra) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {
                eprintln!(
                    "{}",
                    "nmap not found on PATH — install nmap (https://nmap.org/download) to use --nmap"
                        .red()
                );
                // No point retrying the remaining hosts if nmap is absent.
                return;
            }
            Err(e) => {
                eprintln!("{}", format!("Failed to run nmap on {}: {}", host, e).red());
            }
        }
    }
}

/// Filter out excluded addresses, then either mark the survivors up (for `-Pn`)
/// or scan them.
fn scan_filtered(
    addrs: Vec<IpAddr>,
    exclude: &ExcludeSet,
    no_discovery: bool,
    timeout: Option<Duration>,
    retries: u32,
) -> Vec<address::HostHit> {
    let filtered: Vec<IpAddr> = addrs
        .into_iter()
        .filter(|ip| !exclude.contains(*ip))
        .collect();
    if no_discovery {
        all_up(filtered)
    } else {
        address::scan_hosts(filtered, timeout, retries)
    }
}

/// Map a persisted status string back to the `&'static str` the report uses.
fn status_str(status: &str) -> &'static str {
    match status {
        "open|filtered" => "open|filtered",
        "unfiltered" => "unfiltered",
        "filtered" => "filtered",
        _ => "open",
    }
}

/// Map a persisted scan-mode string back to the `&'static str` the report uses.
/// Anything unrecognized (including a checkpoint written before `--scan`
/// existed) is a connect probe.
fn scan_str(scan: &str) -> &'static str {
    match scan {
        "syn" => "syn",
        "ack" => "ack",
        _ => "connect",
    }
}

/// Probe one port with a lone ACK and report what the firewall did with it: an
/// RST back means the probe reached the port (`unfiltered`), silence means
/// something dropped it (`filtered`). Neither says whether the port is open.
///
/// Only silence is retried — a lost probe and a filtered one look identical, so
/// on a lossy link `--retries` buys back some certainty. Returns `None` when the
/// raw path is unusable, so the caller falls back to a connect probe.
fn ack_probe(ip: Ipv4Addr, port: u16, timeout: Duration, retries: u32) -> Option<Finding> {
    let start = Instant::now();
    let mut outcome = None;
    for _ in 0..=retries {
        outcome = syn::probe_port(syn::ProbeMode::Ack, ip, port, timeout);
        if outcome != Some(syn::ProbeOutcome::Filtered) {
            break;
        }
    }
    let status = match outcome {
        Some(syn::ProbeOutcome::Unfiltered) => "unfiltered",
        Some(syn::ProbeOutcome::Filtered) => "filtered",
        // An ACK probe never yields open/closed; `None` means the raw path
        // failed, and both leave the fallback to the caller.
        Some(syn::ProbeOutcome::Open | syn::ProbeOutcome::Closed) | None => return None,
    };
    Some(Finding {
        port,
        latency: start.elapsed(),
        status,
        scan: "ack",
        service: None,
        banner: None,
    })
}

/// Probe a single `(ip, port)` job, returning a [`Finding`] when the result is
/// reportable. A connect or SYN scan yields only open ports (optionally with a
/// grabbed banner); UDP also yields open|filtered; an ACK scan yields every
/// probed port as unfiltered or filtered, since silence is the finding there.
///
/// In [`ScanMode::Syn`] an IPv4 target is probed with a raw-socket SYN first: a
/// definitive open/closed result is used directly, while a filtered/unavailable
/// result falls through to a normal connect probe so nothing open is missed. In
/// [`ScanMode::Ack`] the raw result stands on its own — a connect probe cannot
/// answer the same question — and only an unusable raw path falls through.
///
/// An IPv6 target has no raw path at all and always falls through to a connect
/// probe; the finding then records `connect` as its mode, so a fallback never
/// masquerades as the scan that was asked for.
#[allow(clippy::too_many_arguments)]
fn scan_one(
    udp: bool,
    ip: String,
    port: u16,
    timeout: Option<Duration>,
    connect_timeout: Duration,
    retries: u32,
    detect_service: bool,
    mode: ScanMode,
) -> Option<Finding> {
    if udp {
        return port::scan_udp_port(ip, port, timeout, retries).map(|hit| Finding {
            port: hit.port,
            latency: hit.latency,
            status: if hit.open { "open" } else { "open|filtered" },
            scan: "connect",
            service: None,
            banner: None,
        });
    }

    // Raw-packet pre-check, IPv4 only.
    if let Some(probe) = mode.probe_mode()
        && let Ok(v4) = ip.parse::<Ipv4Addr>()
    {
        match probe {
            syn::ProbeMode::Ack => {
                if let Some(finding) = ack_probe(v4, port, connect_timeout, retries) {
                    return Some(finding);
                }
            }
            syn::ProbeMode::Syn => match syn::syn_scan_port(v4, port, connect_timeout) {
                Some(syn::ProbeOutcome::Open) => {
                    let (service, banner) = if detect_service {
                        service::detect(&ip, port, connect_timeout)
                    } else {
                        (None, None)
                    };
                    return Some(Finding {
                        port,
                        latency: Duration::ZERO,
                        status: "open",
                        scan: "syn",
                        service,
                        banner,
                    });
                }
                Some(syn::ProbeOutcome::Closed) => return None,
                // Filtered, or raw socket unusable: fall back to a connect probe.
                Some(syn::ProbeOutcome::Filtered | syn::ProbeOutcome::Unfiltered) | None => {}
            },
        }
    }

    port::scan_port_with_retries(ip.clone(), port, timeout, retries).map(|hit| {
        let (service, banner) = if detect_service {
            service::detect(&ip, hit.port, connect_timeout)
        } else {
            (None, None)
        };
        Finding {
            port: hit.port,
            latency: hit.latency,
            status: "open",
            scan: "connect",
            service,
            banner,
        }
    })
}

/// Run a port scan that checkpoints to `state_path` and resumes from it.
///
/// A compatible existing state file is loaded and its completed jobs skipped;
/// otherwise a fresh state is started. Progress is flushed periodically and on
/// Ctrl-C, and a final flush is written at the end. The returned findings are
/// the union of prior and freshly-discovered results, sorted by `(host, port)`.
#[allow(clippy::too_many_arguments)]
fn run_resumable_port_scan(
    jobs: &[(usize, u16)],
    resolved: &[(String, String)],
    ports: &[u16],
    proto: &str,
    udp: bool,
    timeout: Option<Duration>,
    connect_timeout: Duration,
    retries: u32,
    detect_service: bool,
    mode: ScanMode,
    state_path: &Path,
    pb: &indicatif::ProgressBar,
) -> Vec<(usize, Finding)> {
    use std::sync::{Arc, Mutex};

    // Flush the checkpoint to disk at most every this many completed jobs.
    const FLUSH_EVERY: usize = 128;

    let targets: Vec<String> = resolved.iter().map(|(_, ip)| ip.clone()).collect();
    let job_count = jobs.len();

    // Resume from a compatible state, else start fresh.
    let initial = ScanState::load(state_path)
        .ok()
        .filter(|s| s.is_compatible(proto, &targets, ports, job_count))
        .unwrap_or_else(|| ScanState::new(proto, targets.clone(), ports.to_vec(), job_count));

    // Account for already-completed jobs on the progress bar.
    pb.inc((job_count - initial.remaining()) as u64);

    let state = Arc::new(Mutex::new(initial));

    // On Ctrl-C, flush a valid checkpoint and exit so the scan can be resumed.
    {
        let state = Arc::clone(&state);
        let path = state_path.to_path_buf();
        let _ = ctrlc::set_handler(move || {
            if let Ok(s) = state.lock() {
                let _ = s.save(&path);
            }
            eprintln!("\nInterrupted — progress saved to {}", path.display());
            std::process::exit(130);
        });
    }

    jobs.par_iter().enumerate().for_each(|(idx, (i, port))| {
        if !state.lock().unwrap().is_pending(idx) {
            return;
        }
        let finding = scan_one(
            udp,
            resolved[*i].1.clone(),
            *port,
            timeout,
            connect_timeout,
            retries,
            detect_service,
            mode,
        );
        let recorded = finding.as_ref().map(|f| StateFinding {
            host: *i,
            port: f.port,
            latency_ms: f.latency.as_millis(),
            status: f.status.to_string(),
            scan: f.scan.to_string(),
            service: f.service.clone(),
            banner: f.banner.clone(),
        });
        {
            let mut s = state.lock().unwrap();
            s.complete(idx, recorded);
            if idx % FLUSH_EVERY == 0 {
                let _ = s.save(state_path);
            }
        }
        pb.inc(1);
    });

    // Final checkpoint, then rebuild the report from every recorded finding.
    let state = state.lock().unwrap();
    let _ = state.save(state_path);

    let mut results: Vec<(usize, Finding)> = state
        .findings
        .iter()
        .map(|f| {
            (
                f.host,
                Finding {
                    port: f.port,
                    latency: Duration::from_millis(f.latency_ms as u64),
                    status: status_str(&f.status),
                    scan: scan_str(&f.scan),
                    service: f.service.clone(),
                    banner: f.banner.clone(),
                },
            )
        })
        .collect();
    results.sort_by_key(|(i, f)| (*i, f.port));
    results
}

/// Resolve the tunable scan options into `args`, layering three sources under a
/// strict precedence: an explicit CLI flag beats a `-T` timing profile, which
/// beats `~/.asphyxia.toml`, which beats the built-in defaults.
///
/// "Explicit CLI flag" is read from clap's value source, so a value that merely
/// came from a `default_value` is still eligible to be overridden by the config
/// or a timing profile.
fn resolve_options(args: &mut Args, matches: &ArgMatches, config: &Config) {
    let Some((_, sub)) = matches.subcommand() else {
        return;
    };
    let from_cli = |id: &str| matches!(sub.value_source(id), Some(ValueSource::CommandLine));

    match args {
        Args::PortScan {
            timeout,
            concurrency,
            retries,
            rate,
            timing,
            output,
            interface,
            ..
        }
        | Args::AddressScan {
            timeout,
            concurrency,
            retries,
            rate,
            timing,
            output,
            interface,
            ..
        } => {
            // Layer 1: config fills anything not set on the command line.
            if !from_cli("timeout")
                && let Some(v) = config.timeout
            {
                *timeout = v;
            }
            if !from_cli("interface") && config.interface.is_some() {
                *interface = config.interface.clone();
            }
            if !from_cli("concurrency")
                && let Some(v) = config.concurrency
            {
                *concurrency = v;
            }
            if !from_cli("retries")
                && let Some(v) = config.retries
            {
                *retries = v;
            }
            if !from_cli("rate") && config.rate.is_some() {
                *rate = config.rate;
            }
            if !from_cli("output")
                && let Some(v) = config.output_format()
            {
                *output = v;
            }

            // Layer 2: a -T profile overrides config/defaults, still yielding to
            // any explicit flag.
            if let Some(level) = *timing {
                let profile = timing::profile(level);
                if !from_cli("timeout") {
                    *timeout = profile.timeout_ms;
                }
                if !from_cli("concurrency") {
                    *concurrency = profile.concurrency;
                }
                if !from_cli("retries") {
                    *retries = profile.retries;
                }
                if !from_cli("rate") {
                    *rate = profile.rate;
                }
            }
        }
    }
}

fn main() {
    let matches = Args::command().get_matches();
    let mut args = Args::from_arg_matches(&matches).expect("clap builds valid Args");
    resolve_options(&mut args, &matches, &Config::load());

    // Pin every probe to the requested interface before scanning. A bad or
    // unusable interface (unknown name, or a bind that needs privileges we lack)
    // is a hard error: silently scanning over the wrong route would be worse.
    if let Some(name) = args.interface()
        && let Err(e) = asphyxia::iface::install(name)
    {
        eprintln!("{}", e.red());
        std::process::exit(2);
    }

    // Size the global rayon pool for I/O-bound scanning before any scan runs.
    init_scan_pool(args.concurrency());

    // Install the global rate limit (a no-op when unset or zero) before scanning.
    if let Some(pps) = args.rate() {
        rate::install(pps);
    }

    let format = args.output_format();
    let output_file = args.output_file().cloned();
    let retries = args.retries();
    let requested_mode = args.scan_mode();

    match args {
        Args::PortScan {
            host,
            stdin,
            target_file,
            range,
            specific,
            all_ports,
            top_ports: top_n,
            port_set,
            exclude_ports,
            exclude_cdn,
            udp,
            service_detection,
            resume,
            nmap,
            nmap_args,
            timeout,
            ..
        } => {
            let connect_timeout = Duration::from_millis(timeout);
            let timeout = Some(connect_timeout);
            let proto = if udp { "udp" } else { "tcp" };

            // The raw-packet modes (--syn, --scan ack) need a raw socket (root /
            // CAP_NET_RAW). When asked for but unavailable, warn once and fall
            // back to the connect scan. The shared pcap receiver is started
            // later, once the targets are resolved and its capture interface can
            // be chosen.
            let mut mode = requested_mode;
            if mode.needs_raw() && !syn::raw_socket_available() {
                let (fallback, message) = mode.downgrade(Unavailable::RawSocket);
                eprintln!("{}", message.yellow());
                mode = fallback;
            }

            let mut ports: Vec<u16> = if all_ports {
                (1..=u16::MAX).collect()
            } else if let Some(range) = range {
                // clap enforces exactly two values via `num_args = 2`.
                let start = range[0];
                let end = range[1];
                if start > end {
                    eprintln!("{}", "Start port must be <= end port".yellow());
                    return;
                }
                (start..=end).collect()
            } else if let Some(spec) = specific {
                match parse_ports(&spec) {
                    Ok(ports) => ports,
                    Err(e) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                }
            } else if let Some(n) = top_n {
                match top_ports(n) {
                    Ok(ports) => ports,
                    Err(e) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                }
            } else if let Some(name) = port_set {
                match named_port_set(&name) {
                    Ok(ports) => ports,
                    Err(e) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                }
            } else {
                eprintln!(
                    "{}",
                    "Please specify either -r, -s, --all-ports, --top-ports, or --ports".yellow()
                );
                return;
            };

            // Drop any explicitly excluded ports from the set.
            if let Some(spec) = exclude_ports {
                match parse_ports(&spec) {
                    Ok(excluded) => {
                        let excluded: std::collections::HashSet<u16> =
                            excluded.into_iter().collect();
                        ports.retain(|p| !excluded.contains(p));
                    }
                    Err(e) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                }
            }

            if ports.is_empty() {
                eprintln!("{}", "No ports left to scan after exclusions".yellow());
                return;
            }

            // When --exclude-cdn is set, CDN/WAF targets are scanned only on the
            // web ports rather than the full set (a deep scan there is pointless
            // and antisocial). Precompute the CDN ranges and the web subset once.
            let cdn = exclude_cdn.then(ExcludeSet::cdn);
            let web_ports: Vec<u16> = ports
                .iter()
                .copied()
                .filter(|p| *p == 80 || *p == 443)
                .collect();

            // Gather the raw targets from exactly one source: a single `-t`
            // host, a batch from stdin, or a batch from a `-iL` file (clap's
            // required `target` group guarantees precisely one is set).
            let targets: Vec<String> = if stdin {
                let targets = read_targets_from_stdin();
                if targets.is_empty() {
                    eprintln!("{}", "No targets read from stdin".yellow());
                    return;
                }
                targets
            } else if let Some(path) = target_file {
                match read_targets_from_file(&path) {
                    Ok(targets) if targets.is_empty() => {
                        eprintln!(
                            "{}",
                            format!("No targets read from file: {}", path.display()).yellow()
                        );
                        return;
                    }
                    Ok(targets) => targets,
                    Err(e) => {
                        eprintln!(
                            "{}",
                            format!("Could not read target file {}: {}", path.display(), e).red()
                        );
                        return;
                    }
                }
            } else {
                // With neither --stdin nor -iL, clap guarantees `host` is set.
                vec![host.expect("clap enforces --host when --stdin/-iL are absent")]
            };

            // Resolve each target to an IP once, so the parallel scan below does
            // not issue a DNS lookup for every single port. Unresolvable targets
            // are reported and skipped rather than aborting the whole batch.
            let resolved: Vec<(String, String)> = targets
                .iter()
                .filter_map(|host| match port::resolve_host(host) {
                    Some(ip) => Some((host.clone(), ip.to_string())),
                    None => {
                        eprintln!("{}", format!("Could not resolve host: {}", host).red());
                        None
                    }
                })
                .collect();

            if resolved.is_empty() {
                return;
            }

            // Start the shared pcap/BPF receiver for raw-probe replies now that
            // the targets are known: the capture interface is chosen from the
            // route to the first IPv4 target. If it cannot be opened (no
            // libpcap, an unusual link type), warn once and fall back to the
            // connect scan.
            if mode.needs_raw() {
                let ipv4_target = resolved
                    .iter()
                    .find_map(|(_, ip)| ip.parse::<Ipv4Addr>().ok());
                let cause = match ipv4_target {
                    Some(target) if syn::init_receiver(target) => None,
                    Some(_) => Some(Unavailable::Capture),
                    // Every target is IPv6, which the raw path cannot probe.
                    None => Some(Unavailable::Ipv6),
                };
                match cause {
                    Some(cause) => {
                        let (fallback, message) = mode.downgrade(cause);
                        eprintln!("{}", message.yellow());
                        mode = fallback;
                    }
                    // The raw mode runs, but only for the IPv4 targets in the
                    // batch; say so rather than let the IPv6 ones quietly report
                    // a different kind of result.
                    None if resolved
                        .iter()
                        .any(|(_, ip)| ip.parse::<Ipv4Addr>().is_err()) =>
                    {
                        eprintln!(
                            "{}",
                            format!(
                                "{} scan is IPv4-only — IPv6 targets fall back to connect scan",
                                mode.label().to_uppercase()
                            )
                            .yellow()
                        );
                    }
                    None => {}
                }
            }

            // Service detection only makes sense over a TCP stream to a port
            // known to be open — which an ACK scan never establishes.
            if service_detection && mode == ScanMode::Ack {
                eprintln!(
                    "{}",
                    "--sV needs an open port, which an ACK scan does not determine — ignoring it"
                        .yellow()
                );
            }
            let detect_service = service_detection && !udp && mode != ScanMode::Ack;

            // An ACK scan answers a different question than a connect or SYN
            // scan over the same grid, so its checkpoints get their own key and
            // the two can never resume from each other.
            let state_proto = if mode == ScanMode::Ack {
                "tcp-ack"
            } else {
                proto
            };

            if format == OutputFormat::Text {
                if let [(host, _)] = resolved.as_slice() {
                    println!(
                        "\n##### {} scanning ports on host: {} #####\n",
                        "Started".bright_blue(),
                        host.bright_green()
                    );
                } else {
                    println!(
                        "\n##### {} scanning ports on {} hosts #####\n",
                        "Started".bright_blue(),
                        resolved.len().to_string().bright_green()
                    );
                }
            }

            // Fan every (host, port) pair out across the shared pool so that
            // multiple hosts are probed concurrently, not one after another.
            // A CDN/WAF target (with --exclude-cdn) is limited to its web ports.
            let jobs: Vec<(usize, u16)> = resolved
                .iter()
                .enumerate()
                .flat_map(|(i, (_, ip))| {
                    let is_cdn = cdn.as_ref().is_some_and(|c| {
                        ip.parse::<IpAddr>().map(|a| c.contains(a)).unwrap_or(false)
                    });
                    let plist: &[u16] = if is_cdn { &web_ports } else { &ports };
                    plist.iter().map(move |&port| (i, port))
                })
                .collect();

            let pb = progress_bar(jobs.len() as u64, "ports scanned");

            // Probe every (host, port) pair. TCP yields only open ports; UDP also
            // reports open|filtered (silent) ports, since silence is meaningful,
            // and an ACK scan reports every port as unfiltered or filtered.
            // With --resume the scan checkpoints to a file and skips work already
            // recorded there; otherwise it is a plain parallel sweep.
            let results: Vec<(usize, Finding)> = if let Some(state_path) = &resume {
                run_resumable_port_scan(
                    &jobs,
                    &resolved,
                    &ports,
                    state_proto,
                    udp,
                    timeout,
                    connect_timeout,
                    retries,
                    detect_service,
                    mode,
                    state_path,
                    &pb,
                )
            } else {
                let mut results: Vec<(usize, Finding)> = jobs
                    .par_iter()
                    .filter_map(|&(i, port)| {
                        let finding = scan_one(
                            udp,
                            resolved[i].1.clone(),
                            port,
                            timeout,
                            connect_timeout,
                            retries,
                            detect_service,
                            mode,
                        );
                        pb.inc(1);
                        finding.map(|f| (i, f))
                    })
                    .collect();
                results.sort_by_key(|(i, f)| (*i, f.port));
                results
            };

            pb.finish_with_message("Scan completed");

            match format {
                OutputFormat::Text => {
                    // An ACK scan lists firewall state for every probed port,
                    // not a list of open ports, so it gets its own heading.
                    let heading = if mode == ScanMode::Ack {
                        "Port states"
                    } else {
                        "Opened ports"
                    };
                    if !results.is_empty() {
                        let mut current: Option<usize> = None;
                        for (i, f) in &results {
                            let host = &resolved[*i].0;
                            if current != Some(*i) {
                                println!(
                                    "\n-- {} for {} --\n",
                                    heading.green(),
                                    host.bright_yellow()
                                );
                                current = Some(*i);
                            }
                            // Base line is host:port; annotate with the status
                            // when it carries information beyond "open" (UDP
                            // open|filtered), and with the service/banner when
                            // --sV identified one.
                            let mut line = format!(
                                "{}:{}",
                                host.bright_cyan(),
                                f.port.to_string().bright_green()
                            );
                            if f.status != "open" {
                                line.push_str(&format!(" {}", f.status.yellow()));
                            }
                            if let Some(service) = &f.service {
                                line.push_str(&format!(" {}", service.bright_magenta()));
                            }
                            if let Some(banner) = &f.banner {
                                line.push_str(&format!(" {}", format!("[{}]", banner).dimmed()));
                            }
                            println!("{}", line);
                        }
                    } else if mode == ScanMode::Ack {
                        println!("\n{}", "No port states observed 😕".yellow());
                    } else {
                        println!("\n{}", "No open ports found 😕".yellow());
                    }

                    println!("\n##### {} #####\n", "Game Over".bright_red());
                }
                _ => {
                    let records: Vec<ScanRecord> = results
                        .iter()
                        .map(|(i, f)| ScanRecord {
                            ip: resolved[*i].1.clone(),
                            port: Some(f.port),
                            proto,
                            scan: f.scan,
                            latency_ms: f.latency.as_millis(),
                            status: f.status,
                            service: f.service.clone(),
                            banner: f.banner.clone(),
                        })
                        .collect();
                    if let Err(e) = emit(&records, format, output_file.as_deref()) {
                        eprintln!("{}", format!("Failed to write output: {}", e).red());
                    }
                }
            }

            // Optional deep-dive: hand each host's open ports to nmap. An ACK
            // scan finds no open ports, so there is nothing to hand over.
            if nmap {
                if mode == ScanMode::Ack {
                    eprintln!(
                        "{}",
                        "--nmap has nothing to hand off: an ACK scan does not determine open ports"
                            .yellow()
                    );
                } else {
                    let extra = nmap_args.as_deref().map(nmap::split_extra_args);
                    run_nmap_handoff(&resolved, &results, extra.as_deref().unwrap_or(&[]));
                }
            }
        }
        Args::AddressScan {
            subnet,
            target,
            range,
            no_discovery,
            exclude,
            exclude_file,
            timeout,
            ..
        } => {
            let timeout = Some(Duration::from_millis(timeout));

            let exclude_set = match build_exclude_set(&exclude, exclude_file.as_deref()) {
                Ok(set) => set,
                Err(e) => {
                    eprintln!("{}", e.red());
                    return;
                }
            };

            // Enumerate-filter-scan only when it earns its keep (exclusions or
            // -Pn); otherwise keep the lazy subnet/range scan that never
            // materializes the whole address space.
            let materialize = no_discovery || !exclude_set.is_empty();

            let available: Vec<address::HostHit> = if let Some(subnet_str) = subnet {
                match parse_subnet(&subnet_str) {
                    Ok(network) => {
                        if format == OutputFormat::Text {
                            println!(
                                "\n##### {} scanning subnet: {} #####\n",
                                "Started".bright_blue(),
                                subnet_str.as_str().bright_green()
                            );
                        }
                        if materialize {
                            scan_filtered(
                                address::subnet_addresses(network),
                                &exclude_set,
                                no_discovery,
                                timeout,
                                retries,
                            )
                        } else {
                            address::scan_subnet_with_retries(network, timeout, retries)
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                }
            } else if let Some(target_str) = target {
                match parse_ip(&target_str) {
                    Ok(ip) => {
                        if format == OutputFormat::Text {
                            println!(
                                "\n##### {} scanning target: {} #####\n",
                                "Started".bright_blue(),
                                target_str.as_str().bright_green()
                            );
                        }
                        if materialize {
                            scan_filtered(vec![ip], &exclude_set, no_discovery, timeout, retries)
                        } else {
                            address::scan_address_with_retries(ip, timeout, retries)
                                .into_iter()
                                .collect()
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                }
            } else if let Some(range_vec) = range {
                // clap enforces exactly two values via `num_args = 2`.
                match (parse_ip(&range_vec[0]), parse_ip(&range_vec[1])) {
                    (Ok(start), Ok(end)) => {
                        if format == OutputFormat::Text {
                            println!(
                                "\n##### {} scanning range: {} - {} #####\n",
                                "Started".bright_blue(),
                                range_vec[0].as_str().bright_green(),
                                range_vec[1].as_str().bright_green()
                            );
                        }
                        if materialize {
                            scan_filtered(
                                address::range_addresses(start, end),
                                &exclude_set,
                                no_discovery,
                                timeout,
                                retries,
                            )
                        } else {
                            address::scan_ip_range_with_retries(start, end, timeout, retries)
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                }
            } else {
                eprintln!("{}", "Please specify either -s, -t, or -r".yellow());
                return;
            };

            match format {
                OutputFormat::Text => {
                    if !available.is_empty() {
                        println!("\n-- {} --\n", "Available hosts".green());
                        for hit in &available {
                            println!("{}", hit.ip.to_string().bright_green());
                        }
                    } else {
                        println!("\n{}", "No available hosts found 😕".yellow());
                    }

                    println!("\n##### {} #####\n", "Game Over".bright_red());
                }
                _ => {
                    let records: Vec<ScanRecord> = available
                        .iter()
                        .map(|hit| ScanRecord {
                            ip: hit.ip.to_string(),
                            port: None,
                            proto: "tcp",
                            scan: "connect",
                            latency_ms: hit.latency.as_millis(),
                            status: "up",
                            service: None,
                            banner: None,
                        })
                        .collect();
                    if let Err(e) = emit(&records, format, output_file.as_deref()) {
                        eprintln!("{}", format!("Failed to write output: {}", e).red());
                    }
                }
            }
        }
    }
}
