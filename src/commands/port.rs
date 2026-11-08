//! `asphyxia ps` command: port scanning, service detection, raw modes,
//! classification and optional reports/nmap handoff.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use owo_colors::OwoColorize;
use rayon::prelude::*;

use asphyxia::cli::{Args, ScanMode, Unavailable};
use asphyxia::output::{OutputFormat, ScanRecord, emit};
use asphyxia::scanner::exclude::ExcludeSet;
use asphyxia::scanner::well_known::{named_port_set, top_ports};
use asphyxia::scanner::{nmap, port, syn};
use asphyxia::utils::{parse_ports, progress_bar, read_targets_from_file, read_targets_from_stdin};

use crate::{
    Finding, asn_info, minimum_scan_seconds, run_nmap_handoff, run_resumable_port_scan, scan_one,
};

/// Run a port scan. `main` has already resolved config/CLI precedence and the
/// scan-wide options, so this module owns only the command behavior.
#[allow(clippy::too_many_arguments)]
pub fn run(
    args: Args,
    format: OutputFormat,
    output_file: Option<std::path::PathBuf>,
    requested_mode: ScanMode,
    scan_concurrency: usize,
    pps: u32,
    requested_delay_ms: Option<u64>,
) {
    let Args::PortScan {
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
        classify,
        asn: asn_enabled,
        watch,
        watch_count,
        report,
        report_file,
        full_banners,
        resume,
        nmap,
        nmap_args,
        timeout,
        source_port,
        retries,
        ..
    } = args
    else {
        return;
    };

    if let Some(spec) = watch {
        match super::watch::run_watch(&spec, watch_count) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("{}", e.red());
                std::process::exit(2);
            }
        }
    }

    let connect_timeout = Duration::from_millis(timeout);
    let timeout = Some(connect_timeout);
    let proto = if udp { "udp" } else { "tcp" };

    // `--nmap-args` implies `--nmap`, and nmap writes to stdout, which
    // would corrupt a JSON/JSONL/CSV/grep stream. Reject that pairing
    // before any probing, unless the machine output goes to a file.
    let nmap = nmap || nmap_args.is_some();
    if nmap && format != OutputFormat::Text && output_file.is_none() {
        eprintln!(
        "{}",
        format!(
            "--nmap streams nmap's report to stdout and cannot be combined with -o {}; use text output or --output-file",
            format!("{:?}", format).to_lowercase()
        )
        .red()
    );
        std::process::exit(2);
    }

    // A fixed source port only applies to raw TCP probes. In a connect or
    // UDP scan it has no effect, so say so rather than silently ignore it.
    if let Some(port) = source_port {
        if !requested_mode.needs_raw() || udp {
            eprintln!(
                "{}",
                format!(
                    "--source-port {port} applies to raw scans only — ignoring it for this scan"
                )
                .yellow()
            );
        } else {
            syn::set_source_port(port);
        }
    }

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
                let excluded: std::collections::HashSet<u16> = excluded.into_iter().collect();
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

    // Warn when the effective scan duration becomes unreasonable. The
    // delay is per host, so one host's probes span at least
    // delay × ports; a global --rate adds a jobs ÷ rate bound. A large
    // sweep with a generous delay can take hours — say so before it
    // starts rather than after.
    if let Some(delay_ms) = requested_delay_ms.filter(|d| *d > 0 && !resolved.is_empty()) {
        let jobs = resolved.len() as u64 * ports.len() as u64;
        let min_secs = minimum_scan_seconds(delay_ms, ports.len(), jobs, pps, scan_concurrency);
        if min_secs > 3600 {
            eprintln!(
            "{}",
            format!(
                "with --delay {} ms, each host's {} ports take at least ~{} h; over {} host(s) the scan will take at least ~{} h — consider a narrower port set or a smaller delay",
                delay_ms,
                ports.len(),
                u128::from(delay_ms) * ports.len() as u128 / 1000 / 3600,
                resolved.len(),
                min_secs / 3600
            )
            .yellow()
        );
        }
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
    // known to be open — which an ACK or FIN/NULL/XMAS scan never
    // establishes.
    if service_detection && mode != ScanMode::Connect && mode != ScanMode::Syn {
        eprintln!(
            "{}",
            format!(
                "--sV needs an open port, which a {} scan does not determine — ignoring it",
                mode.label().to_uppercase()
            )
            .yellow()
        );
    }
    let detect_service = service_detection && !udp && mode != ScanMode::Ack;

    // Each raw mode answers a different question than a connect or SYN
    // scan over the same grid, so its checkpoints get their own key and
    // the two can never resume from each other. The key is computed from
    // the *requested* mode: it must match what was asked for even when
    // this run falls back to connect (a resumed FIN checkpoint belongs
    // to a FIN scan, whatever probe actually ran).
    let state_proto = match requested_mode {
        ScanMode::Ack => "tcp-ack",
        ScanMode::Fin => "tcp-fin",
        ScanMode::Null => "tcp-null",
        ScanMode::Xmas => "tcp-xmas",
        _ => proto,
    };

    if format == OutputFormat::Text && report.is_none() {
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
            let is_cdn = cdn
                .as_ref()
                .is_some_and(|c| ip.parse::<IpAddr>().map(|a| c.contains(a)).unwrap_or(false));
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

    // --classify is a pure post-pass over collected results: no extra
    // probes. Only open ports/banners contribute, so ACK/stealth states
    // classify as unknown rather than inventing evidence.
    let classifications: std::collections::HashMap<usize, asphyxia::classify::Device> = if classify
    {
        let mut map = std::collections::HashMap::new();
        for (host_index, _) in resolved.iter().enumerate() {
            let mut ports = Vec::new();
            let mut services = Vec::new();
            let mut banners = Vec::new();
            for (index, finding) in &results {
                if *index == host_index && finding.status == "open" {
                    ports.push(finding.port);
                    if let Some(service) = &finding.service {
                        services.push(service.as_str());
                    }
                    if let Some(banner) = &finding.banner {
                        banners.push(banner.as_str());
                    }
                }
            }
            map.insert(
                host_index,
                asphyxia::classify::classify_ports(&ports, &services, &banners),
            );
        }
        map
    } else {
        std::collections::HashMap::new()
    };

    // Build the canonical records once: both the machine formats and
    // the report renderer consume the same list.
    let records: Vec<ScanRecord> = results
        .iter()
        .map(|(i, f)| {
            let info = resolved[*i]
                .1
                .parse::<IpAddr>()
                .ok()
                .and_then(|ip| asn_info(ip, asn_enabled));
            ScanRecord {
                ip: resolved[*i].1.clone(),
                port: Some(f.port),
                proto,
                scan: f.scan,
                latency_ms: f.latency.as_millis(),
                status: f.status,
                service: f.service.clone(),
                banner: f.banner.clone(),
                discovery: None,
                mac: None,
                oui: None,
                reason: None,
                ptr: None,
                ptr_confirmed: None,
                device_type: classifications.get(i).map(|d| d.device_type),
                device_confidence: classifications.get(i).map(|d| d.confidence),
                asn: info.map(|info| info.asn),
                asn_org: info.map(|info| info.asn_org),
                cloud: info.and_then(|info| info.cloud),
            }
        })
        .collect();

    if let Some(report_format) = report {
        if nmap {
            eprintln!(
                "{}",
                "--report replaces the normal output and skips the --nmap handoff".yellow()
            );
        }
        let scope = resolved
            .iter()
            .map(|(host, _)| host.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let meta = asphyxia::report::ReportMeta {
            targets: &scope,
            timestamp,
            version: env!("CARGO_PKG_VERSION"),
            scan_mode: mode.label(),
        };
        let rendered = asphyxia::report::render(&records, report_format, &meta, full_banners);
        match report_file {
            Some(path) => {
                if let Err(e) = std::fs::write(&path, rendered) {
                    eprintln!(
                        "{}",
                        format!("Failed to write {}: {e}", path.display()).red()
                    );
                }
            }
            None => print!("{rendered}"),
        }
        return;
    }

    match format {
        OutputFormat::Text => {
            // An ACK, FIN/NULL/XMAS or UDP scan lists a state for every
            // probed port, not a list of open ports, so it gets its own
            // heading.
            let reports_states = udp || mode == ScanMode::Ack || mode.silent_means_open_filtered();
            let heading = if reports_states {
                "Port states"
            } else {
                "Opened ports"
            };
            if !results.is_empty() {
                let mut current: Option<usize> = None;
                for (i, f) in &results {
                    let host = &resolved[*i].0;
                    if current != Some(*i) {
                        let mut line =
                            format!("-- {} for {} --", heading.green(), host.bright_yellow());
                        if let Some(device) = classifications.get(i) {
                            line.push_str(&format!(
                                " [{}/{}]",
                                device.device_type, device.confidence
                            ));
                        }
                        if let Some(info) = asn_info(
                            resolved[*i]
                                .1
                                .parse()
                                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                            asn_enabled,
                        ) {
                            line.push_str(&format!(
                                " [AS{}{}]",
                                info.asn,
                                info.cloud
                                    .map(|cloud| format!(" {cloud}"))
                                    .unwrap_or_default()
                            ));
                        }
                        println!("\n{}\n", line);
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
            } else if reports_states {
                println!("\n{}", "No port states observed 😕".yellow());
            } else {
                println!("\n{}", "No open ports found 😕".yellow());
            }

            println!("\n##### {} #####\n", "Game Over".bright_red());
        }
        _ => {
            if let Err(e) = emit(&records, format, output_file.as_deref()) {
                eprintln!("{}", format!("Failed to write output: {}", e).red());
            }
        }
    }

    // Optional deep-dive: hand each host's open ports to nmap. An ACK or
    // FIN/NULL/XMAS scan finds no definitive open ports, so there is
    // nothing to hand over.
    if nmap {
        if mode == ScanMode::Ack || mode.silent_means_open_filtered() {
            eprintln!(
                "{}",
                format!(
                    "--nmap has nothing to hand off: a {} scan does not determine open ports",
                    mode.label().to_uppercase()
                )
                .yellow()
            );
        } else {
            let extra = nmap_args.as_deref().map(nmap::split_extra_args);
            run_nmap_handoff(&resolved, &results, extra.as_deref().unwrap_or(&[]), udp);
        }
    }
}
