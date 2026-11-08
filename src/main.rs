use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{Duration, Instant};

use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory, FromArgMatches};
use owo_colors::OwoColorize;
use rayon::prelude::*;

use asphyxia::cli::{Args, DiscoveryMode, ScanMode, Unavailable};
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
    /// `"open|filtered"` (a silent UDP port, or a FIN/NULL/XMAS probe that drew
    /// no RST — RFC 793's honest "cannot tell"), `"closed"` from the stealth
    /// family, or `"unfiltered"`/`"filtered"` from an ACK scan, which reports
    /// what a firewall let through rather than whether anything is listening.
    status: &'static str,
    /// The probe that produced this result: `"connect"`, `"syn"`, `"ack"`,
    /// `"fin"`, `"null"` or `"xmas"`.
    /// Recorded per finding, not per scan, because a raw mode falls back to a
    /// connect probe for individual targets (IPv6) and ports (lost replies).
    scan: &'static str,
    /// Detected service, when `--sV` is on and identification succeeded.
    service: Option<String>,
    /// Raw service banner, when `--sV` is on and one was grabbed.
    banner: Option<String>,
}

/// A lower bound, in seconds, on how long a port scan will take.
///
/// `--delay` paces probes *per host*, so one host's probes span at least
/// `delay × ports` regardless of concurrency; `--rate` is a single global cap,
/// so `jobs ÷ rate` is the other bound. The scan cannot finish faster than
/// either, so the estimate is their maximum. This deliberately ignores
/// connection timeouts and retries: it is a "this will take at least this long"
/// warning, not a prediction.
fn minimum_scan_seconds(
    delay_ms: u64,
    ports_per_host: usize,
    jobs: u64,
    rate_pps: u32,
    concurrency: usize,
) -> u128 {
    let per_host = u128::from(delay_ms) * ports_per_host as u128 / 1000;
    // The pool can interleave hosts, so the delay's total thread-time is
    // delay × jobs; with C workers the scan cannot finish faster than that
    // divided by C. A single host still needs delay × ports, hence the floor.
    let parallel = if concurrency > 0 {
        u128::from(delay_ms) * u128::from(jobs) / concurrency as u128 / 1000
    } else {
        0
    };
    let delay_bound = per_host.max(parallel);
    let rate_bound = if rate_pps > 0 {
        u128::from(jobs) / u128::from(rate_pps)
    } else {
        0
    };
    delay_bound.max(rate_bound)
}

/// Resolve the `--discovery` value into an ordered, de-duplicated probe plan.
/// `auto` expands to ARP, ICMP, TCP and must stand alone; the raw probes that
/// cannot run are dropped later, with a warning, once the targets are known.
fn resolve_discovery_plan(requested: &[DiscoveryMode]) -> Result<Vec<DiscoveryMode>, String> {
    if requested.is_empty() {
        return Ok(vec![DiscoveryMode::Tcp]);
    }
    if requested.contains(&DiscoveryMode::Auto) {
        if requested.len() > 1 {
            return Err("--discovery auto cannot be combined with explicit probes".to_string());
        }
        return Ok(vec![
            DiscoveryMode::Arp,
            DiscoveryMode::Icmp,
            DiscoveryMode::Tcp,
        ]);
    }
    let mut plan = Vec::new();
    for mode in requested {
        if !plan.contains(mode) {
            plan.push(*mode);
        }
    }
    Ok(plan)
}

/// Whether the plan is the plain TCP discovery path, which can stay lazy and
/// avoid materializing a large subnet.
fn tcp_only(plan: &[DiscoveryMode]) -> bool {
    plan == [DiscoveryMode::Tcp]
}

/// A negative host-discovery outcome. Kept out of the default report (only up
/// hosts are listed) and emitted when `--show-down` asks for it.
struct DownHit {
    ip: IpAddr,
    /// `"unreachable"` for an ICMP destination-unreachable (a fact) or
    /// `"no-response"` for silence after the retry budget.
    reason: &'static str,
}

/// The full outcome of an address scan: the hosts that answered plus the
/// negative ICMP outcomes, which the caller may choose to include.
struct DiscoveryReport {
    up: Vec<address::HostHit>,
    down: Vec<DownHit>,
}

impl DiscoveryReport {
    /// A report with no negative outcomes (TCP, ARP and `-Pn` scans).
    fn up_only(up: Vec<address::HostHit>) -> Self {
        Self {
            up,
            down: Vec::new(),
        }
    }
}

/// Build the structured record for a negative ICMP outcome. Kept separate so
/// the `reason`/`status` shape is unit-testable without a raw socket.
fn down_record(down: &DownHit) -> ScanRecord {
    ScanRecord {
        ip: down.ip.to_string(),
        port: None,
        proto: "icmp",
        scan: "icmp",
        latency_ms: 0,
        status: "down",
        service: None,
        banner: None,
        discovery: Some("icmp"),
        mac: None,
        oui: None,
        reason: Some(down.reason),
        ptr: None,
        ptr_confirmed: None,
    }
}

/// Mark every address as up without probing, for `-Pn` (skip discovery). The
/// latency is zero since no probe was sent.
fn all_up(addrs: Vec<IpAddr>) -> Vec<address::HostHit> {
    addrs
        .into_iter()
        .map(|ip| address::HostHit {
            ip,
            latency: Duration::ZERO,
            discovery: "none",
            mac: None,
            oui: None,
            ptr: None,
            ptr_confirmed: None,
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
fn run_nmap_handoff(
    resolved: &[(String, String)],
    opened: &[(usize, Finding)],
    extra: &[String],
    udp: bool,
) {
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
        match nmap::run_nmap(host, &ports, extra, udp) {
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
/// or scan them. When `discovery` is ARP, locally-connected IPv4 targets are
/// probed with an ARP request first; anything that doesn't answer (or isn't on
/// a local subnet) falls back to the TCP probe.
fn scan_filtered(
    addrs: Vec<IpAddr>,
    exclude: &ExcludeSet,
    no_discovery: bool,
    discovery: &[DiscoveryMode],
    timeout: Option<Duration>,
    retries: u32,
    ports: &[u16],
) -> DiscoveryReport {
    let filtered: Vec<IpAddr> = addrs
        .into_iter()
        .filter(|ip| !exclude.contains(*ip))
        .collect();
    if no_discovery {
        DiscoveryReport::up_only(all_up(filtered))
    } else {
        scan_discovery(filtered, discovery, timeout, retries, ports)
    }
}

/// Probe each address with an ARP request first (for locally-connected IPv4),
/// falling back to the TCP probe for anything that doesn't answer or isn't on a
/// local subnet. Returns one [`address::HostHit`] per up host, sorted by
/// address, tagged with how it was confirmed and its MAC when known.
///
/// The ARP probes run in parallel through the shared rayon pool. When no target
/// can be reached by ARP (no local IPv4 target, no MAC, or no permission to open
/// a pcap capture), the fallback is reported once and the whole list goes to TCP.
fn scan_hosts_arp_first(
    addrs: Vec<IpAddr>,
    timeout: Option<Duration>,
    retries: u32,
    ports: &[u16],
) -> Vec<address::HostHit> {
    use asphyxia::scanner::discovery::arp;

    let timeout = timeout.unwrap_or(Duration::from_millis(2000));
    if !arp::prepare(&addrs) {
        eprintln!(
            "{}",
            "ARP discovery is unavailable for these targets (needs a local IPv4 target with a MAC, root/CAP_NET_RAW and libpcap) — falling back to TCP"
                .yellow()
        );
        return address::scan_hosts_with_ports(addrs, Some(timeout), retries, ports);
    }

    let pb = progress_bar(addrs.len() as u64, "ARP probes");
    let probed: Vec<(IpAddr, Option<address::HostHit>)> = addrs
        .into_par_iter()
        .map(|ip| {
            let hit = match ip {
                IpAddr::V4(v4) => {
                    arp::arp_probe_with_retries(v4, timeout, retries).map(|hit| address::HostHit {
                        ip: IpAddr::V4(hit.ip),
                        latency: hit.latency,
                        discovery: "arp",
                        mac: Some(hit.mac.to_string()),
                        oui: Some(hit.mac.oui()),
                        ptr: None,
                        ptr_confirmed: None,
                    })
                }
                IpAddr::V6(_) => None,
            };
            pb.inc(1);
            (ip, hit)
        })
        .collect();
    pb.finish_with_message("ARP probing completed");

    let mut hits: Vec<address::HostHit> = Vec::new();
    let mut tcp_fallback: Vec<IpAddr> = Vec::new();
    for (ip, hit) in probed {
        match hit {
            Some(hit) => hits.push(hit),
            // Not local, not IPv4, or no ARP reply — fall back to TCP.
            None => tcp_fallback.push(ip),
        }
    }

    if !tcp_fallback.is_empty() {
        hits.extend(address::scan_hosts_with_ports(
            tcp_fallback,
            Some(timeout),
            retries,
            ports,
        ));
    }

    hits.sort_by_key(|h| h.ip);
    hits
}

/// Probe each IPv4 address with an ICMP echo, in parallel through the shared
/// pool. Hosts that answer become `HostHit`s; an ICMP unreachable and silence
/// after the retry budget are both negative outcomes (a destination-unreachable
/// is a fact, silence is its own `no-response` verdict, not the same guess).
///
/// If the raw socket is unavailable (no root/`CAP_NET_RAW`, or only IPv6
/// targets), the whole list falls back to TCP with one warning.
fn scan_hosts_icmp(
    addrs: Vec<IpAddr>,
    timeout: Option<Duration>,
    retries: u32,
    ports: &[u16],
) -> DiscoveryReport {
    use asphyxia::scanner::discovery::icmp;

    let timeout = timeout.unwrap_or(Duration::from_millis(2000));
    if !icmp::prepare(&addrs) {
        eprintln!(
            "{}",
            "ICMP discovery is unavailable for these targets (IPv4 only; needs root/CAP_NET_RAW) — falling back to TCP"
                .yellow()
        );
        return DiscoveryReport::up_only(address::scan_hosts_with_ports(
            addrs,
            Some(timeout),
            retries,
            ports,
        ));
    }

    let pb = progress_bar(addrs.len() as u64, "ICMP probes");
    let probed: Vec<(IpAddr, icmp::IcmpProbe)> = addrs
        .into_par_iter()
        .map(|ip| {
            let outcome = match ip {
                IpAddr::V4(v4) => icmp::probe_with_retries(v4, timeout, retries),
                // IPv6 cannot be reached by this IPv4 raw socket; send it to TCP.
                IpAddr::V6(_) => icmp::IcmpProbe::Unavailable,
            };
            pb.inc(1);
            (ip, outcome)
        })
        .collect();
    pb.finish_with_message("ICMP probing completed");

    let mut up: Vec<address::HostHit> = Vec::new();
    let mut down: Vec<DownHit> = Vec::new();
    let mut tcp_fallback: Vec<IpAddr> = Vec::new();
    for (ip, outcome) in probed {
        match outcome {
            icmp::IcmpProbe::Up(latency) => up.push(address::HostHit {
                ip,
                latency,
                discovery: "icmp",
                mac: None,
                oui: None,
                ptr: None,
                ptr_confirmed: None,
            }),
            // Both are negative, but a destination-unreachable is a fact and
            // silence is its own verdict. Keep them distinct for --show-down.
            icmp::IcmpProbe::Unreachable => down.push(DownHit {
                ip,
                reason: "unreachable",
            }),
            icmp::IcmpProbe::NoResponse => down.push(DownHit {
                ip,
                reason: "no-response",
            }),
            icmp::IcmpProbe::Unavailable => tcp_fallback.push(ip),
        }
    }

    if !tcp_fallback.is_empty() {
        up.extend(address::scan_hosts_with_ports(
            tcp_fallback,
            Some(timeout),
            retries,
            ports,
        ));
    }
    up.sort_by_key(|h| h.ip);
    DiscoveryReport { up, down }
}

/// Run the resolved discovery plan. Single-probe plans keep their specialized
/// implementations (including their own TCP fallback); a combination goes
/// through [`scan_hosts_combined`].
fn scan_discovery(
    addrs: Vec<IpAddr>,
    plan: &[DiscoveryMode],
    timeout: Option<Duration>,
    retries: u32,
    ports: &[u16],
) -> DiscoveryReport {
    match plan {
        [DiscoveryMode::Tcp] => DiscoveryReport::up_only(address::scan_hosts_with_ports(
            addrs, timeout, retries, ports,
        )),
        [DiscoveryMode::Arp] => {
            DiscoveryReport::up_only(scan_hosts_arp_first(addrs, timeout, retries, ports))
        }
        [DiscoveryMode::Icmp] => scan_hosts_icmp(addrs, timeout, retries, ports),
        _ => scan_hosts_combined(addrs, plan, timeout, retries, ports),
    }
}

/// Try several discovery probes per address, in the requested order, and report
/// a host as soon as any probe confirms it. A probe that cannot run (no local
/// L2 segment, IPv6, missing privileges) is dropped with one warning instead of
/// failing the scan. ICMP unreachable/no-response is remembered as the negative
/// reason if no later probe finds the host.
fn scan_hosts_combined(
    addrs: Vec<IpAddr>,
    plan: &[DiscoveryMode],
    timeout: Option<Duration>,
    retries: u32,
    ports: &[u16],
) -> DiscoveryReport {
    use asphyxia::scanner::discovery::{arp, icmp};

    let timeout = timeout.unwrap_or(Duration::from_millis(2000));
    let mut active: Vec<DiscoveryMode> = plan.to_vec();

    // ARP only makes sense when some target is on a local IPv4 subnet. Do not
    // warn about it for an entirely routed target set.
    if active.contains(&DiscoveryMode::Arp) {
        let any_local = addrs
            .iter()
            .any(|ip| matches!(ip, IpAddr::V4(v4) if arp::is_local_ipv4(*v4)));
        if !any_local {
            active.retain(|mode| *mode != DiscoveryMode::Arp);
        } else if !arp::prepare(&addrs) {
            eprintln!(
                "{}",
                "ARP discovery is unavailable (needs root/CAP_NET_RAW + libpcap) — skipping it"
                    .yellow()
            );
            active.retain(|mode| *mode != DiscoveryMode::Arp);
        }
    }

    // ICMP is IPv4-only and needs a raw socket.
    if active.contains(&DiscoveryMode::Icmp) {
        if !addrs.iter().any(IpAddr::is_ipv4) {
            active.retain(|mode| *mode != DiscoveryMode::Icmp);
        } else if !icmp::prepare(&addrs) {
            eprintln!(
                "{}",
                "ICMP discovery is unavailable (IPv4 only; needs root/CAP_NET_RAW) — skipping it"
                    .yellow()
            );
            active.retain(|mode| *mode != DiscoveryMode::Icmp);
        }
    }

    if active.is_empty() {
        active.push(DiscoveryMode::Tcp);
    }
    if active.len() == 1 {
        return match active[0] {
            DiscoveryMode::Tcp => DiscoveryReport::up_only(address::scan_hosts_with_ports(
                addrs,
                Some(timeout),
                retries,
                ports,
            )),
            DiscoveryMode::Arp => {
                DiscoveryReport::up_only(scan_hosts_arp_first(addrs, Some(timeout), retries, ports))
            }
            DiscoveryMode::Icmp => scan_hosts_icmp(addrs, Some(timeout), retries, ports),
            // Resolved plans never contain Auto.
            DiscoveryMode::Auto => DiscoveryReport::up_only(address::scan_hosts_with_ports(
                addrs,
                Some(timeout),
                retries,
                ports,
            )),
        };
    }

    let pb = progress_bar(addrs.len() as u64, "discovery probes");
    let probed: Vec<(IpAddr, Option<address::HostHit>, Option<&'static str>)> = addrs
        .into_par_iter()
        .map(|ip| {
            let mut down_reason = None;
            for mode in &active {
                match mode {
                    DiscoveryMode::Tcp => {
                        if let Some(hit) =
                            address::scan_address_with_ports(ip, Some(timeout), retries, ports)
                        {
                            pb.inc(1);
                            return (ip, Some(hit), None);
                        }
                    }
                    DiscoveryMode::Arp => {
                        if let IpAddr::V4(v4) = ip
                            && let Some(hit) = arp::arp_probe_with_retries(v4, timeout, retries)
                        {
                            pb.inc(1);
                            return (
                                ip,
                                Some(address::HostHit {
                                    ip,
                                    latency: hit.latency,
                                    discovery: "arp",
                                    mac: Some(hit.mac.to_string()),
                                    oui: Some(hit.mac.oui()),
                                    ptr: None,
                                    ptr_confirmed: None,
                                }),
                                None,
                            );
                        }
                    }
                    DiscoveryMode::Icmp => {
                        if let IpAddr::V4(v4) = ip {
                            match icmp::probe_with_retries(v4, timeout, retries) {
                                icmp::IcmpProbe::Up(latency) => {
                                    pb.inc(1);
                                    return (
                                        ip,
                                        Some(address::HostHit {
                                            ip,
                                            latency,
                                            discovery: "icmp",
                                            mac: None,
                                            oui: None,
                                            ptr: None,
                                            ptr_confirmed: None,
                                        }),
                                        None,
                                    );
                                }
                                icmp::IcmpProbe::Unreachable => down_reason = Some("unreachable"),
                                icmp::IcmpProbe::NoResponse => down_reason = Some("no-response"),
                                icmp::IcmpProbe::Unavailable => {}
                            }
                        }
                    }
                    DiscoveryMode::Auto => {}
                }
            }
            pb.inc(1);
            (ip, None, down_reason)
        })
        .collect();
    pb.finish_with_message("Discovery completed");

    let mut up: Vec<address::HostHit> = Vec::new();
    let mut down: Vec<DownHit> = Vec::new();
    for (ip, hit, reason) in probed {
        match (hit, reason) {
            (Some(hit), _) => up.push(hit),
            (None, Some(reason)) => down.push(DownHit { ip, reason }),
            (None, None) => {}
        }
    }
    up.sort_by_key(|h| h.ip);
    down.sort_by_key(|d| d.ip);
    DiscoveryReport { up, down }
}

/// Map a persisted status string back to the `&'static str` the report uses.
fn status_str(status: &str) -> &'static str {
    match status {
        "open|filtered" => "open|filtered",
        "unfiltered" => "unfiltered",
        "filtered" => "filtered",
        "closed" => "closed",
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
        "fin" => "fin",
        "null" => "null",
        "xmas" => "xmas",
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

/// Probe one port with a FIN/NULL/XMAS profile and report what RFC 793 says it
/// means: an RST back is `closed`, silence is the honest `open|filtered` — an
/// open port drops these unexpected segments just as surely as a filter does,
/// so the two are never merged into a plain `open`.
///
/// Only silence is retried (a lost probe and an open/filtered one look alike),
/// while a definitive RST is final. Returns `None` when the raw path is
/// unusable, so the caller falls back to a connect probe.
fn stealth_probe(
    mode: syn::ProbeMode,
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
    retries: u32,
) -> Option<Finding> {
    let start = Instant::now();
    let mut outcome = None;
    for _ in 0..=retries {
        outcome = syn::probe_port(mode, ip, port, timeout);
        if outcome != Some(syn::ProbeOutcome::Filtered) {
            break;
        }
    }
    let status = match outcome {
        // A closed port answers with an RST; that is the only definitive state.
        Some(syn::ProbeOutcome::Closed) => "closed",
        // Silence: open or filtered, and we say exactly that.
        Some(syn::ProbeOutcome::Filtered) => "open|filtered",
        // FIN/NULL/XMAS never yield open/unfiltered; `None` means the raw path
        // failed, and both leave the fallback to the caller.
        Some(syn::ProbeOutcome::Open | syn::ProbeOutcome::Unfiltered) | None => return None,
    };
    Some(Finding {
        port,
        latency: start.elapsed(),
        status,
        scan: mode.label(),
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
/// [`ScanMode::Ack`], [`ScanMode::Fin`], [`ScanMode::Null`] and
/// [`ScanMode::Xmas`] the raw result stands on its own — a connect probe cannot
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
        let hit = port::scan_udp_port(ip, port, timeout, retries);
        return Some(Finding {
            port: hit.port,
            latency: hit.latency,
            status: hit.status,
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
            syn::ProbeMode::Fin | syn::ProbeMode::Null | syn::ProbeMode::Xmas => {
                if let Some(finding) = stealth_probe(probe, v4, port, connect_timeout, retries) {
                    return Some(finding);
                }
            }
            syn::ProbeMode::Syn => {
                let syn_started = Instant::now();
                match syn::syn_scan_port(v4, port, connect_timeout) {
                    Some(syn::ProbeOutcome::Open) => {
                        let latency = syn_started.elapsed();
                        let (service, banner) = if detect_service {
                            service::detect(&ip, port, connect_timeout)
                        } else {
                            (None, None)
                        };
                        return Some(Finding {
                            port,
                            latency,
                            status: "open",
                            scan: "syn",
                            service,
                            banner,
                        });
                    }
                    Some(syn::ProbeOutcome::Closed) => return None,
                    // Filtered, or raw socket unusable: fall back to a connect probe.
                    Some(syn::ProbeOutcome::Filtered | syn::ProbeOutcome::Unfiltered) | None => {}
                }
            }
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

    // Install the global pacer: a rate cap and/or a minimum inter-probe delay
    // (with optional jitter). The stricter of the two always wins, so combining
    // them never exceeds either bound. A no-op when neither is set.
    let pps = args.rate().unwrap_or(0);
    let delay_ms = args.delay().unwrap_or(0);
    let jitter_pct = args.jitter().unwrap_or(0);
    rate::install(pps, delay_ms, jitter_pct);

    // Capture the delay and concurrency before `args` is moved into the
    // subcommand match below.
    let requested_delay_ms = args.delay();
    let scan_concurrency = args.concurrency().max(1);

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
            source_port,
            ..
        } => {
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
                        format!("--source-port {port} applies to raw scans only — ignoring it for this scan").yellow()
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

            // Warn when the effective scan duration becomes unreasonable. The
            // delay is per host, so one host's probes span at least
            // delay × ports; a global --rate adds a jobs ÷ rate bound. A large
            // sweep with a generous delay can take hours — say so before it
            // starts rather than after.
            if let Some(delay_ms) = requested_delay_ms.filter(|d| *d > 0 && !resolved.is_empty()) {
                let jobs = resolved.len() as u64 * ports.len() as u64;
                let min_secs =
                    minimum_scan_seconds(delay_ms, ports.len(), jobs, pps, scan_concurrency);
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
                    // An ACK, FIN/NULL/XMAS or UDP scan lists a state for every
                    // probed port, not a list of open ports, so it gets its own
                    // heading.
                    let reports_states =
                        udp || mode == ScanMode::Ack || mode.silent_means_open_filtered();
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
                    } else if reports_states {
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
                            discovery: None,
                            mac: None,
                            oui: None,
                            reason: None,
                            ptr: None,
                            ptr_confirmed: None,
                        })
                        .collect();
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
        Args::AddressScan {
            subnet,
            target,
            range,
            no_discovery,
            discovery: discovery_modes,
            discovery_ports,
            show_down,
            resolve_ptr,
            exclude,
            exclude_file,
            timeout,
            ..
        } => {
            let ptr_timeout = Duration::from_millis(timeout);
            let timeout = Some(ptr_timeout);

            // Resolve --discovery before any probing. `auto` expands to the
            // broadest sensible order; explicit combinations keep their order.
            let plan = match resolve_discovery_plan(&discovery_modes) {
                Ok(plan) => plan,
                Err(e) => {
                    eprintln!("{}", e.red());
                    std::process::exit(2);
                }
            };
            if discovery_modes.contains(&DiscoveryMode::Auto) {
                eprintln!(
                    "{}",
                    "discovery auto: arp,icmp,tcp — probes that cannot run are skipped"
                        .bright_black()
                );
            }

            // Host discovery ports: the default TCP spread unless overridden.
            let custom_discovery_ports = discovery_ports.is_some();
            let ports: Vec<u16> = match discovery_ports {
                Some(spec) => match parse_ports(&spec) {
                    Ok(ports) => ports,
                    Err(e) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                },
                None => address::PROBE_PORTS.to_vec(),
            };
            if ports.is_empty() || ports.contains(&0) {
                eprintln!(
                    "{}",
                    "--discovery-ports must contain at least one port in 1..=65535".yellow()
                );
                return;
            }
            if custom_discovery_ports && plan.iter().any(|mode| *mode != DiscoveryMode::Tcp) {
                eprintln!(
                    "{}",
                    "--discovery-ports applies to TCP discovery and the TCP fallback of arp/icmp — it does not change the raw probe itself"
                        .yellow()
                );
            }
            let ports = ports.as_slice();
            let plan = plan.as_slice();

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

            let mut available: DiscoveryReport = if let Some(subnet_str) = subnet {
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
                                plan,
                                timeout,
                                retries,
                                ports,
                            )
                        } else if tcp_only(plan) {
                            DiscoveryReport::up_only(address::scan_subnet_with_ports(
                                network, timeout, retries, ports,
                            ))
                        } else {
                            scan_discovery(
                                address::subnet_addresses(network),
                                plan,
                                timeout,
                                retries,
                                ports,
                            )
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
                            scan_filtered(
                                vec![ip],
                                &exclude_set,
                                no_discovery,
                                plan,
                                timeout,
                                retries,
                                ports,
                            )
                        } else if tcp_only(plan) {
                            DiscoveryReport::up_only(
                                address::scan_address_with_ports(ip, timeout, retries, ports)
                                    .into_iter()
                                    .collect(),
                            )
                        } else {
                            scan_discovery(vec![ip], plan, timeout, retries, ports)
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
                                plan,
                                timeout,
                                retries,
                                ports,
                            )
                        } else if tcp_only(plan) {
                            DiscoveryReport::up_only(address::scan_ip_range_with_ports(
                                start, end, timeout, retries, ports,
                            ))
                        } else {
                            scan_discovery(
                                address::range_addresses(start, end),
                                plan,
                                timeout,
                                retries,
                                ports,
                            )
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

            // Optional reverse-DNS enrichment. Each lookup has its own timeout,
            // so a slow resolver cannot extend the scan past that budget.
            if resolve_ptr {
                available.up.par_iter_mut().for_each(|hit| {
                    let (ptr, confirmed) = asphyxia::dns::resolve_ptr(hit.ip, ptr_timeout);
                    hit.ptr = ptr;
                    hit.ptr_confirmed = confirmed;
                });
            }

            match format {
                OutputFormat::Text => {
                    if !available.up.is_empty() {
                        println!("\n-- {} --\n", "Available hosts".green());
                        for hit in &available.up {
                            let mut line = hit.ip.to_string().bright_green().to_string();
                            if let Some(mac) = &hit.mac {
                                line.push_str(&format!(" {}", mac.as_str().dimmed()));
                            }
                            if let Some(ptr) = &hit.ptr {
                                line.push_str(&format!(" {}", ptr.dimmed()));
                                if hit.ptr_confirmed == Some(false) {
                                    line.push_str(" (unconfirmed)");
                                }
                            }
                            println!("{}", line);
                        }
                    } else {
                        println!("\n{}", "No available hosts found 😕".yellow());
                    }
                    if show_down && !available.down.is_empty() {
                        println!("\n-- {} --\n", "Unreachable / no response".yellow());
                        for down in &available.down {
                            println!(
                                "{} {}",
                                down.ip.to_string().bright_yellow(),
                                down.reason.dimmed()
                            );
                        }
                    }

                    println!("\n##### {} #####\n", "Game Over".bright_red());
                }
                _ => {
                    let mut records: Vec<ScanRecord> = available
                        .up
                        .iter()
                        .map(|hit| ScanRecord {
                            ip: hit.ip.to_string(),
                            port: None,
                            // ARP/ICMP-confirmed hosts were not probed over TCP.
                            proto: match hit.discovery {
                                "arp" => "arp",
                                "icmp" => "icmp",
                                _ => "tcp",
                            },
                            scan: match hit.discovery {
                                "arp" => "arp",
                                "icmp" => "icmp",
                                "none" => "none",
                                _ => "connect",
                            },
                            latency_ms: hit.latency.as_millis(),
                            status: "up",
                            service: None,
                            banner: None,
                            discovery: Some(hit.discovery),
                            mac: hit.mac.clone(),
                            oui: hit.oui.clone(),
                            reason: None,
                            ptr: hit.ptr.clone(),
                            ptr_confirmed: hit.ptr_confirmed,
                        })
                        .collect();
                    if show_down {
                        records.extend(available.down.iter().map(down_record));
                    }
                    if let Err(e) = emit(&records, format, output_file.as_deref()) {
                        eprintln!("{}", format!("Failed to write output: {}", e).red());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DiscoveryMode, minimum_scan_seconds, resolve_discovery_plan, tcp_only};

    #[test]
    fn delay_estimate_is_per_host_not_per_job() {
        // 1 s delay over 100 ports on one host is 100 s, independent of how
        // many hosts run concurrently.
        assert_eq!(minimum_scan_seconds(1000, 100, 1000, 0, 256), 100);
        assert_eq!(minimum_scan_seconds(1000, 100, 10_000, 0, 256), 100);
    }

    #[test]
    fn serial_runs_are_bounded_by_the_whole_job_set() {
        // Concurrency 1 means every delayed probe waits its turn: 10 hosts ×
        // 100 ports × 1 s = 10,000 s, not just one host's 100 s.
        assert_eq!(minimum_scan_seconds(1000, 100, 10_000, 0, 1), 10_000);
    }

    #[test]
    fn rate_estimate_is_global() {
        // 1000 jobs at 10 probes/second needs at least 100 s.
        assert_eq!(minimum_scan_seconds(0, 100, 1000, 10, 256), 100);
    }

    #[test]
    fn estimate_takes_the_stricter_bound() {
        // 500 ms × 100 ports = 50 s per host; 1000 jobs at 10/s = 100 s.
        // The rate cap is the stricter bound.
        assert_eq!(minimum_scan_seconds(500, 100, 1000, 10, 256), 100);
    }

    #[test]
    fn no_delay_and_no_rate_is_zero() {
        assert_eq!(minimum_scan_seconds(0, 100, 1000, 0, 256), 0);
    }

    #[test]
    fn auto_plan_expands_to_arp_icmp_tcp() {
        assert_eq!(
            resolve_discovery_plan(&[DiscoveryMode::Auto]).unwrap(),
            vec![DiscoveryMode::Arp, DiscoveryMode::Icmp, DiscoveryMode::Tcp]
        );
    }

    #[test]
    fn auto_must_stand_alone() {
        assert!(resolve_discovery_plan(&[DiscoveryMode::Auto, DiscoveryMode::Tcp]).is_err());
    }

    #[test]
    fn plan_deduplicates_and_keeps_order() {
        assert_eq!(
            resolve_discovery_plan(&[DiscoveryMode::Icmp, DiscoveryMode::Tcp, DiscoveryMode::Icmp])
                .unwrap(),
            vec![DiscoveryMode::Icmp, DiscoveryMode::Tcp]
        );
        assert_eq!(
            resolve_discovery_plan(&[]).unwrap(),
            vec![DiscoveryMode::Tcp]
        );
    }

    #[test]
    fn only_a_single_tcp_probe_is_the_lazy_path() {
        assert!(tcp_only(&[DiscoveryMode::Tcp]));
        assert!(!tcp_only(&[DiscoveryMode::Tcp, DiscoveryMode::Icmp]));
        assert!(!tcp_only(&[DiscoveryMode::Arp]));
    }

    #[test]
    fn down_records_keep_the_reason_distinct() {
        let unreachable = super::down_record(&super::DownHit {
            ip: "192.0.2.1".parse().unwrap(),
            reason: "unreachable",
        });
        assert_eq!(unreachable.status, "down");
        assert_eq!(unreachable.reason, Some("unreachable"));
        assert_eq!(unreachable.discovery, Some("icmp"));
        assert_eq!(unreachable.proto, "icmp");
        assert_eq!(unreachable.scan, "icmp");

        let silent = super::down_record(&super::DownHit {
            ip: "192.0.2.2".parse().unwrap(),
            reason: "no-response",
        });
        assert_eq!(silent.reason, Some("no-response"));
        assert_ne!(unreachable.reason, silent.reason);
    }
}
