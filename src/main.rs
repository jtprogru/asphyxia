use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{Duration, Instant};

use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory, FromArgMatches};
use owo_colors::OwoColorize;
use rayon::prelude::*;

use asphyxia::cli::{Args, DiscoveryMode, ScanMode};
use asphyxia::config::Config;
use asphyxia::output::ScanRecord;
use asphyxia::rate;
use asphyxia::resume::{ScanState, StateFinding};
use asphyxia::scanner::exclude::ExcludeSet;
use asphyxia::scanner::{address, nmap, port, service, syn};
use asphyxia::timing;
use asphyxia::utils::{init_scan_pool, progress_bar};

mod commands;

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
        device_type: None,
        device_confidence: None,
        asn: None,
        asn_org: None,
        cloud: None,
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

/// Look up offline ASN metadata for `ip` when `--asn` is enabled.
fn asn_info(ip: IpAddr, enabled: bool) -> Option<asphyxia::asn::AsnInfo> {
    if enabled {
        asphyxia::asn::lookup(ip)
    } else {
        None
    }
}

/// Build the canonical records for an address scan: up hosts plus, when
/// requested, ICMP non-responders.
fn address_records(
    available: &DiscoveryReport,
    classify: bool,
    asn_enabled: bool,
    show_down: bool,
) -> Vec<ScanRecord> {
    let mut records: Vec<ScanRecord> = available
        .up
        .iter()
        .map(|hit| {
            let info = asn_info(hit.ip, asn_enabled);
            let device = if classify {
                Some(
                    hit.oui
                        .as_deref()
                        .map(asphyxia::classify::classify_oui)
                        .unwrap_or_else(asphyxia::classify::Device::unknown),
                )
            } else {
                None
            };
            ScanRecord {
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
                device_type: device.map(|device| device.device_type),
                device_confidence: device.map(|device| device.confidence),
                asn: info.map(|info| info.asn),
                asn_org: info.map(|info| info.asn_org),
                cloud: info.and_then(|info| info.cloud),
            }
        })
        .collect();
    if show_down {
        records.extend(available.down.iter().map(|down| {
            let mut record = down_record(down);
            let info = asn_info(down.ip, asn_enabled);
            record.asn = info.map(|info| info.asn);
            record.asn_org = info.map(|info| info.asn_org);
            record.cloud = info.and_then(|info| info.cloud);
            record
        }));
    }
    records
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
        Some(syn::ProbeOutcome::Filtered | syn::ProbeOutcome::Unreachable) => "filtered",
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
        // An ICMP unreachable is a filter/host actively rejecting the probe.
        Some(syn::ProbeOutcome::Unreachable) => "filtered",
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
                    Some(
                        syn::ProbeOutcome::Filtered
                        | syn::ProbeOutcome::Unfiltered
                        | syn::ProbeOutcome::Unreachable,
                    )
                    | None => {}
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
        // `diff` and `trace` have no scan tunables to resolve here.
        Args::Diff { .. } | Args::Trace { .. } => {}
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
    let requested_mode = args.scan_mode();

    match args {
        Args::PortScan { .. } => {
            commands::port::run(
                args,
                format,
                output_file.clone(),
                requested_mode,
                scan_concurrency,
                pps,
                requested_delay_ms,
            );
        }
        Args::AddressScan { .. } => {
            commands::address::run(args, format, output_file.clone());
        }
        Args::Diff {
            old,
            new,
            output,
            output_file,
        } => {
            if let Err(e) = commands::diff::run(&old, &new, output, output_file.as_deref()) {
                eprintln!("{}", e.red());
                std::process::exit(2);
            }
        }
        Args::Trace {
            target,
            transport,
            port,
            max_hops,
            probes,
            timeout,
            output,
            output_file,
            ..
        } => {
            if let Err(e) = commands::trace::run(
                &target,
                transport,
                port,
                max_hops,
                probes,
                timeout,
                output,
                output_file.as_deref(),
            ) {
                eprintln!("{}", e.red());
                std::process::exit(2);
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
