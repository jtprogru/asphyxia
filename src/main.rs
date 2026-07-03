use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use clap::Parser;
use owo_colors::OwoColorize;
use rayon::prelude::*;

use asphyxia::cli::Args;
use asphyxia::output::{OutputFormat, ScanRecord, emit};
use asphyxia::scanner::exclude::ExcludeSet;
use asphyxia::scanner::well_known::{named_port_set, top_ports};
use asphyxia::scanner::{address, nmap, port};
use asphyxia::utils::{
    init_scan_pool, parse_ip, parse_ports, parse_subnet, progress_bar, read_targets_from_stdin,
};

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
fn run_nmap_handoff(
    resolved: &[(String, String)],
    opened: &[(usize, port::PortHit)],
    extra: &[String],
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

fn main() {
    let args = Args::parse();

    // Size the global rayon pool for I/O-bound scanning before any scan runs.
    init_scan_pool(args.concurrency());

    let format = args.output_format();
    let output_file = args.output_file().cloned();
    let retries = args.retries();

    match args {
        Args::PortScan {
            host,
            stdin,
            range,
            specific,
            all_ports,
            top_ports: top_n,
            port_set,
            exclude_ports,
            exclude_cdn,
            nmap,
            nmap_args,
            timeout,
            ..
        } => {
            let timeout = Some(Duration::from_millis(timeout));

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

            // Gather the raw targets: either the single `-t` host, or a batch
            // read from stdin (clap guarantees exactly one of the two is set).
            let targets: Vec<String> = if stdin {
                let targets = read_targets_from_stdin();
                if targets.is_empty() {
                    eprintln!("{}", "No targets read from stdin".yellow());
                    return;
                }
                targets
            } else {
                // clap's required `target` group guarantees `host` is present.
                vec![host.expect("clap enforces --host when --stdin is absent")]
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

            let mut opened: Vec<(usize, port::PortHit)> = jobs
                .into_par_iter()
                .filter_map(|(i, port)| {
                    let hit =
                        port::scan_port_with_retries(resolved[i].1.clone(), port, timeout, retries);
                    pb.inc(1);
                    hit.map(|hit| (i, hit))
                })
                .collect();

            pb.finish_with_message("Scan completed");

            opened.sort_by_key(|(i, hit)| (*i, hit.port));

            match format {
                OutputFormat::Text => {
                    if !opened.is_empty() {
                        let mut current: Option<usize> = None;
                        for (i, hit) in &opened {
                            let host = &resolved[*i].0;
                            if current != Some(*i) {
                                println!(
                                    "\n-- {} for {} --\n",
                                    "Opened ports".green(),
                                    host.bright_yellow()
                                );
                                current = Some(*i);
                            }
                            println!(
                                "{}:{}",
                                host.bright_cyan(),
                                hit.port.to_string().bright_green()
                            );
                        }
                    } else {
                        println!("\n{}", "No open ports found 😕".yellow());
                    }

                    println!("\n##### {} #####\n", "Game Over".bright_red());
                }
                _ => {
                    let records: Vec<ScanRecord> = opened
                        .iter()
                        .map(|(i, hit)| ScanRecord {
                            ip: resolved[*i].1.clone(),
                            port: Some(hit.port),
                            proto: "tcp",
                            latency_ms: hit.latency.as_millis(),
                            status: "open",
                        })
                        .collect();
                    if let Err(e) = emit(&records, format, output_file.as_deref()) {
                        eprintln!("{}", format!("Failed to write output: {}", e).red());
                    }
                }
            }

            // Optional deep-dive: hand each host's open ports to nmap.
            if nmap {
                let extra = nmap_args.as_deref().map(nmap::split_extra_args);
                run_nmap_handoff(&resolved, &opened, extra.as_deref().unwrap_or(&[]));
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
            // materialises the whole address space.
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
                            latency_ms: hit.latency.as_millis(),
                            status: "up",
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
