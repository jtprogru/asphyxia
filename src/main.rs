use std::time::Duration;

use clap::Parser;
use owo_colors::OwoColorize;
use rayon::prelude::*;

use asphyxia::cli::Args;
use asphyxia::output::{OutputFormat, ScanRecord, emit};
use asphyxia::scanner::well_known::{named_port_set, top_ports};
use asphyxia::scanner::{address, port};
use asphyxia::utils::{
    init_scan_pool, parse_ip, parse_ports, parse_subnet, progress_bar, read_targets_from_stdin,
};

fn main() {
    let args = Args::parse();

    // Size the global rayon pool for I/O-bound scanning before any scan runs.
    init_scan_pool(args.concurrency());

    let format = args.output_format();
    let output_file = args.output_file().cloned();

    match args {
        Args::PortScan {
            host,
            stdin,
            range,
            specific,
            all_ports,
            top_ports: top_n,
            port_set,
            timeout,
            ..
        } => {
            let timeout = Some(Duration::from_millis(timeout));

            let ports: Vec<u16> = if all_ports {
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
            let jobs: Vec<(usize, u16)> = resolved
                .iter()
                .enumerate()
                .flat_map(|(i, _)| ports.iter().map(move |&port| (i, port)))
                .collect();

            let pb = progress_bar(jobs.len() as u64, "ports scanned");

            let mut opened: Vec<(usize, port::PortHit)> = jobs
                .into_par_iter()
                .filter_map(|(i, port)| {
                    let hit = port::scan_port(resolved[i].1.clone(), port, timeout);
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
        }
        Args::AddressScan {
            subnet,
            target,
            range,
            timeout,
            ..
        } => {
            let timeout = Some(Duration::from_millis(timeout));

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
                        address::scan_subnet(network, timeout)
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
                        address::scan_address(ip, timeout).into_iter().collect()
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
                        address::scan_ip_range(start, end, timeout)
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
