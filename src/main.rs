use std::time::Duration;

use clap::Parser;
use owo_colors::OwoColorize;
use rayon::prelude::*;

mod cli;
mod output;
mod scanner;
mod utils;

use cli::Args;
use output::{OutputFormat, ScanRecord, print_json, print_jsonl};
use scanner::{address, port};
use utils::{init_scan_pool, parse_ip, parse_ports, parse_subnet, progress_bar};

fn main() {
    let args = Args::parse();

    // Size the global rayon pool for I/O-bound scanning before any scan runs.
    init_scan_pool(args.concurrency());

    let format = args.output_format();

    match args {
        Args::PortScan {
            host,
            range,
            specific,
            timeout,
            ..
        } => {
            let timeout = Some(Duration::from_millis(timeout));

            // Make sure the host resolves before we try to scan it.
            if !port::is_resolvable(&host) {
                eprintln!("{}", format!("Could not resolve host: {}", host).red());
                return;
            }

            let ports: Vec<u16> = if let Some(range) = range {
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
            } else {
                eprintln!("{}", "Please specify either -r or -s".yellow());
                return;
            };

            // Resolve the host to an IP once, so the parallel scan below does
            // not issue a DNS lookup for every single port.
            let scan_host = match port::resolve_host(&host) {
                Some(ip) => ip.to_string(),
                None => {
                    eprintln!("{}", format!("Could not resolve host: {}", host).red());
                    return;
                }
            };

            let total_ports = ports.len();

            if format == OutputFormat::Text {
                println!(
                    "\n##### {} scanning ports on host: {} #####\n",
                    "Started".bright_blue(),
                    host.bright_green()
                );
            }

            let pb = progress_bar(total_ports as u64, "ports scanned");

            let mut opened: Vec<port::PortHit> = ports
                .into_par_iter()
                .filter_map(|port| {
                    let open_port = port::scan_port(scan_host.clone(), port, timeout);
                    pb.inc(1);
                    open_port
                })
                .collect();

            pb.finish_with_message("Scan completed");

            opened.sort_by_key(|hit| hit.port);

            match format {
                OutputFormat::Text => {
                    if !opened.is_empty() {
                        println!(
                            "\n-- {} for {} --\n",
                            "Opened ports".green(),
                            host.bright_yellow()
                        );
                        for hit in &opened {
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
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let records: Vec<ScanRecord> = opened
                        .iter()
                        .map(|hit| ScanRecord {
                            ip: scan_host.clone(),
                            port: Some(hit.port),
                            proto: "tcp",
                            latency_ms: hit.latency.as_millis(),
                            status: "open",
                        })
                        .collect();
                    if format == OutputFormat::Json {
                        print_json(&records);
                    } else {
                        print_jsonl(&records);
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
                OutputFormat::Json | OutputFormat::Jsonl => {
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
                    if format == OutputFormat::Json {
                        print_json(&records);
                    } else {
                        print_jsonl(&records);
                    }
                }
            }
        }
    }
}
