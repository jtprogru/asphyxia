use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use owo_colors::OwoColorize;
use rayon::prelude::*;

mod cli;
mod scanner;
mod utils;

use cli::Args;
use scanner::{address, port};
use utils::{parse_ip, parse_ports, parse_subnet, progress_bar};

fn main() {
    let args = Args::parse();

    match args {
        Args::PortScan {
            host,
            range,
            specific,
            timeout,
        } => {
            let timeout = Some(Duration::from_millis(timeout));

            // Check if host is online
            if !port::is_online(&host) {
                eprintln!("{}", format!("Server/Host: {} is not up!", host).red());
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

            println!(
                "\n##### {} scanning ports on host: {} #####\n",
                "Started".bright_blue(),
                host.bright_green()
            );
            std::thread::sleep(Duration::from_secs(1));

            let pb = progress_bar(total_ports as u64, "ports scanned");

            let opened_ports = Arc::new(Mutex::new(Vec::new()));

            ports.into_par_iter().for_each(|port| {
                if let Some(open_port) = port::scan_port(scan_host.clone(), port, timeout)
                    && let Ok(mut guard) = opened_ports.lock()
                {
                    guard.push(open_port);
                }
                pb.inc(1);
            });

            pb.finish_with_message("Scan completed");

            let mut opened = opened_ports.lock().unwrap();
            opened.sort();

            if !opened.is_empty() {
                println!(
                    "\n-- {} for {} --\n",
                    "Opened ports".green(),
                    host.bright_yellow()
                );
                for port in &*opened {
                    println!("{}:{}", host.bright_cyan(), port.to_string().bright_green());
                }
            } else {
                println!("\n{}", "No open ports found 😕".yellow());
            }

            println!("\n##### {} #####\n", "Game Over".bright_red());
        }
        Args::AddressScan {
            subnet,
            target,
            range,
            timeout,
        } => {
            let timeout = Some(Duration::from_millis(timeout));

            let available_ips: Vec<IpAddr> = if let Some(subnet_str) = subnet {
                match parse_subnet(&subnet_str) {
                    Ok(network) => {
                        println!(
                            "\n##### {} scanning subnet: {} #####\n",
                            "Started".bright_blue(),
                            subnet_str.as_str().bright_green()
                        );
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
                        println!(
                            "\n##### {} scanning target: {} #####\n",
                            "Started".bright_blue(),
                            target_str.as_str().bright_green()
                        );
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
                        println!(
                            "\n##### {} scanning range: {} - {} #####\n",
                            "Started".bright_blue(),
                            range_vec[0].as_str().bright_green(),
                            range_vec[1].as_str().bright_green()
                        );
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

            if !available_ips.is_empty() {
                println!("\n-- {} --\n", "Available hosts".green());
                for ip in available_ips {
                    println!("{}", ip.to_string().bright_green());
                }
            } else {
                println!("\n{}", "No available hosts found 😕".yellow());
            }

            println!("\n##### {} #####\n", "Game Over".bright_red());
        }
    }
}
