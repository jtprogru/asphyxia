use std::net::{Ipv4Addr};
use std::time::Duration;
use std::sync::{Arc, Mutex};

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use owo_colors::OwoColorize;

mod cli;
mod scanner;
mod utils;

use cli::Args;
use scanner::{port, address};
use utils::{parse_ipv4, parse_subnet};

fn main() {
    let args = Args::parse();

    match args {
        Args::PortScan { host, range, specific } => {
            // Check if host is online
            if !port::is_online(&host) {
                eprintln!("{}", format!("Server/Host: {} is not up!", host).red());
                return;
            }

            let ports: Vec<u16> = if let Some(range) = range {
                if range.len() != 2 {
                    eprintln!("{}", "Range requires two numbers".yellow());
                    return;
                }
                let start = range[0];
                let end = range[1];
                if start > end {
                    eprintln!("{}", "Start port must be <= end port".yellow());
                    return;
                }
                (start..=end).collect()
            } else if let Some(ports) = specific {
                ports
            } else {
                eprintln!("{}", "Please specify either -r or -s".yellow());
                return;
            };

            let total_ports = ports.len();

            println!(
                "\n##### {} scanning ports on host: {} #####\n",
                "Started".bright_blue(),
                host.bright_green()
            );
            std::thread::sleep(Duration::from_secs(1));

            let pb = ProgressBar::new(total_ports as u64);
            pb.set_style(
                ProgressStyle::with_template(
                    "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ports scanned",
                )
                .unwrap()
                .progress_chars("=> "),
            );

            let opened_ports = Arc::new(Mutex::new(Vec::new()));

            ports.into_par_iter().for_each(|port| {
                if let Some(open_port) = port::scan_port(host.clone(), port) {
                    if let Ok(mut guard) = opened_ports.lock() {
                        guard.push(open_port);
                    }
                }
                pb.inc(1);
            });

            pb.finish_with_message("Scan completed");

            let mut opened = opened_ports.lock().unwrap();
            opened.sort();

            if !opened.is_empty() {
                println!("\n-- {} for {} --\n", "Opened ports".green(), host.bright_yellow());
                for port in &*opened {
                    println!("{}:{}", host.bright_cyan(), port.to_string().bright_green());
                }
            } else {
                println!("\n{}", "No open ports found 😕".yellow());
            }

            println!("\n##### {} #####\n", "Game Over".bright_red());
        }
        Args::AddressScan { subnet, target, range } => {
            let available_ips: Vec<Ipv4Addr> = if let Some(subnet_str) = subnet {
                match parse_subnet(&subnet_str) {
                    Ok(network) => {
                        println!(
                            "\n##### {} scanning subnet: {} #####\n",
                            "Started".bright_blue(),
                            subnet_str.as_str().bright_green()
                        );
                        address::scan_subnet(network)
                    }
                    Err(e) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                }
            } else if let Some(target_str) = target {
                match parse_ipv4(&target_str) {
                    Ok(ip) => {
                        println!(
                            "\n##### {} scanning target: {} #####\n",
                            "Started".bright_blue(),
                            target_str.as_str().bright_green()
                        );
                        address::scan_address(ip, None).into_iter().collect()
                    }
                    Err(e) => {
                        eprintln!("{}", e.red());
                        return;
                    }
                }
            } else if let Some(range_vec) = range {
                if range_vec.len() != 2 {
                    eprintln!("{}", "Range requires two IP addresses".yellow());
                    return;
                }
                match (parse_ipv4(&range_vec[0]), parse_ipv4(&range_vec[1])) {
                    (Ok(start), Ok(end)) => {
                        println!(
                            "\n##### {} scanning range: {} - {} #####\n",
                            "Started".bright_blue(),
                            range_vec[0].as_str().bright_green(),
                            range_vec[1].as_str().bright_green()
                        );
                        address::scan_ip_range(start, end)
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

