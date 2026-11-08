//! `asphyxia as` command: host discovery, identity enrichment and reports.

use std::time::Duration;

use owo_colors::OwoColorize;
use rayon::prelude::*;

use asphyxia::cli::{Args, DiscoveryMode};
use asphyxia::output::{OutputFormat, emit};
use asphyxia::scanner::address;
use asphyxia::utils::{parse_ip, parse_ports, parse_subnet};

use crate::{
    DiscoveryReport, address_records, asn_info, build_exclude_set, resolve_discovery_plan,
    scan_discovery, scan_filtered, tcp_only,
};

/// Run an address scan. `main` has already resolved config/CLI precedence and
/// the scan-wide options.
pub fn run(args: Args, format: OutputFormat, output_file: Option<std::path::PathBuf>) {
    let Args::AddressScan {
        subnet,
        target,
        range,
        no_discovery,
        discovery: discovery_modes,
        discovery_ports,
        show_down,
        resolve_ptr,
        classify,
        asn: asn_enabled,
        report,
        report_file,
        full_banners,
        exclude,
        exclude_file,
        timeout,
        retries,
        ..
    } = args
    else {
        return;
    };

    let ptr_timeout = Duration::from_millis(timeout);
    let timeout = Some(ptr_timeout);
    let scope = if let Some(subnet) = &subnet {
        subnet.clone()
    } else if let Some(target) = &target {
        target.clone()
    } else if let Some(range) = &range {
        range.join(" - ")
    } else {
        "unknown".to_string()
    };

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
            "discovery auto: arp,icmp,tcp — probes that cannot run are skipped".bright_black()
        );
    }
    let plan_label = plan
        .iter()
        .map(|mode| mode.label())
        .collect::<Vec<_>>()
        .join(",");

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
                if format == OutputFormat::Text && report.is_none() {
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
                if format == OutputFormat::Text && report.is_none() {
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
                if format == OutputFormat::Text && report.is_none() {
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

    // One canonical record list feeds the report renderer and the
    // machine formats; text output reads the same findings.
    let records = address_records(&available, classify, asn_enabled, show_down);
    if let Some(report_format) = report {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let meta = asphyxia::report::ReportMeta {
            targets: &scope,
            timestamp,
            version: env!("CARGO_PKG_VERSION"),
            scan_mode: &plan_label,
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
                    if classify {
                        let device = hit
                            .oui
                            .as_deref()
                            .map(asphyxia::classify::classify_oui)
                            .unwrap_or_else(asphyxia::classify::Device::unknown);
                        line.push_str(&format!(" [{}/{}]", device.device_type, device.confidence));
                    }
                    if let Some(info) = asn_info(hit.ip, asn_enabled) {
                        line.push_str(&format!(
                            " [AS{}{}]",
                            info.asn,
                            info.cloud
                                .map(|cloud| format!(" {cloud}"))
                                .unwrap_or_default()
                        ));
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
            if let Err(e) = emit(&records, format, output_file.as_deref()) {
                eprintln!("{}", format!("Failed to write output: {}", e).red());
            }
        }
    }
}
