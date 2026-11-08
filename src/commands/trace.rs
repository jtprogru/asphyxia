//! `asphyxia trace` command: resolve the target and render the traceroute.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use asphyxia::output::OutputFormat;
use asphyxia::traceroute::Transport;

/// Run the trace command.
#[allow(clippy::too_many_arguments)]
pub fn run(
    target: &str,
    transport: Transport,
    port: u16,
    max_hops: u8,
    probes: u8,
    timeout_ms: u64,
    output: OutputFormat,
    output_file: Option<&Path>,
) -> Result<(), String> {
    if !matches!(
        output,
        OutputFormat::Text | OutputFormat::Json | OutputFormat::Jsonl
    ) {
        return Err("trace supports -o text, -o json, or -o jsonl".to_string());
    }
    if transport == Transport::Tcp && port == 0 {
        return Err("--port must be 1..=65535".to_string());
    }
    if timeout_ms == 0 {
        return Err("--timeout must be greater than zero".to_string());
    }

    let ip = match target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => asphyxia::scanner::port::resolve_host(target)
            .ok_or_else(|| format!("Could not resolve target: {target}"))?,
    };
    let IpAddr::V4(target) = ip else {
        return Err("traceroute is IPv4-only".to_string());
    };

    let report = asphyxia::traceroute::trace(
        target,
        transport,
        port,
        max_hops,
        probes,
        Duration::from_millis(timeout_ms),
    )?;

    let rendered = match output {
        OutputFormat::Text => asphyxia::traceroute::render_text(&report),
        OutputFormat::Json => {
            format!("{}\n", serde_json::to_string_pretty(&report).unwrap())
        }
        OutputFormat::Jsonl => asphyxia::traceroute::render_jsonl(&report),
        OutputFormat::Csv | OutputFormat::Grep => unreachable!("validated above"),
    };
    match output_file {
        Some(path) => std::fs::write(path, rendered)
            .map_err(|e| format!("Failed to write {}: {e}", path.display())),
        None => {
            print!("{rendered}");
            Ok(())
        }
    }
}
