use indicatif::{ProgressBar, ProgressStyle};
use ipnetwork::{IpNetwork, NetworkSize};
use std::collections::HashSet;
use std::io::BufRead;
use std::net::IpAddr;

/// Hard upper bound on the number of concurrent connection attempts.
///
/// A `--concurrency` value larger than this is clamped down so that a single
/// scan cannot spawn an unreasonable number of OS threads.
pub const MAX_CONCURRENCY: usize = 1024;

/// Configure the global rayon thread pool used by every scan.
///
/// Scanning is network-I/O-bound: each probe spends almost all of its time
/// parked on a blocking `connect` waiting for a handshake or a timeout, not on
/// the CPU. So we deliberately run far more concurrent probes than there are
/// cores — the default rayon pool (sized to the core count) would otherwise
/// leave most addresses waiting behind a handful of busy threads. Pool threads
/// get a small stack because a connection probe needs almost none.
///
/// `concurrency` is clamped to `1..=`[`MAX_CONCURRENCY`]. This installs the
/// process-wide global pool, so it must be called once, before any scan runs.
///
/// # Panics
///
/// Panics if the global pool has already been initialised (e.g. called twice).
pub fn init_scan_pool(concurrency: usize) {
    let threads = concurrency.clamp(1, MAX_CONCURRENCY);
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .stack_size(512 * 1024)
        .build_global()
        .expect("failed to initialise the scan thread pool");
}

/// Build a styled progress bar for a scan of `total` items.
///
/// The `suffix` is appended after the `pos/len` counter (e.g. `"ports scanned"`
/// or `"addresses scanned"`), so both the port and address scanners can share
/// the same bar style.
///
/// # Examples
///
/// ```
/// use asphyxia::utils::progress_bar;
///
/// let pb = progress_bar(100, "ports scanned");
/// pb.finish_and_clear();
/// ```
pub fn progress_bar(total: u64, suffix: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(&format!(
            "[{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos}}/{{len}} {suffix}"
        ))
        .unwrap()
        .progress_chars("=> "),
    );
    pb
}

/// Largest CIDR (by host count) expanded inline when a target line is a subnet.
/// Wider blocks are kept as a single token rather than enumerated, so a stray
/// `/8` in a target file cannot balloon into millions of entries.
const MAX_TARGET_CIDR_HOSTS: u128 = 1 << 16; // 65_536 addresses

/// Read scan targets from standard input, one per line.
///
/// This is what turns two separate scans into a pipeline: the hosts an address
/// scan discovers can be streamed straight into a port scan
/// (`asphyxia as ... -o jsonl | asphyxia ps --stdin ...`).
///
/// See [`read_targets`] for the per-line format that is accepted.
pub fn read_targets_from_stdin() -> Vec<String> {
    read_targets(std::io::stdin().lock())
}

/// Read scan targets from a file, one per line (`-iL`/`--target-file`).
///
/// A hand-maintained target list on disk is the repeatable counterpart to
/// piping via `--stdin`. The per-line format is identical — see [`read_targets`].
///
/// Returns an error if the file cannot be opened or read.
pub fn read_targets_from_file(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    let file = std::fs::File::open(path)?;
    Ok(read_targets(std::io::BufReader::new(file)))
}

/// Parse scan targets from any line source.
///
/// The format is auto-detected per line so a hand-written list and the machine
/// output of `asphyxia as` both work without a flag:
///
/// * a line beginning with `{` or `[` is parsed as JSON and every `ip` field it
///   contains is taken as a target (covers `-o json` and `-o jsonl`);
/// * a line in CIDR notation (e.g. `192.168.1.0/28`) is expanded into its
///   individual addresses, up to [`MAX_TARGET_CIDR_HOSTS`];
/// * any other non-empty line is treated as a bare host/IP.
///
/// Blank lines are skipped, JSON lines that fail to parse are ignored, and
/// duplicate targets are removed while preserving first-seen order.
pub fn read_targets<R: BufRead>(reader: R) -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();

    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed.as_bytes().first() {
            Some(b'{') | Some(b'[') => extract_ips(trimmed, &mut raw),
            _ if trimmed.contains('/') => expand_cidr(trimmed, &mut raw),
            _ => raw.push(trimmed.to_string()),
        }
    }

    let mut seen = HashSet::new();
    raw.into_iter()
        .filter(|host| seen.insert(host.clone()))
        .collect()
}

/// Expand a CIDR token into individual address strings, appending each to
/// `out`. A token that is not a valid CIDR is pushed verbatim (it may be a
/// hostname with a slash-path the user mistyped); a CIDR wider than
/// [`MAX_TARGET_CIDR_HOSTS`] is kept as a single token with a warning.
fn expand_cidr(token: &str, out: &mut Vec<String>) {
    let Ok(network) = token.parse::<IpNetwork>() else {
        out.push(token.to_string());
        return;
    };
    let size: u128 = match network.size() {
        NetworkSize::V4(n) => u128::from(n),
        NetworkSize::V6(n) => n,
    };
    if size > MAX_TARGET_CIDR_HOSTS {
        eprintln!(
            "Not expanding {} ({} addresses, limit {}); passing it through as-is",
            token, size, MAX_TARGET_CIDR_HOSTS
        );
        out.push(token.to_string());
        return;
    }
    for ip in network.iter() {
        out.push(ip.to_string());
    }
}

/// Pull every `ip` string out of a JSON object or array of objects, appending
/// each to `out`. Non-JSON or shapes without an `ip` field contribute nothing.
fn extract_ips(json: &str, out: &mut Vec<String>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return;
    };
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                if let Some(ip) = item.get("ip").and_then(|v| v.as_str()) {
                    out.push(ip.to_string());
                }
            }
        }
        serde_json::Value::Object(_) => {
            if let Some(ip) = value.get("ip").and_then(|v| v.as_str()) {
                out.push(ip.to_string());
            }
        }
        _ => {}
    }
}

/// Parse a comma-separated string of port numbers into a vector of u16
///
/// # Arguments
///
/// * `s` - A string containing comma-separated port numbers
///
/// # Returns
///
/// * `Result<Vec<u16>, String>` - A vector of port numbers if parsing was successful,
///   or an error message if parsing failed
///
/// # Examples
///
/// ```
/// use asphyxia::utils::parse_ports;
///
/// assert_eq!(parse_ports("22,80,443"), Ok(vec![22, 80, 443]));
/// assert!(parse_ports("22,abc,443").is_err());
/// ```
pub fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    s.split(',')
        .map(|p| {
            p.parse::<u16>()
                .map_err(|_| format!("Invalid port number: {}", p))
        })
        .collect()
}

/// Parse a string into an IP address (IPv4 or IPv6)
///
/// # Arguments
///
/// * `ip` - A string containing an IPv4 or IPv6 address
///
/// # Returns
///
/// * `Result<IpAddr, String>` - The parsed IP address if successful,
///   or an error message if parsing failed
///
/// # Examples
///
/// ```
/// use asphyxia::utils::parse_ip;
///
/// assert!(parse_ip("192.168.1.1").is_ok());
/// assert!(parse_ip("2001:db8::1").is_ok());
/// assert!(parse_ip("not-an-ip").is_err());
/// ```
pub fn parse_ip(ip: &str) -> Result<IpAddr, String> {
    ip.parse::<IpAddr>()
        .map_err(|_| format!("Invalid IP address: {}", ip))
}

/// Parse a string into an IP subnet (IPv4 or IPv6)
///
/// # Arguments
///
/// * `subnet` - A string containing a subnet in CIDR notation
///   (e.g., "192.168.1.0/24" or "2001:db8::/64")
///
/// # Returns
///
/// * `Result<IpNetwork, String>` - The parsed subnet if successful,
///   or an error message if parsing failed
///
/// # Examples
///
/// ```
/// use asphyxia::utils::parse_subnet;
///
/// assert!(parse_subnet("192.168.1.0/24").is_ok());
/// assert!(parse_subnet("2001:db8::/64").is_ok());
/// assert!(parse_subnet("192.168.1.0/33").is_err());
/// ```
pub fn parse_subnet(subnet: &str) -> Result<IpNetwork, String> {
    subnet
        .parse::<IpNetwork>()
        .map_err(|_| format!("Invalid subnet format: {}", subnet))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn targets(input: &str) -> Vec<String> {
        read_targets(Cursor::new(input))
    }

    #[test]
    fn reads_bare_hosts_and_skips_blanks() {
        assert_eq!(
            targets("example.com\n\n  10.0.0.1  \n"),
            vec!["example.com".to_string(), "10.0.0.1".to_string()]
        );
    }

    #[test]
    fn extracts_ip_from_json_and_jsonl_lines() {
        let input = "{\"ip\":\"127.0.0.1\",\"status\":\"up\"}\n[{\"ip\":\"10.0.0.2\"}]\n";
        assert_eq!(
            targets(input),
            vec!["127.0.0.1".to_string(), "10.0.0.2".to_string()]
        );
    }

    #[test]
    fn expands_a_cidr_line_into_addresses() {
        // A /30 spans 4 addresses (network..broadcast inclusive).
        let out = targets("192.168.1.0/30\n");
        assert_eq!(
            out,
            vec![
                "192.168.1.0".to_string(),
                "192.168.1.1".to_string(),
                "192.168.1.2".to_string(),
                "192.168.1.3".to_string(),
            ]
        );
    }

    #[test]
    fn deduplicates_while_preserving_first_seen_order() {
        assert_eq!(
            targets("10.0.0.1\n10.0.0.2\n10.0.0.1\n"),
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()]
        );
    }

    #[test]
    fn oversized_cidr_is_passed_through_not_expanded() {
        // A /8 is far larger than the expansion cap, so it stays a single token.
        assert_eq!(targets("10.0.0.0/8\n"), vec!["10.0.0.0/8".to_string()]);
    }
}
