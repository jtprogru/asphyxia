//! Machine-readable output for scan results.
//!
//! By default the scanner prints a human-friendly, colorized report. The
//! formats here turn each result into a structured [`ScanRecord`] so the
//! scanner can act as the first stage of a pipeline (e.g. feeding a network
//! map or coverage analyzer) rather than only being read by a human.
//!
//! Machine output is a single self-contained stream:
//! [`OutputFormat::Json`] emits a JSON array, [`OutputFormat::Jsonl`] emits one
//! JSON object per line, [`OutputFormat::Csv`] emits a header plus one row per
//! result, and [`OutputFormat::Grep`] emits one whitespace-separated line per
//! result for `grep`/`awk`. It normally goes to stdout — with the progress bar
//! kept on stderr — but [`emit`] can redirect it to a file instead.

use std::io::{self, Write};
use std::path::Path;

use clap::ValueEnum;
use serde::Serialize;

/// How scan results are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-friendly, colorized report (default).
    Text,
    /// A single JSON array of [`ScanRecord`].
    Json,
    /// JSON Lines: one [`ScanRecord`] object per line.
    Jsonl,
    /// CSV with a header row (`ip,port,proto,status,latency_ms`).
    Csv,
    /// Greppable plain text: one tab-separated line per result.
    Grep,
}

impl OutputFormat {
    /// Whether this is a structured, machine-readable format (everything but
    /// [`OutputFormat::Text`]). Machine formats are rendered by [`render`] and
    /// can be written to a file with [`emit`].
    pub fn is_machine(self) -> bool {
        !matches!(self, OutputFormat::Text)
    }
}

/// One scan result in a normalized, machine-readable shape.
///
/// The fields are a superset of what a port scan and an address scan each
/// produce: `port` is present for port scans and omitted for host discovery.
#[derive(Debug, Serialize)]
pub struct ScanRecord {
    /// Target address (resolved IP for a port scan, host IP for discovery).
    pub ip: String,
    /// Open port; omitted for address (host-availability) scans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Transport protocol of the probe.
    pub proto: &'static str,
    /// Wall-clock latency of the probe, in milliseconds.
    pub latency_ms: u128,
    /// `"open"` for an open port, `"up"` for an available host.
    pub status: &'static str,
    /// Detected service (from `--sV`), omitted when unknown or not requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Raw service banner (from `--sV`), omitted when none was grabbed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

/// Render `records` in a machine-readable `format` into a single string.
///
/// The returned string is the complete output for the format, including any
/// trailing newline. Passing [`OutputFormat::Text`] returns an empty string:
/// the colorized human report is produced by the caller, not here.
pub fn render(records: &[ScanRecord], format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => String::new(),
        OutputFormat::Json => {
            // Serializing a slice of serializable records cannot fail.
            format!("{}\n", serde_json::to_string(records).unwrap())
        }
        OutputFormat::Jsonl => {
            let mut out = String::new();
            for record in records {
                out.push_str(&serde_json::to_string(record).unwrap());
                out.push('\n');
            }
            out
        }
        OutputFormat::Csv => render_csv(records),
        OutputFormat::Grep => render_grep(records),
    }
}

/// CSV with a fixed header. The `port` column is empty for host-discovery
/// records, which have no port.
fn render_csv(records: &[ScanRecord]) -> String {
    let mut out = String::from("ip,port,proto,status,latency_ms\n");
    for r in records {
        let port = r.port.map(|p| p.to_string()).unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            r.ip, port, r.proto, r.status, r.latency_ms
        ));
    }
    out
}

/// Greppable plain text: one tab-separated line per result, no header, so it
/// slots straight into `grep`/`awk`/`cut` pipelines. The port column is `-`
/// for host-discovery records.
fn render_grep(records: &[ScanRecord]) -> String {
    let mut out = String::new();
    for r in records {
        let port = r
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            r.ip, port, r.proto, r.status, r.latency_ms
        ));
    }
    out
}

/// Write `records` in `format` to `path` when given, otherwise to stdout.
///
/// Machine formats ([`OutputFormat::is_machine`]) are rendered via [`render`].
/// [`OutputFormat::Text`] has no machine rendering, so it is a no-op here — the
/// caller prints the human report directly.
pub fn emit(records: &[ScanRecord], format: OutputFormat, path: Option<&Path>) -> io::Result<()> {
    if !format.is_machine() {
        return Ok(());
    }
    let rendered = render(records, format);
    match path {
        Some(path) => std::fs::write(path, rendered),
        None => io::stdout().write_all(rendered.as_bytes()),
    }
}

/// Print all records as a single JSON array. An empty slice prints `[]`.
pub fn print_json(records: &[ScanRecord]) {
    print!("{}", render(records, OutputFormat::Json));
}

/// Print one JSON object per line (JSON Lines). An empty slice prints nothing.
pub fn print_jsonl(records: &[ScanRecord]) {
    print!("{}", render(records, OutputFormat::Jsonl));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<ScanRecord> {
        vec![
            ScanRecord {
                ip: "127.0.0.1".to_string(),
                port: Some(80),
                proto: "tcp",
                latency_ms: 3,
                status: "open",
                service: None,
                banner: None,
            },
            ScanRecord {
                ip: "10.0.0.5".to_string(),
                port: None,
                proto: "tcp",
                latency_ms: 12,
                status: "up",
                service: None,
                banner: None,
            },
        ]
    }

    #[test]
    fn csv_has_header_and_blank_port_for_host_records() {
        let out = render(&sample(), OutputFormat::Csv);
        let mut lines = out.lines();
        assert_eq!(lines.next().unwrap(), "ip,port,proto,status,latency_ms");
        assert_eq!(lines.next().unwrap(), "127.0.0.1,80,tcp,open,3");
        // Host-discovery record has an empty port column.
        assert_eq!(lines.next().unwrap(), "10.0.0.5,,tcp,up,12");
    }

    #[test]
    fn empty_csv_still_has_header() {
        assert_eq!(
            render(&[], OutputFormat::Csv),
            "ip,port,proto,status,latency_ms\n"
        );
    }

    #[test]
    fn grep_is_tab_separated_with_dash_for_missing_port() {
        let out = render(&sample(), OutputFormat::Grep);
        let mut lines = out.lines();
        assert_eq!(lines.next().unwrap(), "127.0.0.1\t80\ttcp\topen\t3");
        assert_eq!(lines.next().unwrap(), "10.0.0.5\t-\ttcp\tup\t12");
    }

    #[test]
    fn json_and_jsonl_shapes_match_expectations() {
        assert_eq!(render(&[], OutputFormat::Json), "[]\n");
        let jsonl = render(&sample(), OutputFormat::Jsonl);
        assert_eq!(jsonl.lines().count(), 2);
        assert!(
            jsonl
                .lines()
                .all(|l| l.starts_with('{') && l.ends_with('}'))
        );
    }

    #[test]
    fn emit_writes_machine_output_to_a_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("asphyxia-emit-test-{}.csv", std::process::id()));
        emit(&sample(), OutputFormat::Csv, Some(&path)).expect("write should succeed");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("ip,port,proto,status,latency_ms\n"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn emit_text_is_a_noop() {
        // Text has no machine rendering; emit must not create a file.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("asphyxia-emit-text-{}.txt", std::process::id()));
        emit(&sample(), OutputFormat::Text, Some(&path)).expect("no-op should succeed");
        assert!(!path.exists());
    }
}
