//! Machine-readable output for scan results.
//!
//! By default the scanner prints a human-friendly, colorized report. The
//! formats here turn each result into a structured [`ScanRecord`] so the
//! scanner can act as the first stage of a pipeline (e.g. feeding a network
//! map or coverage analyzer) rather than only being read by a human.
//!
//! Machine output goes to stdout, one self-contained stream:
//! [`OutputFormat::Json`] emits a single JSON array, [`OutputFormat::Jsonl`]
//! emits one JSON object per line (JSON Lines). The progress bar stays on
//! stderr, so a consumer reading stdout sees only records.

use clap::ValueEnum;
use serde::Serialize;

/// How scan results are rendered to stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-friendly, colorized report (default).
    Text,
    /// A single JSON array of [`ScanRecord`].
    Json,
    /// JSON Lines: one [`ScanRecord`] object per line.
    Jsonl,
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
}

/// Print all records as a single JSON array. An empty slice prints `[]`.
pub fn print_json(records: &[ScanRecord]) {
    // Serializing a slice of serializable records cannot fail.
    println!("{}", serde_json::to_string(records).unwrap());
}

/// Print one JSON object per line (JSON Lines). An empty slice prints nothing.
pub fn print_jsonl(records: &[ScanRecord]) {
    for record in records {
        println!("{}", serde_json::to_string(record).unwrap());
    }
}
