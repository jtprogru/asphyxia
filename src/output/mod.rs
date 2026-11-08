//! Machine-readable output for scan results.
//!
//! By default, the scanner prints a human-friendly, colorized report. The
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
    /// CSV with a header row (`ip,port,proto,scan,status,latency_ms,service,banner,discovery,mac,oui,reason,ptr,ptr_confirmed`).
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
    /// Transport protocol of the probe: `"tcp"`, `"udp"`, or `"arp"` for a host
    /// confirmed on the local L2 segment.
    pub proto: &'static str,
    /// The probe that produced this record: `"connect"`, `"syn"`, `"ack"`,
    /// `"fin"`, `"null"`, `"xmas"`, `"arp"`, or `"none"` for a `-Pn` address
    /// scan that sent no probe. It is per record, not per scan, because a raw
    /// mode can fall back to a connect probe for an individual target or port.
    pub scan: &'static str,
    /// Wall-clock latency of the probe, in milliseconds.
    pub latency_ms: u128,
    /// The observed state: `"open"` or `"open|filtered"` for a port scan (the
    /// latter also from FIN/NULL/XMAS silence), `"closed"` from the stealth
    /// family, `"unfiltered"`/`"filtered"` for an ACK scan, `"up"` for an
    /// available host, or `"down"` for a `--show-down` ICMP non-responder.
    pub status: &'static str,
    /// Detected service (from `--sV`), omitted when unknown or not requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Raw service banner (from `--sV`), omitted when none was grabbed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// The probe that confirmed this host is up (`"tcp"`, `"arp"`, or `"none"`
    /// for `-Pn`); present only for address-scan records and omitted for port
    /// scans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<&'static str>,
    /// MAC address from an ARP reply; present only when the host was confirmed
    /// by an ARP probe on a locally-connected subnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Vendor OUI (the first three MAC octets, `aa-bb-cc`) when `mac` is known;
    /// a raw prefix, not a vendor-name lookup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oui: Option<String>,
    /// Why a host was reported down: `"unreachable"` (an ICMP
    /// destination-unreachable is a fact) or `"no-response"` (silence after the
    /// retry budget). Only present for `--show-down` records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// Reverse-DNS PTR name, when `--resolve-ptr` found one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
    /// Whether `ptr` forward-resolves to `ip`; `None` when no PTR exists or the
    /// lookup timed out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr_confirmed: Option<bool>,
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

/// Escape one CSV field, quoting it when it contains a comma, quote, CR, or LF.
/// Banners are sanitized to a single printable line upstream, but they can still
/// contain commas or quotes.
fn csv_field(value: &str) -> String {
    if value.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r')) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// CSV with a fixed header. The `port` column is empty for host-discovery
/// records, which have no port; enrichment columns are empty when not collected.
fn render_csv(records: &[ScanRecord]) -> String {
    let mut out = String::from(
        "ip,port,proto,scan,status,latency_ms,service,banner,discovery,mac,oui,reason,ptr,ptr_confirmed\n",
    );
    for r in records {
        let port = r.port.map(|p| p.to_string()).unwrap_or_default();
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_field(&r.ip),
            port,
            r.proto,
            r.scan,
            r.status,
            r.latency_ms,
            csv_field(r.service.as_deref().unwrap_or("")),
            csv_field(r.banner.as_deref().unwrap_or("")),
            r.discovery.unwrap_or(""),
            csv_field(r.mac.as_deref().unwrap_or("")),
            csv_field(r.oui.as_deref().unwrap_or("")),
            r.reason.unwrap_or(""),
            csv_field(r.ptr.as_deref().unwrap_or("")),
            r.ptr_confirmed
                .map(|confirmed| confirmed.to_string())
                .unwrap_or_default(),
        ));
    }
    out
}

/// Greppable plain text: one tab-separated line per result, no header, so it
/// slots straight into `grep`/`awk`/`cut` pipelines. The port column is `-`
/// for host-discovery records. The eight enrichment/reason columns after
/// `latency_ms` are empty when not collected, so the original first six columns
/// keep their positions.
fn render_grep(records: &[ScanRecord]) -> String {
    let mut out = String::new();
    for r in records {
        let port = r
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            r.ip,
            port,
            r.proto,
            r.scan,
            r.status,
            r.latency_ms,
            r.service.as_deref().unwrap_or(""),
            r.banner.as_deref().unwrap_or(""),
            r.discovery.unwrap_or(""),
            r.mac.as_deref().unwrap_or(""),
            r.oui.as_deref().unwrap_or(""),
            r.reason.unwrap_or(""),
            r.ptr.as_deref().unwrap_or(""),
            r.ptr_confirmed
                .map(|confirmed| confirmed.to_string())
                .unwrap_or_default(),
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
                scan: "connect",
                latency_ms: 3,
                status: "open",
                service: None,
                banner: None,
                discovery: None,
                mac: None,
                oui: None,
                reason: None,
                ptr: None,
                ptr_confirmed: None,
            },
            ScanRecord {
                ip: "10.0.0.5".to_string(),
                port: None,
                proto: "tcp",
                scan: "connect",
                latency_ms: 12,
                status: "up",
                service: None,
                banner: None,
                discovery: None,
                mac: None,
                oui: None,
                reason: None,
                ptr: None,
                ptr_confirmed: None,
            },
        ]
    }

    #[test]
    fn csv_has_header_and_blank_port_for_host_records() {
        let out = render(&sample(), OutputFormat::Csv);
        let mut lines = out.lines();
        assert_eq!(
            lines.next().unwrap(),
            "ip,port,proto,scan,status,latency_ms,service,banner,discovery,mac,oui,reason,ptr,ptr_confirmed"
        );
        assert_eq!(
            lines.next().unwrap(),
            "127.0.0.1,80,tcp,connect,open,3,,,,,,,,"
        );
        // Host-discovery record has an empty port column.
        assert_eq!(lines.next().unwrap(), "10.0.0.5,,tcp,connect,up,12,,,,,,,,");
    }

    #[test]
    fn empty_csv_still_has_header() {
        assert_eq!(
            render(&[], OutputFormat::Csv),
            "ip,port,proto,scan,status,latency_ms,service,banner,discovery,mac,oui,reason,ptr,ptr_confirmed\n"
        );
    }

    #[test]
    fn grep_is_tab_separated_with_dash_for_missing_port() {
        let out = render(&sample(), OutputFormat::Grep);
        let mut lines = out.lines();
        assert_eq!(
            lines.next().unwrap(),
            "127.0.0.1\t80\ttcp\tconnect\topen\t3\t\t\t\t\t\t\t\t"
        );
        assert_eq!(
            lines.next().unwrap(),
            "10.0.0.5\t-\ttcp\tconnect\tup\t12\t\t\t\t\t\t\t\t"
        );
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
        assert!(contents.starts_with(
            "ip,port,proto,scan,status,latency_ms,service,banner,discovery,mac,oui,reason,ptr,ptr_confirmed\n"
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ack_records_carry_their_mode_and_firewall_state() {
        // An ACK scan reports unfiltered/filtered, never open/closed, and the
        // scan column says which probe produced the state.
        let records = vec![
            ScanRecord {
                ip: "192.0.2.10".to_string(),
                port: Some(22),
                proto: "tcp",
                scan: "ack",
                latency_ms: 4,
                status: "unfiltered",
                service: None,
                banner: None,
                discovery: None,
                mac: None,
                oui: None,
                reason: None,
                ptr: None,
                ptr_confirmed: None,
            },
            ScanRecord {
                ip: "192.0.2.10".to_string(),
                port: Some(23),
                proto: "tcp",
                scan: "ack",
                latency_ms: 2000,
                status: "filtered",
                service: None,
                banner: None,
                discovery: None,
                mac: None,
                oui: None,
                reason: None,
                ptr: None,
                ptr_confirmed: None,
            },
        ];
        let csv = render(&records, OutputFormat::Csv);
        assert!(csv.contains("192.0.2.10,22,tcp,ack,unfiltered,4,,,,,,,,\n"));
        assert!(csv.contains("192.0.2.10,23,tcp,ack,filtered,2000,,,,,,,,\n"));

        let json = render(&records, OutputFormat::Json);
        assert!(json.contains("\"scan\":\"ack\""));
        assert!(json.contains("\"status\":\"unfiltered\""));
        assert!(!json.contains("\"status\":\"open\""));

        let grep = render(&records, OutputFormat::Grep);
        assert!(grep.contains("192.0.2.10\t22\ttcp\tack\tunfiltered\t4\t\t\t\t\t\t\t\t\n"));
    }

    #[test]
    fn stealth_records_carry_their_mode_and_rfc793_states() {
        // FIN/NULL/XMAS report closed or open|filtered — never a bare "open" —
        // and the scan column names which profile produced each state.
        let records = vec![
            ScanRecord {
                ip: "192.0.2.10".to_string(),
                port: Some(22),
                proto: "tcp",
                scan: "fin",
                latency_ms: 4,
                status: "closed",
                service: None,
                banner: None,
                discovery: None,
                mac: None,
                oui: None,
                reason: None,
                ptr: None,
                ptr_confirmed: None,
            },
            ScanRecord {
                ip: "192.0.2.10".to_string(),
                port: Some(23),
                proto: "tcp",
                scan: "null",
                latency_ms: 2000,
                status: "open|filtered",
                service: None,
                banner: None,
                discovery: None,
                mac: None,
                oui: None,
                reason: None,
                ptr: None,
                ptr_confirmed: None,
            },
            ScanRecord {
                ip: "192.0.2.10".to_string(),
                port: Some(24),
                proto: "tcp",
                scan: "xmas",
                latency_ms: 2000,
                status: "open|filtered",
                service: None,
                banner: None,
                discovery: None,
                mac: None,
                oui: None,
                reason: None,
                ptr: None,
                ptr_confirmed: None,
            },
        ];
        let csv = render(&records, OutputFormat::Csv);
        assert!(csv.contains("192.0.2.10,22,tcp,fin,closed,4,,,,,,,,\n"));
        assert!(csv.contains("192.0.2.10,23,tcp,null,open|filtered,2000,,,,,,,,\n"));
        assert!(csv.contains("192.0.2.10,24,tcp,xmas,open|filtered,2000,,,,,,,,\n"));

        let json = render(&records, OutputFormat::Json);
        for scan in ["fin", "null", "xmas"] {
            assert!(json.contains(&format!("\"scan\":\"{scan}\"")));
        }
        assert!(json.contains("\"status\":\"closed\""));
        assert!(json.contains("\"status\":\"open|filtered\""));
        // open|filtered must stay distinguishable from a plain open.
        assert!(!json.contains("\"status\":\"open\""));

        let grep = render(&records, OutputFormat::Grep);
        assert!(grep.contains("192.0.2.10\t22\ttcp\tfin\tclosed\t4\t\t\t\t\t\t\t\t\n"));
    }

    #[test]
    fn enrichment_columns_are_rendered_in_csv_and_grep() {
        let records = vec![ScanRecord {
            ip: "192.0.2.5".to_string(),
            port: None,
            proto: "arp",
            scan: "arp",
            latency_ms: 2,
            status: "up",
            service: Some("http".to_string()),
            banner: Some("HTTP/1.1 200 OK, \"ok\"".to_string()),
            discovery: Some("arp"),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            oui: Some("aa-bb-cc".to_string()),
            reason: None,
            ptr: Some("host.example".to_string()),
            ptr_confirmed: Some(true),
        }];
        let csv = render(&records, OutputFormat::Csv);
        assert!(
            csv.contains(
                "192.0.2.5,,arp,arp,up,2,http,\"HTTP/1.1 200 OK, \"\"ok\"\"\",arp,aa:bb:cc:dd:ee:ff,aa-bb-cc,,host.example,true\n"
            ),
            "{csv}"
        );
        let grep = render(&records, OutputFormat::Grep);
        assert!(
            grep.contains(
                "192.0.2.5\t-\tarp\tarp\tup\t2\thttp\tHTTP/1.1 200 OK, \"ok\"\tarp\taa:bb:cc:dd:ee:ff\taa-bb-cc\t\thost.example\ttrue\n"
            ),
            "{grep}"
        );
    }

    #[test]
    fn csv_field_escapes_commas_quotes_and_newlines() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
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
