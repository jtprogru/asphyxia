//! Markdown and HTML reports built from the same `ScanRecord`s as the CLI.
//!
//! The report is a presentation layer only: every fact comes from the scan
//! records, banners are sanitized and truncated by default, and metadata names
//! the target scope, timestamp, tool version and scan mode.

use std::collections::BTreeMap;

use clap::ValueEnum;

use crate::output::ScanRecord;

/// Report format selected with `--report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// Markdown.
    Md,
    /// Self-contained HTML.
    Html,
}

/// Scan metadata placed in the report header.
#[derive(Debug, Clone, Copy)]
pub struct ReportMeta<'a> {
    pub targets: &'a str,
    pub timestamp: u64,
    pub version: &'a str,
    pub scan_mode: &'a str,
}

/// Render a report from `records`.
pub fn render(
    records: &[ScanRecord],
    format: ReportFormat,
    meta: &ReportMeta<'_>,
    full_banners: bool,
) -> String {
    match format {
        ReportFormat::Md => render_markdown(records, meta, full_banners),
        ReportFormat::Html => render_html(records, meta, full_banners),
    }
}

/// Sanitize a banner for display: strip control characters and truncate to a
/// bounded length unless `full` was explicitly requested.
fn banner(banner: Option<&str>, full: bool) -> String {
    let text: String = banner
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    if full || text.chars().count() <= 80 {
        text
    } else {
        let mut truncated: String = text.chars().take(80).collect();
        truncated.push('…');
        truncated
    }
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn escape_md(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

fn port(record: &ScanRecord) -> String {
    record
        .port
        .map(|port| port.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn service(record: &ScanRecord) -> &str {
    record.service.as_deref().unwrap_or("(unknown)")
}

fn device(record: &ScanRecord) -> &str {
    record.device_type.unwrap_or("(unclassified)")
}

/// Host -> records, sorted by IP.
fn by_host(records: &[ScanRecord]) -> BTreeMap<&str, Vec<&ScanRecord>> {
    let mut grouped: BTreeMap<&str, Vec<&ScanRecord>> = BTreeMap::new();
    for record in records {
        grouped.entry(record.ip.as_str()).or_default().push(record);
    }
    grouped
}

/// Service -> records, sorted by service name.
fn by_service(records: &[ScanRecord]) -> BTreeMap<&str, Vec<&ScanRecord>> {
    let mut grouped: BTreeMap<&str, Vec<&ScanRecord>> = BTreeMap::new();
    for record in records {
        grouped.entry(service(record)).or_default().push(record);
    }
    grouped
}

/// Device type -> records, sorted by type.
fn by_device(records: &[ScanRecord]) -> BTreeMap<&str, Vec<&ScanRecord>> {
    let mut grouped: BTreeMap<&str, Vec<&ScanRecord>> = BTreeMap::new();
    for record in records {
        grouped.entry(device(record)).or_default().push(record);
    }
    grouped
}

fn render_markdown(records: &[ScanRecord], meta: &ReportMeta<'_>, full: bool) -> String {
    let mut out = String::new();
    out.push_str("# Asphyxia scan report\n\n");
    out.push_str(&format!("- **Targets:** {}\n", escape_md(meta.targets)));
    out.push_str(&format!(
        "- **Generated:** {} (Unix time)\n",
        meta.timestamp
    ));
    out.push_str(&format!("- **Version:** {}\n", meta.version));
    out.push_str(&format!("- **Scan mode:** {}\n\n", meta.scan_mode));

    out.push_str("## Hosts\n\n");
    for (ip, rows) in by_host(records) {
        out.push_str(&format!("### {ip}\n\n"));
        out.push_str("| Port | Proto | Status | Service | Device | Banner |\n");
        out.push_str("|---:|---|---|---|---|---|\n");
        for record in rows {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                port(record),
                record.proto,
                record.status,
                escape_md(service(record)),
                escape_md(device(record)),
                escape_md(&banner(record.banner.as_deref(), full)),
            ));
        }
        out.push('\n');
    }

    out.push_str("## By service\n\n");
    for (name, rows) in by_service(records) {
        out.push_str(&format!("### {name}\n\n"));
        for record in rows {
            out.push_str(&format!("- {}:{}\n", record.ip, port(record)));
        }
        out.push('\n');
    }

    out.push_str("## By device type\n\n");
    for (name, rows) in by_device(records) {
        out.push_str(&format!("### {name}\n\n"));
        for record in rows {
            out.push_str(&format!(
                "- {}:{} ({})\n",
                record.ip,
                port(record),
                record.status
            ));
        }
        out.push('\n');
    }
    out
}

fn render_html(records: &[ScanRecord], meta: &ReportMeta<'_>, full: bool) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
    out.push_str("<title>Asphyxia scan report</title>\n");
    out.push_str("<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#1b1b1b}table{border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #ccc;padding:.35rem .6rem;text-align:left}th{background:#f2f2f2}code{background:#f6f6f6;padding:.1rem .25rem}</style>\n");
    out.push_str("</head><body>\n");
    out.push_str("<h1>Asphyxia scan report</h1>\n<ul>\n");
    out.push_str(&format!(
        "<li><strong>Targets:</strong> <code>{}</code></li>\n",
        escape_html(meta.targets)
    ));
    out.push_str(&format!(
        "<li><strong>Generated:</strong> {} (Unix time)</li>\n",
        meta.timestamp
    ));
    out.push_str(&format!(
        "<li><strong>Version:</strong> {}</li>\n",
        escape_html(meta.version)
    ));
    out.push_str(&format!(
        "<li><strong>Scan mode:</strong> {}</li>\n",
        escape_html(meta.scan_mode)
    ));
    out.push_str("</ul>\n<h2>Hosts</h2>\n");

    for (ip, rows) in by_host(records) {
        out.push_str(&format!("<h3>{}</h3>\n", escape_html(ip)));
        out.push_str("<table><thead><tr><th>Port</th><th>Proto</th><th>Status</th><th>Service</th><th>Device</th><th>Banner</th></tr></thead><tbody>\n");
        for record in rows {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                escape_html(&port(record)),
                escape_html(record.proto),
                escape_html(record.status),
                escape_html(service(record)),
                escape_html(device(record)),
                escape_html(&banner(record.banner.as_deref(), full)),
            ));
        }
        out.push_str("</tbody></table>\n");
    }

    out.push_str("<h2>By service</h2>\n");
    for (name, rows) in by_service(records) {
        out.push_str(&format!("<h3>{}</h3><ul>\n", escape_html(name)));
        for record in rows {
            out.push_str(&format!(
                "<li><code>{}:{}</code></li>\n",
                escape_html(&record.ip),
                escape_html(&port(record))
            ));
        }
        out.push_str("</ul>\n");
    }

    out.push_str("<h2>By device type</h2>\n");
    for (name, rows) in by_device(records) {
        out.push_str(&format!("<h3>{}</h3><ul>\n", escape_html(name)));
        for record in rows {
            out.push_str(&format!(
                "<li><code>{}:{}</code> ({})</li>\n",
                escape_html(&record.ip),
                escape_html(&port(record)),
                escape_html(record.status)
            ));
        }
        out.push_str("</ul>\n");
    }

    out.push_str("</body></html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> ScanRecord {
        ScanRecord {
            ip: "192.0.2.10".to_string(),
            port: Some(445),
            proto: "tcp",
            scan: "connect",
            latency_ms: 2,
            status: "open",
            service: Some("smb".to_string()),
            banner: Some("<script>alert(1)</script>".to_string()),
            discovery: None,
            mac: None,
            oui: None,
            reason: None,
            ptr: None,
            ptr_confirmed: None,
            device_type: Some("windows"),
            device_confidence: Some("medium"),
            asn: None,
            asn_org: None,
            cloud: None,
        }
    }

    fn meta() -> ReportMeta<'static> {
        ReportMeta {
            targets: "192.0.2.0/24",
            timestamp: 1_700_000_000,
            version: "0.10.0",
            scan_mode: "connect",
        }
    }

    #[test]
    fn markdown_has_metadata_and_all_groupings() {
        let report = render(&[record()], ReportFormat::Md, &meta(), false);
        assert!(report.contains("Targets:** 192.0.2.0/24"));
        assert!(report.contains("Version:** 0.10.0"));
        assert!(report.contains("## Hosts"));
        assert!(report.contains("192.0.2.10"));
        assert!(report.contains("## By service"));
        assert!(report.contains("### smb"));
        assert!(report.contains("## By device type"));
        assert!(report.contains("### windows"));
    }

    #[test]
    fn html_escapes_banner_and_truncates_by_default() {
        let report = render(&[record()], ReportFormat::Html, &meta(), false);
        assert!(report.contains("&lt;script&gt;"));
        assert!(!report.contains("<script>alert(1)</script>"));
        // The full flag exposes the sanitized text, still HTML-escaped.
        let full = render(&[record()], ReportFormat::Html, &meta(), true);
        assert!(full.contains("&lt;script&gt;"));
    }

    #[test]
    fn long_banners_are_truncated_unless_full() {
        let mut record = record();
        record.banner = Some("x".repeat(200));
        let short = render(&[record.clone()], ReportFormat::Md, &meta(), false);
        assert!(short.contains('…'));
        let full = render(&[record], ReportFormat::Md, &meta(), true);
        assert!(full.contains(&"x".repeat(200)));
    }
}
