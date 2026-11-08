//! Compare two structured scan-result files (`asphyxia diff`).
//!
//! The comparison works on the stable `ScanRecord` identity `(ip, port, proto)`
//! from the machine-readable output, not on the resume state: a result file can
//! be compared across different port sets, and missing records are meaningful.
//! The output is deterministic (sorted) and can be emitted as JSON Lines so a
//! downstream tool can consume change events.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The subset of a `ScanRecord` the diff needs. Unknown fields are ignored, so
/// newer scan output stays readable.
#[derive(Debug, Clone, Deserialize)]
struct InputRecord {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    proto: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    banner: Option<String>,
}

/// A normalized record used for comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Record {
    pub ip: String,
    pub port: Option<u16>,
    pub proto: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

impl From<InputRecord> for Record {
    fn from(input: InputRecord) -> Self {
        Self {
            ip: input.ip,
            port: input.port,
            proto: input.proto,
            status: input.status,
            service: input.service,
            banner: input.banner,
        }
    }
}

/// One field-level change on a port that exists in both files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub ip: String,
    pub port: u16,
    pub proto: String,
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
}

/// The complete deterministic diff between two files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DiffReport {
    pub new_hosts: Vec<String>,
    pub removed_hosts: Vec<String>,
    pub new_ports: Vec<Record>,
    pub removed_ports: Vec<Record>,
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
}

impl DiffReport {
    /// Whether nothing changed and there are no warnings.
    pub fn is_empty(&self) -> bool {
        self.new_hosts.is_empty()
            && self.removed_hosts.is_empty()
            && self.new_ports.is_empty()
            && self.removed_ports.is_empty()
            && self.changes.is_empty()
    }
}

/// Load a JSON array or a JSON Lines file (blank lines are skipped).
pub fn load(path: &Path) -> Result<Vec<Record>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Could not read {}: {e}", path.display()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        let parsed: Vec<InputRecord> = serde_json::from_str(trimmed)
            .map_err(|e| format!("Invalid JSON array in {}: {e}", path.display()))?;
        return Ok(parsed.into_iter().map(Record::from).collect());
    }

    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed: InputRecord = serde_json::from_str(line).map_err(|e| {
            format!(
                "Invalid JSON object at {}:{}: {e}",
                path.display(),
                index + 1
            )
        })?;
        records.push(Record::from(parsed));
    }
    Ok(records)
}

/// Compare `old` and `new` deterministically.
pub fn compare(old: Vec<Record>, new: Vec<Record>) -> DiffReport {
    let mut report = DiffReport::default();

    let old_by_key: BTreeMap<(String, Option<u16>, String), Record> = old
        .into_iter()
        .map(|record| {
            (
                (record.ip.clone(), record.port, record.proto.clone()),
                record,
            )
        })
        .collect();
    let new_by_key: BTreeMap<(String, Option<u16>, String), Record> = new
        .into_iter()
        .map(|record| {
            (
                (record.ip.clone(), record.port, record.proto.clone()),
                record,
            )
        })
        .collect();

    let old_hosts: BTreeSet<String> = old_by_key.keys().map(|(ip, _, _)| ip.clone()).collect();
    let new_hosts: BTreeSet<String> = new_by_key.keys().map(|(ip, _, _)| ip.clone()).collect();

    report.new_hosts = new_hosts.difference(&old_hosts).cloned().collect();
    report.removed_hosts = old_hosts.difference(&new_hosts).cloned().collect();

    for key in new_by_key.keys() {
        if !old_by_key.contains_key(key) && key.1.is_some() {
            report.new_ports.push(new_by_key[key].clone());
        }
    }
    for key in old_by_key.keys() {
        if !new_by_key.contains_key(key) && key.1.is_some() {
            report.removed_ports.push(old_by_key[key].clone());
        }
    }

    for (key, before) in &old_by_key {
        let Some(after) = new_by_key.get(key) else {
            continue;
        };
        let Some(port) = key.1 else {
            continue;
        };
        if before.status != after.status {
            report.changes.push(Change {
                ip: key.0.clone(),
                port,
                proto: key.2.clone(),
                field: "status".to_string(),
                old: Some(before.status.clone()),
                new: Some(after.status.clone()),
            });
        }
        if before.service != after.service {
            report.changes.push(Change {
                ip: key.0.clone(),
                port,
                proto: key.2.clone(),
                field: "service".to_string(),
                old: before.service.clone(),
                new: after.service.clone(),
            });
        }
        if before.banner != after.banner {
            report.changes.push(Change {
                ip: key.0.clone(),
                port,
                proto: key.2.clone(),
                field: "banner".to_string(),
                old: before.banner.clone(),
                new: after.banner.clone(),
            });
        }
    }

    // Deterministic order independent of input order.
    report.new_hosts.sort();
    report.removed_hosts.sort();
    report.new_ports.sort();
    report.removed_ports.sort();
    report.changes.sort_by(|a, b| {
        (&a.ip, a.port, &a.proto, field_rank(&a.field)).cmp(&(
            &b.ip,
            b.port,
            &b.proto,
            field_rank(&b.field),
        ))
    });

    // A visibly different scope makes "removed" hosts ambiguous; say so.
    if old_hosts.is_empty() && new_hosts.is_empty() {
        report
            .warnings
            .push("both result sets are empty".to_string());
    } else if old_hosts.is_empty() || new_hosts.is_empty() {
        report
            .warnings
            .push("one result set is empty; target scope may differ".to_string());
    } else if old_hosts.is_disjoint(&new_hosts) {
        report
            .warnings
            .push("no host appears in both result sets; target scope may differ".to_string());
    }

    let old_protos: BTreeSet<&String> = old_by_key.keys().map(|(_, _, proto)| proto).collect();
    let new_protos: BTreeSet<&String> = new_by_key.keys().map(|(_, _, proto)| proto).collect();
    if old_protos != new_protos {
        report.warnings.push(format!(
            "protocol sets differ (old: {}, new: {})",
            join_set(&old_protos),
            join_set(&new_protos)
        ));
    }

    report
}

/// Keep status/service/banner in a human-friendly order within one port.
fn field_rank(field: &str) -> u8 {
    match field {
        "status" => 0,
        "service" => 1,
        "banner" => 2,
        _ => 3,
    }
}

fn join_set(set: &BTreeSet<&String>) -> String {
    if set.is_empty() {
        "-".to_string()
    } else {
        set.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
    }
}

/// Render a human-readable report. Warnings are included at the end.
pub fn render_text(report: &DiffReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("New hosts: {}\n", report.new_hosts.len()));
    for ip in &report.new_hosts {
        out.push_str(&format!("  + {ip}\n"));
    }
    out.push_str(&format!("Removed hosts: {}\n", report.removed_hosts.len()));
    for ip in &report.removed_hosts {
        out.push_str(&format!("  - {ip}\n"));
    }
    out.push_str(&format!("New ports: {}\n", report.new_ports.len()));
    for record in &report.new_ports {
        out.push_str(&format!("  + {}\n", format_record(record)));
    }
    out.push_str(&format!("Removed ports: {}\n", report.removed_ports.len()));
    for record in &report.removed_ports {
        out.push_str(&format!("  - {}\n", format_record(record)));
    }
    out.push_str(&format!("Changes: {}\n", report.changes.len()));
    for change in &report.changes {
        out.push_str(&format!(
            "  ~ {}:{}/{} {}: {} -> {}\n",
            change.ip,
            change.port,
            change.proto,
            change.field,
            change.old.as_deref().unwrap_or("-"),
            change.new.as_deref().unwrap_or("-"),
        ));
    }
    for warning in &report.warnings {
        out.push_str(&format!("warning: {warning}\n"));
    }
    out
}

fn format_record(record: &Record) -> String {
    let port = record
        .port
        .map(|port| port.to_string())
        .unwrap_or_else(|| "-".to_string());
    let mut out = format!(
        "{}:{} / {} {}",
        record.ip, port, record.proto, record.status
    );
    if let Some(service) = &record.service {
        out.push_str(&format!(" {service}"));
    }
    if let Some(banner) = &record.banner {
        out.push_str(&format!(" [{banner}]"));
    }
    out
}

/// Render one JSON event per line for downstream consumers.
pub fn render_jsonl(report: &DiffReport) -> String {
    let mut out = String::new();
    for ip in &report.new_hosts {
        out.push_str(&serde_json::json!({"event": "new_host", "ip": ip}).to_string());
        out.push('\n');
    }
    for ip in &report.removed_hosts {
        out.push_str(&serde_json::json!({"event": "removed_host", "ip": ip}).to_string());
        out.push('\n');
    }
    for record in &report.new_ports {
        out.push_str(&serde_json::json!({"event": "new_port", "record": record}).to_string());
        out.push('\n');
    }
    for record in &report.removed_ports {
        out.push_str(&serde_json::json!({"event": "removed_port", "record": record}).to_string());
        out.push('\n');
    }
    for change in &report.changes {
        out.push_str(&serde_json::json!({"event": "changed", "change": change}).to_string());
        out.push('\n');
    }
    for warning in &report.warnings {
        out.push_str(&serde_json::json!({"event": "warning", "message": warning}).to_string());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(ip: &str, port: Option<u16>, proto: &str, status: &str) -> Record {
        Record {
            ip: ip.to_string(),
            port,
            proto: proto.to_string(),
            status: status.to_string(),
            service: None,
            banner: None,
        }
    }

    #[test]
    fn detects_new_and_removed_hosts_and_ports() {
        let old = vec![rec("10.0.0.1", Some(22), "tcp", "open")];
        let new = vec![
            rec("10.0.0.1", Some(22), "tcp", "open"),
            rec("10.0.0.2", Some(80), "tcp", "open"),
        ];
        let report = compare(old, new);
        assert_eq!(report.new_hosts, vec!["10.0.0.2"]);
        assert!(report.removed_hosts.is_empty());
        assert_eq!(report.new_ports.len(), 1);
        assert_eq!(report.new_ports[0].port, Some(80));

        let old = vec![rec("10.0.0.1", Some(22), "tcp", "open")];
        let new = vec![rec("10.0.0.2", Some(22), "tcp", "open")];
        let report = compare(old, new);
        assert_eq!(report.removed_hosts, vec!["10.0.0.1"]);
        assert_eq!(report.removed_ports.len(), 1);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("target scope"))
        );
    }

    #[test]
    fn detects_status_service_and_banner_changes() {
        let mut before = rec("10.0.0.1", Some(443), "tcp", "open");
        before.service = Some("https".to_string());
        before.banner = Some("old".to_string());
        let mut after = rec("10.0.0.1", Some(443), "tcp", "open|filtered");
        after.service = Some("nginx".to_string());
        after.banner = Some("new".to_string());

        let report = compare(vec![before], vec![after]);
        let fields: Vec<&str> = report
            .changes
            .iter()
            .map(|change| change.field.as_str())
            .collect();
        assert_eq!(fields, vec!["status", "service", "banner"]);
    }

    #[test]
    fn input_order_does_not_change_the_report() {
        let a = vec![
            rec("10.0.0.2", Some(80), "tcp", "open"),
            rec("10.0.0.1", Some(22), "tcp", "open"),
        ];
        let b = vec![
            rec("10.0.0.1", Some(22), "tcp", "open"),
            rec("10.0.0.2", Some(80), "tcp", "open"),
        ];
        assert_eq!(compare(a.clone(), b.clone()), compare(b, a));
    }

    #[test]
    fn jsonl_events_are_one_valid_object_per_line() {
        let old = vec![rec("10.0.0.1", Some(22), "tcp", "open")];
        let new = vec![rec("10.0.0.2", Some(80), "tcp", "open")];
        let out = render_jsonl(&compare(old, new));
        assert!(!out.is_empty());
        for line in out.lines() {
            let value: serde_json::Value = serde_json::from_str(line).expect("valid JSONL");
            assert!(value.get("event").is_some());
        }
    }
}
