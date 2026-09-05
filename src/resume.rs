//! Resumable scan state for long-running port scans.
//!
//! A big scan (many hosts × `--all-ports`) can take a long time, and losing it
//! to a Ctrl-C, a dropped link, or a crash means starting over. With
//! `--resume <file>` the scan checkpoints its progress to a state file as it
//! goes; re-running the same command with the same file picks up where it left
//! off, skipping completed work and keeping the results already found.
//!
//! The state is keyed to a deterministic job order — the flattened
//! `(target, port)` grid — so a boolean per job records what is done and the
//! same order reproduces on resume. The file is written atomically (temp file
//! plus rename) so an interrupt mid-write cannot corrupt it.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One open result recorded in the state file. Mirrors a scan finding plus the
/// index of the host it belongs to, so the report can be rebuilt on resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFinding {
    /// Index into [`ScanState::targets`] of the host this result is for.
    pub host: usize,
    pub port: u16,
    pub latency_ms: u128,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub banner: Option<String>,
}

/// The persisted state of an in-progress or completed scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanState {
    /// Transport of the scan (`"tcp"` or `"udp"`) — a resume must match.
    pub proto: String,
    /// Resolved target IPs, in order; the order is part of the job identity.
    pub targets: Vec<String>,
    /// Ports scanned, in order.
    pub ports: Vec<u16>,
    /// Total number of `(target, port)` jobs; `done` has this length.
    pub job_count: usize,
    /// One flag per job in deterministic order: `true` once probed.
    pub done: Vec<bool>,
    /// Open results found so far, across every run.
    pub findings: Vec<StateFinding>,
}

impl ScanState {
    /// A fresh state for a scan of `job_count` jobs with nothing done yet.
    pub fn new(proto: &str, targets: Vec<String>, ports: Vec<u16>, job_count: usize) -> Self {
        Self {
            proto: proto.to_string(),
            targets,
            ports,
            job_count,
            done: vec![false; job_count],
            findings: Vec::new(),
        }
    }

    /// Load a state file, returning an error if it is missing or malformed.
    pub fn load(path: &Path) -> io::Result<ScanState> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(io::Error::other)
    }

    /// Write the state to `path` atomically: serialize to a sibling temp file
    /// and rename it into place, so a crash mid-write leaves the old file intact.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_string(self).map_err(io::Error::other)?;
        let tmp = tmp_path(path);
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)
    }

    /// Whether a loaded state describes the same scan as the current invocation
    /// (same protocol, targets, ports, and job count). A mismatch means the
    /// file belongs to a different scan and must not be resumed.
    pub fn is_compatible(
        &self,
        proto: &str,
        targets: &[String],
        ports: &[u16],
        job_count: usize,
    ) -> bool {
        self.proto == proto
            && self.targets == targets
            && self.ports == ports
            && self.job_count == job_count
            && self.done.len() == job_count
    }

    /// The number of jobs still to do.
    pub fn remaining(&self) -> usize {
        self.done.iter().filter(|d| !**d).count()
    }

    /// Whether the job at `idx` still needs to be probed.
    pub fn is_pending(&self, idx: usize) -> bool {
        !self.done.get(idx).copied().unwrap_or(true)
    }

    /// Record that job `idx` is done, optionally with an open finding.
    pub fn complete(&mut self, idx: usize, finding: Option<StateFinding>) {
        if let Some(slot) = self.done.get_mut(idx) {
            *slot = true;
        }
        if let Some(finding) = finding {
            self.findings.push(finding);
        }
    }
}

/// The sibling temp path used for atomic writes.
fn tmp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ScanState {
        let mut s = ScanState::new(
            "tcp",
            vec!["127.0.0.1".into(), "127.0.0.2".into()],
            vec![80, 443],
            4,
        );
        s.complete(
            0,
            Some(StateFinding {
                host: 0,
                port: 80,
                latency_ms: 5,
                status: "open".into(),
                service: Some("http".into()),
                banner: None,
            }),
        );
        s.complete(1, None);
        s
    }

    #[test]
    fn round_trips_through_json() {
        let s = sample();
        let json = serde_json::to_string(&s).unwrap();
        let back: ScanState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn tracks_done_and_remaining() {
        let s = sample();
        assert_eq!(s.remaining(), 2);
        assert!(!s.is_pending(0));
        assert!(!s.is_pending(1));
        assert!(s.is_pending(2));
        assert!(s.is_pending(3));
    }

    #[test]
    fn compatibility_requires_matching_shape() {
        let s = sample();
        let targets = vec!["127.0.0.1".to_string(), "127.0.0.2".to_string()];
        assert!(s.is_compatible("tcp", &targets, &[80, 443], 4));
        // Different protocol, ports, targets, or job count are all incompatible.
        assert!(!s.is_compatible("udp", &targets, &[80, 443], 4));
        assert!(!s.is_compatible("tcp", &targets, &[80], 4));
        assert!(!s.is_compatible("tcp", &["127.0.0.1".to_string()], &[80, 443], 4));
        assert!(!s.is_compatible("tcp", &targets, &[80, 443], 9));
    }

    #[test]
    fn save_then_load_preserves_state() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("asphyxia-state-{}.json", std::process::id()));
        let s = sample();
        s.save(&path).expect("save");
        let back = ScanState::load(&path).expect("load");
        assert_eq!(s, back);
        // The temp sibling must not be left behind.
        assert!(!tmp_path(&path).exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn findings_accumulate_across_completes() {
        let mut s = ScanState::new("tcp", vec!["10.0.0.1".into()], vec![22], 1);
        assert!(s.findings.is_empty());
        s.complete(
            0,
            Some(StateFinding {
                host: 0,
                port: 22,
                latency_ms: 1,
                status: "open".into(),
                service: None,
                banner: None,
            }),
        );
        assert_eq!(s.findings.len(), 1);
        assert_eq!(s.remaining(), 0);
    }
}
