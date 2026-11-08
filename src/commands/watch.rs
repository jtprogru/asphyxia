//! Watch mode: re-run the scan on an interval and emit JSON Lines changes.
//!
//! The controller runs a normal `ps` scan as a child process per pass to a
//! temporary JSONL result, keeps only the previous and current snapshots, and
//! emits a baseline followed by diff events annotated with `pass`/`timestamp`.

use std::path::Path;
use std::time::Duration;

/// Parse a `--watch` interval: a plain number is seconds; `ms`, `s`, `m`, `h`
/// suffixes are accepted.
fn parse_watch_interval(spec: &str) -> Result<Duration, String> {
    let spec = spec.trim();
    let (number, multiplier) = if let Some(number) = spec.strip_suffix("ms") {
        (number, 1u64)
    } else if let Some(number) = spec.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = spec.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = spec.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        (spec, 1_000)
    };
    let value: u64 = number
        .trim()
        .parse()
        .map_err(|_| format!("Invalid --watch interval '{spec}' (use e.g. 30s or 5m)"))?;
    if value == 0 {
        return Err("--watch interval must be greater than zero".to_string());
    }
    let millis = value
        .checked_mul(multiplier)
        .ok_or_else(|| "--watch interval is too large".to_string())?;
    Ok(Duration::from_millis(millis))
}

/// Build the child invocation for one watch pass: the original `ps` arguments
/// with the watch/output flags removed, plus JSONL output to `temp`.
fn watch_child_args(temp: &Path) -> Result<Vec<std::ffi::OsString>, String> {
    let raw: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let mut args = Vec::new();
    let mut index = 0;
    while index < raw.len() {
        let text = raw[index].to_string_lossy();
        if matches!(
            text.as_ref(),
            "--watch"
                | "--watch-count"
                | "-o"
                | "--output"
                | "--output-file"
                | "--oF"
                | "--report"
                | "--report-file"
        ) {
            index += 2;
            continue;
        }
        if text.starts_with("--watch=")
            || text.starts_with("--watch-count=")
            || text.starts_with("--output=")
            || text.starts_with("--output-file=")
            || text.starts_with("--report=")
            || text.starts_with("--report-file=")
            || text == "--full-banners"
            || (text.starts_with("-o") && text.len() > 2)
        {
            index += 1;
            continue;
        }
        if text == "--nmap"
            || text.starts_with("--nmap=")
            || text == "--nmap-args"
            || text.starts_with("--nmap-args=")
        {
            return Err("--watch cannot be combined with --nmap".to_string());
        }
        if text == "--stdin" {
            return Err("--watch cannot be combined with --stdin".to_string());
        }
        if text == "--resume" || text.starts_with("--resume=") {
            return Err("--watch cannot be combined with --resume".to_string());
        }
        args.push(raw[index].clone());
        index += 1;
    }
    args.push("-o".into());
    args.push("jsonl".into());
    args.push("--output-file".into());
    args.push(temp.as_os_str().to_os_string());
    Ok(args)
}

/// Run a scan repeatedly and emit JSON Lines changes between passes. The first
/// pass is a baseline; each later pass is diffed against exactly the previous
/// one, so memory holds at most two result sets.
pub fn run_watch(spec: &str, count: Option<usize>) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let interval = parse_watch_interval(spec)?;
    if count == Some(0) {
        return Err("--watch-count must be at least 1".to_string());
    }
    let executable = std::env::current_exe()
        .map_err(|e| format!("Could not locate the asphyxia binary: {e}"))?;

    static STOP: AtomicBool = AtomicBool::new(false);
    let _ = ctrlc::set_handler(|| STOP.store(true, Ordering::SeqCst));

    let mut previous: Option<Vec<asphyxia::diff::Record>> = None;
    let mut pass = 0usize;
    loop {
        pass += 1;
        let temp = std::env::temp_dir().join(format!(
            "asphyxia-watch-{}-{pass}.jsonl",
            std::process::id()
        ));
        let child_args = watch_child_args(&temp)?;

        let status = std::process::Command::new(&executable)
            .args(&child_args)
            .status()
            .map_err(|e| format!("Could not start watch pass: {e}"))?;

        if !status.success() {
            let _ = std::fs::remove_file(&temp);
            if status.code() == Some(130) {
                // The child was interrupted alongside us; stop cleanly.
                break;
            }
            return Err(format!("watch pass {pass} failed ({status})"));
        }

        let current = match asphyxia::diff::load(&temp) {
            Ok(records) => records,
            Err(e) => {
                let _ = std::fs::remove_file(&temp);
                return Err(e);
            }
        };
        let _ = std::fs::remove_file(&temp);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        if let Some(previous) = previous.take() {
            let report = asphyxia::diff::compare(previous, current.clone());
            let events = asphyxia::diff::events(&report);
            if report.is_empty() {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "no_changes",
                        "timestamp": timestamp,
                        "pass": pass
                    })
                );
            }
            for event in events {
                let mut event = event;
                if let Some(object) = event.as_object_mut() {
                    object.insert("timestamp".into(), serde_json::json!(timestamp));
                    object.insert("pass".into(), serde_json::json!(pass));
                }
                println!("{event}");
            }
        } else {
            println!(
                "{}",
                serde_json::json!({
                    "event": "baseline",
                    "timestamp": timestamp,
                    "pass": pass,
                    "records": current.len()
                })
            );
        }
        previous = Some(current);

        if count.is_some_and(|count| pass >= count) || STOP.load(Ordering::SeqCst) {
            break;
        }

        // Sleep in short slices so Ctrl-C is handled promptly.
        let deadline = std::time::Instant::now() + interval;
        while std::time::Instant::now() < deadline {
            if STOP.load(Ordering::SeqCst) {
                break;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            std::thread::sleep(remaining.min(Duration::from_millis(100)));
        }
    }
    Ok(())
}
