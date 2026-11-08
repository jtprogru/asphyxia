//! `asphyxia diff` command: load two result files and render the comparison.

use std::path::Path;

use asphyxia::output::OutputFormat;
use owo_colors::OwoColorize;

/// Run the diff command. Runtime errors are returned as strings so `main` can
/// print them consistently and choose the exit code.
pub fn run(
    old: &Path,
    new: &Path,
    output: OutputFormat,
    output_file: Option<&Path>,
) -> Result<(), String> {
    if !matches!(
        output,
        OutputFormat::Text | OutputFormat::Json | OutputFormat::Jsonl
    ) {
        return Err("diff supports -o text, -o json, or -o jsonl".to_string());
    }

    let old_records = asphyxia::diff::load(old)?;
    let new_records = asphyxia::diff::load(new)?;
    let report = asphyxia::diff::compare(old_records, new_records);

    // Keep scope warnings visible even when the payload goes to a file.
    if output != OutputFormat::Text {
        for warning in &report.warnings {
            eprintln!("{}", format!("warning: {warning}").yellow());
        }
    }

    let rendered = match output {
        OutputFormat::Text => asphyxia::diff::render_text(&report),
        OutputFormat::Json => {
            format!("{}\n", serde_json::to_string_pretty(&report).unwrap())
        }
        OutputFormat::Jsonl => asphyxia::diff::render_jsonl(&report),
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
