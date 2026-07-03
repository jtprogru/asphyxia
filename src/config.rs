//! Configuration profiles loaded from `~/.asphyxia.toml`.
//!
//! A config file supplies defaults for repeated runs (timeout, concurrency,
//! retries, output format) so common options need not be retyped every time.
//! Every field is optional; a missing field simply falls back to the built-in
//! default. Command-line flags always win over the config — the merge that
//! enforces that precedence lives in `main`, which knows which flags the user
//! actually passed.

use clap::ValueEnum;
use serde::Deserialize;
use std::path::PathBuf;

use crate::output::OutputFormat;

/// Environment variable that overrides the config file location (mainly for
/// tests and non-standard setups).
pub const CONFIG_ENV: &str = "ASPHYXIA_CONFIG";

/// Optional defaults read from `~/.asphyxia.toml`.
///
/// Unknown keys are rejected so a typo surfaces as an error rather than being
/// silently ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Per-connection timeout in milliseconds.
    pub timeout: Option<u64>,
    /// Maximum number of concurrent connection attempts.
    pub concurrency: Option<usize>,
    /// Extra retries per probe on no answer.
    pub retries: Option<u32>,
    /// Probes-per-second cap across the whole scan (0 = no cap).
    pub rate: Option<u32>,
    /// Output format name (`text`, `json`, `jsonl`, `csv`, `grep`).
    pub output: Option<String>,
}

impl Config {
    /// Parse a config from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Config, String> {
        toml::from_str(s).map_err(|e| e.to_string())
    }

    /// Load the config from [`config_path`], returning an empty config when the
    /// file is absent or unreadable. An existing-but-invalid file is reported
    /// on stderr and then ignored, so a broken config never aborts a scan.
    pub fn load() -> Config {
        let Some(path) = config_path() else {
            return Config::default();
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Config::default();
        };
        Self::from_toml_str(&text).unwrap_or_else(|e| {
            eprintln!("warning: ignoring invalid config {}: {}", path.display(), e);
            Config::default()
        })
    }

    /// The configured output format, if set and valid.
    pub fn output_format(&self) -> Option<OutputFormat> {
        self.output
            .as_deref()
            .and_then(|s| OutputFormat::from_str(s, true).ok())
    }
}

/// The path the config is loaded from: `$ASPHYXIA_CONFIG` if set, else
/// `$HOME/.asphyxia.toml`. Returns `None` when neither is available.
pub fn config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(CONFIG_ENV) {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".asphyxia.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_config() {
        let cfg = Config::from_toml_str(
            "timeout = 500\nconcurrency = 128\nretries = 2\noutput = \"json\"\n",
        )
        .unwrap();
        assert_eq!(cfg.timeout, Some(500));
        assert_eq!(cfg.concurrency, Some(128));
        assert_eq!(cfg.retries, Some(2));
        assert_eq!(cfg.output_format(), Some(OutputFormat::Json));
    }

    #[test]
    fn empty_config_is_all_none() {
        let cfg = Config::from_toml_str("").unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.output_format(), None);
    }

    #[test]
    fn partial_config_leaves_the_rest_unset() {
        let cfg = Config::from_toml_str("timeout = 1000\n").unwrap();
        assert_eq!(cfg.timeout, Some(1000));
        assert_eq!(cfg.concurrency, None);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::from_toml_str("bogus = 1\n").is_err());
    }

    #[test]
    fn invalid_output_name_yields_none() {
        let cfg = Config::from_toml_str("output = \"nonsense\"\n").unwrap();
        assert_eq!(cfg.output_format(), None);
    }
}
