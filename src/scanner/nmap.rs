//! Nmap handoff: hand a host's open ports to `nmap` for a deeper look.
//!
//! Asphyxia's job is to find open ports fast; nmap's is to interrogate them
//! (service/version detection, default scripts). This module builds the nmap
//! invocation for a host and its discovered ports and runs it, so the common
//! "scan fast, then deep-dive" workflow is a single command.

use std::io;
use std::process::{Command, ExitStatus};

/// Default nmap scan flags used when the user does not supply their own via
/// `--nmap-args`: service/version detection plus the default script set.
pub const DEFAULT_NMAP_ARGS: &[&str] = &["-sV", "-sC"];

/// Build the full nmap argument vector for `host` and its open `ports`.
///
/// When `extra` is non-empty it replaces the [`DEFAULT_NMAP_ARGS`] scan flags;
/// either way asphyxia always appends `-p <ports>` and the target host, since it
/// owns which ports to hand off. Ports are emitted in the given order as a
/// comma-separated list.
pub fn nmap_args(host: &str, ports: &[u16], extra: &[String]) -> Vec<String> {
    let mut args: Vec<String> = if extra.is_empty() {
        DEFAULT_NMAP_ARGS.iter().map(|s| s.to_string()).collect()
    } else {
        extra.to_vec()
    };

    let port_list = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    args.push("-p".to_string());
    args.push(port_list);
    args.push(host.to_string());
    args
}

/// Split a raw `--nmap-args` string into individual arguments on whitespace.
///
/// This is a simple split, not a full shell parser: it does not honour quotes.
/// Empty input yields no arguments (the defaults then apply).
pub fn split_extra_args(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(|s| s.to_string()).collect()
}

/// Run `nmap` against `host` for the given open `ports`, inheriting stdio so its
/// report streams straight to the terminal.
///
/// Returns the process exit status, or an [`io::Error`] if nmap could not be
/// started — notably [`io::ErrorKind::NotFound`] when nmap is not on `PATH`.
pub fn run_nmap(host: &str, ports: &[u16], extra: &[String]) -> io::Result<ExitStatus> {
    Command::new("nmap")
        .args(nmap_args(host, ports, extra))
        .status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_used_when_no_extra_args() {
        let args = nmap_args("scanme.nmap.org", &[22, 80], &[]);
        assert_eq!(
            args,
            vec!["-sV", "-sC", "-p", "22,80", "scanme.nmap.org"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn extra_args_replace_defaults_but_ports_and_host_are_appended() {
        let extra = split_extra_args("-A -T4");
        let args = nmap_args("10.0.0.1", &[443], &extra);
        assert_eq!(
            args,
            vec!["-A", "-T4", "-p", "443", "10.0.0.1"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn ports_are_joined_in_order() {
        let args = nmap_args("host", &[80, 22, 8080], &[]);
        // The port list is the entry right after "-p".
        let idx = args.iter().position(|a| a == "-p").unwrap();
        assert_eq!(args[idx + 1], "80,22,8080");
    }

    #[test]
    fn split_extra_args_handles_blank_and_whitespace() {
        assert!(split_extra_args("").is_empty());
        assert!(split_extra_args("   ").is_empty());
        assert_eq!(split_extra_args("  -sS   -Pn "), vec!["-sS", "-Pn"]);
    }
}
