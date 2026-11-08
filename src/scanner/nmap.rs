//! Nmap handoff: hand a host's open ports to `nmap` for a deeper look.
//!
//! Asphyxia's job is to find open ports fast; nmap's is to interrogate them
//! (service/version detection, default scripts). This module builds the nmap
//! invocation for a host and its discovered ports and runs it, so the common
//! "scan fast, then deep-dive" workflow is a single command.

use std::io;
use std::process::{Command, ExitStatus};

/// Default nmap scan flags for a TCP handoff when the user does not supply their
/// own via `--nmap-args`: service/version detection plus the default script set.
pub const DEFAULT_NMAP_ARGS: &[&str] = &["-sV", "-sC"];

/// Default nmap scan flags for a UDP handoff: UDP scanning plus version
/// detection. A plain `-sV` would probe the same port numbers over TCP and
/// report nothing for a UDP-only service.
pub const DEFAULT_UDP_NMAP_ARGS: &[&str] = &["-sU", "-sV"];

/// Build the full nmap argument vector for `host` and its open `ports`.
///
/// When `extra` is non-empty it replaces the default scan flags; either way
/// asphyxia always appends `-p <ports>` and the target host, since it owns which
/// ports to hand off. Ports are emitted in the given order as a comma-separated
/// list. A UDP handoff defaults to [`DEFAULT_UDP_NMAP_ARGS`] instead of the TCP
/// profile.
pub fn nmap_args(host: &str, ports: &[u16], extra: &[String], udp: bool) -> Vec<String> {
    let mut args: Vec<String> = if extra.is_empty() {
        let defaults = if udp {
            DEFAULT_UDP_NMAP_ARGS
        } else {
            DEFAULT_NMAP_ARGS
        };
        defaults.iter().map(|s| s.to_string()).collect()
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
/// This is a simple split, not a full shell parser: it does not honor quotes.
/// Empty input yields no arguments (the defaults then apply).
pub fn split_extra_args(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(|s| s.to_string()).collect()
}

/// Run `nmap` against `host` for the given open `ports`, inheriting stdio so its
/// report streams straight to the terminal.
///
/// Returns the process exit status, or an [`io::Error`] if nmap could not be
/// started — notably [`io::ErrorKind::NotFound`] when nmap is not on `PATH`.
pub fn run_nmap(host: &str, ports: &[u16], extra: &[String], udp: bool) -> io::Result<ExitStatus> {
    Command::new("nmap")
        .args(nmap_args(host, ports, extra, udp))
        .status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_used_when_no_extra_args() {
        let args = nmap_args("scanme.nmap.org", &[22, 80], &[], false);
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
        let args = nmap_args("10.0.0.1", &[443], &extra, false);
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
        let args = nmap_args("host", &[80, 22, 8080], &[], false);
        // The port list is the entry right after "-p".
        let idx = args.iter().position(|a| a == "-p").unwrap();
        assert_eq!(args[idx + 1], "80,22,8080");
    }

    #[test]
    fn udp_defaults_scan_udp_and_detect_versions() {
        let args = nmap_args("10.0.0.1", &[53, 123], &[], true);
        assert_eq!(
            args,
            vec!["-sU", "-sV", "-p", "53,123", "10.0.0.1"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn split_extra_args_handles_blank_and_whitespace() {
        assert!(split_extra_args("").is_empty());
        assert!(split_extra_args("   ").is_empty());
        assert_eq!(split_extra_args("  -sS   -Pn "), vec!["-sS", "-Pn"]);
    }
}
