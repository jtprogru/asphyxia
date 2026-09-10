use std::path::PathBuf;

use clap::{ArgGroup, Parser, ValueEnum};

use crate::output::OutputFormat;
use crate::scanner::syn::ProbeMode;

/// Which probe a port scan sends, and hence which port states it can report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ScanMode {
    /// Full TCP connect: needs no privileges and reports open ports.
    #[default]
    Connect,
    /// Half-open SYN over a raw socket: open, closed or filtered.
    Syn,
    /// Lone ACK over a raw socket: unfiltered or filtered. It maps what a
    /// firewall lets through, and never claims a port is open or closed.
    Ack,
}

/// Why a raw-packet scan mode cannot run, so the scan falls back to connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// No raw socket: the process lacks root / `CAP_NET_RAW`.
    RawSocket,
    /// No libpcap/BPF capture, so replies could never be read.
    Capture,
    /// The target is IPv6, which the raw-packet path does not handle.
    Ipv6,
}

impl ScanMode {
    /// The raw-packet probe this mode sends, or `None` for the connect scan.
    pub fn probe_mode(self) -> Option<ProbeMode> {
        match self {
            ScanMode::Connect => None,
            ScanMode::Syn => Some(ProbeMode::Syn),
            ScanMode::Ack => Some(ProbeMode::Ack),
        }
    }

    /// Whether this mode needs a raw socket and a packet capture to run.
    pub fn needs_raw(self) -> bool {
        self.probe_mode().is_some()
    }

    /// Stable name for this mode in structured output and messages.
    pub fn label(self) -> &'static str {
        match self.probe_mode() {
            Some(mode) => mode.label(),
            None => "connect",
        }
    }

    /// Give up on this mode and fall back to a connect scan, with the message
    /// saying which mode was dropped and why.
    ///
    /// Falling back is not a silent equivalence: a connect scan answers a
    /// different question (open/closed) than an ACK scan (unfiltered/filtered),
    /// so the operator has to be told, and every result carries the mode that
    /// actually produced it.
    pub fn downgrade(self, cause: Unavailable) -> (ScanMode, String) {
        let reason = match cause {
            Unavailable::RawSocket => "needs root/CAP_NET_RAW",
            Unavailable::Capture => "needs libpcap/BPF to read replies",
            Unavailable::Ipv6 => "is IPv4-only",
        };
        (
            ScanMode::Connect,
            format!(
                "{} scan {} — falling back to connect scan",
                self.label().to_uppercase(),
                reason
            ),
        )
    }
}

/// Command line arguments for the Asphyxia network scanner
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "A fast and efficient network scanner written in Rust",
    long_about = r#"
A powerful network scanner that allows you to scan for available hosts and ports.

Examples:
  # Scan a range of ports
  asphyxia ps -t example.com -r 80 443

  # Scan specific ports
  asphyxia ps -t example.com -s 22,80,443,8080

  # Scan every port (1-65535)
  asphyxia ps -t example.com --all-ports

  # Scan the N most common TCP ports, or a named port set
  asphyxia ps -t example.com --top-ports 100
  asphyxia ps -t example.com --ports web

  # Scan UDP ports instead of TCP (open or open|filtered)
  asphyxia ps -t example.com -s 53,123,161 --udp

  # SYN/stealth scan via raw sockets (needs root/CAP_NET_RAW)
  sudo asphyxia ps -t example.com --top-ports 1000 --syn

  # ACK scan: which ports a firewall lets through (unfiltered) or blocks (filtered)
  sudo asphyxia ps -t example.com --top-ports 100 --scan ack

  # Grab banners and identify services on open ports
  asphyxia ps -t example.com -s 22,80,443 --sV

  # Checkpoint a long scan and resume it after an interruption
  asphyxia ps -iL targets.txt --all-ports --resume scan.state

  # Find open ports fast, then hand them to nmap for a deep dive
  asphyxia ps -t scanme.nmap.org --top-ports 100 --nmap
  asphyxia ps -t scanme.nmap.org --top-ports 100 --nmap --nmap-args "-A -T4"

  # Read targets from a file (hosts, IPs, or CIDRs; one per line)
  asphyxia ps -i targets.txt --top-ports 100

  # Feed live hosts from an address scan straight into a port scan
  asphyxia as -s 192.168.1.0/24 -o jsonl | asphyxia ps --stdin -s 22,80,443
  asphyxia as -s 192.168.1.0/24 -o jsonl | asphyxia ps --stdin --all-ports

  # Scan a subnet (IPv4 or IPv6)
  asphyxia as -s 192.168.1.0/24
  asphyxia as -s 2001:db8::/120

  # Scan a specific IP address (IPv4 or IPv6)
  asphyxia as -t 192.168.1.1
  asphyxia as -t 2001:db8::1

  # Scan a range of IP addresses
  asphyxia as -r 192.168.1.1 192.168.1.20

  # Skip host discovery and treat every address as up (like nmap -Pn)
  asphyxia as -s 192.168.1.0/24 --Pn

  # Exclude hosts/CIDRs, ports, or known CDN/WAF ranges
  asphyxia as -s 192.168.1.0/24 --exclude 192.168.1.0/28
  asphyxia ps -t example.com --top-ports 1000 --exclude-ports 9100 --exclude-cdn

  # Use a custom connection timeout (milliseconds)
  asphyxia ps -t example.com -s 22,80,443 --timeout 500

  # Raise concurrency to speed up a large subnet scan
  asphyxia as -s 10.0.0.0/22 --concurrency 512

  # Send every probe through a specific interface (like `ssh -B en0` / `nmap -e`)
  asphyxia ps -t fin.example.com --top-ports 1000 --interface en0
  asphyxia as -s 10.20.0.0/24 -e en0

  # Retry probes on a lossy network to cut false negatives (refused ports are not retried)
  asphyxia ps -t example.com --top-ports 1000 --retries 2

  # Cap the scan rate, or pick a timing profile (0 paranoid .. 5 insane)
  asphyxia ps -t example.com --all-ports --rate 1000
  asphyxia ps -t example.com --top-ports 1000 -T4

  # Emit machine-readable output for a pipeline (text | json | jsonl | csv | grep)
  asphyxia ps -t example.com -s 22,80,443 -o jsonl
  asphyxia as -s 10.0.0.0/24 -o json

  # Save machine-readable output to a file instead of stdout
  asphyxia ps -t example.com --top-ports 1000 -o csv --output-file scan.csv

Required arguments:
  For port scanning (ps):
    -t, --host <HOST>    Target host to scan (e.g., example.com)
    --stdin              Read targets from stdin instead of -t (one host per line, or
                         JSON/JSONL from `asphyxia as -o`); mutually exclusive with -t
    -i, --target-file <PATH>     Read targets from a file (hosts, IPs, or CIDRs, one per line)
    -r, --range <START> <END>    Scan a range of ports (e.g., 80 443)
    -s, --specific <PORTS>       Scan specific ports (comma-separated, e.g., 22,80,443)
    -a, --all-ports              Scan the entire port range (1-65535)
    --top-ports <N>              Scan the N most common TCP ports (up to 1000)
    --ports <NAME>               Scan a named port set (web, mail, db, remote, windows)
    -u, --udp                    Scan UDP ports instead of TCP (open or open|filtered)
    --syn                        SYN/stealth scan via raw sockets (needs root; else connect)
    --scan <MODE>                Probe type: connect (default), syn, or ack (raw modes need root)
    --sV                         Grab banners and identify the service on each open port
    --resume <PATH>              Checkpoint progress and resume from PATH if it exists
    --rate <PPS>                 Cap connection attempts per second (0 = no cap)
    -T, --timing <0-5>           Timing profile (paranoid..insane) presetting the tunables
    --timeout <MS>               Connection timeout in milliseconds (default: 2000)
    -e, --interface <NAME>       Bind every probe to this interface (e.g. en0), like `ssh -B`

  For address scanning (as):
    -s, --subnet <SUBNET>        Scan a subnet (e.g., 192.168.1.0/24 or 2001:db8::/120)
    -t, --target <IP>            Scan a specific IP address (IPv4 or IPv6)
    -r, --range <START> <END>    Scan a range of IP addresses
    --Pn                         Skip host discovery; treat every target as up
    --timeout <MS>               Connection timeout in milliseconds (default: 2000)
    -e, --interface <NAME>       Bind every probe to this interface (e.g. en0), like `ssh -B`
"#
)]
pub enum Args {
    /// Port scanning command
    #[command(
        name = "ps",
        about = "Start port scanning",
        // Exactly one target source is required: `-t`, `--stdin`, or `-iL`.
        group = ArgGroup::new("target").required(true).args(["host", "stdin", "target_file"])
    )]
    PortScan {
        /// Target host (e.g., example.com)
        #[arg(short = 't', long, group = "target")]
        host: Option<String>,

        /// Read targets from stdin instead of -t: one host per line, or the
        /// JSON/JSONL emitted by `asphyxia as -o` (the `ip` field is used).
        #[arg(long, group = "target")]
        stdin: bool,

        /// Read targets from a file (hosts, IPs, or CIDRs; one per line)
        #[arg(
            short = 'i',
            long = "target-file",
            visible_alias = "iL",
            value_name = "PATH",
            group = "target"
        )]
        target_file: Option<PathBuf>,

        /// Scan range of ports: start end
        #[arg(short = 'r', long, num_args = 2, group = "ports")]
        range: Option<Vec<u16>>,

        /// Scan specific ports separated by comma
        #[arg(short = 's', long, group = "ports")]
        specific: Option<String>,

        /// Scan the entire port range (1-65535)
        #[arg(short = 'a', long = "all-ports", group = "ports")]
        all_ports: bool,

        /// Scan the N most common TCP ports (e.g. 100 or 1000)
        #[arg(long = "top-ports", value_name = "N", group = "ports")]
        top_ports: Option<usize>,

        /// Scan a named port set (web, mail, db, remote, windows)
        #[arg(long = "ports", value_name = "NAME", group = "ports")]
        port_set: Option<String>,

        /// Remove these comma-separated ports from the scan set
        #[arg(long = "exclude-ports", value_name = "PORTS")]
        exclude_ports: Option<String>,

        /// For known CDN/WAF targets, scan only 80 and 443 instead of the full set
        #[arg(long = "exclude-cdn")]
        exclude_cdn: bool,

        /// Scan UDP ports instead of TCP (results are open or open|filtered)
        #[arg(short = 'u', long = "udp")]
        udp: bool,

        /// SYN/stealth scan via raw sockets (needs root/CAP_NET_RAW; else falls back to connect)
        #[arg(long = "syn", conflicts_with_all = ["udp", "scan"])]
        syn: bool,

        /// Probe type: connect (default), syn (half-open), or ack (firewall state)
        #[arg(
            long = "scan",
            value_name = "MODE",
            value_enum,
            default_value_t = ScanMode::Connect,
            conflicts_with = "udp"
        )]
        scan: ScanMode,

        /// Grab banners and identify the service on each open port (TCP only)
        #[arg(long = "sV", visible_alias = "banner")]
        service_detection: bool,

        /// Checkpoint progress to a file and resume from it if it already exists
        #[arg(long = "resume", value_name = "PATH")]
        resume: Option<PathBuf>,

        /// After the scan, run nmap on each host's open ports for a deep dive
        #[arg(long = "nmap")]
        nmap: bool,

        /// Custom nmap arguments (replace the default -sV -sC); implies --nmap
        #[arg(
            long = "nmap-args",
            value_name = "ARGS",
            requires = "nmap",
            allow_hyphen_values = true
        )]
        nmap_args: Option<String>,

        /// Connection timeout in milliseconds
        #[arg(long, value_name = "MS", default_value_t = 2000)]
        timeout: u64,

        /// Maximum number of concurrent connection attempts
        #[arg(short = 'c', long, value_name = "N", default_value_t = 256)]
        concurrency: usize,

        /// Bind every probe to this network interface (e.g. en0), like `ssh -B`
        #[arg(
            short = 'e',
            long = "interface",
            visible_alias = "iface",
            value_name = "NAME"
        )]
        interface: Option<String>,

        /// Extra retries per probe on no answer (timeout); refused ports are final
        #[arg(long, value_name = "N", default_value_t = 0)]
        retries: u32,

        /// Cap connection attempts per second across the whole scan (0 = no cap)
        #[arg(long, value_name = "PPS")]
        rate: Option<u32>,

        /// Timing profile 0-5 (paranoid..insane) presetting timeout/concurrency/retries/rate
        #[arg(short = 'T', long = "timing", value_name = "0-5", value_parser = clap::value_parser!(u8).range(0..=5))]
        timing: Option<u8>,

        /// Output format
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,

        /// Write machine-readable output to a file instead of stdout
        #[arg(long = "output-file", visible_alias = "oF", value_name = "PATH")]
        output_file: Option<PathBuf>,
    },
    /// Address scanning command
    #[command(name = "as", about = "Start address scanning")]
    AddressScan {
        /// Scan a subnet (e.g., 192.168.1.0/24)
        #[arg(short = 's', long, group = "scan_type")]
        subnet: Option<String>,

        /// Scan a specific IP address
        #[arg(short = 't', long, group = "scan_type")]
        target: Option<String>,

        /// Scan a range of IP addresses
        #[arg(short = 'r', long, num_args = 2, group = "scan_type")]
        range: Option<Vec<String>>,

        /// Skip host discovery and treat every target as up (like nmap -Pn)
        #[arg(long = "Pn", visible_alias = "skip-discovery")]
        no_discovery: bool,

        /// Exclude these hosts/CIDRs from the scan (repeatable, comma-separated)
        #[arg(long = "exclude", value_name = "SPEC")]
        exclude: Vec<String>,

        /// Exclude hosts/CIDRs listed in a file (one per line)
        #[arg(long = "exclude-file", value_name = "PATH")]
        exclude_file: Option<PathBuf>,

        /// Connection timeout in milliseconds
        #[arg(long, value_name = "MS", default_value_t = 2000)]
        timeout: u64,

        /// Maximum number of concurrent connection attempts
        #[arg(short = 'c', long, value_name = "N", default_value_t = 256)]
        concurrency: usize,

        /// Bind every probe to this network interface (e.g. en0), like `ssh -B`
        #[arg(
            short = 'e',
            long = "interface",
            visible_alias = "iface",
            value_name = "NAME"
        )]
        interface: Option<String>,

        /// Extra retries per probe on no answer (timeout); refused ports are final
        #[arg(long, value_name = "N", default_value_t = 0)]
        retries: u32,

        /// Cap connection attempts per second across the whole scan (0 = no cap)
        #[arg(long, value_name = "PPS")]
        rate: Option<u32>,

        /// Timing profile 0-5 (paranoid..insane) presetting timeout/concurrency/retries/rate
        #[arg(short = 'T', long = "timing", value_name = "0-5", value_parser = clap::value_parser!(u8).range(0..=5))]
        timing: Option<u8>,

        /// Output format
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,

        /// Write machine-readable output to a file instead of stdout
        #[arg(long = "output-file", visible_alias = "oF", value_name = "PATH")]
        output_file: Option<PathBuf>,
    },
}

impl Args {
    /// The requested maximum number of concurrent connection attempts,
    /// regardless of which subcommand was invoked.
    pub fn concurrency(&self) -> usize {
        match self {
            Args::PortScan { concurrency, .. } | Args::AddressScan { concurrency, .. } => {
                *concurrency
            }
        }
    }

    /// The requested output format, regardless of which subcommand was invoked.
    pub fn output_format(&self) -> OutputFormat {
        match self {
            Args::PortScan { output, .. } | Args::AddressScan { output, .. } => *output,
        }
    }

    /// The network interface every probe should be bound to, if requested,
    /// regardless of which subcommand was invoked.
    pub fn interface(&self) -> Option<&str> {
        match self {
            Args::PortScan { interface, .. } | Args::AddressScan { interface, .. } => {
                interface.as_deref()
            }
        }
    }

    /// The file to write machine-readable output to, if any, regardless of
    /// which subcommand was invoked.
    pub fn output_file(&self) -> Option<&PathBuf> {
        match self {
            Args::PortScan { output_file, .. } | Args::AddressScan { output_file, .. } => {
                output_file.as_ref()
            }
        }
    }

    /// The number of extra retries per probe, regardless of which subcommand
    /// was invoked.
    pub fn retries(&self) -> u32 {
        match self {
            Args::PortScan { retries, .. } | Args::AddressScan { retries, .. } => *retries,
        }
    }

    /// The probes-per-second cap, if any, regardless of which subcommand was
    /// invoked.
    pub fn rate(&self) -> Option<u32> {
        match self {
            Args::PortScan { rate, .. } | Args::AddressScan { rate, .. } => *rate,
        }
    }

    /// The probe type the invocation asks for, folding the older `--syn` flag
    /// into [`ScanMode`]. UDP and address scans always use plain sockets.
    pub fn scan_mode(&self) -> ScanMode {
        match self {
            Args::PortScan { udp: true, .. } | Args::AddressScan { .. } => ScanMode::Connect,
            Args::PortScan { syn, scan, .. } => {
                if *syn {
                    ScanMode::Syn
                } else {
                    *scan
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn port_scan(extra: &[&str]) -> Args {
        let mut argv = vec!["asphyxia", "ps", "-t", "127.0.0.1", "-s", "80"];
        argv.extend_from_slice(extra);
        Args::parse_from(argv)
    }

    #[test]
    fn default_port_scan_is_a_connect_scan() {
        assert_eq!(port_scan(&[]).scan_mode(), ScanMode::Connect);
        assert_eq!(ScanMode::Connect.probe_mode(), None);
        assert!(!ScanMode::Connect.needs_raw());
    }

    #[test]
    fn scan_flag_selects_the_probe_type() {
        assert_eq!(port_scan(&["--scan", "ack"]).scan_mode(), ScanMode::Ack);
        assert_eq!(port_scan(&["--scan", "syn"]).scan_mode(), ScanMode::Syn);
        assert_eq!(
            port_scan(&["--scan", "connect"]).scan_mode(),
            ScanMode::Connect
        );
    }

    #[test]
    fn the_syn_flag_is_the_syn_mode() {
        assert_eq!(port_scan(&["--syn"]).scan_mode(), ScanMode::Syn);
    }

    #[test]
    fn udp_scans_never_take_a_raw_mode() {
        // --udp conflicts with both flags, so a UDP scan is always connect.
        assert_eq!(port_scan(&["--udp"]).scan_mode(), ScanMode::Connect);
    }

    #[test]
    fn scan_and_syn_flags_conflict() {
        let parsed = Args::try_parse_from([
            "asphyxia",
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "80",
            "--syn",
            "--scan",
            "ack",
        ]);
        assert!(parsed.is_err(), "--syn and --scan must not be combined");
    }

    #[test]
    fn ack_and_udp_conflict() {
        let parsed = Args::try_parse_from([
            "asphyxia",
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "80",
            "--scan",
            "ack",
            "--udp",
        ]);
        assert!(parsed.is_err(), "--scan ack and --udp must not be combined");
    }

    #[test]
    fn raw_modes_map_to_their_packet_profiles() {
        assert_eq!(ScanMode::Syn.probe_mode(), Some(ProbeMode::Syn));
        assert_eq!(ScanMode::Ack.probe_mode(), Some(ProbeMode::Ack));
        assert!(ScanMode::Syn.needs_raw());
        assert!(ScanMode::Ack.needs_raw());
    }

    #[test]
    fn labels_are_stable_output_names() {
        assert_eq!(ScanMode::Connect.label(), "connect");
        assert_eq!(ScanMode::Syn.label(), "syn");
        assert_eq!(ScanMode::Ack.label(), "ack");
    }

    #[test]
    fn every_downgrade_lands_on_connect_and_says_why() {
        for cause in [
            Unavailable::RawSocket,
            Unavailable::Capture,
            Unavailable::Ipv6,
        ] {
            let (mode, message) = ScanMode::Ack.downgrade(cause);
            assert_eq!(mode, ScanMode::Connect);
            assert!(
                message.contains("ACK"),
                "should name the dropped mode: {message}"
            );
            assert!(
                message.contains("falling back to connect scan"),
                "should say what happens instead: {message}"
            );
        }
    }

    #[test]
    fn downgrade_messages_distinguish_their_causes() {
        let (_, raw) = ScanMode::Ack.downgrade(Unavailable::RawSocket);
        let (_, capture) = ScanMode::Ack.downgrade(Unavailable::Capture);
        let (_, ipv6) = ScanMode::Ack.downgrade(Unavailable::Ipv6);
        assert!(raw.contains("CAP_NET_RAW"));
        assert!(capture.contains("libpcap"));
        assert!(ipv6.contains("IPv4-only"));
    }
}
