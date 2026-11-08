use std::path::PathBuf;

use clap::{ArgGroup, Parser, ValueEnum};

use crate::output::OutputFormat;
use crate::report::ReportFormat;
use crate::scanner::syn::ProbeMode;
use crate::traceroute::Transport;

/// The host-discovery probe used by `as`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum DiscoveryMode {
    /// TCP connect probes across a small spread of common ports (default).
    /// Unprivileged and works for any reachable address.
    #[default]
    Tcp,
    /// ARP requests on the local L2 segment. Finds hosts that silently drop all
    /// TCP probe ports; valid only for locally-connected IPv4 subnets.
    Arp,
    /// ICMP echo requests (a ping sweep). Finds hosts that drop the TCP probe
    /// ports but answer ICMP; IPv4 only, needs root/`CAP_NET_RAW`.
    Icmp,
    /// Try ARP, then ICMP, then TCP, skipping probes that cannot run. Only
    /// valid on its own; resolved before the scan starts.
    Auto,
}

impl std::fmt::Display for DiscoveryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl DiscoveryMode {
    /// Stable name for this mode in structured output and messages.
    pub fn label(self) -> &'static str {
        match self {
            DiscoveryMode::Tcp => "tcp",
            DiscoveryMode::Arp => "arp",
            DiscoveryMode::Icmp => "icmp",
            DiscoveryMode::Auto => "auto",
        }
    }
}

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
    /// FIN only (RFC 793): an RST means closed, silence means open|filtered.
    Fin,
    /// No flags set at all: same reply rules as [`ScanMode::Fin`], invisible to
    /// filters that key on SYN or ACK.
    Null,
    /// FIN + PSH + URG ("XMAS"): same reply rules as [`ScanMode::Fin`].
    Xmas,
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
            ScanMode::Fin => Some(ProbeMode::Fin),
            ScanMode::Null => Some(ProbeMode::Null),
            ScanMode::Xmas => Some(ProbeMode::Xmas),
        }
    }

    /// Whether this mode reports silence as `open|filtered` (FIN/NULL/XMAS)
    /// rather than a plain verdict.
    pub fn silent_means_open_filtered(self) -> bool {
        self.probe_mode()
            .is_some_and(ProbeMode::silent_means_open_filtered)
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
    /// different question (open/closed) than an ACK scan (unfiltered/filtered)
    /// or a FIN/NULL/XMAS scan (closed/open|filtered), so the operator has to be
    /// told, and every result carries the mode that actually produced it.
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

  # Discover hosts by ARP on a local IPv4 subnet (needs root/CAP_NET_RAW)
  asphyxia as -s 192.168.1.0/24 --discovery arp

  # Ping sweep with ICMP echo (IPv4; needs root/CAP_NET_RAW)
  asphyxia as -s 192.168.1.0/24 --discovery icmp

  # Probe a custom set of TCP ports for host discovery
  asphyxia as -s 192.168.1.0/24 --discovery-ports 445,3389,8080

  # Enrich live hosts with reverse DNS and a forward-confirmed PTR
  asphyxia as -s 192.168.1.0/24 --resolve-ptr -o jsonl

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

  # Space probes out with a minimum delay and jitter (gentle on sensitive targets)
  asphyxia ps -t example.com --top-ports 1000 --delay 250 --jitter 20

  # Infer a coarse device type from already-collected signals (no new probes)
  asphyxia ps -t example.com --top-ports 1000 --sV --classify
  asphyxia as -s 192.168.1.0/24 --discovery arp --classify -o jsonl

  # Add offline ASN/cloud hints (bundled table; no network requests)
  asphyxia as -s 192.168.1.0/24 --Pn --asn -o jsonl

  # Watch a scan and emit JSON Lines change events (baseline + diffs)
  asphyxia ps -t example.com --top-ports 100 --watch 5m --watch-count 3

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
  --classify                   Infer device type from ports/banners/OUI (no new probes)
  --asn                        Add offline ASN/cloud hints from the bundled table
  --report <md|html>           Generate a Markdown/HTML report from the scan records
  --report-file <PATH>         Write the report to a file instead of stdout
  --full-banners               Keep full sanitized banners in the report (default: truncated)
  --watch <INTERVAL>           Rescan every INTERVAL (30s, 5m) and emit JSONL change events
  --watch-count <N>            Stop watch mode after N passes (requires --watch)
    --resume <PATH>              Checkpoint progress and resume from PATH if it exists
    --rate <PPS>                 Cap connection attempts per second (0 = no cap)
    -T, --timing <0-5>           Timing profile (paranoid..insane) presetting the tunables
    --timeout <MS>               Connection timeout in milliseconds (default: 2000)
    -e, --interface <NAME>       Bind every probe to this interface (e.g. en0), like `ssh -B`

  For address scanning (as):
    -s, --subnet <SUBNET>        Scan a subnet (e.g., 192.168.1.0/24 or 2001:db8::/120)
    -t, --target <IP>            Scan a specific IP address (IPv4 or IPv6)
    -r, --range <START> <END>    Scan a range of IP addresses
    --discovery <MODES>          Host-discovery probe(s): tcp (default), arp, icmp,
                                 or a comma-separated combination (arp,icmp,tcp);
                                 auto tries arp,icmp,tcp. Raw probes need root/CAP_NET_RAW
    --Pn                         Skip host discovery; treat every target as up
    --discovery-ports <PORTS>    Comma-separated TCP ports for host discovery (default 80,443,22,3389)
    --show-down                  Include ICMP non-responders as status "down" with a reason
    --resolve-ptr                Enrich live hosts with PTR and forward-confirmed PTR
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

        /// Probe type: connect (default), syn (half-open), ack (firewall state),
        /// or fin/null/xmas (stealth; closed or open|filtered)
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

        /// Infer a coarse device type from collected ports/banners (no new probes)
        #[arg(long = "classify")]
        classify: bool,

        /// Add offline ASN/cloud hints from the bundled prefix table (no network)
        #[arg(long = "asn")]
        asn: bool,

        /// Generate a Markdown or HTML report from the scan records
        #[arg(long = "report", value_name = "FORMAT", value_enum)]
        report: Option<ReportFormat>,

        /// Write the report to a file instead of stdout
        #[arg(long = "report-file", value_name = "PATH", requires = "report")]
        report_file: Option<PathBuf>,

        /// Include full (sanitized) banners in the report instead of truncating
        #[arg(long = "full-banners", requires = "report")]
        full_banners: bool,

        /// Rescan every INTERVAL (e.g. 30s, 5m) and emit JSON Lines change events
        #[arg(long = "watch", value_name = "INTERVAL")]
        watch: Option<String>,

        /// Stop watch mode after N passes (baseline counts as pass 1)
        #[arg(long = "watch-count", value_name = "N", requires = "watch")]
        watch_count: Option<usize>,

        /// After the scan, run nmap on each host's open ports for a deep dive
        #[arg(long = "nmap")]
        nmap: bool,

        /// Custom nmap arguments (replace the default -sV -sC); implies --nmap
        #[arg(long = "nmap-args", value_name = "ARGS", allow_hyphen_values = true)]
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

        /// Minimum delay between probes to the same host, in milliseconds.
        /// Combined with `--jitter`, each probe's interval is randomized within
        /// ±PCT of this value (e.g. `--delay 250 --jitter 20` → 200–300 ms).
        #[arg(long, value_name = "MS")]
        delay: Option<u64>,

        /// Jitter as a percentage (0–100) of `--delay`, randomizing each probe's
        /// interval within ±PCT. Ignored without `--delay`.
        #[arg(
            long,
            value_name = "PCT",
            requires = "delay",
            value_parser = clap::value_parser!(u32).range(0..=100)
        )]
        jitter: Option<u32>,

        /// Timing profile 0-5 (paranoid..insane) presetting timeout/concurrency/retries/rate
        #[arg(short = 'T', long = "timing", value_name = "0-5", value_parser = clap::value_parser!(u8).range(0..=5))]
        timing: Option<u8>,

        /// Fixed source port for raw TCP probes (raw modes only; ignored with a
        /// warning in connect/UDP scans) — useful for testing firewall rules
        /// keyed on source port.
        #[arg(long, value_name = "PORT")]
        source_port: Option<u16>,

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

        /// Host-discovery probe(s): `tcp` (default, unprivileged), `arp`
        /// (locally-connected IPv4 subnets), `icmp` (IPv4 ping sweep), or a
        /// comma-separated combination such as `arp,icmp,tcp`. `auto` tries
        /// ARP, ICMP and TCP in that order. ARP/ICMP need root/CAP_NET_RAW;
        /// probes that cannot run degrade to a warning and the next probe.
        #[arg(
            long = "discovery",
            value_name = "MODES",
            value_delimiter = ',',
            default_value = "tcp"
        )]
        discovery: Vec<DiscoveryMode>,

        /// Comma-separated TCP ports used for host discovery (default: 80,443,22,3389)
        #[arg(long = "discovery-ports", value_name = "PORTS")]
        discovery_ports: Option<String>,

        /// Include hosts that did not answer in structured output (status "down",
        /// reason "unreachable" or "no-response"). ICMP discovery only.
        #[arg(long = "show-down")]
        show_down: bool,

        /// Enrich live hosts with reverse DNS and a forward-confirmed PTR
        #[arg(long = "resolve-ptr")]
        resolve_ptr: bool,

        /// Infer a coarse device type from collected ports/banners/OUI (no new probes)
        #[arg(long = "classify")]
        classify: bool,

        /// Add offline ASN/cloud hints from the bundled prefix table (no network)
        #[arg(long = "asn")]
        asn: bool,

        /// Generate a Markdown or HTML report from the scan records
        #[arg(long = "report", value_name = "FORMAT", value_enum)]
        report: Option<ReportFormat>,

        /// Write the report to a file instead of stdout
        #[arg(long = "report-file", value_name = "PATH", requires = "report")]
        report_file: Option<PathBuf>,

        /// Include full (sanitized) banners in the report instead of truncating
        #[arg(long = "full-banners", requires = "report")]
        full_banners: bool,

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
    /// Compare two structured scan result files
    #[command(name = "diff", about = "Compare two structured scan result files")]
    Diff {
        /// Older result file (JSON array or JSON Lines)
        old: PathBuf,

        /// Newer result file (JSON array or JSON Lines)
        new: PathBuf,

        /// Output format: text (default), json, or jsonl (change events)
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,

        /// Write the report to a file instead of stdout
        #[arg(long = "output-file", visible_alias = "oF", value_name = "PATH")]
        output_file: Option<PathBuf>,
    },
    /// Trace the network path to an IPv4 target
    #[command(name = "trace", about = "Trace the network path to an IPv4 target")]
    Trace {
        /// Target IPv4 address (or hostname)
        target: String,

        /// Probe transport: tcp (default) or icmp
        #[arg(long, value_enum, default_value_t = Transport::Tcp)]
        transport: Transport,

        /// Destination TCP port for tcp probes
        #[arg(long, default_value_t = 80)]
        port: u16,

        /// Maximum number of hops
        #[arg(long = "max-hops", value_name = "N", default_value_t = 30, value_parser = clap::value_parser!(u8).range(1..=64))]
        max_hops: u8,

        /// Probes per hop
        #[arg(long, value_name = "N", default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=10))]
        probes: u8,

        /// Per-probe timeout in milliseconds
        #[arg(long, value_name = "MS", default_value_t = 1000)]
        timeout: u64,

        /// Bind the raw probe socket to this interface (e.g. en0)
        #[arg(
            short = 'e',
            long = "interface",
            visible_alias = "iface",
            value_name = "NAME"
        )]
        interface: Option<String>,

        /// Output format: text (default), json, or jsonl (one hop per line)
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,

        /// Write the report to a file instead of stdout
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
            Args::Diff { .. } | Args::Trace { .. } => 256,
        }
    }

    /// The requested output format, regardless of which subcommand was invoked.
    pub fn output_format(&self) -> OutputFormat {
        match self {
            Args::PortScan { output, .. } | Args::AddressScan { output, .. } => *output,
            Args::Diff { output, .. } | Args::Trace { output, .. } => *output,
        }
    }

    /// The network interface every probe should be bound to, if requested,
    /// regardless of which subcommand was invoked.
    pub fn interface(&self) -> Option<&str> {
        match self {
            Args::PortScan { interface, .. } | Args::AddressScan { interface, .. } => {
                interface.as_deref()
            }
            Args::Diff { .. } => None,
            Args::Trace { interface, .. } => interface.as_deref(),
        }
    }

    /// The file to write machine-readable output to, if any, regardless of
    /// which subcommand was invoked.
    pub fn output_file(&self) -> Option<&PathBuf> {
        match self {
            Args::PortScan { output_file, .. } | Args::AddressScan { output_file, .. } => {
                output_file.as_ref()
            }
            Args::Diff { output_file, .. } | Args::Trace { output_file, .. } => {
                output_file.as_ref()
            }
        }
    }

    /// The number of extra retries per probe, regardless of which subcommand
    /// was invoked.
    pub fn retries(&self) -> u32 {
        match self {
            Args::PortScan { retries, .. } | Args::AddressScan { retries, .. } => *retries,
            Args::Diff { .. } | Args::Trace { .. } => 0,
        }
    }

    /// The probes-per-second cap, if any, regardless of which subcommand was
    /// invoked.
    pub fn rate(&self) -> Option<u32> {
        match self {
            Args::PortScan { rate, .. } | Args::AddressScan { rate, .. } => *rate,
            Args::Diff { .. } | Args::Trace { .. } => None,
        }
    }

    /// The minimum inter-probe delay in milliseconds, if requested. Applies to
    /// port scans only (address scans have no per-probe pacing).
    pub fn delay(&self) -> Option<u64> {
        match self {
            Args::PortScan { delay, .. } => *delay,
            Args::AddressScan { .. } | Args::Diff { .. } | Args::Trace { .. } => None,
        }
    }

    /// The jitter percentage (0–100) applied to `--delay`, if requested.
    pub fn jitter(&self) -> Option<u32> {
        match self {
            Args::PortScan { jitter, .. } => *jitter,
            Args::AddressScan { .. } | Args::Diff { .. } | Args::Trace { .. } => None,
        }
    }

    /// The probe type the invocation asks for, folding the older `--syn` flag
    /// into [`ScanMode`]. UDP and address scans always use plain sockets.
    pub fn scan_mode(&self) -> ScanMode {
        match self {
            Args::PortScan { udp: true, .. }
            | Args::AddressScan { .. }
            | Args::Diff { .. }
            | Args::Trace { .. } => ScanMode::Connect,
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
        assert_eq!(port_scan(&["--scan", "fin"]).scan_mode(), ScanMode::Fin);
        assert_eq!(port_scan(&["--scan", "null"]).scan_mode(), ScanMode::Null);
        assert_eq!(port_scan(&["--scan", "xmas"]).scan_mode(), ScanMode::Xmas);
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
        assert_eq!(ScanMode::Fin.probe_mode(), Some(ProbeMode::Fin));
        assert_eq!(ScanMode::Null.probe_mode(), Some(ProbeMode::Null));
        assert_eq!(ScanMode::Xmas.probe_mode(), Some(ProbeMode::Xmas));
        for mode in [
            ScanMode::Syn,
            ScanMode::Ack,
            ScanMode::Fin,
            ScanMode::Null,
            ScanMode::Xmas,
        ] {
            assert!(mode.needs_raw());
        }
    }

    #[test]
    fn labels_are_stable_output_names() {
        assert_eq!(ScanMode::Connect.label(), "connect");
        assert_eq!(ScanMode::Syn.label(), "syn");
        assert_eq!(ScanMode::Ack.label(), "ack");
        assert_eq!(ScanMode::Fin.label(), "fin");
        assert_eq!(ScanMode::Null.label(), "null");
        assert_eq!(ScanMode::Xmas.label(), "xmas");
    }

    #[test]
    fn only_the_stealth_modes_report_silence_as_open_filtered() {
        for mode in [ScanMode::Fin, ScanMode::Null, ScanMode::Xmas] {
            assert!(mode.silent_means_open_filtered());
        }
        for mode in [ScanMode::Connect, ScanMode::Syn, ScanMode::Ack] {
            assert!(!mode.silent_means_open_filtered());
        }
    }

    #[test]
    fn stealth_downgrades_land_on_connect_and_name_their_mode() {
        for (mode, name) in [
            (ScanMode::Fin, "FIN"),
            (ScanMode::Null, "NULL"),
            (ScanMode::Xmas, "XMAS"),
        ] {
            let (fallback, message) = mode.downgrade(Unavailable::Ipv6);
            assert_eq!(fallback, ScanMode::Connect);
            assert!(message.contains(name), "{mode:?}: {message}");
            assert!(
                message.contains("falling back to connect scan"),
                "{mode:?}: {message}"
            );
        }
    }

    #[test]
    fn source_port_flag_is_accepted() {
        // The flag parses and carries a valid port; it applies to raw scans only,
        // but must not reject a connect/UDP scan at parse time.
        let args = port_scan(&["--source-port", "53"]);
        match args {
            Args::PortScan { source_port, .. } => assert_eq!(source_port, Some(53)),
            _ => panic!("expected PortScan"),
        }
    }

    #[test]
    fn source_port_flag_rejects_non_numeric() {
        let parsed = Args::try_parse_from([
            "asphyxia",
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "80",
            "--source-port",
            "lots",
        ]);
        assert!(parsed.is_err(), "--source-port must be numeric");
    }

    #[test]
    fn delay_and_jitter_flags_are_accepted() {
        let args = port_scan(&["--delay", "250", "--jitter", "20"]);
        match args {
            Args::PortScan { delay, jitter, .. } => {
                assert_eq!(delay, Some(250));
                assert_eq!(jitter, Some(20));
            }
            _ => panic!("expected PortScan"),
        }
    }

    #[test]
    fn jitter_requires_delay() {
        // --jitter without --delay is a parse error (clap `requires`).
        let parsed = Args::try_parse_from([
            "asphyxia",
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "80",
            "--jitter",
            "20",
        ]);
        assert!(parsed.is_err(), "--jitter requires --delay");
    }

    #[test]
    fn jitter_rejects_out_of_range() {
        let parsed = Args::try_parse_from([
            "asphyxia",
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "80",
            "--delay",
            "100",
            "--jitter",
            "150",
        ]);
        assert!(parsed.is_err(), "--jitter must be 0-100");
    }

    #[test]
    fn delay_rejects_non_numeric() {
        let parsed = Args::try_parse_from([
            "asphyxia",
            "ps",
            "-t",
            "127.0.0.1",
            "-s",
            "80",
            "--delay",
            "lots",
        ]);
        assert!(parsed.is_err(), "--delay must be numeric");
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
