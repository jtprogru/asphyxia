use std::path::PathBuf;

use clap::{ArgGroup, Parser};

use crate::output::OutputFormat;

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

  # Use a custom connection timeout (milliseconds)
  asphyxia ps -t example.com -s 22,80,443 --timeout 500

  # Raise concurrency to speed up a large subnet scan
  asphyxia as -s 10.0.0.0/22 --concurrency 512

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
    -r, --range <START> <END>    Scan a range of ports (e.g., 80 443)
    -s, --specific <PORTS>       Scan specific ports (comma-separated, e.g., 22,80,443)
    -a, --all-ports              Scan the entire port range (1-65535)
    --top-ports <N>              Scan the N most common TCP ports (up to 1000)
    --ports <NAME>               Scan a named port set (web, mail, db, remote, windows)
    --timeout <MS>               Connection timeout in milliseconds (default: 2000)

  For address scanning (as):
    -s, --subnet <SUBNET>        Scan a subnet (e.g., 192.168.1.0/24 or 2001:db8::/120)
    -t, --target <IP>            Scan a specific IP address (IPv4 or IPv6)
    -r, --range <START> <END>    Scan a range of IP addresses
    --timeout <MS>               Connection timeout in milliseconds (default: 2000)
"#
)]
pub enum Args {
    /// Port scanning command
    #[command(
        name = "ps",
        about = "Start port scanning",
        // Exactly one target source is required: a `-t` host or `--stdin`.
        group = ArgGroup::new("target").required(true).args(["host", "stdin"])
    )]
    PortScan {
        /// Target host (e.g., example.com)
        #[arg(short = 't', long, group = "target")]
        host: Option<String>,

        /// Read targets from stdin instead of -t: one host per line, or the
        /// JSON/JSONL emitted by `asphyxia as -o` (the `ip` field is used).
        #[arg(long, group = "target")]
        stdin: bool,

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

        /// Connection timeout in milliseconds
        #[arg(long, value_name = "MS", default_value_t = 2000)]
        timeout: u64,

        /// Maximum number of concurrent connection attempts
        #[arg(short = 'c', long, value_name = "N", default_value_t = 256)]
        concurrency: usize,

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

        /// Connection timeout in milliseconds
        #[arg(long, value_name = "MS", default_value_t = 2000)]
        timeout: u64,

        /// Maximum number of concurrent connection attempts
        #[arg(short = 'c', long, value_name = "N", default_value_t = 256)]
        concurrency: usize,

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

    /// The file to write machine-readable output to, if any, regardless of
    /// which subcommand was invoked.
    pub fn output_file(&self) -> Option<&PathBuf> {
        match self {
            Args::PortScan { output_file, .. } | Args::AddressScan { output_file, .. } => {
                output_file.as_ref()
            }
        }
    }
}
