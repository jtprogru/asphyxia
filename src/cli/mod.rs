use clap::Parser;

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

  # Scan a subnet
  asphyxia as -s 192.168.1.0/24

  # Scan a specific IP address
  asphyxia as -t 192.168.1.1

  # Scan a range of IP addresses
  asphyxia as -r 192.168.1.1 192.168.1.20

Required arguments:
  For port scanning (ps):
    -t, --host <HOST>    Target host to scan (e.g., example.com)
    -r, --range <START> <END>    Scan a range of ports (e.g., 80 443)
    -s, --specific <PORTS>       Scan specific ports (comma-separated, e.g., 22,80,443)

  For address scanning (as):
    -s, --subnet <SUBNET>        Scan a subnet (e.g., 192.168.1.0/24)
    -t, --target <IP>            Scan a specific IP address
    -r, --range <START> <END>    Scan a range of IP addresses
"#
)]
pub enum Args {
    /// Port scanning command
    #[command(name = "ps", about = "Start port scanning")]
    PortScan {
        /// Target host (e.g., example.com)
        #[arg(short = 't', long)]
        host: String,

        /// Scan range of ports: start end
        #[arg(short = 'r', long, num_args = 2, group = "ports")]
        range: Option<Vec<u16>>,

        /// Scan specific ports separated by comma
        #[arg(short = 's', long, value_parser = crate::utils::parse_ports, group = "ports")]
        specific: Option<Vec<u16>>,
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
    }
}
