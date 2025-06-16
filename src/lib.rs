//! Asphyxia - A fast and efficient network scanner
//!
//! This library provides high-performance network scanning capabilities for both port scanning
//! and address scanning operations. It's designed to be efficient, reliable, and easy to use.
//!
//! ## Features
//!
//! - **Port Scanning**: Scan individual ports or ranges of ports on target hosts
//! - **Address Scanning**: Check host availability and scan IP ranges
//! - **Subnet Scanning**: Scan entire subnets for available hosts
//! - **Utility Functions**: Helper functions for parsing ports, IPs, and subnets
//!
//! ## Module Organization
//!
//! - `scanner::port`: Port scanning functionality
//! - `scanner::address`: Address and subnet scanning functionality
//! - `utils`: Utility functions for parsing and validation
//! - `cli`: Command-line interface implementation
//!
//! ## Examples
//!
//! ### Basic Port Scanning
//! ```rust
//! use asphyxia::{scan_port, scan_address};
//!
//! // Scan a single port
//! if let Some(port) = scan_port("example.com".to_string(), 80) {
//!     println!("Port 80 is open");
//! }
//!
//! // Scan multiple ports
//! let ports = vec![80, 443, 8080];
//! for port in ports {
//!     if let Some(_) = scan_port("example.com".to_string(), port) {
//!         println!("Port {} is open", port);
//!     }
//! }
//! ```
//!
//! ### Address and Subnet Scanning
//! ```rust
//! use asphyxia::{scan_address, scan_subnet, scan_ip_range};
//! use std::net::Ipv4Addr;
//! use std::time::Duration;
//!
//! // Check if a host is available
//! let ip = "192.168.1.1".parse::<Ipv4Addr>().unwrap();
//! let timeout = Duration::from_secs(1);
//! if let Some(_) = scan_address(ip, Some(timeout)) {
//!     println!("Host is available");
//! }
//!
//! // Scan a subnet
//! let subnet = "192.168.1.0/24".parse().unwrap();
//! let available_hosts = scan_subnet(subnet);
//! println!("Found {} available hosts", available_hosts.len());
//!
//! // Scan an IP range
//! let start = "192.168.1.1".parse::<Ipv4Addr>().unwrap();
//! let end = "192.168.1.10".parse::<Ipv4Addr>().unwrap();
//! let hosts = scan_ip_range(start, end);
//! println!("Found {} hosts in range", hosts.len());
//! ```
//!
//! ### Using Utility Functions
//! ```rust
//! use asphyxia::{parse_ports, parse_ipv4, parse_subnet};
//!
//! // Parse port ranges
//! let ports = parse_ports("80,443,8000,8080").unwrap();
//! println!("Ports to scan: {:?}", ports);
//!
//! // Parse IP address
//! let ip = parse_ipv4("192.168.1.1").unwrap();
//! println!("IP address: {}", ip);
//!
//! // Parse subnet
//! let subnet = parse_subnet("192.168.1.0/24").unwrap();
//! println!("Subnet: {}", subnet);
//! ```
//!
//! ## Error Handling
//!
//! Most functions return `Option<T>` or `Result<T, E>` to handle potential errors
//! gracefully. Always check the return values to ensure proper error handling.
//!
//! ## Performance Considerations
//!
//! The library is designed for performance and uses asynchronous operations where
//! appropriate. For large-scale scanning operations, consider using the subnet
//! scanning functions which are optimized for scanning multiple hosts.

pub mod cli;
pub mod scanner;
pub mod utils;

/// Re-export commonly used types and functions
pub use scanner::port::{scan_port, is_online};
pub use scanner::address::{scan_address, scan_subnet, scan_ip_range};
pub use utils::{parse_ports, parse_ipv4, parse_subnet};
