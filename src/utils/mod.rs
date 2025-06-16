use std::net::Ipv4Addr;
use ipnetwork::IpNetwork;

/// Parse a comma-separated string of port numbers into a vector of u16
///
/// # Arguments
///
/// * `s` - A string containing comma-separated port numbers
///
/// # Returns
///
/// * `Result<Vec<u16>, String>` - A vector of port numbers if parsing was successful,
///   or an error message if parsing failed
///
/// # Examples
///
/// ```
/// use asphyxia::utils::parse_ports;
///
/// assert_eq!(parse_ports("22,80,443"), Ok(vec![22, 80, 443]));
/// assert!(parse_ports("22,abc,443").is_err());
/// ```
pub fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    s.split(',')
        .map(|p| p.parse::<u16>().map_err(|_| format!("Invalid port number: {}", p)))
        .collect()
}

/// Parse a string into an IPv4 address
///
/// # Arguments
///
/// * `ip` - A string containing an IPv4 address
///
/// # Returns
///
/// * `Result<Ipv4Addr, String>` - The parsed IPv4 address if successful,
///   or an error message if parsing failed
///
/// # Examples
///
/// ```
/// use asphyxia::utils::parse_ipv4;
///
/// assert!(parse_ipv4("192.168.1.1").is_ok());
/// assert!(parse_ipv4("256.168.1.1").is_err());
/// ```
pub fn parse_ipv4(ip: &str) -> Result<Ipv4Addr, String> {
    ip.parse::<Ipv4Addr>()
        .map_err(|_| format!("Invalid IPv4 address: {}", ip))
}

/// Parse a string into an IPv4 subnet
///
/// # Arguments
///
/// * `subnet` - A string containing a subnet in CIDR notation (e.g., "192.168.1.0/24")
///
/// # Returns
///
/// * `Result<IpNetwork, String>` - The parsed subnet if successful,
///   or an error message if parsing failed
///
/// # Examples
///
/// ```
/// use asphyxia::utils::parse_subnet;
///
/// assert!(parse_subnet("192.168.1.0/24").is_ok());
/// assert!(parse_subnet("192.168.1.0/33").is_err());
/// assert!(parse_subnet("2001:db8::/32").is_err()); // IPv6 not supported
/// ```
pub fn parse_subnet(subnet: &str) -> Result<IpNetwork, String> {
    subnet.parse::<IpNetwork>()
        .map_err(|_| format!("Invalid subnet format: {}", subnet))
        .and_then(|network| {
            if network.is_ipv4() {
                Ok(network)
            } else {
                Err("Only IPv4 subnets are supported".to_string())
            }
        })
}
