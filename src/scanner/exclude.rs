//! Address exclusions for scans.
//!
//! An [`ExcludeSet`] is a collection of individual IPs and CIDR blocks that a
//! scan should skip. It backs `--exclude`/`--exclude-file` (user-supplied
//! addresses to leave alone) and `--exclude-cdn` (a built-in set of CDN/WAF
//! ranges where an exhaustive port scan is pointless and antisocial).

use std::net::IpAddr;

use ipnetwork::IpNetwork;

/// A set of addresses to skip, expressed as CIDR blocks.
///
/// A bare IP is stored as a host route (`/32` or `/128`), so membership is a
/// single containment test against every block.
#[derive(Debug, Clone, Default)]
pub struct ExcludeSet {
    nets: Vec<IpNetwork>,
}

impl ExcludeSet {
    /// Parse exclusion specs into a set. Each spec may itself be a
    /// comma-separated list, and every token is either a CIDR (`10.0.0.0/8`) or
    /// a bare IP (`192.168.1.5`, treated as a host route).
    ///
    /// Returns an error naming the first token that does not parse.
    pub fn parse<I, S>(specs: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut nets = Vec::new();
        for spec in specs {
            for token in spec.as_ref().split(',') {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                nets.push(parse_net(token)?);
            }
        }
        Ok(Self { nets })
    }

    /// The built-in set of well-known CDN/WAF ranges (Cloudflare, Akamai, …).
    ///
    /// This list is baked in and static: it is a convenience, not an
    /// authoritative registry, and can drift as providers change allocations.
    pub fn cdn() -> Self {
        let nets = CDN_RANGES
            .iter()
            // The built-in ranges are known-valid CIDRs.
            .map(|c| c.parse::<IpNetwork>().expect("valid built-in CDN CIDR"))
            .collect();
        Self { nets }
    }

    /// Whether the set contains no exclusions.
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Whether `ip` falls inside any excluded block.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(ip))
    }
}

/// Parse one token as a CIDR, or as a bare IP promoted to a host route.
fn parse_net(token: &str) -> Result<IpNetwork, String> {
    if token.contains('/') {
        return token
            .parse::<IpNetwork>()
            .map_err(|_| format!("Invalid exclude CIDR: {}", token));
    }
    let ip = token
        .parse::<IpAddr>()
        .map_err(|_| format!("Invalid exclude address: {}", token))?;
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    // A host route with the full prefix cannot be rejected for a parsed IP.
    IpNetwork::new(ip, prefix).map_err(|_| format!("Invalid exclude address: {}", token))
}

/// Well-known CDN/WAF IPv4 ranges. Static and best-effort — see [`ExcludeSet::cdn`].
static CDN_RANGES: &[&str] = &[
    // Cloudflare (https://www.cloudflare.com/ips/)
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    // Fastly
    "151.101.0.0/16",
    // A couple of Akamai blocks (non-exhaustive)
    "23.32.0.0/11",
    "104.64.0.0/10",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mixed_ips_and_cidrs_across_and_within_args() {
        let set = ExcludeSet::parse(["192.168.1.5", "10.0.0.0/8,172.16.0.0/12"]).unwrap();
        assert!(set.contains("192.168.1.5".parse().unwrap()));
        assert!(!set.contains("192.168.1.6".parse().unwrap()));
        assert!(set.contains("10.1.2.3".parse().unwrap()));
        assert!(set.contains("172.16.5.5".parse().unwrap()));
        assert!(!set.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn empty_specs_yield_an_empty_set() {
        let set = ExcludeSet::parse(Vec::<String>::new()).unwrap();
        assert!(set.is_empty());
        assert!(!set.contains("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn blank_tokens_are_skipped() {
        let set = ExcludeSet::parse([" , ,10.0.0.0/8, "]).unwrap();
        assert!(set.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_garbage_tokens() {
        assert!(ExcludeSet::parse(["not-an-ip"]).is_err());
        assert!(ExcludeSet::parse(["10.0.0.0/99"]).is_err());
    }

    #[test]
    fn ipv6_host_route_matches_only_itself() {
        let set = ExcludeSet::parse(["2001:db8::1"]).unwrap();
        assert!(set.contains("2001:db8::1".parse().unwrap()));
        assert!(!set.contains("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn cdn_set_flags_cloudflare_ranges() {
        let cdn = ExcludeSet::cdn();
        // 104.16.0.1 is inside Cloudflare's 104.16.0.0/13.
        assert!(cdn.contains("104.16.0.1".parse().unwrap()));
        // A random private address is not a CDN.
        assert!(!cdn.contains("192.168.0.1".parse().unwrap()));
    }
}
