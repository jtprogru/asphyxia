//! Offline ASN / cloud-provider hints (`--asn`).
//!
//! Enrichment is a local lookup against a small bundled prefix table: no DNS,
//! no API calls, and no target IP leaves the machine. A prefix that is not in
//! the table yields no fields rather than a guessed provider. The table is
//! intentionally non-exhaustive — it covers the common clouds and CDNs an
//! operator is likely to meet first.

use std::net::IpAddr;
use std::sync::OnceLock;

use ipnetwork::IpNetwork;

/// ASN metadata for one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsnInfo {
    /// Autonomous system number.
    pub asn: u32,
    /// Registered organisation name.
    pub asn_org: &'static str,
    /// Cloud/provider short name, when the prefix belongs to a known one.
    pub cloud: Option<&'static str>,
}

/// One bundled prefix. More specific entries are listed before broader ones so
/// the first containment match is the best match.
struct Prefix {
    network: &'static str,
    asn: u32,
    org: &'static str,
    cloud: Option<&'static str>,
}

/// Bundled, deliberately non-exhaustive prefix table. ASN assignments and cloud
/// ranges drift; treat this as a hint, not an authoritative registry.
static PREFIXES: &[Prefix] = &[
    // Azure (before the broad AWS 52/8 block below).
    Prefix {
        network: "52.96.0.0/12",
        asn: 8075,
        org: "Microsoft Corporation",
        cloud: Some("azure"),
    },
    Prefix {
        network: "40.64.0.0/10",
        asn: 8075,
        org: "Microsoft Corporation",
        cloud: Some("azure"),
    },
    Prefix {
        network: "20.0.0.0/8",
        asn: 8075,
        org: "Microsoft Corporation",
        cloud: Some("azure"),
    },
    Prefix {
        network: "13.64.0.0/11",
        asn: 8075,
        org: "Microsoft Corporation",
        cloud: Some("azure"),
    },
    Prefix {
        network: "51.104.0.0/13",
        asn: 8075,
        org: "Microsoft Corporation",
        cloud: Some("azure"),
    },
    Prefix {
        network: "104.40.0.0/13",
        asn: 8075,
        org: "Microsoft Corporation",
        cloud: Some("azure"),
    },
    // AWS.
    Prefix {
        network: "52.0.0.0/8",
        asn: 16509,
        org: "Amazon.com, Inc.",
        cloud: Some("aws"),
    },
    Prefix {
        network: "54.0.0.0/8",
        asn: 16509,
        org: "Amazon.com, Inc.",
        cloud: Some("aws"),
    },
    Prefix {
        network: "3.0.0.0/8",
        asn: 16509,
        org: "Amazon.com, Inc.",
        cloud: Some("aws"),
    },
    Prefix {
        network: "18.0.0.0/8",
        asn: 16509,
        org: "Amazon.com, Inc.",
        cloud: Some("aws"),
    },
    Prefix {
        network: "34.192.0.0/10",
        asn: 16509,
        org: "Amazon.com, Inc.",
        cloud: Some("aws"),
    },
    Prefix {
        network: "44.192.0.0/10",
        asn: 16509,
        org: "Amazon.com, Inc.",
        cloud: Some("aws"),
    },
    Prefix {
        network: "35.160.0.0/12",
        asn: 16509,
        org: "Amazon.com, Inc.",
        cloud: Some("aws"),
    },
    // Google Cloud.
    Prefix {
        network: "34.64.0.0/10",
        asn: 15169,
        org: "Google LLC",
        cloud: Some("gcp"),
    },
    Prefix {
        network: "35.184.0.0/13",
        asn: 15169,
        org: "Google LLC",
        cloud: Some("gcp"),
    },
    Prefix {
        network: "35.192.0.0/14",
        asn: 15169,
        org: "Google LLC",
        cloud: Some("gcp"),
    },
    Prefix {
        network: "35.196.0.0/15",
        asn: 15169,
        org: "Google LLC",
        cloud: Some("gcp"),
    },
    Prefix {
        network: "35.198.0.0/16",
        asn: 15169,
        org: "Google LLC",
        cloud: Some("gcp"),
    },
    Prefix {
        network: "104.196.0.0/14",
        asn: 15169,
        org: "Google LLC",
        cloud: Some("gcp"),
    },
    Prefix {
        network: "130.211.0.0/22",
        asn: 15169,
        org: "Google LLC",
        cloud: Some("gcp"),
    },
    Prefix {
        network: "162.216.148.0/22",
        asn: 15169,
        org: "Google LLC",
        cloud: Some("gcp"),
    },
    // Cloudflare.
    Prefix {
        network: "173.245.48.0/20",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "103.21.244.0/22",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "103.22.200.0/22",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "103.31.4.0/22",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "141.101.64.0/18",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "108.162.192.0/18",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "188.114.96.0/20",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "197.234.240.0/22",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "198.41.128.0/17",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "162.158.0.0/15",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "104.16.0.0/13",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "172.64.0.0/13",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "190.93.240.0/20",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    // Fastly, DigitalOcean, GitHub.
    Prefix {
        network: "151.101.0.0/16",
        asn: 54113,
        org: "Fastly, Inc.",
        cloud: Some("fastly"),
    },
    Prefix {
        network: "104.131.0.0/16",
        asn: 14061,
        org: "DigitalOcean, LLC",
        cloud: Some("digitalocean"),
    },
    Prefix {
        network: "159.89.0.0/16",
        asn: 14061,
        org: "DigitalOcean, LLC",
        cloud: Some("digitalocean"),
    },
    Prefix {
        network: "167.99.0.0/16",
        asn: 14061,
        org: "DigitalOcean, LLC",
        cloud: Some("digitalocean"),
    },
    Prefix {
        network: "206.189.0.0/16",
        asn: 14061,
        org: "DigitalOcean, LLC",
        cloud: Some("digitalocean"),
    },
    Prefix {
        network: "140.82.112.0/20",
        asn: 36459,
        org: "GitHub, Inc.",
        cloud: Some("github"),
    },
    // IPv6 examples.
    Prefix {
        network: "2606:4700::/32",
        asn: 13335,
        org: "Cloudflare, Inc.",
        cloud: Some("cloudflare"),
    },
    Prefix {
        network: "2600:1900::/28",
        asn: 15169,
        org: "Google LLC",
        cloud: Some("gcp"),
    },
    Prefix {
        network: "2600:1f00::/24",
        asn: 16509,
        org: "Amazon.com, Inc.",
        cloud: Some("aws"),
    },
];

/// The parsed table, built once on first lookup.
fn table() -> &'static [(IpNetwork, AsnInfo)] {
    static TABLE: OnceLock<Vec<(IpNetwork, AsnInfo)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        PREFIXES
            .iter()
            .filter_map(|prefix| {
                let network = prefix.network.parse::<IpNetwork>().ok()?;
                Some((
                    network,
                    AsnInfo {
                        asn: prefix.asn,
                        asn_org: prefix.org,
                        cloud: prefix.cloud,
                    },
                ))
            })
            .collect()
    })
}

/// Look `ip` up in the bundled table. Returns `None` when no prefix matches.
pub fn lookup(ip: IpAddr) -> Option<AsnInfo> {
    table()
        .iter()
        .find(|(network, _)| network.contains(ip))
        .map(|(_, info)| *info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_cloud_prefixes() {
        let aws = lookup("52.1.2.3".parse().unwrap()).expect("AWS prefix");
        assert_eq!(aws.asn, 16509);
        assert_eq!(aws.cloud, Some("aws"));

        let gcp = lookup("34.64.1.1".parse().unwrap()).expect("GCP prefix");
        assert_eq!(gcp.asn, 15169);

        let azure = lookup("20.1.2.3".parse().unwrap()).expect("Azure prefix");
        assert_eq!(azure.asn, 8075);
    }

    #[test]
    fn specific_azure_prefix_wins_over_broad_aws() {
        // 52.96.0.0/12 is Azure even though 52.0.0.0/8 is AWS; order matters.
        let info = lookup("52.96.1.1".parse().unwrap()).expect("Azure prefix");
        assert_eq!(info.cloud, Some("azure"));
    }

    #[test]
    fn matches_ipv6_prefixes() {
        let info = lookup("2606:4700::1".parse().unwrap()).expect("Cloudflare IPv6");
        assert_eq!(info.asn, 13335);
    }

    #[test]
    fn unknown_addresses_have_no_hint() {
        assert!(lookup("192.0.2.1".parse().unwrap()).is_none());
        assert!(lookup("2001:db8::1".parse().unwrap()).is_none());
    }
}
