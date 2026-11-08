//! Host-discovery probes beyond the default TCP connect check.
//!
//! * `arp` — ARP-request discovery for locally-connected IPv4 subnets, finding
//!   hosts that silently drop all TCP probe ports.
//! * `icmp` — IPv4 ICMP echo (ping sweep) for routed hosts that answer ICMP.

pub mod arp;
pub mod icmp;
