//! Network scanning functionality
//!
//! This module provides functionality for scanning networks and ports.
//! It is split into two submodules:
//!
//! * `port` - Port scanning functionality
//! * `address` - Address scanning functionality
//! * `well_known` - Frequency-ordered top ports and named port sets
//! * `exclude` - Address and CDN exclusions for scans
//! * `nmap` - Handoff of discovered open ports to nmap
//! * `service` - Banner grabbing and service/version detection
//! * `syn` - SYN/stealth scan packet assembly and parsing

pub mod address;
pub mod exclude;
pub mod nmap;
pub mod port;
pub mod service;
pub mod syn;
pub mod well_known;
