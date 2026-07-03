//! Network scanning functionality
//!
//! This module provides functionality for scanning networks and ports.
//! It is split into two submodules:
//!
//! * `port` - Port scanning functionality
//! * `address` - Address scanning functionality
//! * `well_known` - Frequency-ordered top ports and named port sets

pub mod address;
pub mod port;
pub mod well_known;
