//! Lightweight asset classification (`--classify`).
//!
//! Classification is a *conclusion* built only from signals already collected:
//! open ports, service labels, banners, and (for address scans) the vendor OUI
//! from an ARP reply. It performs no new network probes and never overwrites the
//! raw facts; the structured record keeps `device_type` and `confidence` next to
//! them, and an unrecognised asset is `unknown`, not a guess.

/// A classification result: a coarse device type and how much evidence backed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    /// `windows`, `printer`, `hypervisor`, `network-device`, `web-server`, or
    /// `unknown`.
    pub device_type: &'static str,
    /// `low` or `medium`.
    pub confidence: &'static str,
}

impl Device {
    fn new(device_type: &'static str, confidence: &'static str) -> Self {
        Self {
            device_type,
            confidence,
        }
    }

    /// The honest "no signature matched" result.
    pub fn unknown() -> Self {
        Self::new("unknown", "low")
    }
}

/// Classify from already-collected open ports, service labels and banners.
///
/// `services` and `banners` are the values recorded for the same host; empty
/// strings are ignored. The rules are intentionally small and ordered from the
/// most specific signature to the least.
pub fn classify_ports(ports: &[u16], services: &[&str], banners: &[&str]) -> Device {
    let has = |wanted: &[u16]| ports.iter().any(|port| wanted.contains(port));
    let any_text = |needles: &[&str]| {
        services.iter().chain(banners.iter()).any(|text| {
            let lower = text.to_ascii_lowercase();
            needles.iter().any(|needle| lower.contains(needle))
        })
    };

    // Hypervisors first: 902 is the VMware auth port, and the banner check
    // catches an HTTPS-only ESXi/vCenter endpoint.
    if has(&[902]) || any_text(&["vmware", "esxi", "vsphere", "virtualcenter"]) {
        return Device::new("hypervisor", "medium");
    }

    // Printers: raw (9100), LPD (515), IPP (631).
    if has(&[9100, 515, 631]) {
        return Device::new("printer", "medium");
    }

    // Windows: SMB/NetBIOS/RDP. SMB is stronger evidence than RDP alone.
    if has(&[445, 139, 135]) {
        return Device::new("windows", "medium");
    }
    if has(&[3389]) {
        return Device::new("windows", "low");
    }

    // Network gear: SSH plus a vendor identity, or telnet/SNMP alone.
    if has(&[22])
        && any_text(&[
            "cisco", "juniper", "mikrotik", "routeros", "switch", "router",
        ])
    {
        return Device::new("network-device", "medium");
    }
    if has(&[23, 161]) {
        return Device::new("network-device", "low");
    }

    // A plain web server is the weakest, most generic signal.
    if has(&[80, 443, 8080, 8443, 8000, 8008]) {
        return Device::new("web-server", "low");
    }

    Device::unknown()
}

/// Classify from a vendor OUI (`aa-bb-cc`) captured by ARP discovery.
///
/// The table is deliberately tiny and local: it recognises a few common
/// hypervisor, network-gear and printer prefixes, and returns `unknown` for
/// everything else rather than inventing a vendor.
pub fn classify_oui(oui: &str) -> Device {
    match oui.to_ascii_lowercase().as_str() {
        // VMware virtual NICs.
        "00-0c-29" | "00-50-56" | "00-05-69" => Device::new("hypervisor", "medium"),
        // Cisco / Juniper / MikroTik prefixes (non-exhaustive).
        "00-00-0c" | "00-1b-0c" | "00-1e-13" | "00-24-97" | "00-26-0b" | "00-0c-42"
        | "00-1b-c0" | "4c-5e-0c" => Device::new("network-device", "medium"),
        // Canon / HP printer prefixes (non-exhaustive).
        "00-00-85" | "00-1e-8f" | "00-21-5a" | "00-1f-29" => Device::new("printer", "medium"),
        _ => Device::unknown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb_and_rdp_classify_as_windows() {
        assert_eq!(classify_ports(&[445, 139], &[], &[]).device_type, "windows");
        let rdp = classify_ports(&[3389], &[], &[]);
        assert_eq!(rdp.device_type, "windows");
        assert_eq!(rdp.confidence, "low");
    }

    #[test]
    fn printer_ports_classify_as_printer() {
        assert_eq!(
            classify_ports(&[631, 22], &["ssh"], &[]).device_type,
            "printer"
        );
    }

    #[test]
    fn hypervisor_needs_902_or_a_vendor_banner() {
        assert_eq!(classify_ports(&[902], &[], &[]).device_type, "hypervisor");
        assert_eq!(
            classify_ports(&[443], &["https"], &["VMware ESXi"]).device_type,
            "hypervisor"
        );
    }

    #[test]
    fn network_device_needs_ssh_plus_vendor_text() {
        assert_eq!(
            classify_ports(&[22], &["ssh"], &["Cisco IOS"]).device_type,
            "network-device"
        );
        // Plain SSH is not enough to call something network gear.
        assert_eq!(classify_ports(&[22], &["ssh"], &[]).device_type, "unknown");
        assert_eq!(
            classify_ports(&[23], &[], &[]).device_type,
            "network-device"
        );
    }

    #[test]
    fn web_ports_are_a_weak_web_server() {
        let web = classify_ports(&[8080], &[], &[]);
        assert_eq!(web.device_type, "web-server");
        assert_eq!(web.confidence, "low");
    }

    #[test]
    fn unknown_ports_stay_unknown() {
        assert_eq!(classify_ports(&[4444], &[], &[]), Device::unknown());
    }

    #[test]
    fn oui_table_recognises_known_prefixes() {
        assert_eq!(classify_oui("00-0c-29").device_type, "hypervisor");
        assert_eq!(classify_oui("00-00-0c").device_type, "network-device");
        assert_eq!(classify_oui("00-00-85").device_type, "printer");
        assert_eq!(classify_oui("aa-bb-cc"), Device::unknown());
    }
}
