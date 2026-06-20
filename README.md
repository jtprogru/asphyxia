# Asphyxia

[![CI](https://github.com/jtprogru/asphyxia/actions/workflows/ci.yml/badge.svg)](https://github.com/jtprogru/asphyxia/actions/workflows/ci.yml)
[![Rust Release](https://github.com/jtprogru/asphyxia/actions/workflows/rust-release.yml/badge.svg)](https://github.com/jtprogru/asphyxia/actions/workflows/rust-release.yml)
[![crates.io](https://img.shields.io/crates/v/asphyxia.svg)](https://crates.io/crates/asphyxia)
[![docs.rs](https://img.shields.io/docsrs/asphyxia)](https://docs.rs/asphyxia)
[![Downloads](https://img.shields.io/crates/d/asphyxia.svg)](https://crates.io/crates/asphyxia)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/crates/l/asphyxia.svg)](LICENSE)

A fast and efficient network scanner written in Rust.

## Description

Asphyxia is a command-line network scanner that helps you discover open ports on a host and find reachable hosts on a network. It runs scans in parallel for speed and shows live progress while it works.

## Features

- **Port scanning** — scan a range of ports or a specific comma-separated list on a target host.
- **Address scanning** — check a single IP, scan an IP range, or scan an entire subnet (CIDR).
- **IPv4 and IPv6** — every scan mode accepts both address families.
- **Configurable timeout** — tune the per-connection timeout with `--timeout`.
- **Parallel execution** — scans run concurrently via [rayon](https://crates.io/crates/rayon).
- **Live progress bars** — long-running scans show real-time progress.
- **Colorized output** — readable, colored terminal output.

> Note: IPv6 subnet and range scans are capped at 65 536 addresses (e.g. a `/112`), since larger IPv6 spaces are impractical to walk exhaustively.

## Installation

### Homebrew (macOS & Linux)

```bash
brew tap jtprogru/tap
brew install jtprogru/tap/asphyxia
```

The formula is published automatically to the [jtprogru/homebrew-tap](https://github.com/jtprogru/homebrew-tap) tap on every release and supports macOS (Apple Silicon) and Linux (x86_64 & arm64).

### Cargo

Install the latest published release from [crates.io](https://crates.io/crates/asphyxia):

```bash
cargo install asphyxia
```

Or install the current `main` branch straight from the repository:

```bash
cargo install --git https://github.com/jtprogru/asphyxia
```

### Prebuilt binaries

Download the archive for your platform from the [latest release](https://github.com/jtprogru/asphyxia/releases/latest), unzip it, and place the `asphyxia` binary somewhere on your `PATH`. Builds are provided for:

- Linux: `x86_64`, `aarch64`
- macOS: `aarch64` (Apple Silicon)

Each archive is shipped with a detached GPG signature (`.asc`). After importing the signing key you can verify an archive with:

```bash
gpg --verify asphyxia-<target>.zip.asc asphyxia-<target>.zip
```

### Building from source

Requires Rust 1.88 or newer (the project uses the 2024 edition).

```bash
git clone https://github.com/jtprogru/asphyxia.git
cd asphyxia
cargo build --release
```

The compiled binary will be available at `target/release/asphyxia`.

## Usage

Asphyxia exposes two subcommands: `ps` (port scan) and `as` (address scan).

```bash
asphyxia --help        # general help
asphyxia ps --help     # port scan options
asphyxia as --help     # address scan options
```

### Port scanning (`ps`)

```bash
# Scan a range of ports (start end)
asphyxia ps -t example.com -r 80 443

# Scan specific ports (comma-separated)
asphyxia ps -t example.com -s 22,80,443,8080

# Scan an IPv6 host with a shorter timeout
asphyxia ps -t 2001:db8::1 -s 22,80,443 --timeout 500
```

| Flag | Description |
|------|-------------|
| `-t, --host <HOST>` | Target host (hostname, IPv4, or IPv6) |
| `-r, --range <START> <END>` | Scan an inclusive range of ports |
| `-s, --specific <PORTS>` | Scan specific comma-separated ports |
| `--timeout <MS>` | Per-connection timeout in milliseconds (default: 2000) |

### Address scanning (`as`)

```bash
# Scan a subnet in CIDR notation (IPv4 or IPv6)
asphyxia as -s 192.168.1.0/24
asphyxia as -s 2001:db8::/120

# Scan a single IP address (IPv4 or IPv6)
asphyxia as -t 192.168.1.1
asphyxia as -t 2001:db8::1

# Scan a range of IP addresses (start end)
asphyxia as -r 192.168.1.1 192.168.1.20

# Scan a subnet with a custom timeout
asphyxia as -s 192.168.1.0/24 --timeout 300
```

| Flag | Description |
|------|-------------|
| `-s, --subnet <SUBNET>` | Scan a subnet, e.g. `192.168.1.0/24` or `2001:db8::/120` |
| `-t, --target <IP>` | Scan a single IPv4 or IPv6 address |
| `-r, --range <START> <END>` | Scan an inclusive range of IPs (start and end must share the same family) |
| `--timeout <MS>` | Per-connection timeout in milliseconds (default: 2000) |

> Host availability is inferred from a TCP probe: a host counts as up when it either accepts the connection or actively refuses it (a closed port still proves the host answered). A host that times out or is unreachable is reported as down — so a live host behind a firewall that silently drops packets may appear offline. This is an unprivileged, best-effort check, not an ICMP ping.

## Dependencies

- [clap](https://crates.io/crates/clap) — command-line argument parsing
- [rayon](https://crates.io/crates/rayon) — parallel computing
- [indicatif](https://crates.io/crates/indicatif) — progress bars and spinners
- [owo-colors](https://crates.io/crates/owo-colors) — terminal colors
- [ipnetwork](https://crates.io/crates/ipnetwork) — IP network address handling

## Development

```bash
cargo fmt --all          # format
cargo clippy --all-targets -- -D warnings   # lint
cargo test               # run unit and doc tests
```

CI runs formatting, Clippy (warnings denied), build, and tests on every pull request and push to `main`.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
