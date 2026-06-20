# Asphyxia

[![CI](https://github.com/jtprogru/asphyxia/actions/workflows/ci.yml/badge.svg)](https://github.com/jtprogru/asphyxia/actions/workflows/ci.yml)
[![Rust Release](https://github.com/jtprogru/asphyxia/actions/workflows/rust-release.yml/badge.svg)](https://github.com/jtprogru/asphyxia/actions/workflows/rust-release.yml)

A fast and efficient network scanner written in Rust.

## Description

Asphyxia is a command-line network scanner that helps you discover open ports on a host and find reachable hosts on a network. It runs scans in parallel for speed and shows live progress while it works.

## Features

- **Port scanning** — scan a range of ports or a specific comma-separated list on a target host.
- **Address scanning** — check a single IP, scan an IP range, or scan an entire subnet (CIDR).
- **Parallel execution** — scans run concurrently via [rayon](https://crates.io/crates/rayon).
- **Live progress bars** — long-running scans show real-time progress.
- **Colorized output** — readable, colored terminal output.

> Note: Asphyxia currently works with IPv4 targets.

## Installation

### Homebrew (macOS & Linux)

```bash
brew tap jtprogru/asphyxia
brew install jtprogru/asphyxia/asphyxia
```

The formula is published automatically to the [jtprogru/homebrew-asphyxia](https://github.com/jtprogru/homebrew-asphyxia) tap on every release and supports macOS (Intel & Apple Silicon) and Linux (x86_64 & arm64).

### Prebuilt binaries

Download the archive for your platform from the [latest release](https://github.com/jtprogru/asphyxia/releases/latest), unzip it, and place the `asphyxia` binary somewhere on your `PATH`. Builds are provided for:

- Linux: `x86_64`, `aarch64`
- macOS: `x86_64`, `aarch64` (Apple Silicon)

### Building from source

Requires a recent stable Rust toolchain (the project uses the 2024 edition).

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
```

| Flag | Description |
|------|-------------|
| `-t, --host <HOST>` | Target host (hostname or IP) |
| `-r, --range <START> <END>` | Scan an inclusive range of ports |
| `-s, --specific <PORTS>` | Scan specific comma-separated ports |

### Address scanning (`as`)

```bash
# Scan a subnet in CIDR notation
asphyxia as -s 192.168.1.0/24

# Scan a single IP address
asphyxia as -t 192.168.1.1

# Scan a range of IP addresses (start end)
asphyxia as -r 192.168.1.1 192.168.1.20
```

| Flag | Description |
|------|-------------|
| `-s, --subnet <SUBNET>` | Scan a subnet, e.g. `192.168.1.0/24` |
| `-t, --target <IP>` | Scan a single IPv4 address |
| `-r, --range <START> <END>` | Scan an inclusive range of IPv4 addresses |

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
