# Asphyxia

[![Rust Release](https://github.com/jtprogru/asphyxia/actions/workflows/rust-release.yml/badge.svg)](https://github.com/jtprogru/asphyxia/actions/workflows/rust-release.yml)

A powerful network utility tool written in Rust.

## Description

Asphyxia is a command-line network utility tool that provides efficient network operations and analysis capabilities. Built with performance and reliability in mind, it leverages Rust's powerful features to deliver fast and secure network operations.

## Features

- Command-line interface with intuitive argument parsing
- Parallel processing capabilities
- Progress indication for long-running operations
- Network address handling and manipulation
- Colorized terminal output

## Installation

### Prerequisites

- Rust and Cargo (latest stable version recommended)
- Git

### Building from Source

1. Clone the repository:

    ```bash
    git clone https://github.com/jtprogru/asphyxia.git
    cd asphyxia
    ```

2. Build the project:

    ```bash
    cargo build --release
    ```

The compiled binary will be available at `target/release/asphyxia`

## Usage

```bash
# Basic usage
./target/release/asphyxia [OPTIONS]

# For more information
./target/release/asphyxia --help
```

## Dependencies

- [clap](https://crates.io/crates/clap) - Command line argument parsing
- [rayon](https://crates.io/crates/rayon) - Parallel computing
- [indicatif](https://crates.io/crates/indicatif) - Progress bars and spinners
- [owo-colors](https://crates.io/crates/owo-colors) - Terminal colors
- [ipnetwork](https://crates.io/crates/ipnetwork) - IP network address handling

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
