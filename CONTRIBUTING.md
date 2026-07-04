# Contributing to Asphyxia

Thanks for your interest in improving Asphyxia! This document explains how to set up your environment, the conventions the project follows, and what to expect when you open a pull request.

Contributions of all kinds are welcome: bug reports, feature requests, documentation fixes, and code.

## Code of conduct

Be respectful and constructive. Assume good intent, keep discussion focused on the work, and help keep the project a welcoming place for everyone.

## Responsible use

Asphyxia is a network scanner. Only scan hosts and networks you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction. Please keep issues, examples, and test cases limited to targets you are allowed to probe (your own machines, `localhost`, RFC 5737 documentation ranges, etc.).

## Getting started

You need a Rust toolchain. The project targets the **2024 edition** with a minimum supported Rust version (**MSRV**) of **1.88**. Install Rust via [rustup](https://rustup.rs/) and make sure `rustfmt` and `clippy` components are present:

```bash
rustup toolchain install stable
rustup component add rustfmt clippy
```

Clone the repository and build it:

```bash
git clone https://github.com/jtprogru/asphyxia
cd asphyxia
cargo build --locked
```

## Development workflow

A `Makefile` wraps the common tasks; run `make help` to see them all. The most useful targets:

```bash
make build        # cargo build --locked
make test         # cargo test --locked
make fmt          # cargo fmt --all
make lint         # fmt-check + clippy (warnings denied)
make ci           # fmt-check + clippy + build + test — mirrors GitHub Actions
```

Before pushing, run `make ci` locally. It runs the exact same checks CI enforces, so if it passes on your machine it should pass on the pipeline.

If you prefer raw cargo commands:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo build --locked
cargo test --locked
```

## Coding conventions

- **Formatting** — all code must be formatted with `cargo fmt`. CI rejects unformatted code.
- **Linting** — Clippy runs with `-D warnings`, so any Clippy warning fails the build. Fix the lint or, in the rare case it's a false positive, `#[allow(...)]` it narrowly with a comment explaining why.
- **MSRV** — do not use language or standard-library features newer than Rust 1.88. If a dependency bump raises the MSRV, call it out in your PR.
- **Dependencies** — keep the dependency footprint small. If you add a crate, explain why an existing dependency or the standard library won't do.
- **Style** — match the surrounding code. Prefer clear, readable code over cleverness, and keep modules focused (the scanner logic lives under `src/scanner/`, output formats under `src/output/`, CLI parsing under `src/cli/`).

## Tests

- Add tests for new behavior and for bug fixes (a regression test that fails before your change and passes after).
- Unit tests live alongside the code they cover; end-to-end CLI tests live in `tests/cli.rs` and use `assert_cmd` / `predicates`.
- CLI tests must not depend on a real `~/.asphyxia.toml` or on reaching external hosts — keep them hermetic.
- Run the full suite with `cargo test --locked` (or `make test`) before opening a PR.

## Commit messages

Write clear, imperative commit subjects that describe the change, for example:

```
Add UDP port scanning (--udp)
docs: add an Examples cookbook to the README
test: isolate CLI tests from a real ~/.asphyxia.toml
```

Keep each commit focused on one logical change. A short body explaining the *why* is welcome when the change isn't obvious from the subject.

## Pull requests

1. Fork the repo (or create a branch if you have push access) and base your work on the latest `main`.
2. Make your change, add tests and documentation, and ensure `make ci` passes.
3. Open a pull request against `main` with a description of what changed and why. Link any related issue.
4. CI (formatting, Clippy, build, tests) must be green before review.
5. Address review feedback; maintainers merge PRs once they're approved and green.

Keep PRs reasonably scoped — several small, focused PRs are easier to review than one large one. If you're planning a large change, open an issue first to discuss the approach.

## Reporting bugs and requesting features

Open an [issue](https://github.com/jtprogru/asphyxia/issues) and include, where relevant:

- what you ran (the exact command and flags),
- what you expected to happen,
- what actually happened (output, error messages),
- your OS and `asphyxia --version`.

## Documentation

User-facing behavior is documented in `README.md`. If your change adds or alters a flag, scan mode, or output format, update the README (and the Examples section) in the same PR. Follow the existing Markdown style: one paragraph per line, no manual line wrapping.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE), the same license that covers the project.
