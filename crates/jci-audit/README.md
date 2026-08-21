# jci-audit

A context-aware Rust security gate that orchestrates
[`cargo-audit`](https://crates.io/crates/cargo-audit) and
[`cargo-deny`](https://crates.io/crates/cargo-deny), using the complementary
strengths of each and validating security **reproducibly at release time**.

[![Crates.io](https://img.shields.io/crates/v/jci-audit.svg)](https://crates.io/crates/jci-audit)
[![License](https://img.shields.io/crates/l/jci-audit.svg)](https://github.com/jerus-org/jci-audit#license)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14065/badge)](https://www.bestpractices.dev/projects/14065)

## Why

`cargo audit` and `cargo deny` have complementary strengths, and jci-audit uses each for
what it does best rather than reimplementing either:

- **`cargo audit`** — fresh, *live* advisories from the RustSec database.
- **`cargo deny`** — policy enforcement (advisories, bans, licenses, sources)
  with **file-based** ignores that carry written justifications.

jci-audit allows `deny.toml` to be the single source of truth for both advisory ignores and
license policy; `.cargo/audit.toml` and every crate's `about.toml` are derived from it.
Release validation locks `cargo deny` to a **pinned advisory-db commit** and runs it offline
for reproducibility; `cargo audit` keeps running live, as a non-blocking currency check.

> **Status:** early development (0.1.x). The CLI surface is in place; subcommand
> behaviour is landing incrementally (see the phased roadmap).

## Runtime prerequisites

`jci-audit` **orchestrates the `cargo audit` and `cargo deny` binaries as
subprocesses** — it does not bundle them. Both must be on `PATH`:

```bash
cargo binstall cargo-audit cargo-deny
```

In CI they are provided by the `jci-audit` orb's executor image
(`jerusdp/jci-audit`), which is built to ship both tools. Every subcommand that
shells out runs a **preflight** check first and reports, with actionable
guidance, if either tool is missing — rather than failing opaquely.

## Installation

```bash
cargo binstall jci-audit
# or
cargo install jci-audit
```

## Usage

```bash
# PR / dev gate: cargo-deny policy checks AND a live cargo-audit scan (both blocking)
jci-audit check

# Release gate: reproducible validation against a pinned advisory-db + live audit
jci-audit release --release-version 1.2.0

# Derive .cargo/audit.toml and every crate's about.toml from the canonical
# deny.toml (CI: --check fails on drift)
jci-audit sync [--check]

# Report advisory ignores that no longer fire (stale-ignore detector)
jci-audit prune [--check]

# Re-verify a past release against the advisory snapshot it was locked to;
# run from a checkout of the released tag
jci-audit verify --release-version 1.2.0

# Scaffold a standard deny.toml + derived .cargo/audit.toml
jci-audit init
```

## Contributing

Contributions are welcome. See the
[Contributing Guide](https://github.com/jerus-org/jci-audit/blob/main/CONTRIBUTING.md)
and [Code of Conduct](https://github.com/jerus-org/jci-audit/blob/main/CODE_OF_CONDUCT.md).
Changes follow Conventional Commits with DCO sign-off (`git commit -s`) and
RED/GREEN TDD.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Third-party dependency notices are in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
