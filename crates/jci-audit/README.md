# jci-audit

A context-aware Rust security gate that orchestrates
[`cargo-audit`](https://crates.io/crates/cargo-audit) and
[`cargo-deny`](https://crates.io/crates/cargo-deny), using the complementary
strengths of each and validating security **reproducibly at release time**.

- **`cargo audit`** — fresh, *live* advisories from the RustSec database.
- **`cargo deny`** — policy enforcement (advisories, bans, licenses, sources)
  with **file-based** ignores that carry written justifications.

`deny.toml` is the single source of truth for advisory ignores; `.cargo/audit.toml`
is derived from it. Release validation runs both tools **offline against a pinned
advisory-db commit** for reproducibility, then a live audit as a non-blocking warning.

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
jci-audit release --version 1.2.0

# Derive .cargo/audit.toml from the canonical deny.toml (CI: --check fails on drift)
jci-audit sync [--check]

# Report advisory ignores that no longer fire (stale-ignore detector)
jci-audit prune [--check]

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
