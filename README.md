# jci-audit

A context-aware Rust security gate that orchestrates
[`cargo-audit`](https://crates.io/crates/cargo-audit) and
[`cargo-deny`](https://crates.io/crates/cargo-deny) — using the complementary
strengths of each and validating security **reproducibly at release time**.

[![Crates.io](https://img.shields.io/crates/v/jci-audit.svg)](https://crates.io/crates/jci-audit)
[![License](https://img.shields.io/crates/l/jci-audit.svg)](#license)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14065/badge)](https://www.bestpractices.dev/projects/14065)

This is a Cargo workspace. The published crate lives in
[`crates/jci-audit`](crates/jci-audit) — see its
[README](crates/jci-audit/README.md) for installation, usage, and the runtime
prerequisites.

## Quick start

```bash
cargo binstall jci-audit              # or: cargo install jci-audit
cargo binstall cargo-audit cargo-deny # jci-audit orchestrates these; both must be on PATH

jci-audit init                        # scaffold a standard deny.toml + derived .cargo/audit.toml
jci-audit check                       # PR/dev gate: cargo-deny policy + a live cargo-audit scan
jci-audit release-prep --release-version 1.2.0  # release gate: reproducible, pinned-advisory-db validation
```

See the [crate README](crates/jci-audit/README.md) for the full usage guide, and the
[Documentation](#documentation) table below for architecture, design, and release-signing guides.

## Why

- `cargo audit` gives **fresh, live** advisories; `cargo deny` gives **policy**
  (advisories, bans, licenses, sources) with **file-based, justified** ignores.
- `deny.toml` is the single source of truth; `.cargo/audit.toml` and every crate's
  `about.toml` are derived from it.
- **Release** validation is reproducible: `cargo deny` locks to a **pinned advisory-db
  commit** and runs offline; `cargo audit` keeps running live, as a non-blocking check.

## Development

```bash
just test        # clippy + check + doc + tests
just audit       # cargo deny (advisories, bans, licenses, sources)
just msrv        # verify the declared MSRV builds
just fmt         # nightly rustfmt (+ stable check)
just licenses    # regenerate THIRD-PARTY-LICENSES.md (cargo-about)
```

## Documentation

| Document | Purpose |
|----------|---------|
| [crate README](crates/jci-audit/README.md) | Full usage guide, CLI reference, runtime prerequisites |
| [docs/getting-started.md](docs/getting-started.md) | First-run walkthrough |
| [docs/user-guide.md](docs/user-guide.md) | Every subcommand in depth |
| [docs/configuration-guide.md](docs/configuration-guide.md) / [docs/advanced-configuration.md](docs/advanced-configuration.md) | The `deny.toml`/`about.toml` fields jci-audit interacts with; release record storage, advisory-db overrides, troubleshooting |
| [docs/architecture.md](docs/architecture.md) | High-level architecture |
| [docs/design.md](docs/design.md) | Detailed design document |
| [docs/assurance-case.md](docs/assurance-case.md) | Security assurance case & threat model |
| [docs/RELEASING.md](docs/RELEASING.md) | Release signing & how to verify a release |
| [docs/openssf-badge.md](docs/openssf-badge.md) | OpenSSF Best Practices criterion → evidence mapping |
| [ROADMAP.md](ROADMAP.md) | Planned direction |
| [PRLOG.md](PRLOG.md) / [crate CHANGELOG](crates/jci-audit/CHANGELOG.md) | Release history |

## Contributing & project information

- [Contributing guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Governance](GOVERNANCE.md)
- [Security policy](SECURITY.md)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
