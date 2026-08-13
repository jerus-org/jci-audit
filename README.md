# jci-audit

A context-aware Rust security gate that orchestrates
[`cargo-audit`](https://crates.io/crates/cargo-audit) and
[`cargo-deny`](https://crates.io/crates/cargo-deny) — using the complementary
strengths of each and validating security **reproducibly at release time**.

[![Crates.io](https://img.shields.io/crates/v/jci-audit.svg)](https://crates.io/crates/jci-audit)
[![Documentation](https://docs.rs/jci-audit/badge.svg)](https://docs.rs/jci-audit)
[![License](https://img.shields.io/crates/l/jci-audit.svg)](#license)

This is a Cargo workspace. The published crate lives in
[`crates/jci-audit`](crates/jci-audit) — see its
[README](crates/jci-audit/README.md) for installation, usage, and the runtime
prerequisites.

## Why

- `cargo audit` gives **fresh, live** advisories; `cargo deny` gives **policy**
  (advisories, bans, licenses, sources) with **file-based, justified** ignores.
- `deny.toml` is the single source of truth; `.cargo/audit.toml` and every crate's
  `about.toml` are derived from it.
- **Release** validation is reproducible: both tools run offline against a
  **pinned advisory-db commit**, with a live audit as a non-blocking warning.

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
| [docs/architecture.md](docs/architecture.md) | High-level architecture |
| [docs/design.md](docs/design.md) | Detailed design document |
| [docs/assurance-case.md](docs/assurance-case.md) | Security assurance case & threat model |
| [docs/RELEASING.md](docs/RELEASING.md) | Release signing & how to verify a release |
| [ROADMAP.md](ROADMAP.md) | Planned direction |
| [PRLOG.md](PRLOG.md) / [crate CHANGELOG](crates/jci-audit/CHANGELOG.md) | Release history |

## Contributing & project information

- [Contributing guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Governance](GOVERNANCE.md)
- [Security policy](SECURITY.md)

## License

Licensed under either of Apache-2.0 or MIT at your option
([LICENSE-APACHE](crates/jci-audit/LICENSE-APACHE) /
[LICENSE-MIT](crates/jci-audit/LICENSE-MIT)).
