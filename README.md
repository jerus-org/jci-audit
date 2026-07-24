# jci-audit

A context-aware Rust security gate that orchestrates
[`cargo-audit`](https://crates.io/crates/cargo-audit) and
[`cargo-deny`](https://crates.io/crates/cargo-deny) — using the complementary
strengths of each and validating security **reproducibly at release time**.

This is a Cargo workspace. The published crate lives in
[`crates/jci-audit`](crates/jci-audit) — see its
[README](crates/jci-audit/README.md) for installation, usage, and the runtime
prerequisites.

## Why

- `cargo audit` gives **fresh, live** advisories; `cargo deny` gives **policy**
  (advisories, bans, licenses, sources) with **file-based, justified** ignores.
- `deny.toml` is the single source of truth; `.cargo/audit.toml` is derived from it.
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

## License

Licensed under either of Apache-2.0 or MIT at your option
([LICENSE-APACHE](crates/jci-audit/LICENSE-APACHE) /
[LICENSE-MIT](crates/jci-audit/LICENSE-MIT)).
