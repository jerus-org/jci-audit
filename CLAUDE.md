# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository. It supplements the garden-level and global CLAUDE.md.

## Overview

**jci-audit** is a context-aware Rust security gate that orchestrates the
`cargo audit` and `cargo deny` **binaries** (as subprocesses — it does not link
them as libraries) and validates security reproducibly at release time. It ships
a crate to crates.io and (from P1) a generated CircleCI orb `jerus-org/jci-audit`
in tag-lockstep, produced by `gen-circleci-orb`.

Origin: circleci-toolkit issue #497. See the implementation plan for phasing
(P0 scaffold → P1 check/sync/init + orb → P2 prune → P3 release → P4 publish +
consumer migration).

## Architecture

```
crates/jci-audit/
├── src/
│   ├── main.rs       # crate doc + mod declarations, tracing setup
│   ├── cli.rs        # Cli + Commands (check/release/sync/prune/init), run()
│   └── preflight.rs  # tool-presence detection for cargo-audit / cargo-deny
└── tests/cmd/*.trycmd  # CLI snapshot tests (trycmd)
```

Bin-only crate, deliberately — no `[lib]` target (`autolib = false`; no `src/lib.rs`).
Nothing depends on `jci_audit` as a library, and publishing to crates.io shouldn't make it
importable ([#90](https://github.com/jerus-org/jci-audit/issues/90)). Internal items use
`pub(crate)`, never bare `pub`.

- **`deny.toml`** (workspace root) is the **single source of truth** for both
  advisory ignores and license policy. **`.cargo/audit.toml`** and every
  **`crates/*/about.toml`**'s `accepted` lists are DERIVED from it by `jci-audit
  sync` — never edit either by hand. `about.toml`'s license lists are scoped to
  each crate's own dependency graph (not a copy of the workspace-wide policy);
  everything else in `about.toml` (comments, `.clarify` attribution pins) is
  hand-authored and untouched by `sync`.
- `jci-audit` shells out to the tools; every shelling subcommand runs
  `preflight::ensure_available` first so a missing `cargo audit` / `cargo deny`
  fails loudly and actionably rather than silently no-opping.

## Development commands

```bash
just test            # clippy + check + doc + unit/CLI tests
just clippy          # cargo clippy --all --tests --all-features -- -D warnings
just audit           # cargo deny check advisories bans licenses sources
just msrv            # cargo msrv verify (workstation tool; verifies declared floor)
just fmt             # nightly rustfmt + stable check
just cov             # coverage via cargo-llvm-cov
just licenses        # regenerate THIRD-PARTY-LICENSES.md (cargo-about)
just licenses-check  # fail if notices are stale
```

Regenerate CLI snapshots after intentional CLI changes:
`TRYCMD=overwrite cargo test --test cli_tests`.

## Conventions

- **RED/GREEN TDD** for all Rust work — failing test first.
- **Edition 2024**, MSRV **1.89** — set by `pcu`'s own floor, not by edition 2024
  (whose floor is 1.85). Verify with `just msrv` before every PR that changes
  deps/`Cargo.lock`; keep `rust-version` and `min_rust_version` in
  `.circleci/config.yml` in lockstep.
- `#[cfg(test)]` modules at the END of each file.
- Conventional Commits, first line < 50 chars, DCO sign-off (`git commit -s`).
- Workspace `release.toml` uses `consolidate-commits = false` — crates release
  individually in a chosen dependency order.
- Tag prefixes: crate `jci-audit-v<VERSION>`, workspace `v<VERSION>`.

## CI/CD

CircleCI, 3-file model (`.circleci/{config.yml,release.yml,update_prlog.yml}`)
on `jerus-org/circleci-toolkit@6.6.2`. `config.yml` is validation-only until the
orb is added in P1, at which point `gen-circleci-orb`-managed regions and an
`orb-release` workflow are introduced (edit those via the generator, never by
hand). Release calculates versions before an approval gate, then
`toolkit/release_crate` + `toolkit/release_prlog`.

Never commit to `main`; all changes via PR. Do not merge/approve/close PRs.
