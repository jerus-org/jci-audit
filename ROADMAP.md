<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Roadmap

_Last updated: 2026-08-23._

This roadmap describes the intended direction of jci-audit over roughly the next year.
It is a statement of intent, not a commitment: priorities may shift with user feedback and
maintainer availability (see [GOVERNANCE.md](GOVERNANCE.md)). Concrete work is tracked in the
[issue tracker](https://github.com/jerus-org/jci-audit/issues); this document groups that work
into themes and horizons.

## Current status

jci-audit is **pre-1.0 (0.0.x)**. All six subcommands (`check`, `release`, `sync`, `prune`,
`verify`, `init`) are implemented and tested; the crate and its generated orb
(`jerus-org/jci-audit`) publish in tag-lockstep. `deny.toml` is the single source of truth
for both advisory ignores and license policy — `.cargo/audit.toml` and every crate's
`about.toml` are derived from it.

## Delivered phases

The original build phased as follows:

| Phase | Scope | Status |
|-------|-------|--------|
| **P0 — scaffold** | New repo, workspace + clap skeleton, release lockstep, CI | ✅ Done |
| **P1 — `check` + `sync` + `init` + orb** | Both tools in one gate; `deny.toml` → `.cargo/audit.toml` single source; standard policy template; generated orb | ✅ Done |
| **P2 — `prune`** | Automated stale-ignore detection (naked-DB diff) | ✅ Done |
| **P3 — `release` + `verify`** | Pinned-advisory-db reproducible validation, signed release record, independent re-verification | ✅ Done |
| **P4 — publish** | crates.io + orb published in lockstep | ✅ Done |

## Near term (before 1.0 preview / `0.1.0`)

- **[#90 — publish as bin-only; no importable library.](https://github.com/jerus-org/jci-audit/issues/90)**
  Nothing depends on `jci_audit` as a library today; the lib/bin split was an internal
  testability artifact, not an intended public API. ✅ Restructure done (crate carries no
  `[lib]` target) — **remaining: yank 0.0.1–0.0.7 on crates.io**, so new dependents can't
  resolve the versions that still carry the accidentally-importable library (their docs.rs
  pages stay published regardless — yanking only affects dependency resolution). Lock this
  in before `0.1.0` sets a publish-shape expectation.
- **Project hardening / OpenSSF Best Practices badge.** Complete the governance, security, and
  quality documentation and achieve (and display) at least the Silver badge.
- **License policy scoped per crate.** ✅ Done — `about.toml`'s `accepted` list is derived from
  each crate's own reachable dependency graph via SPDX evaluation, not copied verbatim from the
  workspace-wide `deny.toml` allow-list.
- **Documentation and a project presence** (user guides, jrussell.ie project page, announcement
  draft) ahead of any consumer migration.
- **Consumer migration (P4's remaining half).** Add the published orb to `gen-changelog`, `pcu`,
  `nextsv`, and `gen-circleci-orb`; wire `jci-audit check`/`release` into their pipelines;
  standardize each `deny.toml` on the shared template; retire ad-hoc `--ignore` CI flags. Deferred
  until the 0.1.0 preview gates above are met — no repo should be told to adopt a tool with no
  docs or public credibility signal yet.

## Backlog (tracked as issues, not yet scheduled)

- **[#62 — per-crate package selection for release/verify.](https://github.com/jerus-org/jci-audit/issues/62)**
  Support the release pattern used in `pcu`: let the user choose crate release order in a
  multi-crate workspace, so a dependent crate releases against its dependency's latest version.
- **[#63 — `license_scope` and `about.toml`'s `ignore-build-dependencies`/`ignore-transitive-dependencies`.](https://github.com/jerus-org/jci-audit/issues/63)**
  Honour those settings in the derivation instead of always including build dependencies.
- **[#49 — accept warnings at release time and record the acceptances.](https://github.com/jerus-org/jci-audit/issues/49)**
- **[#36 — run `licenses-check` in validation so notices cannot go stale.](https://github.com/jerus-org/jci-audit/issues/36)**
- **[#31 — resolve the cargo-deny warnings (unmatched license allowances, duplicate syn).](https://github.com/jerus-org/jci-audit/issues/31)**

## Medium term — toward 1.0

- **Stabilise the CLI and configuration surface.** Settle the subcommand flags and `deny.toml`
  policy template so that `0.x → 1.0` is a stability milestone with documented migration guidance
  for existing consumers.
- **Deprecate overlapping audit coverage in consumers' shared CI tooling.** Once `jci-audit` owns
  audit+deny for its consumers, any equivalent audit step in their existing shared CI job set
  becomes redundant. This needs a decision on where SonarQube scanning lives once that overlap is
  removed — before it can actually be deprecated.
- **Scheduled live-audit pipeline.** A cron-triggered `jci-audit check`/`prune` run against
  already-released lockfiles, for early warning on shipped releases rather than only at the next
  PR or release.

## Longer term (beyond 1.0)

- Fold `jci-audit` into consumers' shared CI job sets as the default security gate, once the
  CLI/config surface is stable and consumer migration is complete.
- Broaden the reproducibility model (e.g. attesting the release record itself) as the SLSA/sigstore
  tooling this org already uses elsewhere matures.

## How to influence the roadmap

Open an issue (feature request) or comment on an existing roadmap issue. Contributions that move
roadmap items forward are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
