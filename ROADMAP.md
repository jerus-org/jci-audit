<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Roadmap

_Last updated: 2026-08-27._

This roadmap describes the intended direction of jci-audit over roughly the next year.
It is a statement of intent, not a commitment: priorities may shift with user feedback and
maintainer availability (see [GOVERNANCE.md](GOVERNANCE.md)). Concrete work is tracked in the
[issue tracker](https://github.com/jerus-org/jci-audit/issues); this document groups that work
into themes and horizons.

## Current status

jci-audit is **pre-1.0, currently `0.1.1`** — published bin-only (no importable `[lib]` target,
[#90](https://github.com/jerus-org/jci-audit/issues/90)) and, unlike every earlier version, both
installable and verifiable. **`0.0.1`–`0.1.0` are yanked**: `0.0.1`–`0.0.7` for the
accidentally-importable library (#90), and `0.1.0` because its release-security-record was
unrecoverable (never committed, never uploaded as a release asset, and the CI build-artifact copy
expired — see [#75](https://github.com/jerus-org/jci-audit/issues/75)) and can never be
reconstructed. `0.1.1` closed that gap: it's the first release cut after #75 phase 2's release-asset
distribution landed, and `jci-audit verify --release-version 0.1.1`, run unauthenticated from a bare
directory, confirmed it end-to-end. All seven subcommands (`check`, `release-prep`, `sync`, `prune`,
`verify`, `init`, `publish-record`) are implemented and tested; the crate and its generated orb
(`jerus-org/jci-audit`) publish in tag-lockstep. `deny.toml` is the single source of truth for
both advisory ignores and license policy — `.cargo/audit.toml` and every crate's `about.toml` are
derived from it.

## Delivered phases

The original build phased as follows:

| Phase | Scope | Status |
|-------|-------|--------|
| **P0 — scaffold** | New repo, workspace + clap skeleton, release lockstep, CI | ✅ Done |
| **P1 — `check` + `sync` + `init` + orb** | Both tools in one gate; `deny.toml` → `.cargo/audit.toml` single source; standard policy template; generated orb | ✅ Done |
| **P2 — `prune`** | Automated stale-ignore detection (naked-DB diff) | ✅ Done |
| **P3 — `release-prep` + `verify`** | Pinned-advisory-db reproducible validation, signed release record, independent re-verification | ✅ Done (the original commit-based signing was later removed by #75 phase 1; see the #75 gate below for the current, unfinished replacement) |
| **P4 — publish** | crates.io + orb published in lockstep | ✅ Done — publishing itself works; whether any given *version* is currently installable is separate, see Current status above |

## Near term (0.1.0 preview credibility gates, before consumer migration)

`0.1.0` has already shipped as a version number — an automatic minor bump from #90's breaking
bin-only change, released 2026-08-25. The gates below are about public-facing *readiness*, not the
version tag itself, and still gate consumer migration.

- **[#90 — publish as bin-only; no importable library.](https://github.com/jerus-org/jci-audit/issues/90)**
  ✅ Done — restructured (crate carries no `[lib]` target), released in `0.1.0`, and
  `0.0.1`–`0.0.7` yanked on crates.io so new dependents can't resolve the versions that carried
  the accidentally-importable library (their docs.rs pages stay published regardless — yanking
  only affects dependency resolution).
- **[#75 — release record retrievability.](https://github.com/jerus-org/jci-audit/issues/75)**
  ✅ **Done** — both phase-2 distribution paths are shipped and confirmed working, and phases 1/3
  are unchanged. Phase 1 (stop git-committing the record) shipped before `0.1.0`; phase 3
  (`verify`'s signed remote-fetch path) is built and wired. Phase 2 signs the record and uploads it,
  with its signature and pubkey, to the release before publish — two ways, per PR review on
  #105/#75: **path B**, the fully self-contained `jci-audit publish-record` subcommand and its
  matching orb job, needs nothing beyond this orb and a GitHub token — usable today by any consumer
  with no equivalent signing facility of its own. **Path A**, jci-audit's own pipeline reusing the
  same ephemeral key that already signs the binary tarball (a stronger, crates.io-anchored trust
  chain), needed two generic hooks in circleci-toolkit's `release_crate` job
  (digital-prstv/circleci-toolkit#533, released in toolkit 7.4.0), wired into `.circleci/release.yml`
  — and **confirmed on a real release**: `jci-audit-v0.1.1` produced `release-0.1.1.json`, `.sig`,
  and `.pub` on the published release (the `.pub` key matching `Cargo.toml`'s), and
  `jci-audit verify --release-version 0.1.1`, run unauthenticated from a bare directory, fetched and
  authenticated it successfully. `0.1.1` is the first release since phase 1 removed the commit path
  to be both installable and verifiable — closing the gap `0.1.0`'s yanking exposed. That damage is
  now historical: `0.1.0`'s own record fell through every available path (no commit, no release
  asset, and the CI build-artifact copy expired) and can never be reconstructed, so **`0.1.0` stays
  yanked from crates.io** — not a verifiable release, and not retroactively fixable. This isn't
  jci-audit's first release with a record, though: `0.0.4`–`0.0.7` each carry a real, GPG-signed,
  git-committed record and are still independently verifiable from a checkout — they're separately
  yanked, for the unrelated #90 reason.
- **Project hardening / OpenSSF Best Practices badge.** ✅ Done — the project has reached
  [Silver](https://www.bestpractices.dev/projects/14065) (confirmed 2026-08-25; 100% of Silver's
  55 criteria met, Gold at 35%).
- **License policy scoped per crate.** ✅ Done — `about.toml`'s `accepted` list is derived from
  each crate's own reachable dependency graph via SPDX evaluation, not copied verbatim from the
  workspace-wide `deny.toml` allow-list.
- **Documentation and a project presence.** Repo docs ✅ done. jrussell.ie project page:
  [digital-prstv/jrussell.ie#264](https://github.com/digital-prstv/jrussell.ie/pull/264) open.
  Announcement draft for the jrussell.ie blog: not yet started.
- **Consumer migration (P4's remaining half).** Add the published orb to `gen-changelog`, `pcu`,
  `nextsv`, and `gen-circleci-orb`; wire `jci-audit check`/`release-prep` into their pipelines;
  standardize each `deny.toml` on the shared template; retire ad-hoc `--ignore` CI flags. Deferred
  until the remaining preview gates above (jrussell.ie page merged, announcement drafted) are
  met — no repo should be told to adopt a tool with no docs or public credibility signal yet.

## Backlog (tracked as issues, not yet scheduled)

- **[#62 — per-crate package selection for release/verify.](https://github.com/jerus-org/jci-audit/issues/62)**
  Support the release pattern used in `pcu`: let the user choose crate release order in a
  multi-crate workspace, so a dependent crate releases against its dependency's latest version.
- **[#63 — `license_scope` and `about.toml`'s `ignore-build-dependencies`/`ignore-transitive-dependencies`.](https://github.com/jerus-org/jci-audit/issues/63)**
  Honour those settings in the derivation instead of always including build dependencies.
- **[#49 — accept warnings at release time and record the acceptances.](https://github.com/jerus-org/jci-audit/issues/49)**
- **[#36 — run `licenses-check` in validation so notices cannot go stale.](https://github.com/jerus-org/jci-audit/issues/36)**
- **[#31 — resolve the cargo-deny warnings (unmatched license allowances, duplicate syn).](https://github.com/jerus-org/jci-audit/issues/31)**
- **[#100 — `about.toml` sync assumes a `crates/*/` layout instead of reading the workspace manifest.](https://github.com/jerus-org/jci-audit/issues/100)**
  A workspace laid out any other way silently never gets its `about.toml` synced.
- **[#101 — no command wires the orb into a consumer's CI config.](https://github.com/jerus-org/jci-audit/issues/101)**
  Today it's a manual copy-the-YAML step; `gen-circleci-orb init`/`update` already automates the
  equivalent for its own consumers.
- **[#80 — fold the `cargo-about` license-policy resolution check into `check`/`release-prep`.](https://github.com/jerus-org/jci-audit/issues/80)**
  ✅ Done — `check` now runs it too (previously only `release-prep` did), and this repo's own
  `.circleci/config.yml` dogfoods the published `jci-audit/check` orb job directly (self-contained,
  its own public image — no dependency on the private toolkit's executors), replacing the
  hand-authored `licenses_policy` job. `toolkit/security`'s redundant `cargo_audit` calls were
  dropped in the same change. **Separately still open**: `.circleci/release.yml`'s `record-release`
  job carries its own `TEMPORARY WORKAROUND` — a different hand-authored job, not part of #80,
  still pending its own cleanup once the orb's release-time constraints allow it.
- **[#111 — redundant per-call tokio runtime construction in `block_on`-based network clients.](https://github.com/jerus-org/jci-audit/issues/111)**
  Not a correctness bug — `PcuAssetWriter`/`PcuAssetSource`/`ManifestPubkeySource` each build a
  fresh runtime per call instead of one per invocation. Low priority.

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
