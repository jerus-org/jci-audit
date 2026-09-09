<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Roadmap

_Last updated: 2026-09-09._

This roadmap describes the intended direction of jci-audit over roughly the next year.
It is a statement of intent, not a commitment: priorities may shift with user feedback and
maintainer availability (see [GOVERNANCE.md](GOVERNANCE.md)). Concrete work is tracked in the
[issue tracker](https://github.com/jerus-org/jci-audit/issues); this document groups that work
into themes and horizons.

## Current status

jci-audit is **pre-1.0, currently `0.1.9`** — published bin-only (no importable `[lib]` target,
[#90](https://github.com/jerus-org/jci-audit/issues/90)) and, unlike every earlier version, both
installable and verifiable. **`0.0.1`–`0.1.0` are yanked**: `0.0.1`–`0.0.7` for the
accidentally-importable library (#90), and `0.1.0` because its release-security-record was
unrecoverable (never committed, never uploaded as a release asset, and the CI build-artifact copy
expired — see [#75](https://github.com/jerus-org/jci-audit/issues/75)) and can never be
reconstructed. `0.1.1` closed that gap: it's the first release cut after #75 phase 2's release-asset
distribution landed, and `jci-audit verify 0.1.1`, run unauthenticated from a bare
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
  `jci-audit verify 0.1.1`, run unauthenticated from a bare directory, fetched and
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
  **Exception: `pcu`** — see the `v0.2.0` section below; adoption there is blocked on real
  capability gaps (#62, #101), not just on the general readiness gates.

## Next: `v0.2.0` — the initial pre-release

Scope set 2026-09-06. `0.2.0` is a **pre-release milestone, not a feature release**: it's the point
where the still-manual, still-workspace-scoped edges of the tool get closed off before any further
consumer beyond jci-audit's own dogfooding is asked to adopt it. `jci-audit` is already past `0.1.0`
as a version number (however incidentally — see Current status above), and `pcu` — a real
multi-crate workspace in this org — cannot adopt `jci-audit` as its release gate until the
per-crate item below ships. This is a deliberate minor release, not folded into the routine patch
releases Phase 0-2 bugfixes have been shipping as.

- **[#142 — pin tool versions in `orb/Dockerfile` for traceability.](https://github.com/jerus-org/jci-audit/issues/142)**
  ⚠️ **Closed, but not actually fixed.** PR #161 genuinely added `ENV CARGO_ABOUT_VERSION=...`-style
  pins, but `orb/Dockerfile` is a **generated** file and `gen-circleci-orb.toml`'s `cargo_tools`
  field has no version-pin syntax at all — the `jerus-bot` regenerate-orb auto-commit that lands
  mid-PR silently reverted the pins back to the generator's unpinned template *before* #161 merged,
  and that reverted, unpinned state is what's on `main` today. Root-caused and re-opened for
  tracking as [#180](https://github.com/jerus-org/jci-audit/issues/180); the actual fix is blocked
  on the generator gaining pin support
  ([gen-circleci-orb#321](https://github.com/jerus-org/gen-circleci-orb/issues/321)) — a per-repo
  hand-edit to the Dockerfile again would just get reverted the same way.
- **[#62 — per-crate package selection for release/verify.](https://github.com/jerus-org/jci-audit/issues/62)**
  ✅ Done — `release-prep`/`verify --package <NAME>` scope the dependency digest to that crate's
  reachable graph (via `cargo metadata`, reusing `license_scope`'s reachability rule) and the
  record's own path (`.security/<name>-release-<version>.json`), so multiple crates can release
  under different versions in one pipeline run without colliding. The advisory gate itself
  (deny.toml, cargo-deny) stays workspace-wide, matching cargo-deny's own model. `publish-record`
  and `verify`'s remote-fetch path don't take a per-package record path yet — deferred until a
  real multi-crate consumer needs the full pipeline, per the issue's own "why post-MVP" note.
- **[#101 — no command wires the orb into a consumer's CI config.](https://github.com/jerus-org/jci-audit/issues/101)**
  ✅ Done (in two parts) — [#163](https://github.com/jerus-org/jci-audit/pull/163) shipped
  `wire-ci`/`check-ci-wiring` for a single job in a single workflow (e.g. `jci-audit/check` in a
  `validation`-style workflow), and [#171](https://github.com/jerus-org/jci-audit/issues/171)
  (merged as #172) made `jci-audit.toml` canonical in both directions — resyncing a
  toml-declared job whose config has drifted or was never marked, and discovering an existing
  `jci-audit/*` config job that has no toml entry yet and writing one. #101 itself is closed; the
  one piece explicitly deferred out of it — wiring the three-job **release workflow**
  (`release_prep`/the consumer's own release job/`publish_record`) — is tracked separately as
  #164, below.
- **[#164 — wire-ci support for the release workflow.](https://github.com/jerus-org/jci-audit/issues/164)**
  In scope for `0.2.0` (added 2026-09-09). The release workflow is a three-job chain, not a single
  job — `jci-audit/release_prep` → the consumer's own release job → `jci-audit/publish_record` —
  with mechanics `wire_job_into`/`CiConfig` don't handle yet: `context:`, `post-steps:
  [persist_to_workspace]`, `attach_workspace: true`, and new `--tag`/`--owner`/`--repo`/`--version`
  fields. The middle job is always the consumer's own; `wire-ci` can only wire the first and third
  around wherever a `--release-job <name>`-style flag says it is. Also open: whether this needs its
  own `[ci.release]` config table alongside `[ci]`, decided during implementation.
- **[#63 — `license_scope`/`about.toml` ignore-build/ignore-transitive-dependencies.](https://github.com/jerus-org/jci-audit/issues/63)**
  Honour those settings in the derivation instead of always including build dependencies. Not
  started; no external blocker.
- **[#36 — run `licenses-check` in validation so notices cannot go stale.](https://github.com/jerus-org/jci-audit/issues/36)**
  The "which container's `cargo-about` gets used" half is unblocked now that #101 is done. The
  determinism half is still blocked — not on #101 any more, but on #180/#142 above: the
  cold/warm-cache cargo-about investigation in this issue's own history depends on the orb image
  actually running a pinned, known-good cargo-about version, which it currently does not.
- **[#138 — clippy::pedantic adoption.](https://github.com/jerus-org/jci-audit/issues/138)**
  ✅ Done — whole-group `warn` (with `too_many_lines` allowed) in `[workspace.lints.clippy]`.
- **[#136 — invoke cargo-audit/cargo-deny/cargo-about via `cargo <sub>`.](https://github.com/jerus-org/jci-audit/issues/136)**
  ✅ Done — every invocation (and version probe) now dispatches through `cargo <sub>`, including
  the one asymmetry discovered along the way (`cargo-audit`'s dispatch reinserts `audit` itself).

**Remaining before `0.2.0` can ship:** #180 (blocked on upstream gen-circleci-orb#321), #63, #36
(blocked on #180), #164. #142/#101/#62/#138/#136 are genuinely done.

## Backlog (tracked as issues, not yet scheduled)

- **[#49 — accept warnings at release time and record the acceptances.](https://github.com/jerus-org/jci-audit/issues/49)**
  ✅ Done — shipped as `[[bans.skip]]` support in `jci-audit-v0.1.6` (PR #143).
- **[#31 — resolve the cargo-deny warnings (unmatched license allowances, duplicate syn).](https://github.com/jerus-org/jci-audit/issues/31)**
  ✅ Done — both halves (`--deny-unused-licenses`, `multiple-versions = "deny"` +
  `--deny-stale-exceptions`) dogfooded live on this repo's own CI and merged.
- **[#100 — `about.toml` sync assumes a `crates/*/` layout instead of reading the workspace manifest.](https://github.com/jerus-org/jci-audit/issues/100)**
  ✅ Done — `find_about_toml_paths`/`about_toml_digest` now derive workspace members from
  `cargo metadata --no-deps`, not a hardcoded `crates/` walk. Shipped in `jci-audit-v0.1.4`.
- **[#80 — fold the `cargo-about` license-policy resolution check into `check`/`release-prep`.](https://github.com/jerus-org/jci-audit/issues/80)**
  ✅ Done — `check` now runs it too (previously only `release-prep` did), and this repo's own
  `.circleci/config.yml` dogfoods the published `jci-audit/check` orb job directly (self-contained,
  its own public image — no dependency on the private toolkit's executors), replacing the
  hand-authored `licenses_policy` job. `toolkit/security`'s redundant `cargo_audit` calls were
  dropped in the same change. **Separately still open**: `.circleci/release.yml`'s `record-release`
  job carries its own `TEMPORARY WORKAROUND` — a different hand-authored job, not part of #80,
  still pending its own cleanup once the orb's release-time constraints allow it.
- **[#111 — redundant per-call tokio runtime construction in `block_on`-based network clients.](https://github.com/jerus-org/jci-audit/issues/111)**
  ✅ Done — `PcuAssetWriter`/`PcuAssetSource`/`ManifestPubkeySource` each build one runtime in
  `new()` now and reuse it, instead of a fresh one per call. Shipped in `jci-audit-v0.1.5`.
- **[#121 — verify's remote path takes an explicit owner/repo/tag-prefix.](https://github.com/jerus-org/jci-audit/issues/121)**
  ✅ Done — `verify` takes `--owner`/`--repo`/`--tag-prefix` on the remote-fetch fallback, naming
  which release to check. Pubkey sources are tried asset-first: the source that depends on nothing
  about how the release was published, ahead of the crates.io/cargo-binstall manifest convention.
- **[#120 — verify's remote fallback misreports Cargo.lock/deny.toml as absent.](https://github.com/jerus-org/jci-audit/issues/120)**
  ✅ Done — the "not checked" message now reflects Cargo.lock/deny.toml independently, instead of
  blaming both when only the version-specific `.security/release-<VERSION>.json` is missing.
  Shipped in `jci-audit-v0.1.3`.

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
