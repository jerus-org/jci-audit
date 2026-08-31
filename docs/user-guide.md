<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# User guide

In-depth reference for every jci-audit subcommand. See [getting-started.md](getting-started.md)
for a first-run walkthrough, and [configuration-guide.md](configuration-guide.md) for the
`deny.toml`/`about.toml` fields jci-audit interacts with.

All commands print `0` on success and `1` (with an error message) on failure — the standard
`anyhow`-backed exit convention. `-v`/`-q` (repeatable) raise or lower log verbosity; they're
available on every subcommand.

## `check`

```
jci-audit check [OPTIONS]

Options:
      --manifest-path <MANIFEST_PATH>  Path to the Cargo.toml (or its directory) to check [default: .]
      --deny-warnings                  Fail if the tools report any warning
```

The PR/dev gate. Runs four independently-blocking steps and aggregates the results — a failure
in one never hides a failure in another; the error message names every step that failed:

1. `cargo deny check advisories bans licenses sources` (policy).
2. A **live** `cargo audit` scan (fresh RustSec database).
3. The `about.toml`/`deny.toml` drift check ([`sync`](#sync)'s check mode) — a stale derived
   license-policy file fails `check` on its own, even when both tools above pass.
4. The `cargo-about` license-policy resolution check — can `cargo-about` actually attribute every
   reachable dependency's licence with what's on disk right now? Independent of drift: an
   in-sync `about.toml` can still fail this if an SPDX expression isn't covered by any
   allow/exception combination. Previously only `release-prep` caught this, at the most
   expensive point in the pipeline (jerus-org/jci-audit#80).

`--deny-warnings` escalates warnings (e.g. cargo-deny's `unmaintained = "all"` scope, which
reports as a warning rather than an error by default) to failures. Use this on a schedule or a
stricter branch policy where warnings shouldn't be allowed to accumulate silently.

```bash
jci-audit check                              # current directory
jci-audit check --manifest-path crates/foo   # a specific crate in a workspace
jci-audit check --deny-warnings              # treat warnings as failures too
```

## `release-prep`

```
jci-audit release-prep [OPTIONS]

Options:
      --release-version <VERSION>  The release version being validated (e.g. "1.2.0")
      --version-env <VERSION_ENV>  Env var NAME holding the version when --release-version is not given [default: SEMVER]
      --advisory-db <ADVISORY_DB>  Advisory-db root; cargo-deny's checkout lives beneath it [default: ~/.cargo/advisory-db]
      --deny-warnings               Fail if the tools report any warning
```

The release gate. Locks `cargo-deny` to a **pinned advisory-db commit** and runs it offline for
reproducibility; `cargo-audit` always runs against the **live** database (PRs already gate on
it continuously via `check`), so at release time it only runs again as a non-blocking currency
check, not a second pinned/offline pass. Writes `.security/release-<VERSION>.json` to the working
directory — see [design.md §5](design.md#5-reproducibility-the-release-record) for exactly what
that record contains and why, and
[advanced-configuration.md](advanced-configuration.md#the-release-record-is-local-only-for-now)
for the record's current (local-only, not yet distributed) storage model.

The version comes from `--release-version`, or (for CI pipelines that compute the version at
runtime, e.g. via `nextsv`) from the environment variable named by `--version-env` (default
`SEMVER`) when `--release-version` is omitted.

```bash
jci-audit release-prep --release-version 1.2.0   # validate and write the record locally
```

## `sync`

```
jci-audit sync [OPTIONS]

Options:
      --check       Fail (non-zero) on drift instead of rewriting the file. For CI
```

Derives `.cargo/audit.toml` (from `deny.toml`'s `[advisories].ignore`) and every
`crates/*/about.toml`'s `accepted` license list (from `deny.toml`'s `[licenses]` policy, scoped
to each crate's own dependency graph) — see
[design.md §4](design.md#4-the-sync-derivation) for the full derivation algorithm. Writing is a
**merge**: hand-authored content in `about.toml` (comments, `.clarify` attribution pins) is left
untouched.

```bash
jci-audit sync           # regenerate both derived files
jci-audit sync --check   # CI: exit 1 if either has drifted, without writing
```

Wire `sync --check` into your validation workflow: a `deny.toml` edit that nobody re-synced
shows up as a failing check instead of silently shipping a stale `.cargo/audit.toml` or
`about.toml`.

## `prune`

```
jci-audit prune [OPTIONS]

Options:
      --check       Fail (non-zero) when a stale ignore is found. For CI
```

Stale-ignore detector. Runs the audit tools from **outside** the workspace (so no local
`.cargo/audit.toml` is discovered) against a **naked** advisory-db, and reports every configured
ignore in `deny.toml [advisories].ignore` that no longer fires — the advisory got a fix release,
the dependency was dropped, or the advisory was withdrawn. A suppression that no longer fires is
dead weight that quietly widens the policy.

```bash
jci-audit prune           # report stale ignores
jci-audit prune --check   # CI: exit 1 if any are found
```

Run this on a schedule (not just on PRs) — an ignore can go stale without any change to your own
repository, purely because upstream state moved.

## `verify`

```
jci-audit verify --release-version <VERSION> [OPTIONS]

Options:
      --release-version <VERSION>  The released version to verify (required)
      --advisory-db <ADVISORY_DB>  Advisory-db root [default: ~/.cargo/advisory-db]
      --deny-warnings               Fail if the tools report any warning
```

Re-verifies a past release's `.security/release-<VERSION>.json` record against a real checkout:
recomputes the dependency-set digest, the `deny.toml` (and, schema ≥4, `about.toml`) policy
digests, and re-runs `cargo deny --offline` against the record's pinned advisory-db commit. See
[design.md §5.3](design.md#53-verify-closing-the-loop) for exactly what "verified" vs
"unverified" vs "mismatch" mean, and
[advanced-configuration.md](advanced-configuration.md#troubleshooting-a-verify-mismatch) if a
verification comes back with a mismatch.

**Run this from a checkout of the released tag** — it reads the current working tree, not the
tag's tree, so verifying against the wrong checkout will report a false mismatch.

```bash
git checkout jci-audit-v1.2.0
jci-audit verify --release-version 1.2.0
```

## `init`

```
jci-audit init [OPTIONS]

Options:
      --force       Overwrite existing files without confirmation
```

Scaffolds a standard `deny.toml` (see [configuration-guide.md](configuration-guide.md) for what
each section means) plus the `.cargo/audit.toml` derived from it. Refuses to overwrite an
existing `deny.toml` unless `--force` is given. Non-interactive — every value in the template is
fixed; edit the written `deny.toml` afterwards for anything project-specific (license
exceptions, additional advisory ignores).

```bash
jci-audit init            # refuses if deny.toml already exists
jci-audit init --force    # overwrite
```
