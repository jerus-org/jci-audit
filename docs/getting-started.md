<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Getting started with jci-audit

This guide takes you from installation to a working `check`/`release-prep` gate for a Rust project.

## Install

```bash
cargo binstall jci-audit
```

Or build from source:

```bash
cargo install jci-audit
```

`jci-audit` orchestrates `cargo audit`, `cargo deny`, and `cargo about` as subprocesses rather
than bundling them — install all three:

```bash
cargo binstall cargo-audit cargo-deny cargo-about
```

`cargo-about` is only needed for `check`'s license-notices resolution/staleness checks — skip it
if you only run `sync`, `prune`, or `init`. Every subcommand that shells out to one of these tools
checks for it first and reports, with actionable install guidance, if it's missing — see
[preflight in the design doc](design.md#7-preflight-failing-loud-on-a-missing-tool).

## Scaffold a policy with `init`

`init` writes a standard `deny.toml` (advisories, licenses, bans, sources) plus the
`.cargo/audit.toml` derived from it, into the current directory:

```bash
jci-audit init
```

It refuses to overwrite an existing `deny.toml` unless you pass `--force`. The template denies
all licenses except an explicit allow-list, and leaves `[advisories].ignore` empty — see
[the configuration guide](configuration-guide.md) for what each section means and how to extend
it (e.g. admitting a weak-copyleft license for one specific dependency).

`init` only writes `deny.toml`/`.cargo/audit.toml` — it doesn't touch your CI config. Wiring
`jci-audit check` into your pipeline is `wire-ci`'s job, next.

## Wire the orb into your CI config

```bash
jci-audit wire-ci
```

Writes (or resyncs) the `jerus-org/jci-audit` orb job(s) declared in `jci-audit.toml`'s `[ci]`
table into your `.circleci/config.yml`. On a project with no `jci-audit.toml` yet, the first run
scaffolds one with a single example `jci-audit/check` job in a `validation` workflow — review and
adapt it by hand (add `release-prep`/`sync`/`prune` jobs, change the workflow name, tune params),
then re-run `wire-ci` to apply what you edited. It's local/human-only: run it, review the diff,
and commit the result.

```bash
jci-audit check-ci-wiring
```

The CI-facing counterpart — fails (non-zero) on drift between `jci-audit.toml` and what's actually
in `.circleci/config.yml`, and never writes either file. Add it to your validation workflow so a
hand-edit to the managed CI region, or an orb version bump, gets caught before `wire-ci` needs to
be re-run by hand.

## Run the PR/dev gate

```bash
jci-audit check
```

This runs `cargo deny check advisories bans licenses sources` (policy), a **live** `cargo audit`
scan (fresh RustSec advisories), a check that `about.toml` still matches `deny.toml`'s license
policy, and a check that `cargo-about` can resolve every dependency's license — all four
independently blocking, aggregated so a failure in one never hides another. A fifth, opt-in check
(`--deny-stale-notices`) only fails if a dependency's license set actually grew (a license
substituted or added); a version bump or a new dependency under an already-accepted license warns
instead. Wire this into your CI's validation workflow (via `wire-ci` above) so every PR gets all
of it (see [the user guide](user-guide.md#check) for what each check covers).

## Keep derived files in sync

`.cargo/audit.toml` and every crate's `about.toml` (if you use [`cargo-about`](https://github.com/EmbarkStudios/cargo-about)
for license notices) are **derived** from `deny.toml` — never hand-edit them:

```bash
jci-audit sync             # regenerate
jci-audit sync --check     # CI: fail instead of writing, if they've drifted
```

Add `sync --check` to your validation workflow so a hand-edit to either derived file — or a
`deny.toml` change nobody re-synced — surfaces as a failing check.

## Run the release gate

Once you're ready to cut a release:

```bash
jci-audit release-prep 1.2.0
```

This locks `cargo-deny` to a **pinned advisory-db commit** and runs it offline for
reproducibility, then runs a **live** `cargo audit` as a non-blocking currency check (PRs already
gate on live audit results continuously, so this is informational, not re-pinned), and writes
`.security/release-1.2.0.json` — a record of exactly what was checked. See
[the design doc §5](design.md#5-reproducibility-the-release-record) for why this is reproducible
and what the record contains, and [RELEASING.md](RELEASING.md) if you also want the record
committed and signed as part of your release pipeline.

To confirm a past release still checks out against what's on disk today:

```bash
jci-audit verify 1.2.0
```

Run this from a checkout of the released tag — see [the user guide](user-guide.md#verify) for
what it compares and what a mismatch means.

## Next steps

- [User guide](user-guide.md) — every subcommand in depth: flags, exit codes, what each does
  under the hood.
- [Configuration guide](configuration-guide.md) — the `deny.toml`/`about.toml` fields
  jci-audit interacts with.
- [Advanced configuration](advanced-configuration.md) — the release record's current storage
  model, advisory-db overrides, and troubleshooting `verify` mismatches.
