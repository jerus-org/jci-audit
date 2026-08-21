<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Getting started with jci-audit

This guide takes you from installation to a working `check`/`release` gate for a Rust project.

## Install

```bash
cargo binstall jci-audit
```

Or build from source:

```bash
cargo install jci-audit
```

`jci-audit` orchestrates `cargo audit` and `cargo deny` as subprocesses rather than bundling
them — install both too:

```bash
cargo binstall cargo-audit cargo-deny
```

Every subcommand that shells out checks for these first and reports, with actionable install
guidance, if either is missing — see [preflight in the design doc](design.md#7-preflight-failing-loud-on-a-missing-tool).

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

## Run the PR/dev gate

```bash
jci-audit check
```

This runs `cargo deny check advisories bans licenses sources` (policy), a **live** `cargo audit`
scan (fresh RustSec advisories), and a check that `about.toml` still matches `deny.toml`'s
license policy — all three independently blocking, aggregated so a failure in one never hides
another. Wire this into your CI's validation workflow so every PR gets all three (see
[the user guide](user-guide.md#check) for what each one covers).

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
jci-audit release --release-version 1.2.0
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
jci-audit verify --release-version 1.2.0
```

Run this from a checkout of the released tag — see [the user guide](user-guide.md#verify) for
what it compares and what a mismatch means.

## Next steps

- [User guide](user-guide.md) — every subcommand in depth: flags, exit codes, what each does
  under the hood.
- [Configuration guide](configuration-guide.md) — `deny.toml` and `about.toml` field reference.
- [Advanced configuration](advanced-configuration.md) — the release record's current storage
  model, advisory-db overrides, and troubleshooting `verify` mismatches.
