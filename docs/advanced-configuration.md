<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Advanced configuration

Less common configuration: how the release record is stored today, overriding the
advisory-db location, and troubleshooting a `verify` mismatch. See
[configuration-guide.md](configuration-guide.md) for the subset of `deny.toml`/`about.toml`
fields jci-audit interacts with, and [user-guide.md](user-guide.md) for every subcommand's
basic flags.

## How the release record is stored and distributed

`jci-audit release-prep` writes `.security/release-<VERSION>.json` to the working directory and
does nothing else with it there — no git commit, no push, no signing. `.security/*.json` is
`.gitignore`'d, so `cargo-release`'s dirty-tree check is unaffected by the write. A subsequent job
needs the record handed to it explicitly to do anything durable with it.

`jci-audit publish-record` is that handoff: it signs the record with a one-use minisign keypair
and uploads the record/`.sig`/`.pub` as named assets on the release, before (optionally,
with `--publish`) un-drafting it. `verify`'s remote-fetch path then fetches and signature-checks
that record with no local checkout at all. See [RELEASING.md](RELEASING.md#what-is-signed) for
what's signed and how, and [design.md §3.2](design.md#32-release-gate) for the write-time flow.

## Overriding the advisory-db location

`release-prep` and `verify` both accept `--advisory-db <PATH>`, and both treat it the same way: it's
the advisory-db **root** (not a specific checkout), passed straight through to `deny.toml`'s
`[advisories].db-path` — the directory beneath which `cargo-deny` nests its own managed checkout
as `advisory-db-<hash>`. Default `~/.cargo/advisory-db`.

- **`release-prep`** discovers/refreshes that checkout and pins the release to its resulting commit.
- **`verify`** discovers the existing checkout beneath the given root and moves it to the commit
  recorded in `.security/release-<VERSION>.json`.

Pointing either flag at a specific pre-checked-out commit directory (rather than its parent) is
a common mistake — you'll see `no advisory-db checkout found under '<path>'`, since jci-audit is
looking one level down for the `advisory-db-<hash>` subdirectory. Override the flag when your CI
caches the advisory-db root somewhere other than the default, to avoid a redundant clone.

## `--deny-warnings`

Present on `check`, `release-prep`, and `verify`. `cargo-deny` reports some conditions (e.g.
`unmaintained = "all"`) as warnings rather than hard errors by default. Pass `--deny-warnings` to
escalate every warning to a failure — useful for a stricter branch policy or a scheduled run
where warnings shouldn't be allowed to silently accumulate. Without it, warnings are still
surfaced (counted and printed) but don't affect the exit code.

## Troubleshooting a `verify` mismatch

`jci-audit verify <V>` prints one line per input it couldn't verify or that
didn't match, then a final verdict. On success (an old-schema record can still print `not
verified` notes and pass):

```
verifying release 1.2.0 against advisory-db <commit>
  not verified: <schema too old to check this input>
reproduced: the release passes the gate against its recorded snapshot
```

On a real mismatch, verification fails instead — no `reproduced` line is printed once any
`MISMATCH` is found:

```
verifying release 1.2.0 against advisory-db <commit>
  MISMATCH: <what didn't match>
Error: verification failed: inputs do not match the record
```

- **`not verified` lines** are not failures — they mean the record predates that field (e.g. a
  `schema_version: 1` record has no `deny.toml` policy digest to compare) and are reported
  honestly rather than silently skipped or treated as a pass. See
  [design.md §5.2](design.md#52-record-schema-schema_version-4) for the schema version history.
- **`MISMATCH` lines** mean something genuinely differs between the record and the checkout.
  Common causes, in order of likelihood:
  1. **Wrong checkout.** `verify` reads the *current working tree*, not the tag's tree — if you
     didn't `git checkout jci-audit-v<VERSION>` first, a dependency-set or policy mismatch is
     expected, not a real problem. Check out the exact tag and re-run.
  2. **`Cargo.lock` changed since release** (a manual edit, or a lockfile-maintenance commit
     landed on the wrong branch). The dependency-set digest covers the *external* package set
     (not the crate's own version, which the release commit legitimately rewrites) — so this
     means a real third-party dependency actually differs from what was released.
  3. **`deny.toml`/`about.toml` changed since release** without a new release being cut. The
     policy that's currently in force differs from what was validated at release time.

If everything above checks out and you still see a `MISMATCH`, treat it as a real finding — it
means the released artifact no longer matches what its own record says was validated.

**A separate failure mode prints no `MISMATCH` line at all**: if the advisory-db commit the
record pins to is unreachable (garbage-collected, or the checkout was never made), `verify` fails
outright — before the `verifying release...` banner or any comparison output prints — with its
own top-level error rather than a `MISMATCH`. Re-fetch the advisory-db (`cargo deny fetch`, or
just re-run `jci-audit check`/`release-prep` once to let cargo-deny refresh it) and retry.

## Multi-crate workspaces

`sync`'s `about.toml` derivation already scopes each crate's `accepted` list to its own
dependency graph (see [design.md §4.2](design.md#42-abouttoml--a-per-crate-spdx-aware-derivation)),
and honours that crate's own `about.toml` `ignore-build-dependencies`/`ignore-transitive-dependencies`
settings. `release-prep`/`verify` take a `-p`/`--package <NAME>` selector to scope the dependency
digest and record path to one crate at a time, for a workspace releasing crates individually in
dependency order. `publish-record` and `verify`'s remote-fetch path don't take a per-package
record path yet — point `--record-path` at the right file explicitly if you're publishing records
for more than one crate from the same pipeline.
