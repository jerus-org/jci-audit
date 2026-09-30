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
      --deny-stale-exceptions          Fail if a configured [[bans.skip]] exception no longer fires
      --deny-unused-licenses           Fail if deny.toml allows a license nothing in the graph uses
      --deny-stale-notices             Fail if the license set changed since the committed notices
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
   allow/exception combination.

Three more flags narrow cargo-deny's own warnings into their own blocking checks, so a repo can
require cleanup on just that one thing without failing on every unrelated warning:

- `--deny-stale-exceptions` — a configured `[[bans.skip]]` exception cargo-deny already reports
  as `warning[unmatched-skip]`/`warning[unnecessary-skip]`. Mirrors [`prune --check`](#prune).
- `--deny-unused-licenses` — a `deny.toml` allow-list entry nothing in the graph actually uses,
  reported as `warning[license-not-encountered]`.
- `--deny-stale-notices` — compares a fresh `cargo-about` render's license names against the
  committed `THIRD-PARTY-LICENSES.md`. Only fails if the set grew (a license substituted or
  added); a version bump or a new dependency under an already-accepted license warns instead,
  since this exists to catch a licensing change, not to keep the file byte-current.

`--deny-warnings` escalates every remaining warning (e.g. cargo-deny's `unmaintained = "all"`
scope, which reports as a warning rather than an error by default) to a failure too. Use this on
a schedule or a stricter branch policy where warnings shouldn't be allowed to accumulate silently.

```bash
jci-audit check                              # current directory
jci-audit check --manifest-path crates/foo   # a specific crate in a workspace
jci-audit check --deny-stale-notices         # also catch a licensing change early
jci-audit check --deny-warnings              # treat warnings as failures too
```

## `release-prep`

```
jci-audit release-prep <VERSION> [OPTIONS]

Arguments:
  <VERSION>  The release version being validated (e.g. "1.2.0")

Options:
      --advisory-db <ADVISORY_DB>  Advisory-db root; cargo-deny's checkout lives beneath it [default: ~/.cargo/advisory-db]
  -p, --package <PACKAGE>          The crate's package name — scopes the dependency digest and
                                     record path to just this crate's reachable graph. Omit for a
                                     single-crate workspace's whole-graph record
      --deny-warnings               Fail if the tools report any warning
```

The release gate. Locks `cargo-deny` to a **pinned advisory-db commit** and runs it offline for
reproducibility; `cargo-audit` always runs against the **live** database (PRs already gate on
it continuously via `check`), so at release time it only runs again as a non-blocking currency
check, not a second pinned/offline pass. Writes `.security/release-<VERSION>.json` to the working
directory — see [design.md §5](design.md#5-reproducibility-the-release-record) for exactly what
that record contains and why, and
[advanced-configuration.md](advanced-configuration.md#how-the-release-record-is-stored-and-distributed)
for how to sign and distribute it with `publish-record`.

For a CI pipeline that computes the version at runtime (e.g. via `nextsv`), pass it straight
through, e.g. `jci-audit release-prep "$SEMVER"`.

```bash
jci-audit release-prep 1.2.0   # validate and write the record locally
```

## `sync`

```
jci-audit sync [OPTIONS]

Options:
      --check       Fail (non-zero) on drift instead of rewriting the file. For CI
```

Derives `.cargo/audit.toml` (from `deny.toml`'s `[advisories].ignore`) and every workspace
member's `about.toml` `accepted` license list (from `deny.toml`'s `[licenses]` policy, scoped
to each crate's own dependency graph) — see
[design.md §4](design.md#4-the-sync-derivation) for the full derivation algorithm. Members are
found via `cargo metadata`, not an assumption about directory layout — `crates/*/` is this
project's own convention, not a requirement. Writing is a **merge**:
hand-authored content in `about.toml` (comments, `.clarify` attribution pins) is left untouched.

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
jci-audit verify <VERSION> [OPTIONS]

Arguments:
  <VERSION>  The released version to verify (required)

Options:
      --advisory-db <ADVISORY_DB>  Advisory-db root [default: ~/.cargo/advisory-db]
  -p, --package <PACKAGE>          The crate's package name — must match whatever
                                     `release-prep --package` (if any) the record was written under
      --owner <OWNER>               GitHub repository owner (remote-fetch fallback only)
      --repo <REPO>                 GitHub repository name (remote-fetch fallback only)
      --tag-prefix <TAG_PREFIX>     Release tag prefix (remote-fetch fallback only)
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
jci-audit verify 1.2.0
```

**With no local record** (no checkout, or a checkout whose `.security/` doesn't carry this
version), `verify` falls back to fetching the record and its signature from the published GitHub
release instead — see [design.md §5.4](design.md#54-verifying-without-a-checkout). That path
needs `--owner`/`--repo`/`--tag-prefix` to know which release to check:

```bash
jci-audit verify 1.2.0 \
  --owner some-org --repo some-repo --tag-prefix some-repo-v
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

`init` only writes the policy files above — it doesn't touch your CI config. Run [`wire-ci`](#wire-ci)
next to get `jci-audit check` actually running in your pipeline.

## `wire-ci`

```
jci-audit wire-ci [OPTIONS]

Options:
      --config <CONFIG>                  Path to the jci-audit.toml-shaped wiring spec to read
                                          (and, if it has no [[ci.jobs]] entries yet, scaffold an
                                          example into)
      --workflow <WORKFLOW>               First-run scaffold only: which workflow the example
                                          check job joins
      --deny-unused-licenses <true|false> First-run scaffold only: whether the example enables
                                          --deny-unused-licenses
      --deny-stale-exceptions <true|false> First-run scaffold only: whether the example enables
                                          --deny-stale-exceptions
      --deny-stale-notices <true|false>   First-run scaffold only: whether the example enables
                                          --deny-stale-notices
```

Writes (or resyncs) the `jerus-org/jci-audit` orb job(s) declared in `jci-audit.toml`'s `[ci]`
table into the CircleCI config named there (`.circleci/config.yml` by default). With no
`jci-audit.toml` yet, the first run scaffolds one with a single example `jci-audit/check` job —
review and adapt it by hand (add more jobs, rename the workflow, change params), then re-run
`wire-ci` to apply what you edited. Every run after that applies whatever `[[ci.jobs]]` currently
says, without rewriting entries you didn't touch. Local/human-only: run it, review the diff, and
commit the result.

The four flags above only shape that first-run scaffold, never an already-scaffolded
`jci-audit.toml`. With a terminal attached and nothing set, scaffolding **prompts** for the
workflow (offering any workflow names already declared in the target CircleCI config, alongside
`validation`) and each check flag, defaulting to this repo's own dogfooded example
(`validation`, `deny_unused_licenses`/`deny_stale_exceptions` on, `deny_stale_notices` off). In CI,
or with no terminal attached, it silently uses those same defaults instead of prompting — set the
flags explicitly there if you want something else.

```bash
jci-audit wire-ci                            # jci-audit.toml at the default location
jci-audit wire-ci --config path/to/jci-audit.toml
jci-audit wire-ci --workflow build --deny-stale-notices true   # non-interactive, e.g. in a script
```

## `check-ci-wiring`

```
jci-audit check-ci-wiring [OPTIONS]

Options:
      --config <CONFIG>  Path to the jci-audit.toml-shaped wiring spec to read. Same resolution
                          rules as `wire-ci --config`
```

The CI-facing counterpart to `wire-ci` — fails (non-zero) on drift between `jci-audit.toml` and
what's actually in the CircleCI config, and never writes either file: there is no flag to make it
write, so a workflow wiring this job in can't regress to write mode by mistake. Add it to your
validation workflow so a hand-edit to the managed CI region, or an orb version bump, gets caught
before `wire-ci` needs to be re-run by hand.

```bash
jci-audit check-ci-wiring
```

## `publish-record`

```
jci-audit publish-record [OPTIONS] --tag <TAG> --owner <OWNER> --repo <REPO> <VERSION>

Arguments:
  <VERSION>  The release version whose record to publish (e.g. "1.2.0")

Options:
      --tag <TAG>            The exact release tag to attach assets to (e.g. "myapp-v1.2.0")
      --owner <OWNER>        GitHub repository owner that owns the release
      --repo <REPO>          GitHub repository name that owns the release
      --publish              Un-draft the release once the assets are attached
      --record-path <PATH>   Where to find the record to sign and upload
```

Self-contained: generates a one-use minisign keypair, signs a `release-prep`-written record, and
uploads the record/`.sig`/`.pub` as assets on the given release tag — the source `verify`'s
remote-fetch path fetches from later. The private key never leaves this one invocation. Needs a
`GITHUB_TOKEN` environment variable with permission to upload (and, with `--publish`, publish) the
release — read from the environment only, never a CLI flag, so it can't end up in a command line
or CI log.

```bash
GITHUB_TOKEN=... jci-audit publish-record 1.2.0 \
  --tag myapp-v1.2.0 --owner your-org --repo your-repo \
  --record-path .security/release-1.2.0.json --publish
```
