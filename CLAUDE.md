# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository. It supplements the garden-level and global CLAUDE.md.

## Overview

**jci-audit** is a context-aware Rust security and license gate that orchestrates the
`cargo audit`, `cargo deny` and `cargo about` **binaries** (as subprocesses — it does not link
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
│   ├── main.rs             # crate doc + mod declarations, tracing setup
│   ├── cli.rs              # Cli + Commands, dispatch
│   ├── check.rs            # PR/dev gate: cargo-deny, cargo-audit, license drift/resolution/notices
│   ├── release.rs          # reproducible release gate (pinned advisory-db)
│   ├── verify.rs           # re-verify a past release against its recorded snapshot
│   ├── remote.rs           # verify's no-checkout fetch path (published release assets)
│   ├── publish_record.rs   # uploads the release record + signature as release assets
│   ├── sync.rs             # derive .cargo/audit.toml + about.toml from deny.toml
│   ├── license_scope.rs    # per-crate license-acceptance scope from cargo metadata
│   ├── exceptions.rs       # visibility for cargo-deny's [[bans.skip]] exceptions
│   ├── prune.rs            # stale-ignore detector
│   ├── init.rs             # scaffold or complete deny.toml + derived .cargo/audit.toml
│   ├── wire_ci.rs          # wire the published orb job(s) into a consumer's CI config
│   ├── preflight.rs        # tool-presence detection for cargo-audit/-deny/-about/rsign
│   ├── runtime.rs          # shared single-thread tokio runtime idiom
│   ├── diagnostics.rs      # summarises the warnings the underlying tools emit
│   └── fs_atomic.rs        # replace a file without leaving a partial one on disk
└── tests/cmd/*.trycmd      # CLI snapshot tests (trycmd)
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

## Git and pull requests

- Never commit to `main`. Branch from a freshly fetched `origin/main`, named
  `<type>/<description>` (`feat`, `fix`, `docs`, `chore`, `refactor`). A cloud
  session works on the branch it was given.
- Never merge, approve or close a pull request, including your own superseded
  ones: open it, return the URL, comment, and recommend closure.
- Stop and report before any commit, amend or push, and wait for "go",
  "commit and push" or "commit and pr". After a review or fixes, apply them
  locally, then stop.
- Stage explicit paths; never `git add -A`.
- Before pushing to a branch that has a PR, check the PR's state: it may have
  been merged. A `[new branch]` line on push means a merged branch was
  re-created.
- One PR at a time per workpackage: wait for the merge before starting the next
  unless told otherwise.
- Never force-push a Renovate branch. A fix needed only because of a Renovate
  update goes on that PR's branch as a new commit.
- Prefer merge commits to squash, to keep attribution.

## Commits

- Conventional Commits, subject under 50 characters, `git commit -s` for the
  DCO sign-off. Commits are also GPG-signed as the agent's GitHub account, never
  as the generic `noreply@anthropic.com` identity: pcu's verifier cannot tie
  that address to a known operator and rejects it. Run
  `.claude/hooks/agent-signing.sh` at the start of a session and check
  `git var GIT_AUTHOR_IDENT` before the first commit; see
  `.claude/hooks/README.md` for the environment variables and the security
  rules for the dedicated environment.
- A commit made with Claude Code carries these trailers before the sign-off:

  ```
  Generated-by: claude-code/<version> (model: <model-id>; operator: <operator-email>)
  Claude-Session: <session-url>
  ```

  `<version>` is `claude --version`, `<model-id>` the model serving the session,
  `<operator-email>` the person directing it.
- Never write the literal CI-skip token in a commit or PR message.

## Rust work

- **RED/GREEN TDD** for all Rust work, features, fixes and refactors: write the
  failing test, show it fail, then make it pass. Write characterisation tests
  before refactoring and mutation-check them.
- `#[cfg(test)]` modules at the END of each file, with the existing ones. Tests
  that spawn git run with `GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1`
  and give fixtures their own identity.
- **Edition 2024**, MSRV **1.91** — set by `pcu-release-assets`'s own floor, not
  by edition 2024 (whose floor is 1.85). `rust-version` is the genuine minimum;
  do not contort code to protect a low MSRV. Verify with `just msrv` before every
  PR that changes deps/`Cargo.lock`; keep `rust-version`, `min_rust_version` in
  `.circleci/config.yml`, and the `Rust 1.91+` README badges (both `README.md`
  and `crates/jci-audit/README.md`) in lockstep. `toolkit/msrv_verify` also
  gates this in CI (jerus-org/jci-audit#222) — `toolkit/common_tests`'s rolling
  toolchain alone can't catch a floor bump.
- Before a PR, on every Rust PR even config-only ones, run what CI runs (read
  `.circleci/config.yml`): `just fmt` (nightly rustfmt via
  `rustfmt-nightly.toml`, then the stable check; revert drift onto unrelated
  files), `just clippy`, `just test`, `just audit`, and `just msrv` when deps or
  `Cargo.lock` changed. Re-run the format check after any edit. A new advisory
  can fail a PR that touches no Rust.
- Run `/code-review` once per PR, on the final diff, before the commit. Report
  the findings and stop. Comment-only or docs-only PRs skip it.
- Workspace `release.toml` uses `consolidate-commits = false` — crates release
  individually in a chosen dependency order.
- Tag prefixes: crate `jci-audit-v<VERSION>`, workspace `v<VERSION>`.
- `THIRD-PARTY-LICENSES.md` is refreshed at release time; drift between
  releases is expected and not a PR concern.

## Working practice

- Fix the root cause, not the symptom. Age is not evidence of soundness.
- An advisory ignore in `deny.toml` needs a written justification, a link to
  the upstream tracking issue, and the condition for removing it. Prefer
  removing the dependency to ignoring the advisory.
- File a follow-up as an issue as soon as it is found, labelled `investigate`,
  with the evidence, why it was deferred, the options and a recommendation. One
  item per issue. Security findings are the exception: see the next rule.
- Report a security finding (a way around a check, an exposed or over-broad
  credential, a gap in verification) privately, never in a public issue, PR
  text, comment, doc or commit message. Say nothing public about it, not even
  that one exists: a placeholder or "moved to a private report" note also draws
  attention. If unsure whether something is a security finding, treat it as one.
- Private routes, in order: the repository's private vulnerability reporting
  (Security tab, "Report a vulnerability"); when the session cannot reach it
  (the session proxy blocks writes to that API), write a report file (title,
  severity, description), send it to the user in the same turn with the
  file-delivery tool, and log it as an issue in the private findings repository
  `jerus-org/security-findings` (attach it with `add_repo`, push access),
  assigned to `jerusdp`. That repository is for trusted agents only;
  `SECURITY.md` never mentions it. Highlight the finding strongly in the chat
  until the user has filed it.
- Show a CI gate working, not just an explanation: reintroduce the failure,
  watch it fail, then revert.
- Comments state only the rule a reader cannot infer from the code, and
  describe current behaviour only. History belongs in commits, PRs and issues.
- Published text (PRs, issues, docs) uses placeholders, not real bot or user
  identities. Policy files that need real identifiers are the exception. Never
  print a token or key.
- Use the Context7 connector (`resolve-library-id`, `query-docs`) for library
  documentation when it is available.

## CI/CD

CircleCI, 3-file model (`.circleci/{config.yml,release.yml,update_prlog.yml}`)
on `jerus-org/circleci-toolkit` (version pinned in those files, bumped by
Renovate). The `gen-circleci-orb`-managed regions and the `orb-release` workflow
are edited via the generator, never by hand. Release calculates versions before
an approval gate, then `toolkit/release_crate` + `toolkit/release_prlog`.
