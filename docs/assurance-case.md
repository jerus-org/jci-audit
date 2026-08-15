<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Security Assurance Case

This document is the project's **assurance case**: a structured argument, with
supporting evidence, that jci-audit is adequately secure for its intended use. It
states the security requirements, the threat model, the secure-design principles
applied, and how inputs and cryptography are handled. It complements the reporting
process in [`SECURITY.md`](../SECURITY.md).

## 1. What the software is and does

jci-audit is a **context-aware security gate** for Rust projects. It orchestrates two
independently maintained tools — `cargo audit` (live RustSec advisories) and
`cargo deny` (policy enforcement: advisories, bans, licenses, sources) — as
subprocesses, using each for what it is best at rather than reimplementing either:

1. **`jci-audit check`** — PR/dev gate: `cargo deny` policy checks and a live
   `cargo audit` scan, both blocking (`src/check.rs`).
2. **`jci-audit release`** — release gate: locks `cargo deny` to a **pinned advisory-db
   commit** and runs it offline for reproducibility; `cargo audit` runs live as a
   non-blocking currency check; writes the release record locally (`src/release.rs`).
3. **`jci-audit sync`** — derives `.cargo/audit.toml` and every crate's `about.toml`
   from the canonical `deny.toml`, merging into (not overwriting) hand-authored
   content (`src/sync.rs`, `src/license_scope.rs`).
4. **`jci-audit prune`** — detects advisory ignores that no longer fire against the
   live database (`src/prune.rs`).
5. **`jci-audit verify`** — re-derives a past release's inputs from a checkout and
   compares them against the recorded snapshot (`src/verify.rs`).
6. **`jci-audit init`** — scaffolds a standard `deny.toml` template (`src/init.rs`).

It runs on a developer workstation or in CI. It is **not** a network service and has
no users, sessions, or stored credentials of its own.

## 2. Security requirements

The security objectives, in priority order, are:

- **R1 — No arbitrary code execution surface.** The tool must only ever invoke its
  own fixed set of dependency binaries (`cargo-audit`, `cargo-deny`, `cargo-about`,
  `cargo`), never a caller- or config-supplied program.
- **R2 — Protection of credentials.** Any signing key or token the tool is given
  access to must never be leaked into generated files, logs, or the repository. No
  code path currently reads a credential at all (see T3); this stays a live
  requirement for when [#75](https://github.com/jerus-org/jci-audit/issues/75)
  reintroduces signing.
- **R3 — Reproducibility of release validation.** A release's pass/fail result must
  be re-derivable later from the same recorded inputs (advisory-db commit, policy
  digest, dependency-set digest), not just asserted once and trusted forever.
- **R4 — Integrity of derived files.** `.cargo/audit.toml` and `about.toml` must
  accurately reflect `deny.toml`'s policy, scoped correctly to what each crate's
  dependency graph actually ships — an over- or under-claiming derived file is a
  correctness *and* security defect (see R3's cousin: reproducible, but wrong).
- **R5 — Supply-chain integrity of jci-audit itself.** Its own dependencies must be
  pinned, monitored, and free of known vulnerabilities to the extent practical.
- **R6 — Safe failure.** When a required tool is missing, inputs are malformed, or
  the environment is misconfigured, the tool must fail loudly and actionably rather
  than silently no-op or produce a false pass.

## 3. Trust boundaries and assumptions

| Boundary | Trusted? | Assumption |
|----------|----------|------------|
| The **`cargo-audit`/`cargo-deny`/`cargo-about`/`cargo` binaries** invoked | Trusted, fixed | Always one of these four fixed names, resolved from `PATH`; never a config- or argument-supplied program (unlike a generic "run this binary" tool — see R1). |
| The **`deny.toml` policy** | Trusted | Authored and reviewed by the repository owner; canonical source for both advisory ignores and license policy. |
| **The RustSec advisory-db** | Semi-trusted, pinned | `release`/`verify` lock to a specific commit for reproducibility rather than trusting whatever the live clone contains at run time. |
| **Third-party crates** (jci-audit's own dependencies) | Semi-trusted | Pinned via `Cargo.lock`; monitored — see R5/T4. |
| **The network** (advisory-db fetch, managed by `cargo-deny` itself) | Untrusted transport | Confidentiality/integrity via TLS; see T5. jci-audit's own code makes no network calls of its own at present. |

## 4. Threat model

| ID | Threat | Mitigation |
|----|--------|------------|
| **T1** | **Arbitrary code execution via a caller-controlled program name.** | Does not apply the way it would to a tool that executes a user-supplied binary: every `Command::new(...)` call in the codebase names one of the four fixed tool binaries (`preflight::Tool`), with arguments passed as a typed `&[&str]` list, never shell-interpolated. There is no configuration surface that substitutes a different program. |
| **T2** | **Tampering with generated/derived files** (`.cargo/audit.toml`, `about.toml`). | Derivation is a **merge** via `toml_edit` (`sync::merge_about_toml`, `sync::render_audit_toml`) that only touches keys attributable to `deny.toml`'s policy, leaving hand-authored content (comments, `.clarify` attribution) untouched. `sync --check` fails on drift rather than silently rewriting. Generated output is always reviewed in a diff before commit, same discipline as any generated file in this org. |
| **T3** | **Credential leakage** — a signing key or token exposed in output, logs, or generated files. | No code path in jci-audit currently reads any credential — the release record is written locally and left there; nothing is signed, committed, or pushed by the tool itself. Trivially satisfies R2 for now. When [#75](https://github.com/jerus-org/jci-audit/issues/75) reintroduces signing (for the record's distribution as a release asset), this entry gets a real mitigation to describe again, not just an absence. |
| **T4** | **Supply-chain compromise** — a malicious or vulnerable dependency of jci-audit itself. | `Cargo.lock` is committed; `cargo-audit` and `cargo-deny` (advisories, bans, licenses, sources) run in this project's own CI; `deny.toml` is the single source of truth for both advisory ignores and license policy (`sync`); Renovate keeps dependencies current; sources are restricted to crates.io. Satisfies R5. |
| **T5** | **Man-in-the-middle on advisory-db network operations.** | The advisory-db clone (managed by `cargo-deny`, not jci-audit's own code) goes over HTTPS with TLS certificate verification enabled by default. |
| **T6** | **A stale or forged release record** — claiming a release passed validation when it did not, or when the environment has since drifted. | `jci-audit verify` independently re-derives all three recorded inputs from a real checkout — the dependency-set digest, the `deny.toml` policy digest (and, since schema 4, the `about.toml` policy digest), and the advisory-db commit — and re-runs `cargo-deny --offline` against that pinned commit, rather than trusting the record's stored verdict at face value. The record itself is not currently signed (see T3) — its integrity today rests on the CI pipeline that produced it, not on a cryptographic attestation; [#75](https://github.com/jerus-org/jci-audit/issues/75) tracks closing that gap. Partially satisfies R3. |
| **T7** | **Incorrect derived license scope** — `about.toml` claiming a license is in use (or omitting one) that the crate's actual dependency graph does not (or does) carry. | `license_scope` computes the crate-scoped set from `cargo metadata --all-features`'s real dependency graph (excluding dev-only edges, matching `about.toml`'s own `ignore-dev-dependencies`) and evaluates each reachable package's SPDX expression with the `spdx` crate — the same library `cargo-deny` itself uses internally — rather than copying the workspace-wide allow-list verbatim into every crate. Satisfies R4. |
| **T8** | **Malformed input causing an incorrect (especially a false-pass) result.** | Tool subprocess output is parsed as structured JSON (`serde_json`) or via `toml_edit`'s typed document model, not by pattern-matching raw text; a missing/absent value is an explicit unrecognised-shape error rather than a default "pass". Every subcommand that shells out runs `preflight::ensure_available` first, so a missing tool fails loudly instead of silently no-opping (R6). |

## 5. Secure-design principles applied

- **Fixed, minimal execution surface.** The tool never executes a caller-supplied
  program — only its own four named dependency binaries, resolved from `PATH`. This
  is a materially smaller attack surface than a general-purpose "run this and parse
  its output" design.
- **Least privilege.** The tool holds no ambient credentials, and currently reads
  none at all — see T3.
- **Defense in depth.** Reproducible release validation, an independent `verify`
  step, and drift-detecting `sync --check`/`prune` are independent controls, not a
  single point of assurance.
- **Fail safe / fail closed.** A missing tool, malformed policy, or drifted derived
  file is a hard, actionable error (`preflight`, `sync --check`), never a silent
  no-op or a default pass.
- **Economy of mechanism / no home-grown crypto.** SPDX license-expression
  evaluation is delegated to the `spdx` crate — the same one `cargo-deny` uses. jci-audit's
  own code currently performs no cryptographic operations of its own — see §7.
- **Complete mediation of output.** Derived files (`.cargo/audit.toml`, `about.toml`)
  and release records are always subject to review (diff, or `verify` after the
  fact) before or after they take effect.

## 6. Input validation

All external input is converted to typed, validated models before use:

- **CLI arguments** are parsed and validated by `clap`.
- **`deny.toml`** is parsed with `toml_edit` into a typed document; policy extraction
  (`extract_ignores`, `extract_license_policy`) reads known keys only.
- **`cargo metadata` / `cargo audit` / `cargo deny` JSON output** is parsed with
  `serde_json` into typed structures; unrecognised shapes are treated as errors, not
  defaulted.
- **SPDX license expressions** are parsed and evaluated by the `spdx` crate, not by
  ad-hoc string matching.
- Subprocess arguments are always a typed `&[&str]` list (see the `CommandRunner`
  trait in `src/check.rs`), never built by string concatenation or passed through a
  shell.

## 7. Cryptography posture

- **jci-audit's own code currently performs no cryptographic operations** — no
  signing, no credential handling, no network calls of its own (see T3). The one
  remaining transport-level touchpoint is TLS on the advisory-db fetch, which is
  entirely delegated to `cargo-deny`'s own HTTPS client, not code this project
  writes or controls.
- **This does not mean jci-audit *releases* are unsigned.** The crate's own tag,
  commit, and binary tarball are still GPG-signed and SLSA-attested exactly as
  documented in [`docs/RELEASING.md`](RELEASING.md) — that's a property of the
  release *pipeline* (`cargo-release` plus the CI configuration), independent of
  jci-audit's own runtime code. What changed here is narrower: the
  release *record* (the JSON file) is no longer signed as part of a git commit —
  see T3/T6 and [#75](https://github.com/jerus-org/jci-audit/issues/75).
- **No known-weak algorithms** are selected by the project; the one remaining
  algorithm choice (SPDX expression evaluation) is the `spdx` crate's, not a
  project-authored implementation.

## 8. Residual risk

- **Bus factor of one** (single maintainer) is a project-continuity risk, addressed
  by organisation-level ownership and documented processes in
  [`GOVERNANCE.md`](../GOVERNANCE.md).
- **Trust in the RustSec advisory-db and the wrapped tools themselves.** jci-audit's
  reproducibility guarantee covers *which* advisory-db commit and policy were used,
  not the correctness of `cargo-audit`/`cargo-deny`/`cargo-about`/the advisory-db's
  own content — those are out of this project's control (see `SECURITY.md`'s
  scope section).

This assurance case is reviewed when the threat surface changes materially (new
input sources, new network or credential handling, or new release mechanisms).
