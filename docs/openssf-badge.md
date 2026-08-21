<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# OpenSSF Best Practices — criterion → evidence

Working sheet for completing the [OpenSSF Best Practices Badge](https://www.bestpractices.dev/projects/14065)
questionnaire (project **14065**), targeting at least **Silver**. Silver requires the **Passing**
badge first, so both levels are mapped below.

Status key: **Met** · **N/A** (not applicable, with justification) · **Met (justified SHOULD gap)**.

Repository paths are relative to the repo root; the primary crate is `crates/jci-audit/`.

## Passing level

### Basics
| Criterion | Status | Evidence |
|-----------|--------|----------|
| description_good | Met | `README.md` / crate `README.md` overview — states what it does and the problem solved |
| interact | Met | Crate `README.md` (install, Contributing section links to issues + `CONTRIBUTING.md`) |
| contribution | Met | `CONTRIBUTING.md` — PR workflow |
| contribution_requirements | Met | `CONTRIBUTING.md` — coding standards, testing policy, DCO |
| floss_license | Met | Dual **MIT OR Apache-2.0** |
| floss_license_osi | Met | Both licenses are OSI-approved |
| license_location | Met | `LICENSE-MIT` / `LICENSE-APACHE` at repo root **and** crate dir, plus `LICENSES/` (SPDX REUSE convention — the auto-detector's `license_location` check does not recognise the Rust-convention `LICENSE-APACHE`/`LICENSE-MIT` naming, but does recognise a top-level `LICENSES/` dir) |
| documentation_basics | Met | `README.md`, `docs/architecture.md`, `docs/design.md` |
| documentation_interface | Met | Crate README Usage section (all six subcommands) + `--help` |
| sites_https | Met | GitHub and crates.io both serve over HTTPS/TLS (no docs.rs page — jci-audit is bin-only, [#90](https://github.com/jerus-org/jci-audit/issues/90)) |
| discussion | Met | GitHub Issues — searchable, URL-addressable, open participation |
| english | Met | All documentation is in English |
| maintained | Met | Active development (recent commits, releases, Renovate) |

### Change control
| Criterion | Status | Evidence |
|-----------|--------|----------|
| repo_public | Met | `https://github.com/jerus-org/jci-audit` |
| repo_track | Met | Git records author/date/change |
| repo_interim | Met | Full commit history + merged PRs, not only releases |
| repo_distributed | Met | Git |
| version_unique | Met | SemVer versions + `jci-audit-v*` tags |
| version_semver | Met | SemVer — declared in `PRLOG.md` / crate `CHANGELOG.md` |
| version_tags | Met | Signed `jci-audit-v*` git tags |
| release_notes | Met | `PRLOG.md` (workspace) + `crates/jci-audit/CHANGELOG.md` |
| release_notes_vulns | Met | `SECURITY.md` documents the `security:` commit convention → CHANGELOG **Security** section + advisory id in PR title → PRLOG. No CVE-assigned vulns fixed to date |

### Reporting
| Criterion | Status | Evidence |
|-----------|--------|----------|
| report_process | Met | GitHub Issues + `.github/ISSUE_TEMPLATE/` |
| report_tracker | Met | GitHub Issues |
| report_responses | Met | Maintainer responds to issues (see issue history) |
| enhancement_responses | Met | Enhancement issues triaged into `ROADMAP.md` (e.g. #62, #63) |
| report_archive | Met | GitHub Issues public archive |
| vulnerability_report_process | Met | `SECURITY.md` |
| vulnerability_report_private | Met | GitHub **private** Security Advisories (Security tab) |
| vulnerability_report_response | Met | `SECURITY.md` commits to acknowledge within **3 business days** (≤14 days) |

### Quality
| Criterion | Status | Evidence |
|-----------|--------|----------|
| build | Met | `cargo build` (workspace) |
| build_common_tools | Met | Cargo |
| build_floss_tools | Met | Rust/Cargo toolchain is FLOSS |
| test | Met | `cargo test --all` (incl. `--test cli_tests`); how-to in `CONTRIBUTING.md` / `justfile` |
| test_invocation | Met | `cargo test` (standard) |
| test_most | Met | **89.27% line coverage** (`cargo llvm-cov --all-features --summary-only`) |
| test_continuous_integration | Met | CircleCI on every PR |
| test_policy | Met | `CONTRIBUTING.md` — testing policy (RED/GREEN TDD) |
| tests_are_added | Met | Every PR adds tests (RED/GREEN TDD, enforced by convention and PR template) |
| tests_documented_added | Met | `CONTRIBUTING.md` + `.github/PULL_REQUEST_TEMPLATE.md` tests checklist |
| warnings | Met | Clippy + compiler warnings |
| warnings_fixed | Met | CI + `just clippy` run `-D warnings` (zero warnings) |
| warnings_strict | Met | `cargo clippy --all --tests --all-features -- -D warnings`, `RUSTDOCFLAGS="-D warnings"` |

### Security
| Criterion | Status | Evidence |
|-----------|--------|----------|
| know_secure_design | Met | `docs/assurance-case.md` §5 (secure-design principles) |
| know_common_errors | Met | `docs/assurance-case.md` §4 (8-item threat model: fixed execution surface, derived-file tampering, credential leakage, supply chain, MITM, forged records, incorrect license scope, malformed input) |
| crypto_published | Met | Only published algorithms — GPG (release signing), Sigstore/minisign (attestation), TLS (crates.io/GitHub distribution) |
| crypto_call | Met | No home-grown crypto; delegates to GPG/Sigstore/`rsign`/`spdx` |
| crypto_floss | Met | All crypto via FLOSS libraries |
| crypto_keylength | Met | Defaults from the underlying libraries meet NIST minimums |
| crypto_working | Met | No broken algorithms selected |
| crypto_weaknesses | Met | No dependence on SHA-1/MD5 etc. |
| crypto_pfs | N/A | No key-agreement protocol implemented (delegated to TLS libs, which provide PFS) |
| crypto_password_storage | N/A | The tool stores no passwords |
| crypto_random | Met | No custom key/nonce generation; delegated to Sigstore/rsign (secure RNG) |
| delivery_mitm | Met | Distribution over HTTPS (crates.io, GitHub) |
| delivery_unsigned | Met | Releases are signed (GPG tags, SLSA/Sigstore, minisign); every step verified against a real release in `docs/RELEASING.md` |
| vulnerabilities_fixed_60_days | Met | `deny.toml [advisories].ignore` and the derived `.cargo/audit.toml` are both currently empty — no advisory is being suppressed |
| vulnerabilities_critical_fixed | Met | No known critical vulnerabilities outstanding |
| no_leaked_credentials | Met | Secrets come from CI env/contexts, referenced only by variable *name*; none in the repo (`docs/assurance-case.md` §3, §6) |

### Analysis
| Criterion | Status | Evidence |
|-----------|--------|----------|
| static_analysis | Met | Clippy + SonarCloud (`sonar-project.properties`) |
| static_analysis_common_vulnerabilities | Met | `cargo audit` (live) runs on every PR; `cargo-about` license-policy resolution runs on every PR (`licenses_policy` job); full `cargo deny` policy checks (bans/licenses/sources) run locally (`just audit`) and are enforced as a hard release gate (`jci-audit release`) — CI-time wiring of `jci-audit check` on every PR is tracked in `ROADMAP.md` (post-migration) |
| static_analysis_fixed | Met | Findings addressed; CI enforces |
| static_analysis_often | Met | Runs on every PR |
| dynamic_analysis | N/A | Memory-safe Rust; the only `unsafe` blocks are in test code (`std::env::set_var`/`remove_var`), none in production logic |
| dynamic_analysis_unsafe | N/A | Memory-safe language; no `unsafe` blocks outside tests |
| dynamic_analysis_enable_assertions | Met | Debug/test builds run with assertions enabled |
| dynamic_analysis_fixed | Met | None found to fix |

## Silver level

### Basics — project oversight & documentation
| Criterion | Status | Evidence |
|-----------|--------|----------|
| achieve_passing | Prerequisite | Complete the Passing level above first |
| dco | Met | `CONTRIBUTING.md` DCO section; commits use `git commit -s` |
| governance | Met | `GOVERNANCE.md` |
| code_of_conduct | Met | `CODE_OF_CONDUCT.md` (Contributor Covenant) |
| roles_responsibilities | Met | `GOVERNANCE.md` — roles table |
| access_continuity | Met | `GOVERNANCE.md` — access & continuity plan |
| bus_factor | Met (justified SHOULD gap) | Single maintainer; documented honestly in `GOVERNANCE.md` with mitigations (org ownership, automated processes) |
| documentation_roadmap | Met | `ROADMAP.md` (delivered phases + near/medium/long term) |
| documentation_architecture | Met | `docs/architecture.md` + `docs/design.md` |
| documentation_security | Met | `SECURITY.md` + `docs/assurance-case.md` |
| documentation_quick_start | Met | Root README "Quick start" section + crate README Installation/Usage sections |
| documentation_current | Met | Docs kept current with the release |
| documentation_achievements | Met | OpenSSF badge displayed in root + crate READMEs (project 14065) |
| accessibility_best_practices | N/A | Developer CLI; no GUI/web UI |
| internationalization | N/A | Developer CLI; English-only interface by design |
| sites_password_security | N/A | No site with user passwords |

### Change control
| Criterion | Status | Evidence |
|-----------|--------|----------|
| maintenance_or_update | Met | `SECURITY.md` supported-versions + upgrade path (latest `0.1.x`) |

### Reporting
| Criterion | Status | Evidence |
|-----------|--------|----------|
| report_tracker | Met | GitHub Issues |
| vulnerability_report_credit | Met | `SECURITY.md` credits reporters unless anonymity requested |
| vulnerability_response_process | Met | `SECURITY.md` response process + timelines |

### Quality
| Criterion | Status | Evidence |
|-----------|--------|----------|
| coding_standards | Met | `CONTRIBUTING.md` — rustfmt, Clippy, Conventional Commits, RED/GREEN TDD |
| coding_standards_enforced | Met | CI (`fmt`/`clippy`) + `just clippy -- -D warnings` |
| build_standard_variables | Met | Cargo honors `RUSTFLAGS`/`CC`/etc. |
| build_preserve_debug | Met | Cargo release/debug profiles preserve debug info as configured |
| build_non_recursive | Met | Cargo builds are non-recursive |
| build_repeatable | Met | `Cargo.lock` committed; digest-pinned CI images |
| installation_common | Met | `cargo install` / `cargo binstall` |
| installation_standard_variables | Met | Cargo honors `CARGO_INSTALL_ROOT` etc. |
| installation_development_quick | Met | `cargo build` / `just test` (see `CONTRIBUTING.md`) |
| external_dependencies | Met | `Cargo.toml` + `Cargo.lock` (machine-readable) |
| dependency_monitoring | Met | Renovate + `cargo-audit`/`cargo-deny` (the latter dogfooded on itself via `jci-audit release`) |
| updateable_reused_components | Met | Cargo dependencies, versioned |
| interfaces_current | Met | No deprecated APIs relied upon |
| automated_integration_testing | Met | CI runs the suite on every check-in |
| regression_tests_added50 | Met | `CONTRIBUTING.md` mandates a regression test per bug fix (RED/GREEN TDD); followed in practice |
| test_statement_coverage80 | Met | **89.27%** line coverage (`cargo llvm-cov --all-features`) |
| test_policy_mandated | Met | `CONTRIBUTING.md` testing policy |
| tests_documented_added | Met | `CONTRIBUTING.md` + PR template |
| warnings_strict | Met | `cargo clippy --all --tests --all-features -- -D warnings`, `RUSTDOCFLAGS="-D warnings"` |

### Security
| Criterion | Status | Evidence |
|-----------|--------|----------|
| implement_secure_design | Met | `docs/assurance-case.md` §5 (secure-design principles) |
| crypto_weaknesses | Met | No known-weak algorithms |
| crypto_algorithm_agility | Met | Algorithms provided by updatable libraries (GPG, Sigstore, `rsign`) |
| crypto_credential_agility | Met | The crate's own release signing reads its key material via CI-context env vars, rotatable without recompiling; `verify`'s remote path reads its one credential (a GitHub token) from `GITHUB_TOKEN` only — no CLI flag, no hardcoded value (`docs/assurance-case.md` T3) |
| crypto_used_network | Met | HTTPS by default (crates.io, GitHub, the advisory-db fetch delegated to `cargo-deny`); jci-audit's own code makes network calls only from `verify`'s remote path (GitHub REST/GraphQL + `raw.githubusercontent.com`), also over HTTPS (`docs/assurance-case.md` §7, T9) |
| crypto_tls12 | Met | TLS ≥1.2 via the underlying HTTPS clients (cargo, `cargo-deny`) |
| crypto_certificate_verification | Met | TLS certificates verified by default by the underlying HTTPS clients |
| crypto_verification_private | Met | Credentials only sent over verified HTTPS |
| signed_releases | Met | `docs/RELEASING.md` — GPG tags + SLSA/Sigstore attestation + minisign binary, with verification steps checked against a real release |
| version_tags_signed | Met | `release.toml` `sign-tag = true` |
| input_validation | Met | `docs/assurance-case.md` §6 — typed parsing of CLI args, TOML policy, JSON tool output, and SPDX expressions; no raw-text pattern matching |
| hardening | N/A | Developer CLI; no long-running network service to harden |
| assurance_case | Met | `docs/assurance-case.md` |

### Analysis
| Criterion | Status | Evidence |
|-----------|--------|----------|
| static_analysis_common_vulnerabilities | Met | SonarCloud + `cargo-audit` on every PR; `cargo-deny` at release time (see Passing-level note on CI-time wiring) |
| dynamic_analysis_unsafe | N/A | Memory-safe Rust; no `unsafe` outside test code |

## Notes for the questionnaire

- The bestpractices.dev URL for the project is **https://www.bestpractices.dev/projects/14065**.
  Work through the questionnaire using this document as the answer key.
- For `bus_factor` (Silver SHOULD), select the honest answer and reference `GOVERNANCE.md`, which
  records the single-maintainer limitation and its mitigations.
- N/A answers above each carry a one-line justification to paste into the questionnaire's rationale.
- The `static_analysis_common_vulnerabilities` answer is honest about a real, tracked gap: `cargo
  deny`'s bans/licenses/sources checks do not yet run on every PR, only locally and at release time.
  This does not block Silver (the criterion is about vulnerability-relevant static analysis, which
  `cargo audit` + SonarCloud already cover), but should be revisited once consumer migration wires
  `jci-audit check` into this repo's own CI.
