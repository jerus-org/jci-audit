//! The PR / dev gate: run cargo-deny policy checks, a live cargo-audit scan,
//! the about.toml/deny.toml license-policy drift check, and the cargo-about
//! license-policy resolution check, all blocking.
//!
//! `cargo deny` enforces policy (advisories, bans, licenses, sources) with the
//! justified, file-based ignores in `deny.toml`; `cargo audit` adds a fresh
//! scan against the live RustSec database; the drift check confirms each
//! crate's `about.toml` still reflects `deny.toml`'s license policy — a pure
//! derivation, the same one `jci-audit sync --check` performs, no
//! `cargo-about` invocation needed. The resolution check is a separate,
//! independent question: given what's on disk right now, can `cargo-about`
//! actually attribute every reachable dependency's licence? (see issue #80 —
//! previously only `release-prep` caught this, at the most expensive point in
//! the pipeline). All four run — exit codes are **aggregated**, not
//! short-circuited, so one failing check never hides another's findings —
//! and each tool's stderr is surfaced (per the CI-diagnostics discipline:
//! never swallow the output of a tool whose result drives a decision).

use std::{path::Path, process::Command};

use anyhow::{Context, Result};

use crate::sync;

/// The captured result of running one external tool. Modelled instead of
/// `std::process::Output` so orchestration is testable without constructing a
/// platform-specific `ExitStatus`.
#[derive(Debug, Clone)]
pub(crate) struct ToolOutput {
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// Abstraction over running an external command, so the check orchestration is
/// unit-testable with a mock in place of real cargo subcommands.
pub(crate) trait CommandRunner {
    fn run(&self, program: &str, args: &[&str], cwd: &Path) -> Result<ToolOutput>;
}

/// Runs commands as real subprocesses.
pub(crate) struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[&str], cwd: &Path) -> Result<ToolOutput> {
        let output = Command::new(program)
            .args(args)
            .current_dir(cwd)
            .output()
            .with_context(|| format!("failed to run `{program} {}`", args.join(" ")))?;
        Ok(ToolOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// One tool invocation within a check and whether it passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckStep {
    pub(crate) label: String,
    pub(crate) success: bool,
}

/// Aggregate result of a `check` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckReport {
    pub(crate) steps: Vec<CheckStep>,
    /// Warnings the tools reported, for `--deny-warnings`.
    pub(crate) warnings: Vec<crate::diagnostics::WarningCount>,
}

impl CheckReport {
    /// The check passes only when every step passed.
    pub(crate) fn success(&self) -> bool {
        self.steps.iter().all(|s| s.success)
    }

    /// Labels of the steps that failed.
    pub(crate) fn failures(&self) -> Vec<&str> {
        self.steps
            .iter()
            .filter(|s| !s.success)
            .map(|s| s.label.as_str())
            .collect()
    }
}

// Tools are invoked as their STANDALONE binaries (`cargo-deny`, `cargo-audit`)
// rather than via `cargo <sub>`, so they run in a cargo-less executor image
// (the orb runtime ships the tool binaries but no Rust toolchain). Both forms
// resolve to the same binaries on a dev machine.

/// cargo-deny standalone: full policy enforcement.
const DENY_ARGS: &[&str] = &["check", "advisories", "bans", "licenses", "sources"];
/// cargo-audit standalone: the `audit` subcommand runs the live advisory scan
/// (`cargo-audit audit` — the exact form `cargo audit` dispatches to; a bare
/// `cargo-audit` does not scan).
const AUDIT_ARGS: &[&str] = &["audit"];

/// Run cargo-deny and cargo-audit in `cwd` (the workspace root — both need to
/// find `deny.toml`/`Cargo.lock` there), then the about.toml drift check and
/// the cargo-about resolution check, surfacing each one's output, and return
/// the aggregated report. All four always run — a failing check never skips
/// the others.
///
/// The drift check isn't scoped to `cwd`: `deny.toml` is located by walking
/// up from `cwd`, but each crate's `cargo metadata` call runs with *that
/// crate's own directory* as its working directory (resolved from its
/// `about.toml`'s path — see [`crate::license_scope::scope_for_crate`]), not
/// `cwd` itself, since a workspace can hold more than one crate.
pub(crate) fn check_with<R: CommandRunner>(
    runner: &R,
    cwd: &Path,
    detail: crate::diagnostics::Detail,
) -> Result<CheckReport> {
    let mut steps = Vec::with_capacity(4);

    let deny = runner.run("cargo-deny", DENY_ARGS, cwd)?;
    let mut warnings = surface(
        "cargo-deny check advisories bans licenses sources",
        &deny,
        detail,
    );
    steps.push(CheckStep {
        label: "cargo deny".to_string(),
        success: deny.success,
    });

    // Always run cargo-audit too — never short-circuit on cargo-deny's result,
    // so both tools' findings are surfaced in one pass.
    let audit = runner.run("cargo-audit", AUDIT_ARGS, cwd)?;
    warnings.extend(surface("cargo-audit audit", &audit, detail));
    steps.push(CheckStep {
        label: "cargo audit".to_string(),
        success: audit.success,
    });

    // A hard error here (e.g. a crate's `cargo metadata` failing) is caught
    // rather than propagated with `?`, so it becomes this step's own failure
    // instead of discarding the deny/audit results already computed above.
    println!("$ about.toml license policy (deny.toml -> about.toml)");
    match sync::sync_about_toml_at(runner, cwd, true) {
        Ok(about_results) => {
            let mut drift_ok = true;
            for result in &about_results {
                if result.outcome == sync::SyncOutcome::Drift {
                    drift_ok = false;
                    println!(
                        "  {} is out of sync with deny.toml",
                        result.about_toml_path.display()
                    );
                }
            }
            steps.push(CheckStep {
                label: "about.toml license policy".to_string(),
                success: drift_ok,
            });

            // Independent of drift: can cargo-about actually attribute every
            // reachable dependency's licence using what's on disk right now,
            // not just is about.toml internally consistent with deny.toml?
            // Always runs, even when the drift check above failed, so a PR
            // fixing drift can't also be hiding an unresolvable licence the
            // same push would only otherwise be caught by `release-prep`
            // (see issue #80). Cache-independent (`--output-file /dev/null`
            // discards the rendered text — see release.rs's identical check
            // and scripts/licenses.sh's comment on why rendered bytes aren't
            // reproducible across machines).
            println!("$ cargo-about license policy resolution");
            let mut unresolved = Vec::new();
            for result in &about_results {
                let crate_dir = match result.about_toml_path.parent() {
                    Some(p) => p,
                    None => {
                        unresolved.push(format!(
                            "{}: about.toml path has no parent directory",
                            result.about_toml_path.display()
                        ));
                        continue;
                    }
                };
                match runner.run(
                    "cargo-about",
                    &[
                        "generate",
                        "--locked",
                        "about.hbs",
                        "--output-file",
                        "/dev/null",
                    ],
                    crate_dir,
                ) {
                    Ok(resolve) if !resolve.success => {
                        println!(
                            "  {}: cargo-about could not resolve licences",
                            crate_dir.display()
                        );
                        unresolved.push(format!(
                            "{}: {}",
                            crate_dir.display(),
                            resolve.stderr.trim()
                        ));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        println!("  {}: {e:#}", crate_dir.display());
                        unresolved.push(format!("{}: {e:#}", crate_dir.display()));
                    }
                }
            }
            steps.push(CheckStep {
                label: "cargo-about license policy".to_string(),
                success: unresolved.is_empty(),
            });
        }
        Err(e) => {
            println!("  error: {e:#}");
            steps.push(CheckStep {
                label: "about.toml license policy".to_string(),
                success: false,
            });
            steps.push(CheckStep {
                label: "cargo-about license policy".to_string(),
                success: false,
            });
        }
    }

    Ok(CheckReport { steps, warnings })
}

/// Print a tool's output under a labelled command header, returning its warnings.
fn surface(
    label: &str,
    out: &ToolOutput,
    detail: crate::diagnostics::Detail,
) -> Vec<crate::diagnostics::WarningCount> {
    println!("$ {label}");
    crate::diagnostics::emit(&out.stdout, &out.stderr, detail)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Records invocations and replays canned outputs in order.
    struct MockRunner {
        responses: Vec<ToolOutput>,
        calls: RefCell<Vec<Vec<String>>>,
        idx: RefCell<usize>,
    }

    impl MockRunner {
        fn new(responses: Vec<ToolOutput>) -> Self {
            Self {
                responses,
                calls: RefCell::new(Vec::new()),
                idx: RefCell::new(0),
            }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str], _cwd: &Path) -> Result<ToolOutput> {
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|s| s.to_string()));
            self.calls.borrow_mut().push(call);
            let i = *self.idx.borrow();
            *self.idx.borrow_mut() = i + 1;
            Ok(self.responses[i].clone())
        }
    }

    fn ok() -> ToolOutput {
        ToolOutput {
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn fail(stderr: &str) -> ToolOutput {
        ToolOutput {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    /// A workspace root with a `deny.toml` but no `crates/` directory — the
    /// about.toml drift check trivially passes (nothing to check) without
    /// consuming a mock `cargo metadata` response, so these fixtures don't
    /// need to know about that step at all.
    fn empty_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deny.toml"), "[licenses]\nallow = []\n").unwrap();
        dir
    }

    #[test]
    fn both_pass_is_success_and_invokes_expected_commands() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![ok(), ok()]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(report.success());

        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 2);
        // Standalone binaries (no `cargo` dispatch) so the tools run in a
        // cargo-less executor image.
        assert_eq!(
            calls[0],
            vec![
                "cargo-deny",
                "check",
                "advisories",
                "bans",
                "licenses",
                "sources"
            ]
        );
        assert_eq!(calls[1], vec!["cargo-audit", "audit"]);
    }

    #[test]
    fn deny_failure_still_runs_audit_and_fails_overall() {
        // cargo deny fails; cargo audit passes. Both must run (no short-circuit).
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![fail("license denied"), ok()]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(!report.success());
        assert_eq!(runner.calls.borrow().len(), 2, "audit must still run");
        assert_eq!(report.failures(), vec!["cargo deny"]);
    }

    #[test]
    fn audit_failure_fails_overall() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![ok(), fail("RUSTSEC-2024-0001")]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(!report.success());
        assert_eq!(report.failures(), vec!["cargo audit"]);
    }

    #[test]
    fn both_failing_reports_both() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![fail("policy"), fail("advisory")]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(!report.success());
        assert_eq!(report.failures(), vec!["cargo deny", "cargo audit"]);
    }

    #[test]
    fn stale_about_toml_fails_even_when_deny_and_audit_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("deny.toml"),
            "[licenses]\nallow = [\"MIT\"]\n",
        )
        .unwrap();
        let crate_dir = dir.path().join("crates/demo");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        // Drifted: asserts something deny.toml's allow list does not.
        std::fs::write(crate_dir.join("about.toml"), "accepted = [\"MPL-2.0\"]\n").unwrap();

        // deny and audit both mock-pass; the mocked cargo-metadata call the
        // about.toml check triggers returns a trivial no-deps graph, so the
        // drift is purely "committed content != freshly derived content".
        let metadata = r#"{
          "packages": [ { "name": "root", "version": "0.0.0", "id": "path+file:///demo#0.0.0", "license": null } ],
          "resolve": { "root": "path+file:///demo#0.0.0", "nodes": [ { "id": "path+file:///demo#0.0.0", "deps": [] } ] }
        }"#;
        let runner = MockRunner::new(vec![
            ok(),
            ok(),
            ToolOutput {
                success: true,
                stdout: metadata.to_string(),
                stderr: String::new(),
            },
            // cargo-about resolution still runs even though drift already
            // failed (aggregated, not short-circuited) — this one succeeds,
            // so only the drift step ends up in `failures()`.
            ok(),
        ]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(!report.success());
        assert_eq!(report.failures(), vec!["about.toml license policy"]);
    }

    /// Independent of drift: about.toml can be perfectly in sync with
    /// deny.toml and cargo-about can still fail to resolve a reachable
    /// dependency's licence (e.g. an SPDX expression no allow/exception
    /// combination covers) — this is exactly the gap issue #80 identifies:
    /// today only `release-prep` catches it, not the PR-time `check` gate.
    #[test]
    fn cargo_about_resolution_failure_fails_even_when_in_sync() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("deny.toml"),
            "[licenses]\nallow = [\"MIT\"]\n",
        )
        .unwrap();
        let crate_dir = dir.path().join("crates/demo");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        // In sync: the derivation for a no-deps graph is an empty `accepted`.
        std::fs::write(crate_dir.join("about.toml"), "accepted = []\n").unwrap();

        let metadata = r#"{
          "packages": [ { "name": "root", "version": "0.0.0", "id": "path+file:///demo#0.0.0", "license": null } ],
          "resolve": { "root": "path+file:///demo#0.0.0", "nodes": [ { "id": "path+file:///demo#0.0.0", "deps": [] } ] }
        }"#;
        let runner = MockRunner::new(vec![
            ok(),
            ok(),
            ToolOutput {
                success: true,
                stdout: metadata.to_string(),
                stderr: String::new(),
            },
            fail("error: failed to satisfy license requirements"),
        ]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(!report.success());
        assert_eq!(report.failures(), vec!["cargo-about license policy"]);

        let calls = runner.calls.borrow();
        assert_eq!(
            calls[3],
            vec![
                "cargo-about",
                "generate",
                "--locked",
                "about.hbs",
                "--output-file",
                "/dev/null"
            ]
        );
    }

    #[test]
    fn about_toml_in_sync_and_resolvable_all_steps_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("deny.toml"),
            "[licenses]\nallow = [\"MIT\"]\n",
        )
        .unwrap();
        let crate_dir = dir.path().join("crates/demo");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(crate_dir.join("about.toml"), "accepted = []\n").unwrap();

        let metadata = r#"{
          "packages": [ { "name": "root", "version": "0.0.0", "id": "path+file:///demo#0.0.0", "license": null } ],
          "resolve": { "root": "path+file:///demo#0.0.0", "nodes": [ { "id": "path+file:///demo#0.0.0", "deps": [] } ] }
        }"#;
        let runner = MockRunner::new(vec![
            ok(),
            ok(),
            ToolOutput {
                success: true,
                stdout: metadata.to_string(),
                stderr: String::new(),
            },
            ok(),
        ]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(report.success());
    }

    #[test]
    fn about_toml_step_error_is_a_failed_step_not_a_propagated_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("deny.toml"),
            "[licenses]\nallow = [\"MIT\"]\n",
        )
        .unwrap();
        let crate_dir = dir.path().join("crates/demo");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(crate_dir.join("about.toml"), "accepted = []\n").unwrap();

        // deny and audit both mock-pass; the mocked cargo-metadata call fails
        // outright (e.g. a broken Cargo.toml), which scope_for_crate turns
        // into a hard error via bail!, not a ToolOutput{success:false}.
        let runner = MockRunner::new(vec![
            ok(),
            ok(),
            ToolOutput {
                success: false,
                stdout: String::new(),
                stderr: "error: could not find `Cargo.toml`".to_string(),
            },
        ]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).expect(
            "a failing about.toml step must not propagate as an Err — \
                     it must become a failed CheckStep so deny/audit results survive",
        );
        assert!(!report.success());
        // Both about-related steps fail together: sync_about_toml_at errored
        // before it could tell us which crates even have an about.toml, so
        // there's nothing to run cargo-about against either.
        assert_eq!(
            report.failures(),
            vec!["about.toml license policy", "cargo-about license policy"]
        );
    }
}
