//! The PR / dev gate: run cargo-deny policy checks **and** a live cargo-audit
//! scan, both blocking.
//!
//! `cargo deny` enforces policy (advisories, bans, licenses, sources) with the
//! justified, file-based ignores in `deny.toml`; `cargo audit` adds a fresh
//! scan against the live RustSec database. Both run — exit codes are
//! **aggregated**, not short-circuited, so one failing tool never hides the
//! other's findings — and each tool's stderr is surfaced (per the
//! CI-diagnostics discipline: never swallow the output of a tool whose result
//! drives a decision).

use std::{path::Path, process::Command};

use anyhow::{Context, Result};

/// The captured result of running one external tool. Modelled instead of
/// `std::process::Output` so orchestration is testable without constructing a
/// platform-specific `ExitStatus`.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Abstraction over running an external command, so the check orchestration is
/// unit-testable with a mock in place of real cargo subcommands.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str], cwd: &Path) -> Result<ToolOutput>;
}

/// Runs commands as real subprocesses.
pub struct SystemRunner;

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
pub struct CheckStep {
    pub label: String,
    pub success: bool,
}

/// Aggregate result of a `check` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    pub steps: Vec<CheckStep>,
    /// Warnings the tools reported, for `--deny-warnings`.
    pub warnings: Vec<crate::diagnostics::WarningCount>,
}

impl CheckReport {
    /// The check passes only when every step passed.
    pub fn success(&self) -> bool {
        self.steps.iter().all(|s| s.success)
    }

    /// Labels of the steps that failed.
    pub fn failures(&self) -> Vec<&str> {
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

/// Run both tools in `cwd`, surfacing each one's output, and return the
/// aggregated report. Both always run — a failing cargo-deny does not skip
/// cargo-audit.
pub fn check_with<R: CommandRunner>(
    runner: &R,
    cwd: &Path,
    detail: crate::diagnostics::Detail,
) -> Result<CheckReport> {
    let mut steps = Vec::with_capacity(2);

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
    use std::{cell::RefCell, path::PathBuf};

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

    #[test]
    fn both_pass_is_success_and_invokes_expected_commands() {
        let runner = MockRunner::new(vec![ok(), ok()]);
        let report = check_with(
            &runner,
            &PathBuf::from("."),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
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
        let runner = MockRunner::new(vec![fail("license denied"), ok()]);
        let report = check_with(
            &runner,
            &PathBuf::from("."),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
        assert!(!report.success());
        assert_eq!(runner.calls.borrow().len(), 2, "audit must still run");
        assert_eq!(report.failures(), vec!["cargo deny"]);
    }

    #[test]
    fn audit_failure_fails_overall() {
        let runner = MockRunner::new(vec![ok(), fail("RUSTSEC-2024-0001")]);
        let report = check_with(
            &runner,
            &PathBuf::from("."),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
        assert!(!report.success());
        assert_eq!(report.failures(), vec!["cargo audit"]);
    }

    #[test]
    fn both_failing_reports_both() {
        let runner = MockRunner::new(vec![fail("policy"), fail("advisory")]);
        let report = check_with(
            &runner,
            &PathBuf::from("."),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
        assert!(!report.success());
        assert_eq!(report.failures(), vec!["cargo deny", "cargo audit"]);
    }
}
