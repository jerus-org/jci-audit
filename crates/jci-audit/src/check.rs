//! The PR / dev gate: run cargo-deny policy checks, a live cargo-audit scan,
//! the about.toml/deny.toml license-policy drift check, and the cargo-about
//! license-policy resolution check, all blocking.
//!
//! `cargo deny` enforces policy (advisories, bans, licenses, sources) with the
//! justified, file-based ignores in `deny.toml`; `cargo audit` adds a fresh
//! scan against the live RustSec database; the drift check confirms each
//! crate's `about.toml` still reflects `deny.toml`'s license policy — a pure
//! derivation, the same one `jci-audit sync --check` performs, no
//! `cargo-about` invocation needed; the resolution check confirms
//! `cargo-about` can actually attribute every reachable dependency's licence
//! with what's on disk right now, independent of drift. All four run — exit
//! codes are **aggregated**, not short-circuited, so one failing check never
//! hides another's findings — and each tool's stderr is surfaced (per the
//! CI-diagnostics discipline: never swallow the output of a tool whose
//! result drives a decision).

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
    /// `deny.toml`'s configured `[[bans.skip]]` exceptions, split by whether
    /// cargo-deny flagged each one stale (`unmatched-skip` or
    /// `unnecessary-skip`) this run. See [`crate::exceptions`] — cargo-deny
    /// is otherwise silent about a skip
    /// that's actively suppressing a real duplicate, so this is jci-audit's
    /// own visibility on top of it, not a cargo-deny diagnostic.
    pub(crate) accepted_warnings: crate::exceptions::AcceptedWarnings,
    /// Licenses `deny.toml`'s `[licenses] allow` list permits but that
    /// nothing in the graph carries (cargo-deny's `license-not-encountered`),
    /// named individually — see [`unused_license_names`] for why this needs
    /// its own parse rather than reusing [`CheckReport::warnings`]' counts.
    pub(crate) unused_licenses: Vec<String>,
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
// rather than via `cargo <sub>`, matching how preflight.rs probes them. Both
// forms resolve to the same binaries — the orb's executor image ships a full
// Rust toolchain alongside these tool binaries (it's built `FROM
// rust:*-slim`), so this is a presence-detection choice, not a constraint
// imposed by a toolchain-less environment.

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
    let (deny_toml, accepted_warnings) =
        read_deny_toml_and_accepted_warnings(cwd, &deny.stderr).unwrap_or_default();
    crate::exceptions::print_notice(&accepted_warnings);
    report_accepted_duplicates_in_detail(runner, cwd, &deny_toml, &accepted_warnings, detail);
    let unused_licenses = unused_license_names(&deny.stderr);

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

            // Runs even when the drift check above failed, so a PR fixing
            // drift can't also leave an unresolvable licence unnoticed.
            println!("$ cargo-about license policy resolution");
            let unresolved = resolve_license_policy(runner, &about_results);
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

    Ok(CheckReport {
        steps,
        warnings,
        accepted_warnings,
        unused_licenses,
    })
}

/// Names of licenses cargo-deny flagged `license-not-encountered`: allowed by
/// `deny.toml`'s `[licenses] allow` list but not carried by anything in the
/// current graph. The diagnostic's headline (`warning[license-not-encountered]:
/// license was not encountered`) never names the license — only the annotated
/// `deny.toml` source snippet printed underneath it does, e.g.:
///
/// ```text
/// warning[license-not-encountered]: license was not encountered
///    ┌─ deny.toml:35:6
///    │
/// 35 │     "BSD-2-Clause",
///    │      ━━━━━━━━━━━━ unmatched license allowance
/// ```
///
/// so this walks each such block for the first quoted string in the lines
/// that follow — the only quoted text in the block — stopping at the blank
/// line that separates diagnostics, or at the next diagnostic's own header if
/// there is no blank line (defends against swallowing a neighbouring block
/// into this one, which would both misname it and drop it from the count).
///
/// Best-effort only: a block whose name can't be found this way contributes
/// nothing here. Callers must not treat this list's length as the count of
/// occurrences — [`CheckReport::warnings`]' own `license-not-encountered`
/// count is the fail-safe source for "did this happen at all"; this is purely
/// for naming what it can.
fn unused_license_names(stderr: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut lines = stderr.lines().map(strip_ansi).peekable();
    while let Some(line) = lines.next() {
        if !line.starts_with("warning[license-not-encountered]") {
            continue;
        }
        while let Some(detail_line) = lines.peek() {
            if detail_line.trim().is_empty() || detail_line.starts_with("warning[") {
                break;
            }
            let detail_line = lines.next().expect("just peeked Some");
            if let Some(name) = quoted_substring(&detail_line) {
                names.push(name);
                break;
            }
        }
    }
    names
}

/// The contents of the first `"..."` pair on the line, if any.
fn quoted_substring(line: &str) -> Option<String> {
    let start = line.find('"')? + 1;
    let end = start + line[start..].find('"')?;
    Some(line[start..end].to_string())
}

/// Duplicated from `crate::diagnostics`'s private `strip_ansi` rather than
/// exposed across the module boundary — four lines, and classification here
/// is policy, not the counting `diagnostics` already owns (same rationale as
/// `crate::exceptions`'s own copy).
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        for c in chars.by_ref() {
            if c.is_ascii_alphabetic() {
                break;
            }
        }
    }
    out
}

/// Read `deny.toml` and classify its configured `[[bans.skip]]` exceptions
/// against this run's cargo-deny stderr. Returns the raw `deny.toml` text
/// alongside the classification — [`report_accepted_duplicates_in_detail`]
/// needs that same text to derive its own ephemeral config from, so it isn't
/// re-read a second time. Deliberately non-fatal: a missing or unparsable
/// `deny.toml` is already the "cargo deny" step's own failure (or, for a
/// workspace with no bans.skip at all, simply has nothing to report) — this
/// is a visibility layer on top, not a new source of hard errors.
fn read_deny_toml_and_accepted_warnings(
    cwd: &Path,
    deny_stderr: &str,
) -> Option<(String, crate::exceptions::AcceptedWarnings)> {
    let (deny_path, _) = sync::locate_paths(cwd).ok()?;
    let deny_toml = std::fs::read_to_string(&deny_path).ok()?;
    let configured = crate::exceptions::extract_bans_skips(&deny_toml).ok()?;
    let accepted = crate::exceptions::accepted_warnings(configured, deny_stderr);
    Some((deny_toml, accepted))
}

/// Opt-in, `-vv`-only informational pass: cargo-deny is silent about a
/// `[[bans.skip]]` entry that's actively suppressing a real duplicate (see
/// [`crate::exceptions`]), so `-v`/`-vv` have nothing to show for an in-force
/// exception the way they do for every other kind of finding. This recovers
/// that by re-running `cargo-deny check bans` against an ephemeral config
/// with `multiple-versions` forced to `"warn"` and every skip removed — "as
/// if the config was warn and the skips didn't exist" — so every duplicate,
/// including accepted ones, shows up as a plain `warning[duplicate]` and
/// flows through the existing [`surface`]/[`crate::diagnostics::emit`]
/// tiering unchanged.
///
/// Only runs when there's something to explain: measured live, a single
/// `cargo deny check bans` costs real wall time (graph resolution, not the
/// check itself, dominates), so this must not run on a routine default/`-v`
/// check, or when nothing is actually being hidden. Its output is purely
/// informational — the returned warning counts are discarded, never merged
/// into [`CheckReport::warnings`], so an accepted exception can never be
/// penalised by `--deny-warnings`. Any failure deriving/writing the config or
/// running cargo-deny is swallowed, matching
/// [`read_deny_toml_and_accepted_warnings`]'s "visibility layer, never a new
/// hard-error source" principle.
fn report_accepted_duplicates_in_detail<R: CommandRunner>(
    runner: &R,
    cwd: &Path,
    deny_toml: &str,
    accepted: &crate::exceptions::AcceptedWarnings,
    detail: crate::diagnostics::Detail,
) {
    if detail != crate::diagnostics::Detail::Full || accepted.in_force.is_empty() {
        return;
    }
    let Ok(derived) = crate::exceptions::as_warn_without_skip(deny_toml) else {
        return;
    };
    let work_dir =
        std::env::temp_dir().join(format!("jci-audit-check-naked-{}", std::process::id()));
    if std::fs::create_dir_all(&work_dir).is_err() {
        return;
    }
    let config_path = work_dir.join("deny.toml");
    if std::fs::write(&config_path, derived).is_err() {
        let _ = std::fs::remove_dir_all(&work_dir);
        return;
    }
    if let Some(config_str) = config_path.to_str()
        && let Ok(naked) = runner.run(
            "cargo-deny",
            &["--config", config_str, "check", "bans"],
            cwd,
        )
    {
        surface(
            "cargo-deny check bans (informational — every duplicate, accepted exceptions included)",
            &naked,
            detail,
        );
    }
    let _ = std::fs::remove_dir_all(&work_dir);
}

/// Run cargo-about's resolution check for every crate in `about_results`,
/// returning a description of each crate cargo-about couldn't attribute
/// (empty when every crate resolves cleanly). Cache-independent
/// (`--output-file /dev/null` discards the rendered text — see
/// `scripts/licenses.sh`'s own comment on why rendered bytes aren't
/// reproducible across machines). Shared by `check`'s PR-time gate and
/// `release-prep`'s release-time gate so the two invocations can't drift
/// apart from each other.
pub(crate) fn resolve_license_policy<R: CommandRunner>(
    runner: &R,
    about_results: &[sync::AboutSyncResult],
) -> Vec<String> {
    let mut unresolved = Vec::new();
    for result in about_results {
        let crate_dir = match result.about_toml_path.parent() {
            Some(p) => p,
            None => {
                println!(
                    "  {}: about.toml path has no parent directory",
                    result.about_toml_path.display()
                );
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
    unresolved
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

    /// The `cargo metadata --no-deps` response `find_about_toml_paths`
    /// consumes to enumerate workspace members (jerus-org/jci-audit#100) —
    /// every scenario needs one of these, even an empty workspace, since the
    /// call always happens regardless of what's found.
    fn workspace_metadata(manifest_paths: &[&Path]) -> ToolOutput {
        let packages: Vec<String> = manifest_paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                format!(
                    r#"{{"name":"crate{i}","version":"0.0.0","id":"id{i}","manifest_path":"{}"}}"#,
                    p.display()
                )
            })
            .collect();
        ToolOutput {
            success: true,
            stdout: format!(r#"{{"packages":[{}]}}"#, packages.join(",")),
            stderr: String::new(),
        }
    }

    /// A workspace root with a `deny.toml` but no crates — the about.toml
    /// drift check finds no workspace members via the mocked empty
    /// `workspace_metadata`, so there's nothing to sync.
    fn empty_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deny.toml"), "[licenses]\nallow = []\n").unwrap();
        dir
    }

    #[test]
    fn both_pass_is_success_and_invokes_expected_commands() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![ok(), ok(), workspace_metadata(&[])]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(report.success());

        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 3);
        // Standalone binaries (no `cargo` dispatch) — matches how
        // preflight.rs probes them; the executor image has a full Rust
        // toolchain regardless (see check.rs's module comment above).
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
        let runner = MockRunner::new(vec![fail("license denied"), ok(), workspace_metadata(&[])]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(!report.success());
        assert_eq!(
            runner.calls.borrow().len(),
            3,
            "audit and the about.toml check must still run"
        );
        assert_eq!(report.failures(), vec!["cargo deny"]);
    }

    #[test]
    fn audit_failure_fails_overall() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![
            ok(),
            fail("RUSTSEC-2024-0001"),
            workspace_metadata(&[]),
        ]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(!report.success());
        assert_eq!(report.failures(), vec!["cargo audit"]);
    }

    #[test]
    fn both_failing_reports_both() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![
            fail("policy"),
            fail("advisory"),
            workspace_metadata(&[]),
        ]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(!report.success());
        assert_eq!(report.failures(), vec!["cargo deny", "cargo audit"]);
    }

    #[test]
    fn reports_in_force_and_stale_accepted_warnings_from_deny_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("deny.toml"),
            "[licenses]\nallow = []\n\n\
             [[bans.skip]]\n\
             name = \"syn\"\n\
             reason = \"genuinely duplicates today\"\n\n\
             [[bans.skip]]\n\
             name = \"widget\"\n",
        )
        .unwrap();
        // cargo-deny flags 'widget' as unmatched (stale); says nothing about
        // 'syn' at all, since a matching skip is silent — exactly the live
        // behaviour captured in exceptions.rs.
        let deny_stderr = "warning[unmatched-skip]: skipped crate 'widget' was not encountered\n";
        let runner = MockRunner::new(vec![fail(deny_stderr), ok(), workspace_metadata(&[])]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();

        assert_eq!(report.accepted_warnings.in_force.len(), 1);
        assert_eq!(report.accepted_warnings.in_force[0].name, "syn");
        assert_eq!(report.accepted_warnings.stale.len(), 1);
        assert_eq!(report.accepted_warnings.stale[0].name, "widget");
    }

    /// A workspace with a genuine in-force `[[bans.skip]]` entry, for the
    /// lazy informational-report tests below.
    fn workspace_with_in_force_skip() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("deny.toml"),
            "[licenses]\nallow = []\n\n\
             [[bans.skip]]\n\
             name = \"syn\"\n\
             reason = \"genuinely duplicates today\"\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn full_detail_with_an_in_force_exception_runs_the_informational_pass() {
        let dir = workspace_with_in_force_skip();
        // Call order: deny, [naked informational], audit, cargo-metadata.
        // deny.stderr names nothing unmatched, so 'syn' is in force.
        let runner = MockRunner::new(vec![ok(), ok(), ok(), workspace_metadata(&[])]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Full).unwrap();
        assert_eq!(report.accepted_warnings.in_force.len(), 1);

        let calls = runner.calls.borrow();
        assert_eq!(
            calls.len(),
            4,
            "expected a 4th, informational cargo-deny call: {calls:?}"
        );
        let naked = &calls[1];
        assert_eq!(naked[0], "cargo-deny");
        assert!(naked.contains(&"--config".to_string()), "call: {naked:?}");
        assert!(naked.contains(&"bans".to_string()), "call: {naked:?}");
        assert!(
            !naked.contains(&"advisories".to_string()),
            "must be scoped to bans only: {naked:?}"
        );
    }

    #[test]
    fn full_detail_with_no_in_force_exceptions_skips_the_informational_pass() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![ok(), ok(), workspace_metadata(&[])]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Full).unwrap();
        assert!(report.accepted_warnings.in_force.is_empty());
        assert_eq!(
            runner.calls.borrow().len(),
            3,
            "nothing to explain, so no extra call"
        );
    }

    #[test]
    fn list_detail_with_an_in_force_exception_skips_the_informational_pass() {
        let dir = workspace_with_in_force_skip();
        let runner = MockRunner::new(vec![ok(), ok(), workspace_metadata(&[])]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::List).unwrap();
        assert_eq!(report.accepted_warnings.in_force.len(), 1);
        assert_eq!(
            runner.calls.borrow().len(),
            3,
            "the informational pass is -vv only"
        );
    }

    #[test]
    fn no_bans_skip_entries_means_no_accepted_warnings() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![ok(), ok(), workspace_metadata(&[])]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(report.accepted_warnings.in_force.is_empty());
        assert!(report.accepted_warnings.stale.is_empty());
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

        // deny and audit both mock-pass; the mocked per-crate cargo-metadata
        // call the about.toml check triggers returns a trivial no-deps
        // graph, so the drift is purely "committed content != freshly
        // derived content".
        let metadata = r#"{
          "packages": [ { "name": "root", "version": "0.0.0", "id": "path+file:///demo#0.0.0", "license": null } ],
          "resolve": { "root": "path+file:///demo#0.0.0", "nodes": [ { "id": "path+file:///demo#0.0.0", "deps": [] } ] }
        }"#;
        let runner = MockRunner::new(vec![
            ok(),
            ok(),
            workspace_metadata(&[&crate_dir.join("Cargo.toml")]),
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
            workspace_metadata(&[&crate_dir.join("Cargo.toml")]),
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
            calls[4],
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
            workspace_metadata(&[&crate_dir.join("Cargo.toml")]),
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
        // outright (e.g. a broken workspace Cargo.toml), which
        // find_about_toml_paths turns into a hard error via bail!, not a
        // ToolOutput{success:false}.
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

    /// Real, live-captured cargo-deny 0.20.2 stderr for two unmatched
    /// license allowances (`deny.toml`'s `BSD-2-Clause` and `Zlib` entries),
    /// piped (non-tty), so no ANSI codes.
    const LICENSE_NOT_ENCOUNTERED_STDERR: &str = "\
warning[license-not-encountered]: license was not encountered
   \u{250c}\u{2500} deny.toml:35:6
   \u{2502}
35 \u{2502}     \"BSD-2-Clause\",
   \u{2502}      \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501} unmatched license allowance

warning[license-not-encountered]: license was not encountered
   \u{250c}\u{2500} deny.toml:39:6
   \u{2502}
39 \u{2502}     \"Zlib\",
   \u{2502}      \u{2501}\u{2501}\u{2501}\u{2501} unmatched license allowance

licenses ok
";

    #[test]
    fn unused_license_names_extracts_every_flagged_license() {
        assert_eq!(
            unused_license_names(LICENSE_NOT_ENCOUNTERED_STDERR),
            vec!["BSD-2-Clause".to_string(), "Zlib".to_string()]
        );
    }

    #[test]
    fn unused_license_names_handles_adjacent_blocks_with_no_blank_line_between() {
        // No blank line separates the two diagnostics here — the inner scan
        // for the first block must stop at the second block's own header
        // rather than reading through it looking for a quote, which would
        // both misattribute the second license to the first block and drop
        // the second block from the count entirely.
        let stderr = "warning[license-not-encountered]: license was not encountered\n\
             35 \u{2502}     \"BSD-2-Clause\",\n\
             warning[license-not-encountered]: license was not encountered\n\
             39 \u{2502}     \"Zlib\",\n";
        assert_eq!(
            unused_license_names(stderr),
            vec!["BSD-2-Clause".to_string(), "Zlib".to_string()]
        );
    }

    #[test]
    fn unused_license_names_skips_a_block_it_cannot_parse_a_name_from() {
        // A block whose annotated snippet never yields a quoted name (e.g. a
        // future cargo-deny rendering change) must not swallow the next
        // block's header while scanning for one.
        let stderr = "warning[license-not-encountered]: license was not encountered\n\
             (unexpected rendering, no quoted value here)\n\
             \n\
             warning[license-not-encountered]: license was not encountered\n\
             39 \u{2502}     \"Zlib\",\n";
        assert_eq!(unused_license_names(stderr), vec!["Zlib".to_string()]);
    }

    #[test]
    fn unused_license_names_is_empty_when_nothing_flagged() {
        assert!(unused_license_names("licenses ok\n").is_empty());
        assert!(unused_license_names("warning[duplicate]: found 2\n").is_empty());
    }

    #[test]
    fn unused_license_names_ignores_ansi_colour_codes() {
        let coloured = "\u{1b}[33mwarning[license-not-encountered]\u{1b}[0m: license was not encountered\n\
             35 \u{2502}     \"\u{1b}[33mBSD-2-Clause\u{1b}[0m\",\n";
        assert_eq!(
            unused_license_names(coloured),
            vec!["BSD-2-Clause".to_string()]
        );
    }

    #[test]
    fn deny_stderr_naming_unused_licenses_populates_the_report() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![
            fail(LICENSE_NOT_ENCOUNTERED_STDERR),
            ok(),
            workspace_metadata(&[]),
        ]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert_eq!(report.unused_licenses, vec!["BSD-2-Clause", "Zlib"]);
    }

    #[test]
    fn no_license_not_encountered_warnings_means_no_unused_licenses() {
        let dir = empty_workspace();
        let runner = MockRunner::new(vec![ok(), ok(), workspace_metadata(&[])]);
        let report = check_with(&runner, dir.path(), crate::diagnostics::Detail::Summary).unwrap();
        assert!(report.unused_licenses.is_empty());
    }
}
