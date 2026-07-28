//! Stale-ignore detector.
//!
//! An advisory ignore in `deny.toml` is a deliberate, justified exception — but
//! exceptions rot: the advisory gets a fixed release, the dependency is dropped,
//! or the advisory is withdrawn. A suppression that no longer fires is dead
//! weight that quietly widens the policy, so `prune` finds them.
//!
//! It automates the manual probe of running the audit from **outside** the
//! workspace so no `.cargo/audit.toml` is discovered: the tool is run with its
//! working directory in the system temp dir and an absolute `--file` pointing at
//! the repo's `Cargo.lock`. That yields the **naked** result — every advisory the
//! database reports, with no suppression applied. Any configured ignore missing
//! from that set no longer fires and can be removed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::{
    check::CommandRunner,
    sync::{extract_ignores, locate_paths},
};

/// Outcome of a prune run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneReport {
    /// Advisory ids configured as ignores in `deny.toml`.
    pub configured: Vec<String>,
    /// Advisory ids the naked database reports for this lockfile.
    pub firing: Vec<String>,
    /// Configured ignores that no longer fire — safe to remove.
    pub stale: Vec<String>,
}

impl PruneReport {
    /// Whether every configured ignore still fires.
    pub fn is_clean(&self) -> bool {
        self.stale.is_empty()
    }
}

/// Collect every advisory id in a `cargo-audit --json` report: both
/// `vulnerabilities.list[]` and each `warnings.<kind>[]` bucket (an ignore may
/// suppress an `unmaintained`/`yanked` warning as well as a vulnerability).
pub fn parse_firing_ids(json: &str) -> Result<Vec<String>> {
    let doc: Value =
        serde_json::from_str(json).context("failed to parse the cargo-audit JSON report")?;

    let vulnerabilities = doc
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    // `warnings` is an object keyed by kind (unmaintained, yanked, …); flatten
    // every bucket, since an ignore can suppress a warning as well as a
    // vulnerability.
    let warnings = doc
        .get("warnings")
        .and_then(Value::as_object)
        .map(|buckets| {
            buckets
                .values()
                .filter_map(Value::as_array)
                .flatten()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut ids: Vec<String> = vulnerabilities
        .iter()
        .chain(warnings)
        .filter_map(|entry| advisory_id(entry))
        .map(str::to_string)
        .collect();

    // Order-preserving dedupe: the same advisory can appear more than once
    // (multiple affected packages, or both a vulnerability and a warning).
    let mut seen = std::collections::HashSet::new();
    ids.retain(|id| seen.insert(id.clone()));
    Ok(ids)
}

/// The advisory id of one report entry, if present.
fn advisory_id(entry: &Value) -> Option<&str> {
    entry
        .get("advisory")
        .and_then(|a| a.get("id"))
        .and_then(Value::as_str)
}

/// Configured ignores that do not appear in the naked results, preserving the
/// order they were declared in.
pub fn stale_ignores(configured: &[String], firing: &[String]) -> Vec<String> {
    configured
        .iter()
        .filter(|id| !firing.iter().any(|f| f == *id))
        .cloned()
        .collect()
}

/// The naked audit invocation: an absolute lockfile path plus JSON output.
fn audit_args(lockfile: &Path) -> Vec<String> {
    vec![
        "audit".to_string(),
        "--file".to_string(),
        lockfile.display().to_string(),
        "--json".to_string(),
    ]
}

/// Run the naked audit for the workspace found from `start` and diff its results
/// against the ignores configured in `deny.toml`.
///
/// `naked_cwd` must be a directory **outside** the repository, so cargo does not
/// discover the repo's `.cargo/audit.toml` and apply the very suppressions we
/// are testing.
pub fn prune_with<R: CommandRunner>(
    runner: &R,
    start: &Path,
    naked_cwd: &Path,
) -> Result<PruneReport> {
    let (deny_path, _audit_path) = locate_paths(start)?;
    let root = deny_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let lockfile = root.join("Cargo.lock");
    if !lockfile.is_file() {
        bail!("no Cargo.lock found at '{}'", lockfile.display());
    }

    let deny = std::fs::read_to_string(&deny_path)
        .with_context(|| format!("failed to read '{}'", deny_path.display()))?;
    let configured: Vec<String> = extract_ignores(&deny)?
        .into_iter()
        .map(|entry| entry.id)
        .collect();

    let args = audit_args(&lockfile);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = runner.run("cargo-audit", &arg_refs, naked_cwd)?;
    // cargo-audit exits NON-ZERO whenever it reports anything, and a naked run
    // reports everything — so the exit status carries no failure signal here.
    // The JSON report on stdout is what matters. Surface stderr only when there
    // is no parseable report to work with (below).
    let firing = parse_firing_ids(&out.stdout).map_err(|e| {
        let stderr = out.stderr.trim();
        if stderr.is_empty() {
            e
        } else {
            e.context(format!("cargo-audit stderr: {stderr}"))
        }
    })?;

    let stale = stale_ignores(&configured, &firing);
    Ok(PruneReport {
        configured,
        firing,
        stale,
    })
}

/// A directory outside any repository, used as the working directory for the
/// naked run. Process-scoped so concurrent runs cannot collide.
pub fn naked_run_dir() -> PathBuf {
    std::env::temp_dir().join(format!("jci-audit-prune-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::PathBuf};

    use super::*;
    use crate::check::ToolOutput;

    /// Replays a canned cargo-audit response and records the invocation.
    struct MockRunner {
        response: ToolOutput,
        calls: RefCell<Vec<(String, Vec<String>, PathBuf)>>,
    }

    impl MockRunner {
        fn new(response: ToolOutput) -> Self {
            Self {
                response,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str], cwd: &Path) -> Result<ToolOutput> {
            self.calls.borrow_mut().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
                cwd.to_path_buf(),
            ));
            Ok(self.response.clone())
        }
    }

    /// cargo-audit exits NON-ZERO whenever it reports anything, so a naked run
    /// that finds advisories fails by design — the JSON is still on stdout.
    fn found(json: &str) -> ToolOutput {
        ToolOutput {
            success: false,
            stdout: json.to_string(),
            stderr: String::new(),
        }
    }

    fn clean_json() -> &'static str {
        r#"{"vulnerabilities":{"count":0,"found":false,"list":[]},"warnings":{}}"#
    }

    fn one_vuln_json() -> &'static str {
        r#"{"vulnerabilities":{"count":1,"found":true,"list":[
             {"advisory":{"id":"RUSTSEC-2023-0071"},"package":{"name":"rsa"}}
           ]},"warnings":{}}"#
    }

    fn vuln_and_warning_json() -> &'static str {
        r#"{"vulnerabilities":{"count":1,"found":true,"list":[
             {"advisory":{"id":"RUSTSEC-2023-0071"},"package":{"name":"rsa"}}
           ]},
           "warnings":{"unmaintained":[
             {"advisory":{"id":"RUSTSEC-2024-0384"},"package":{"name":"instant"}}
           ]}}"#
    }

    fn write_repo(ignores: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut deny = String::from("[advisories]\nignore = [\n");
        for id in ignores {
            deny.push_str(&format!("    \"{id}\",\n"));
        }
        deny.push_str("]\n");
        std::fs::write(dir.path().join("deny.toml"), deny).unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "# lockfile\n").unwrap();
        dir
    }

    #[test]
    fn parse_ids_from_vulnerabilities() {
        let ids = parse_firing_ids(one_vuln_json()).unwrap();
        assert_eq!(ids, vec!["RUSTSEC-2023-0071"]);
    }

    #[test]
    fn parse_ids_includes_warning_buckets() {
        // An ignore can suppress an unmaintained/yanked warning too, so warnings
        // must count as "firing".
        let ids = parse_firing_ids(vuln_and_warning_json()).unwrap();
        assert!(
            ids.contains(&"RUSTSEC-2023-0071".to_string()),
            "got {ids:?}"
        );
        assert!(
            ids.contains(&"RUSTSEC-2024-0384".to_string()),
            "got {ids:?}"
        );
    }

    #[test]
    fn parse_ids_on_clean_report_is_empty() {
        assert!(parse_firing_ids(clean_json()).unwrap().is_empty());
    }

    #[test]
    fn parse_ids_rejects_malformed_json() {
        assert!(parse_firing_ids("not json").is_err());
    }

    #[test]
    fn stale_is_configured_minus_firing_in_order() {
        let configured = vec!["RUSTSEC-A".to_string(), "RUSTSEC-B".to_string()];
        let firing = vec!["RUSTSEC-B".to_string()];
        assert_eq!(stale_ignores(&configured, &firing), vec!["RUSTSEC-A"]);
    }

    #[test]
    fn no_configured_ignores_means_nothing_stale() {
        assert!(stale_ignores(&[], &["RUSTSEC-A".to_string()]).is_empty());
    }

    #[test]
    fn prune_flags_an_ignore_that_no_longer_fires() {
        // Configured ignore is absent from the naked report -> stale.
        let dir = write_repo(&["RUSTSEC-2023-0071"]);
        let runner = MockRunner::new(found(clean_json()));
        let report = prune_with(&runner, dir.path(), Path::new("/tmp")).unwrap();
        assert_eq!(report.configured, vec!["RUSTSEC-2023-0071"]);
        assert!(report.firing.is_empty());
        assert_eq!(report.stale, vec!["RUSTSEC-2023-0071"]);
        assert!(!report.is_clean());
    }

    #[test]
    fn prune_is_clean_when_the_ignore_still_fires() {
        let dir = write_repo(&["RUSTSEC-2023-0071"]);
        let runner = MockRunner::new(found(one_vuln_json()));
        let report = prune_with(&runner, dir.path(), Path::new("/tmp")).unwrap();
        assert!(report.is_clean(), "ignore still fires: {report:?}");
        assert_eq!(report.firing, vec!["RUSTSEC-2023-0071"]);
    }

    #[test]
    fn prune_runs_the_naked_audit_outside_the_repo() {
        let dir = write_repo(&[]);
        let runner = MockRunner::new(found(clean_json()));
        prune_with(&runner, dir.path(), Path::new("/tmp")).unwrap();

        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        let (program, args, cwd) = &calls[0];
        assert_eq!(program, "cargo-audit");
        assert_eq!(args[0], "audit");
        assert!(args.contains(&"--json".to_string()), "args: {args:?}");
        // Absolute lockfile path, and cwd OUTSIDE the repo so the repo's
        // .cargo/audit.toml is not discovered.
        let lock = dir.path().join("Cargo.lock");
        assert!(
            args.contains(&lock.display().to_string()),
            "must pass the absolute lockfile path, args: {args:?}"
        );
        assert_eq!(cwd, Path::new("/tmp"));
    }

    #[test]
    fn prune_errors_when_lockfile_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deny.toml"), "[advisories]\nignore = []\n").unwrap();
        let runner = MockRunner::new(found(clean_json()));
        let err = prune_with(&runner, dir.path(), Path::new("/tmp")).unwrap_err();
        assert!(err.to_string().contains("Cargo.lock"), "got: {err}");
    }

    #[test]
    fn naked_run_dir_is_outside_any_repo() {
        let dir = naked_run_dir();
        assert!(dir.starts_with(std::env::temp_dir()));
    }
}
