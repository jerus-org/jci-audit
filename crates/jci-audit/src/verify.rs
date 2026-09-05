//! Re-verify a past release against the snapshot it was locked to.
//!
//! [`crate::release`] writes a record attesting that a release passed the gate.
//! This module answers the auditor's question — *did it really, under the
//! exceptions documented at the time?* — by reconstructing the three inputs and
//! re-running the gate:
//!
//! 1. **Dependency set** — the external dependency set in the checked-out
//!    `Cargo.lock` must match the record's digest, which proves you are on the
//!    released dependency set. The digest deliberately covers the third-party
//!    packages rather than the raw file, because the release itself rewrites the
//!    crate's own version in `Cargo.lock`. Records predating that (schema 1 and
//!    2) carry a raw-file digest, which is compared instead.
//! 2. **Policy** — the checked-out `deny.toml` must match the record's policy
//!    digest, which proves the exception set is the one that was in force.
//!    Records written before that digest existed (`schema_version` 1) cannot be
//!    checked this way; the policy is then trusted from git history and the
//!    verification says so plainly rather than implying more assurance than it has.
//! 3. **Advisory snapshot** — the advisory-db checkout is moved to the recorded
//!    commit and cargo-deny runs `--offline`, so it cannot fetch and drift
//!    mid-verification.
//!
//! Run it from a checkout of the released tag; the dependency-set check is what
//! makes "are we on the right state?" self-evident rather than assumed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::{
    check::CommandRunner,
    release::{
        DENY_CHECKS, dependency_set_digest, discover_db_checkout, lockfile_digest, record_path,
        with_db_path,
    },
    sync::{about_toml_digest, locate_paths},
};

/// Digests computed from the checked-out tree, compared against the record.
#[derive(Debug, Clone)]
pub(crate) struct CheckoutDigests {
    /// Digest of the external dependency set (schema 3+).
    pub(crate) dependencies: String,
    /// Raw digest of Cargo.lock, for records predating the dependency digest.
    pub(crate) lockfile_raw: String,
    /// Digest of deny.toml — the exception set in force.
    pub(crate) deny_toml: String,
    /// Digest of every crate's about.toml (schema 4+). `None` when the
    /// checked-out workspace has no about.toml at all.
    pub(crate) about_toml: Option<String>,
}

/// What a verification concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifyOutcome {
    /// The release version verified.
    pub(crate) version: String,
    /// The advisory-db commit the record locked the release to.
    pub(crate) db_commit: String,
    /// Whether re-running the gate reproduced the record's verdict.
    pub(crate) reproduced: bool,
    /// Checks that could not be performed, e.g. an absent policy digest.
    pub(crate) unverified: Vec<String>,
    /// Inputs that did not match the record.
    pub(crate) mismatches: Vec<String>,
    /// Warnings the gate reported, for `--deny-warnings`.
    pub(crate) warnings: Vec<crate::diagnostics::WarningCount>,
    /// Configured `[[bans.skip]]` exceptions this fresh re-run flagged stale
    /// (`unmatched-skip` or `unnecessary-skip`) — safe to remove from
    /// `deny.toml`. See [`crate::exceptions`].
    pub(crate) stale_exceptions: Vec<String>,
}

impl VerifyOutcome {
    /// A verification succeeds only when nothing mismatched and the gate agreed.
    pub(crate) fn is_ok(&self) -> bool {
        self.reproduced && self.mismatches.is_empty()
    }
}

/// Read a release record from disk.
pub(crate) fn load_record(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("no release record at '{}'", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("failed to parse release record '{}'", path.display()))
}

/// A required string field, erroring rather than silently verifying nothing.
///
/// Shared with [`crate::remote`], which re-verifies the same record schema
/// from a fetched copy rather than a checked-out one.
pub(crate) fn field<'a>(record: &'a Value, path: &[&str]) -> Result<&'a str> {
    let mut cur = record;
    for key in path {
        cur = cur
            .get(key)
            .with_context(|| format!("release record has no '{}'", path.join(".")))?;
    }
    cur.as_str()
        .with_context(|| format!("release record '{}' is not a string", path.join(".")))
}

/// Compare the checked-out inputs against the record.
///
/// Returns `(mismatches, unverified)`. A record without a policy digest
/// (`schema_version` 1) yields an `unverified` note rather than a false pass.
pub(crate) fn compare_inputs(
    record: &Value,
    digests: &CheckoutDigests,
) -> (Vec<String>, Vec<String>) {
    let mut mismatches = Vec::new();
    let mut unverified = Vec::new();

    let lockfile = record.get("lockfile");
    let recorded_deps = lockfile
        .and_then(|l| l.get("dependencies_sha256"))
        .and_then(Value::as_str);
    // Records predating schema 3 digest the raw file instead. That digest cannot
    // survive the release that produced it (cargo-release rewrites the crate's
    // own version in Cargo.lock), so it is only meaningful for a record made
    // from the released state itself.
    let recorded_raw = lockfile
        .and_then(|l| l.get("sha256"))
        .and_then(Value::as_str);

    match (recorded_deps, recorded_raw) {
        (Some(recorded), _) if recorded == digests.dependencies => {}
        (Some(recorded), _) => mismatches.push(format!(
            "dependency set does not match the record (recorded {recorded}, found {}) \
             — you are not on the released dependency set",
            digests.dependencies
        )),
        (None, Some(recorded)) if recorded == digests.lockfile_raw => {}
        (None, Some(recorded)) => mismatches.push(format!(
            "Cargo.lock does not match the record (recorded {recorded}, found {}) \
             — you are not on the released state",
            digests.lockfile_raw
        )),
        (None, None) => unverified.push("record has no dependency digest".to_string()),
    }

    match record
        .get("policy")
        .and_then(|p| p.get("deny_toml_sha256"))
        .and_then(Value::as_str)
    {
        Some(recorded) if recorded == digests.deny_toml => {}
        Some(recorded) => mismatches.push(format!(
            "deny.toml does not match the record (recorded {recorded}, found {}) \
             — the exception set differs from the one in force at release",
            digests.deny_toml
        )),
        // schema_version 1 predates the policy digest.
        None => unverified.push(
            "record carries no deny.toml digest (schema_version 1) — the exception set is \
             trusted from git history, not proven by the record"
                .to_string(),
        ),
    }

    match record
        .get("policy")
        .and_then(|p| p.get("about_toml_sha256"))
        .and_then(Value::as_str)
    {
        Some(recorded) if Some(recorded) == digests.about_toml.as_deref() => {}
        Some(recorded) => mismatches.push(format!(
            "about.toml does not match the record (recorded {recorded}, found {}) \
             — the license policy differs from the one in force at release",
            digests.about_toml.as_deref().unwrap_or("none")
        )),
        // schema_version 3 and earlier predate this digest; a schema_version
        // 4+ record with an explicit null means the workspace had no
        // about.toml at release time. Neither is a mismatch — mirrors the
        // deny_toml_sha256 v1 case above, so an auditor sees exactly what
        // wasn't checked rather than a clean result implying more assurance
        // than was actually attested.
        None => unverified.push(
            "record carries no about.toml digest (schema_version 3 or earlier, or no \
             about.toml existed at release) — the license policy is not proven by the record"
                .to_string(),
        ),
    }

    (mismatches, unverified)
}

/// Re-verify the release named by `version`.
pub(crate) fn verify_with<R: CommandRunner>(
    runner: &R,
    start: &Path,
    version: &str,
    db_root: &Path,
    work_dir: &Path,
    detail: crate::diagnostics::Detail,
) -> Result<VerifyOutcome> {
    let (deny_path, _audit_path) = locate_paths(start)?;
    let root = deny_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let record = load_record(&record_path(&root, version))?;
    let db_commit = field(&record, &["advisory_db", "commit"])?.to_string();

    // Compare the checked-out inputs with what the record attests.
    let lock_text = std::fs::read_to_string(root.join("Cargo.lock"))
        .with_context(|| format!("no Cargo.lock at '{}'", root.display()))?;
    let deny_toml = std::fs::read_to_string(&deny_path)
        .with_context(|| format!("failed to read '{}'", deny_path.display()))?;
    let digests = CheckoutDigests {
        dependencies: dependency_set_digest(&lock_text)?,
        lockfile_raw: lockfile_digest(lock_text.as_bytes()),
        deny_toml: lockfile_digest(deny_toml.as_bytes()),
        about_toml: about_toml_digest(runner, &root)?,
    };
    let (mismatches, unverified) = compare_inputs(&record, &digests);

    // The tool's semantics can change between versions, so a difference is worth
    // surfacing even though we cannot install the recorded version here.
    let mut unverified = unverified;
    if let Ok(recorded_tool) = field(&record, &["tools", "cargo_deny"]) {
        let installed = runner.run("cargo-deny", &["--version"], &root)?;
        let installed = installed.stdout.lines().next().unwrap_or_default().trim();
        if !installed.is_empty() && installed != recorded_tool {
            unverified.push(format!(
                "cargo-deny is {installed} but the release used {recorded_tool} \
                 — install the recorded version for an exact reproduction"
            ));
        }
    }

    // Pin the advisory database to the recorded commit.
    let checkout = discover_db_checkout(db_root)?;
    let checkout_str = checkout.to_str().unwrap_or_default().to_string();

    // Note where the checkout was, so it can be put back. cargo-deny and
    // cargo-audit share it; leaving it on a historical commit would silently give
    // a later scan an old snapshot of the advisories.
    let previous_head = runner
        .run("git", &["-C", &checkout_str, "rev-parse", "HEAD"], &root)
        .ok()
        .filter(|o| o.success)
        .map(|o| o.stdout.trim().to_string())
        .filter(|s| !s.is_empty());

    // Only a shallow clone can be unshallowed — git rejects the flag outright on a
    // complete repository ("--unshallow on a complete repository does not make
    // sense"). Asking for it unconditionally meant the fetch failed on every run
    // after the first, so no commit newer than the local clone could ever be
    // reached, and verification failed with an unhelpful "reference is not a tree".
    let shallow = runner
        .run(
            "git",
            &["-C", &checkout_str, "rev-parse", "--is-shallow-repository"],
            &root,
        )
        .map(|o| o.stdout.trim() == "true")
        .unwrap_or(false);
    let fetch_args: Vec<&str> = if shallow {
        vec!["-C", &checkout_str, "fetch", "--unshallow", "origin"]
    } else {
        vec!["-C", &checkout_str, "fetch", "origin"]
    };
    let fetched = runner.run("git", &fetch_args, &root)?;

    let co = runner.run(
        "git",
        &["-C", &checkout_str, "checkout", "--quiet", &db_commit],
        &root,
    )?;
    if !co.success {
        // A failed fetch is only worth reporting once it has cost something, but
        // then it is usually the real cause.
        let cause = if fetched.success {
            String::new()
        } else {
            format!("\n\nfetching it first failed: {}", fetched.stderr.trim())
        };
        bail!(
            "could not check the advisory-db out at {db_commit}: {}{cause}",
            co.stderr.trim()
        );
    }

    // Re-run the gate with the historical policy, offline so it cannot drift.
    let derived = with_db_path(&deny_toml, db_root)?;
    std::fs::create_dir_all(work_dir)
        .with_context(|| format!("failed to create '{}'", work_dir.display()))?;
    let config_path = work_dir.join("deny.toml");
    std::fs::write(&config_path, derived)
        .with_context(|| format!("failed to write '{}'", config_path.display()))?;

    let mut args = vec![
        "--offline",
        "--config",
        config_path.to_str().unwrap_or_default(),
        "check",
    ];
    args.extend_from_slice(DENY_CHECKS);
    let gate = runner.run("cargo-deny", &args, &root);

    // The gate is the last thing that needs the database pinned, so put the shared
    // checkout back now — before propagating any failure from it.
    if let Some(head) = &previous_head {
        let _ = runner.run(
            "git",
            &["-C", &checkout_str, "checkout", "--quiet", head],
            &root,
        );
    }

    let gate = gate?;
    let warnings = crate::diagnostics::emit(&gate.stdout, &gate.stderr, detail);

    // Re-derive from the checked-out deny.toml against this fresh run's stderr
    // — a configured exception may have stopped firing since the release, and
    // this is the same check `deny_toml`'s digest comparison above cannot
    // answer (that proves the config text is unchanged, not that every
    // exception in it is still needed).
    let configured_skips = crate::exceptions::extract_bans_skips(&deny_toml)?;
    let stale_exceptions = crate::exceptions::accepted_warnings(configured_skips, &gate.stderr)
        .stale
        .into_iter()
        .map(|e| e.name)
        .collect();

    let recorded_pass = record
        .get("checks")
        .and_then(|c| c.get("deny"))
        .and_then(|d| d.get("passed"))
        .and_then(Value::as_bool)
        .unwrap_or(true);

    Ok(VerifyOutcome {
        version: version.to_string(),
        db_commit,
        reproduced: gate.success == recorded_pass,
        unverified,
        mismatches,
        warnings,
        stale_exceptions,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use serde_json::json;

    use super::*;
    use crate::check::ToolOutput;

    /// Current schema: also digests each crate's about.toml.
    fn record_v4(deps: &str, policy: &str, about: Option<&str>) -> Value {
        json!({
            "schema_version": 4,
            "version": "1.2.0",
            "advisory_db": { "commit": "abc1234def" },
            "tools": { "cargo_deny": "cargo-deny 0.20.2", "cargo_audit": "cargo-audit 0.22.0" },
            "lockfile": { "dependencies_sha256": deps },
            "policy": { "deny_toml_sha256": policy, "about_toml_sha256": about },
            "checks": { "deny": { "passed": true, "checks": DENY_CHECKS } },
        })
    }

    /// Predates the license-policy digest.
    fn record_v3(deps: &str, policy: &str) -> Value {
        json!({
            "schema_version": 3,
            "version": "1.2.0",
            "advisory_db": { "commit": "abc1234def" },
            "tools": { "cargo_deny": "cargo-deny 0.20.2", "cargo_audit": "cargo-audit 0.22.0" },
            "lockfile": { "dependencies_sha256": deps },
            "policy": { "deny_toml_sha256": policy },
            "checks": { "deny": { "passed": true, "checks": DENY_CHECKS } },
        })
    }

    /// Legacy schema: digests the raw lockfile.
    fn record_v2(lock: &str, policy: &str) -> Value {
        json!({
            "schema_version": 2,
            "version": "1.2.0",
            "advisory_db": { "commit": "abc1234def" },
            "tools": { "cargo_deny": "cargo-deny 0.20.2", "cargo_audit": "cargo-audit 0.22.0" },
            "lockfile": { "sha256": lock },
            "policy": { "deny_toml_sha256": policy },
            "checks": { "deny": { "passed": true, "checks": DENY_CHECKS } },
        })
    }

    fn record_v1(lock: &str) -> Value {
        json!({
            "schema_version": 1,
            "version": "1.2.0",
            "advisory_db": { "commit": "abc1234def" },
            "tools": { "cargo_deny": "cargo-deny 0.20.2", "cargo_audit": "cargo-audit 0.22.0" },
            "lockfile": { "sha256": lock },
            "checks": { "deny": { "passed": true, "checks": DENY_CHECKS } },
        })
    }

    struct MockRunner {
        deny_ok: bool,
        deny_stderr: String,
        shallow: bool,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl MockRunner {
        fn new(deny_ok: bool) -> Self {
            Self {
                deny_ok,
                deny_stderr: String::new(),
                shallow: false,
                calls: RefCell::new(Vec::new()),
            }
        }

        fn shallow(mut self) -> Self {
            self.shallow = true;
            self
        }

        fn with_deny_stderr(mut self, stderr: &str) -> Self {
            self.deny_stderr = stderr.to_string();
            self
        }

        /// The git invocation matching `verb`, if verify made one.
        fn git_call(&self, verb: &str) -> Option<Vec<String>> {
            self.calls
                .borrow()
                .iter()
                .find(|c| c[0] == "git" && c.contains(&verb.to_string()))
                .cloned()
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str], _cwd: &Path) -> Result<ToolOutput> {
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|s| s.to_string()));
            self.calls.borrow_mut().push(call);
            let ok = |s: &str| ToolOutput {
                success: true,
                stdout: s.to_string(),
                stderr: String::new(),
            };
            let has = |needle: &str| args.contains(&needle);
            Ok(match (program, args.first().copied()) {
                ("cargo-deny", Some("--version")) => ok("cargo-deny 0.20.2\n"),
                // Model the behaviour that caused the bug: git refuses --unshallow
                // on a repository that is already complete.
                ("git", _) if has("--unshallow") && !self.shallow => ToolOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "fatal: --unshallow on a complete repository does not make sense"
                        .to_string(),
                },
                ("git", _) if has("--is-shallow-repository") => {
                    ok(if self.shallow { "true\n" } else { "false\n" })
                }
                ("git", _) if has("rev-parse") => ok("0ldc0mm1t\n"),
                ("git", _) => ok(""),
                ("cargo-deny", _) => ToolOutput {
                    success: self.deny_ok,
                    stdout: "advisories ok\n".to_string(),
                    stderr: self.deny_stderr.clone(),
                },
                // No test scenario here has a real about.toml on disk, so an
                // empty workspace is always correct — find_about_toml_paths
                // filters by file existence anyway.
                ("cargo", Some("metadata")) => ok(r#"{"packages":[]}"#),
                _ => ok(""),
            })
        }
    }

    const DENY: &str = "[advisories]\ndb-path = \"~/.cargo/advisory-db\"\nignore = []\n";
    const LOCK: &str = "# lockfile\n";

    /// Repo at the released state, plus a db root with the nested checkout.
    fn scenario(record: &Value) -> (tempfile::TempDir, tempfile::TempDir) {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("deny.toml"), DENY).unwrap();
        std::fs::write(repo.path().join("Cargo.lock"), LOCK).unwrap();
        let dir = repo.path().join(".security");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("release-1.2.0.json"),
            serde_json::to_string_pretty(record).unwrap(),
        )
        .unwrap();
        let db = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(db.path().join("advisory-db-3157b0e258782691")).unwrap();
        (repo, db)
    }

    #[test]
    fn matching_inputs_have_no_mismatches() {
        // v4, with every digest present and matching: nothing left unverified.
        let rec = record_v4("deps-sha", "policy-sha", Some("about-sha"));
        let d = CheckoutDigests {
            dependencies: "deps-sha".into(),
            lockfile_raw: "raw".into(),
            deny_toml: "policy-sha".into(),
            about_toml: Some("about-sha".to_string()),
        };
        let (mismatches, unverified) = compare_inputs(&rec, &d);
        assert!(mismatches.is_empty(), "got {mismatches:?}");
        assert!(unverified.is_empty(), "got {unverified:?}");
    }

    #[test]
    fn lockfile_mismatch_is_reported() {
        let rec = record_v3("deps-sha", "policy-sha");
        let d = CheckoutDigests {
            dependencies: "DIFFERENT".into(),
            lockfile_raw: "raw".into(),
            deny_toml: "policy-sha".into(),
            about_toml: None,
        };
        let (mismatches, _) = compare_inputs(&rec, &d);
        assert_eq!(mismatches.len(), 1);
        assert!(
            mismatches[0].contains("dependency set"),
            "got {mismatches:?}"
        );
    }

    #[test]
    fn policy_mismatch_is_reported() {
        let rec = record_v3("deps-sha", "policy-sha");
        let d = CheckoutDigests {
            dependencies: "deps-sha".into(),
            lockfile_raw: "raw".into(),
            deny_toml: "DIFFERENT".into(),
            about_toml: None,
        };
        let (mismatches, _) = compare_inputs(&rec, &d);
        assert_eq!(mismatches.len(), 1);
        assert!(mismatches[0].contains("deny.toml"), "got {mismatches:?}");
    }

    #[test]
    fn about_toml_digest_mismatch_is_reported() {
        let rec = record_v4("deps-sha", "policy-sha", Some("about-sha"));
        let d = CheckoutDigests {
            dependencies: "deps-sha".into(),
            lockfile_raw: "raw".into(),
            deny_toml: "policy-sha".into(),
            about_toml: Some("DIFFERENT".to_string()),
        };
        let (mismatches, _) = compare_inputs(&rec, &d);
        assert_eq!(mismatches.len(), 1);
        assert!(mismatches[0].contains("about.toml"), "got {mismatches:?}");
    }

    #[test]
    fn recorded_digest_but_no_about_toml_now_is_a_mismatch() {
        // The record attests about.toml content that no longer exists at all.
        let rec = record_v4("deps-sha", "policy-sha", Some("about-sha"));
        let d = CheckoutDigests {
            dependencies: "deps-sha".into(),
            lockfile_raw: "raw".into(),
            deny_toml: "policy-sha".into(),
            about_toml: None,
        };
        let (mismatches, _) = compare_inputs(&rec, &d);
        assert_eq!(mismatches.len(), 1);
        assert!(mismatches[0].contains("about.toml"), "got {mismatches:?}");
    }

    #[test]
    fn v3_record_has_no_about_toml_digest_and_is_reported_unverified() {
        // No about_toml_sha256 field at all (schema_version 3) — not a
        // mismatch, but flagged unverified, mirroring the v1 deny_toml_sha256
        // case: not checked is not the same as verified clean.
        let rec = record_v3("deps-sha", "policy-sha");
        let d = CheckoutDigests {
            dependencies: "deps-sha".into(),
            lockfile_raw: "raw".into(),
            deny_toml: "policy-sha".into(),
            about_toml: Some("anything".to_string()),
        };
        let (mismatches, unverified) = compare_inputs(&rec, &d);
        assert!(mismatches.is_empty(), "got {mismatches:?}");
        assert_eq!(unverified.len(), 1);
        assert!(
            unverified[0].contains("about.toml"),
            "must say the license policy was not verified: {unverified:?}"
        );
    }

    #[test]
    fn v4_record_with_null_about_toml_digest_is_reported_unverified() {
        // schema_version 4, but the workspace had no about.toml at release
        // time (about_toml_sha256: null) — also not a mismatch, but still
        // worth flagging: the checkout may have gained an about.toml since.
        let rec = record_v4("deps-sha", "policy-sha", None);
        let d = CheckoutDigests {
            dependencies: "deps-sha".into(),
            lockfile_raw: "raw".into(),
            deny_toml: "policy-sha".into(),
            about_toml: Some("something-added-since".to_string()),
        };
        let (mismatches, unverified) = compare_inputs(&rec, &d);
        assert!(mismatches.is_empty(), "got {mismatches:?}");
        assert_eq!(unverified.len(), 1);
    }

    #[test]
    fn v1_record_cannot_verify_policy_but_still_checks_the_lockfile() {
        let rec = record_v1("raw-lock-sha");
        let d = CheckoutDigests {
            dependencies: "deps".into(),
            lockfile_raw: "raw-lock-sha".into(),
            deny_toml: "anything".into(),
            about_toml: None,
        };
        let (mismatches, unverified) = compare_inputs(&rec, &d);
        assert!(mismatches.is_empty(), "v1 policy absence is not a mismatch");
        // A v1 record predates both the deny.toml and the about.toml digest.
        assert_eq!(unverified.len(), 2, "got {unverified:?}");
        assert!(
            unverified
                .iter()
                .any(|u| u.contains("deny.toml") || u.contains("policy")),
            "must say the advisory policy was not verified: {unverified:?}"
        );
        assert!(
            unverified.iter().any(|u| u.contains("about.toml")),
            "must say the license policy was not verified: {unverified:?}"
        );
        // …but a v1 lockfile mismatch is still caught, via the raw digest.
        let d = CheckoutDigests {
            lockfile_raw: "DIFFERENT".into(),
            ..d
        };
        let (mismatches, _) = compare_inputs(&rec, &d);
        assert_eq!(mismatches.len(), 1);
    }

    #[test]
    fn verify_reproduces_a_good_release() {
        let rec = record_v2(
            &lockfile_digest(LOCK.as_bytes()),
            &lockfile_digest(DENY.as_bytes()),
        );
        let (repo, db) = scenario(&rec);
        let runner = MockRunner::new(true);
        let out = verify_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
        assert!(out.is_ok(), "should reproduce: {out:?}");
        assert_eq!(out.db_commit, "abc1234def");
    }

    #[test]
    fn stale_bans_skip_entries_are_reported_from_the_fresh_gate_run() {
        let rec = record_v2(
            &lockfile_digest(LOCK.as_bytes()),
            &lockfile_digest(
                "[advisories]\ndb-path = \"~/.cargo/advisory-db\"\nignore = []\n\n\
                 [[bans.skip]]\nname = \"widget\"\n"
                    .as_bytes(),
            ),
        );
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(
            repo.path().join("deny.toml"),
            "[advisories]\ndb-path = \"~/.cargo/advisory-db\"\nignore = []\n\n\
             [[bans.skip]]\nname = \"widget\"\n",
        )
        .unwrap();
        std::fs::write(repo.path().join("Cargo.lock"), LOCK).unwrap();
        let dir = repo.path().join(".security");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("release-1.2.0.json"),
            serde_json::to_string_pretty(&rec).unwrap(),
        )
        .unwrap();
        let db = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(db.path().join("advisory-db-3157b0e258782691")).unwrap();

        // widget no longer duplicates by the time of this re-run.
        let runner = MockRunner::new(true).with_deny_stderr(
            "warning[unmatched-skip]: skipped crate 'widget' was not encountered\n",
        );
        let out = verify_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();

        assert_eq!(out.stale_exceptions, vec!["widget".to_string()]);
    }

    #[test]
    fn verify_pins_the_db_to_the_recorded_commit_and_runs_offline() {
        let rec = record_v2(
            &lockfile_digest(LOCK.as_bytes()),
            &lockfile_digest(DENY.as_bytes()),
        );
        let (repo, db) = scenario(&rec);
        let runner = MockRunner::new(true);
        verify_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();

        let calls = runner.calls.borrow();
        let checkout = calls
            .iter()
            .find(|c| c[0] == "git" && c.contains(&"checkout".to_string()))
            .expect("must check the db out at the recorded commit");
        assert!(
            checkout.contains(&"abc1234def".to_string()),
            "call: {checkout:?}"
        );
        let gate = calls
            .iter()
            .find(|c| c[0] == "cargo-deny" && c.contains(&"check".to_string()))
            .expect("must re-run the gate");
        assert!(
            gate.contains(&"--offline".to_string()),
            "the gate must not be able to fetch: {gate:?}"
        );
    }

    #[test]
    fn a_complete_checkout_is_fetched_without_unshallow() {
        // git refuses --unshallow once the clone is complete, and cargo-deny's
        // checkout becomes complete the first time verify unshallows it. Asking
        // for it unconditionally meant every later run fetched nothing, so a
        // record naming a newer commit could not be verified at all — which is
        // every release after the first.
        let rec = record_v2(
            &lockfile_digest(LOCK.as_bytes()),
            &lockfile_digest(DENY.as_bytes()),
        );
        let (repo, db) = scenario(&rec);
        let runner = MockRunner::new(true);
        verify_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();

        let fetch = runner
            .git_call("fetch")
            .expect("must fetch before checking out");
        assert!(
            !fetch.contains(&"--unshallow".to_string()),
            "a complete clone must be fetched plainly: {fetch:?}"
        );
    }

    #[test]
    fn a_shallow_checkout_is_unshallowed() {
        // The other half: a shallow clone genuinely lacks the history, so the
        // recorded commit is only reachable after unshallowing.
        let rec = record_v2(
            &lockfile_digest(LOCK.as_bytes()),
            &lockfile_digest(DENY.as_bytes()),
        );
        let (repo, db) = scenario(&rec);
        let runner = MockRunner::new(true).shallow();
        verify_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();

        let fetch = runner.git_call("fetch").expect("must fetch");
        assert!(
            fetch.contains(&"--unshallow".to_string()),
            "a shallow clone needs its history: {fetch:?}"
        );
    }

    #[test]
    fn the_shared_checkout_is_put_back_afterwards() {
        // cargo-deny and cargo-audit share this checkout. Leaving it parked on the
        // release's historical commit would hand a later, unrelated scan an old
        // snapshot of the advisories without saying so.
        let rec = record_v2(
            &lockfile_digest(LOCK.as_bytes()),
            &lockfile_digest(DENY.as_bytes()),
        );
        let (repo, db) = scenario(&rec);
        let runner = MockRunner::new(true);
        verify_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();

        let checkouts: Vec<Vec<String>> = runner
            .calls
            .borrow()
            .iter()
            .filter(|c| c[0] == "git" && c.contains(&"checkout".to_string()))
            .cloned()
            .collect();
        assert_eq!(checkouts.len(), 2, "pin then restore: {checkouts:?}");
        assert!(
            checkouts[0].contains(&"abc1234def".to_string()),
            "first pins the recorded commit: {:?}",
            checkouts[0]
        );
        assert!(
            checkouts[1].contains(&"0ldc0mm1t".to_string()),
            "then restores where it was: {:?}",
            checkouts[1]
        );
    }

    #[test]
    fn the_checkout_is_restored_even_when_the_gate_fails() {
        let rec = record_v2(
            &lockfile_digest(LOCK.as_bytes()),
            &lockfile_digest(DENY.as_bytes()),
        );
        let (repo, db) = scenario(&rec);
        let runner = MockRunner::new(false); // gate fails
        let _ = verify_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        );
        let restored = runner
            .calls
            .borrow()
            .iter()
            .any(|c| c[0] == "git" && c.contains(&"0ldc0mm1t".to_string()));
        assert!(
            restored,
            "a failing gate must not strand the shared checkout"
        );
    }

    #[test]
    fn diverging_gate_fails_verification() {
        let rec = record_v2(
            &lockfile_digest(LOCK.as_bytes()),
            &lockfile_digest(DENY.as_bytes()),
        );
        let (repo, db) = scenario(&rec);
        let runner = MockRunner::new(false); // gate now fails
        let out = verify_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
        assert!(!out.is_ok(), "a failing gate must not verify");
        assert!(!out.reproduced);
    }

    #[test]
    fn wrong_checkout_is_caught_before_the_gate_runs() {
        // Record describes a different dependency set than the one checked out.
        let rec = record_v3(
            "some-other-dependency-digest",
            &lockfile_digest(DENY.as_bytes()),
        );
        let (repo, db) = scenario(&rec);
        let runner = MockRunner::new(true);
        let out = verify_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
        assert!(!out.is_ok());
        assert!(
            out.mismatches.iter().any(|m| m.contains("dependency set")),
            "got {:?}",
            out.mismatches
        );
    }

    #[test]
    fn missing_record_is_an_error() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("deny.toml"), DENY).unwrap();
        std::fs::write(repo.path().join("Cargo.lock"), LOCK).unwrap();
        let db = tempfile::tempdir().unwrap();
        let runner = MockRunner::new(true);
        let err = verify_with(
            &runner,
            repo.path(),
            "9.9.9",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap_err();
        assert!(err.to_string().contains("release record"), "got: {err}");
    }
}
