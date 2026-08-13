//! Reproducible release gate.
//!
//! Division of labour between the two tools:
//!
//! - **cargo-audit is the currency check** — it always runs against the *live*
//!   RustSec database. Every PR gates on it (see [`crate::check`]), so newly
//!   published advisories are caught continuously between releases. At release
//!   time it runs again purely as a **non-blocking** warning.
//! - **cargo-deny is the release gate** — it runs against a **local copy** of the
//!   advisory database, which is refreshed as part of the release and whose commit
//!   is then recorded. That *locks* the release to a known advisory snapshot.
//!
//! cargo-deny manages the local copy itself, at `<db-path>/advisory-db-<hash>`
//! (`db-path` defaults to `~/.cargo/advisory-db`). It is a shallow, depth-1 clone
//! of ~10 MB, so in CI — where the path is ephemeral per job — it is simply
//! re-cloned at the start of the release run, which is exactly what makes the
//! copy current at release time. The hash segment is URL-derived and
//! undocumented, so the checkout is **discovered**, never computed.
//!
//! The db path can only be set through cargo-deny's config, not its CLI, so the
//! repo's `deny.toml` is copied to an **ephemeral** derived config with only
//! `[advisories].db-path` overridden. Every other policy — licenses, bans,
//! sources, and the justified ignores — is inherited verbatim, keeping
//! `deny.toml` the single source of truth (nothing derived is committed except
//! the record itself).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use toml_edit::{DocumentMut, Item, value};

use crate::{
    check::CommandRunner,
    sync::{SyncOutcome, about_toml_digest, locate_paths, sync_about_toml_at},
};

/// Schema version of the emitted record, so consumers can evolve with it.
///
/// v4 adds `policy.about_toml_sha256`: the release gate now also verifies
/// each crate's `about.toml` still matches `deny.toml`'s license policy and
/// that `cargo-about` can resolve every reachable dependency's license,
/// before the record is written. `verify` treats a missing
/// `about_toml_sha256` on a v3-or-earlier record as "not checked," not a
/// failure.
pub const RECORD_SCHEMA_VERSION: u64 = 4;

/// The cargo-deny checks the release gate enforces.
pub const DENY_CHECKS: &[&str] = &["advisories", "bans", "licenses", "sources"];

/// Outcome of a release validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseOutcome {
    /// Where the record was written.
    pub record_path: PathBuf,
    /// Warnings the gate reported, for `--deny-warnings`.
    pub warnings: Vec<crate::diagnostics::WarningCount>,
    /// The advisory-db commit the release is locked to.
    pub db_commit: String,
    /// Whether the blocking cargo-deny gate passed.
    pub deny_passed: bool,
    /// Advisory ids the live (non-blocking) audit reported.
    pub live_findings: Vec<String>,
}

/// Override `[advisories].db-path` in a `deny.toml`, leaving every other setting
/// untouched. Creates the `[advisories]` table if the config lacks one.
pub fn with_db_path(deny_toml: &str, db_path: &Path) -> Result<String> {
    let mut doc = deny_toml
        .parse::<DocumentMut>()
        .context("failed to parse deny.toml")?;
    let advisories = doc
        .entry("advisories")
        .or_insert(toml_edit::table())
        .as_table_mut()
        .context("deny.toml [advisories] is not a table")?;
    advisories["db-path"] = value(db_path.display().to_string());
    Ok(doc.to_string())
}

/// Hex-encoded SHA-256 of the lockfile bytes — records exactly which dependency
/// set was validated.
pub fn lockfile_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut acc, byte| {
            use std::fmt::Write;
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

/// Digest of the **external** dependency set in a `Cargo.lock`.
///
/// Only `[[package]]` entries carrying a `source` are included. Workspace-local
/// packages have none, and their version lines are rewritten by the release
/// itself — cargo-release bumps the crate's version in `Cargo.lock` as part of
/// the release commit — so hashing them would make the record depend on the
/// release rather than on what was audited, and a later `verify` against the
/// released tag would report a false mismatch.
///
/// The digest therefore states exactly what it means: the third-party
/// dependency set the gate validated. Entries are sorted, so it does not depend
/// on lockfile ordering.
pub fn dependency_set_digest(lockfile_toml: &str) -> Result<String> {
    let doc = lockfile_toml
        .parse::<DocumentMut>()
        .context("failed to parse Cargo.lock")?;

    let mut entries: Vec<String> = doc
        .get("package")
        .and_then(Item::as_array_of_tables)
        .map(|packages| {
            packages
                .iter()
                .filter_map(|pkg| {
                    // No `source` => a workspace-local package, excluded.
                    let source = pkg.get("source")?.as_str()?;
                    let name = pkg.get("name")?.as_str()?;
                    let version = pkg.get("version")?.as_str()?;
                    let checksum = pkg
                        .get("checksum")
                        .and_then(|c| c.as_str())
                        .unwrap_or_default();
                    Some(format!("{name} {version} {source} {checksum}"))
                })
                .collect()
        })
        .unwrap_or_default();
    entries.sort();

    Ok(lockfile_digest(entries.join("\n").as_bytes()))
}

/// Discover cargo-deny's advisory-db checkout beneath `root`.
///
/// cargo-deny nests it as `advisory-db-<url-hash>`; the hash is undocumented, so
/// the single matching directory is located rather than derived. Errors when
/// none or several exist, since neither can be recorded unambiguously.
pub fn discover_db_checkout(root: &Path) -> Result<PathBuf> {
    let entries = std::fs::read_dir(root)
        .with_context(|| format!("cannot read advisory-db root '{}'", root.display()))?;
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("advisory-db-"))
        })
        .collect();
    found.sort();

    match found.len() {
        1 => Ok(found.remove(0)),
        0 => bail!(
            "no advisory-db checkout found under '{}' — cargo-deny nests it as \
             advisory-db-<hash>; run the release gate so cargo-deny clones it first",
            root.display()
        ),
        n => bail!(
            "found {n} advisory-db checkouts under '{}'; cannot record which snapshot \
             the release is locked to — leave exactly one",
            root.display()
        ),
    }
}

/// Path of the release record for `version`, relative to the repo root.
pub fn record_path(root: &Path, version: &str) -> PathBuf {
    root.join(".security")
        .join(format!("release-{version}.json"))
}

/// Build the release record.
///
/// Deterministic by construction: no timestamps, and no live-audit results (the
/// live database moves, so including it would break byte-identical re-runs).
/// `serde_json` maps are sorted, so key order is stable too.
pub fn build_record(
    version: &str,
    db_commit: &str,
    deny_version: &str,
    audit_version: &str,
    dependencies_sha256: &str,
    deny_toml_sha256: &str,
    about_toml_sha256: Option<&str>,
) -> Value {
    json!({
        "schema_version": RECORD_SCHEMA_VERSION,
        "version": version,
        "advisory_db": { "commit": db_commit },
        "tools": { "cargo_deny": deny_version, "cargo_audit": audit_version },
        // The EXTERNAL dependency set, not the raw file: cargo-release rewrites
        // the crate's own version in Cargo.lock as part of the release commit,
        // so a raw digest would not survive the release it describes.
        "lockfile": { "dependencies_sha256": dependencies_sha256 },
        // The policy digest makes the record self-verifying: it proves WHICH
        // exception set (deny.toml ignores, licenses, bans, sources) was in
        // force, rather than trusting git history to supply it.
        // about_toml_sha256 is the same guarantee for license policy, only
        // present once the drift + policy-resolution checks have passed —
        // `None` (-> null) when the workspace has no about.toml at all.
        "policy": { "deny_toml_sha256": deny_toml_sha256, "about_toml_sha256": about_toml_sha256 },
        "checks": { "deny": { "passed": true, "checks": DENY_CHECKS } },
    })
}

/// Serialise the record exactly as it is written to disk (pretty, trailing
/// newline) so callers can compare runs byte-for-byte.
pub fn render_record(record: &Value) -> Result<String> {
    let mut out = serde_json::to_string_pretty(record)?;
    out.push('\n');
    Ok(out)
}

/// First line of a `--version` output, e.g. `cargo-deny 0.20.2`.
fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_string()
}

/// Default env var consulted for the release version when `--version` is not
/// given. Release pipelines compute the version at runtime (nextsv), so it
/// cannot always be supplied as a config-time orb parameter.
pub const DEFAULT_VERSION_ENV: &str = "SEMVER";

/// Resolve the release version: the explicit value wins, otherwise the named
/// environment variable. Erroring here beats recording a release under an empty
/// or wrong version.
pub fn resolve_version(explicit: Option<&str>, env_name: &str) -> Result<String> {
    if let Some(v) = explicit.map(str::trim).filter(|v| !v.is_empty()) {
        return Ok(v.to_string());
    }
    match std::env::var(env_name) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => bail!(
            "no release version: pass --version, or export the variable named by \
             --version-env (currently {env_name})"
        ),
    }
}

/// Run the release gate.
///
/// `db_root` is cargo-deny's `db-path` (it clones/refreshes its checkout
/// beneath it); `work_dir` holds the ephemeral derived config. The record is
/// written only when the blocking gate passes — it attests a good release.
pub fn release_with<R: CommandRunner>(
    runner: &R,
    start: &Path,
    version: &str,
    db_root: &Path,
    work_dir: &Path,
    detail: crate::diagnostics::Detail,
) -> Result<ReleaseOutcome> {
    let (deny_path, _audit_path) = locate_paths(start)?;
    let root = deny_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let lockfile = root.join("Cargo.lock");
    let lock_text = std::fs::read_to_string(&lockfile)
        .with_context(|| format!("no Cargo.lock found at '{}'", lockfile.display()))?;
    let dependencies_sha256 = dependency_set_digest(&lock_text)?;

    // License-policy checks, before the expensive advisory-db refresh below —
    // the same "catch it before the expensive part" pattern this org uses for
    // release version calculation. Pure derivation first (cheap, no
    // cargo-about needed): does every crate's about.toml still match
    // deny.toml's policy?
    let about_sync = sync_about_toml_at(runner, start, true)?;
    let drifted: Vec<String> = about_sync
        .iter()
        .filter(|r| r.outcome == SyncOutcome::Drift)
        .map(|r| r.about_toml_path.display().to_string())
        .collect();
    if !drifted.is_empty() {
        bail!(
            "release gate failed: about.toml is out of sync with deny.toml ({}); \
             run `jci-audit sync` (no record written)",
            drifted.join(", ")
        );
    }

    // Then policy resolvability: can cargo-about actually attribute every
    // reachable dependency's license, not just is about.toml internally
    // consistent with deny.toml? Cache-independent (`--output-file /dev/null`
    // discards the rendered text — see `scripts/licenses.sh`'s own comment on
    // why the rendered bytes are not reproducible across machines). Aggregated
    // across every crate before bailing, matching the drift check above —
    // one release attempt should surface every unresolvable crate, not just
    // whichever happened to sort first.
    let mut unresolved = Vec::new();
    for result in &about_sync {
        let crate_dir = result
            .about_toml_path
            .parent()
            .context("about.toml path has no parent directory")?;
        let resolve = runner.run(
            "cargo-about",
            &[
                "generate",
                "--locked",
                "about.hbs",
                "--output-file",
                "/dev/null",
            ],
            crate_dir,
        )?;
        if !resolve.success {
            unresolved.push(format!(
                "{}: {}",
                crate_dir.display(),
                resolve.stderr.trim()
            ));
        }
    }
    if !unresolved.is_empty() {
        bail!(
            "release gate failed: cargo-about could not resolve licences for {} crate(s) \
             (no record written):\n{}",
            unresolved.len(),
            unresolved.join("\n")
        );
    }
    let about_toml_sha256 = about_toml_digest(&root)?;

    // Derived config: only db-path is overridden, so the repo's deny.toml stays
    // the single source of truth for every actual policy decision.
    let deny_toml = std::fs::read_to_string(&deny_path)
        .with_context(|| format!("failed to read '{}'", deny_path.display()))?;
    let deny_toml_sha256 = lockfile_digest(deny_toml.as_bytes());
    let derived = with_db_path(&deny_toml, db_root)?;
    std::fs::create_dir_all(work_dir)
        .with_context(|| format!("failed to create '{}'", work_dir.display()))?;
    let config_path = work_dir.join("deny.toml");
    std::fs::write(&config_path, derived)
        .with_context(|| format!("failed to write '{}'", config_path.display()))?;
    tracing::info!(db_path = %db_root.display(), "release gate: cargo-deny against the local advisory-db copy");

    // Blocking gate. Fetching is allowed here: refreshing the local copy is what
    // makes the snapshot current at release time.
    let mut deny_args = vec![
        "--config",
        config_path.to_str().unwrap_or_default(),
        "check",
    ];
    deny_args.extend_from_slice(DENY_CHECKS);
    let deny = runner.run("cargo-deny", &deny_args, &root)?;
    let warnings = crate::diagnostics::emit(&deny.stdout, &deny.stderr, detail);

    // Read the commit AFTER the gate, so it reflects the refreshed copy.
    let checkout = discover_db_checkout(db_root)?;
    let rev = runner.run(
        "git",
        &[
            "-C",
            checkout.to_str().unwrap_or_default(),
            "rev-parse",
            "HEAD",
        ],
        &root,
    )?;
    if !rev.success {
        bail!(
            "failed to read the advisory-db commit from '{}': {}",
            checkout.display(),
            rev.stderr.trim()
        );
    }
    let db_commit = first_line(&rev.stdout);
    if db_commit.is_empty() {
        bail!("advisory-db commit came back empty; cannot lock the release");
    }

    let deny_version = first_line(&runner.run("cargo-deny", &["--version"], &root)?.stdout);
    let audit_version = first_line(&runner.run("cargo-audit", &["--version"], &root)?.stdout);

    // Currency check — informational only. PRs already gate on the live audit, so
    // a fresh advisory here is a warning, not a release blocker.
    let live = runner.run(
        "cargo-audit",
        &[
            "audit",
            "--file",
            lockfile.to_str().unwrap_or_default(),
            "--json",
        ],
        &root,
    )?;
    let live_findings = crate::prune::parse_firing_ids(&live.stdout).unwrap_or_default();

    if !deny.success {
        bail!("release gate failed: cargo-deny reported findings (no record written)");
    }

    let record = build_record(
        version,
        &db_commit,
        &deny_version,
        &audit_version,
        &dependencies_sha256,
        &deny_toml_sha256,
        about_toml_sha256.as_deref(),
    );
    let path = record_path(&root, version);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create '{}'", parent.display()))?;
    }
    std::fs::write(&path, render_record(&record)?)
        .with_context(|| format!("failed to write '{}'", path.display()))?;

    Ok(ReleaseOutcome {
        record_path: path,
        warnings,
        db_commit,
        deny_passed: deny.success,
        live_findings,
    })
}

/// Ephemeral directory for the derived cargo-deny config. Process-scoped so
/// concurrent runs cannot collide; nothing here is committed.
pub fn work_dir() -> PathBuf {
    std::env::temp_dir().join(format!("jci-audit-release-{}", std::process::id()))
}

/// cargo-deny's default `db-path`, resolved from `$HOME`.
pub fn default_db_root() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".cargo")
        .join("advisory-db")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY_WITH_PATH: &str = r#"[advisories]
db-path = "~/.cargo/advisory-db"
unmaintained = "all"
ignore = ["RUSTSEC-2023-0071"]

[licenses]
allow = ["MIT"]
"#;

    const DENY_WITHOUT_ADVISORIES: &str = r#"[licenses]
allow = ["MIT"]
"#;

    #[test]
    fn db_path_is_overridden_and_policy_preserved() {
        let out = with_db_path(DENY_WITH_PATH, Path::new("/pinned/db")).unwrap();
        assert!(out.contains(r#"db-path = "/pinned/db""#), "got:\n{out}");
        assert!(
            !out.contains("~/.cargo/advisory-db"),
            "old path remains:\n{out}"
        );
        // Every other policy setting is inherited verbatim.
        assert!(out.contains(r#"unmaintained = "all""#), "got:\n{out}");
        assert!(
            out.contains("RUSTSEC-2023-0071"),
            "ignores must survive:\n{out}"
        );
        assert!(out.contains("[licenses]"), "got:\n{out}");
    }

    #[test]
    fn db_path_added_when_advisories_table_missing() {
        let out = with_db_path(DENY_WITHOUT_ADVISORIES, Path::new("/pinned/db")).unwrap();
        assert!(out.contains("[advisories]"), "got:\n{out}");
        assert!(out.contains(r#"db-path = "/pinned/db""#), "got:\n{out}");
        assert!(out.contains("[licenses]"), "existing config kept:\n{out}");
    }

    #[test]
    fn digest_is_stable_and_content_sensitive() {
        let a = lockfile_digest(b"# lockfile\n");
        assert_eq!(a, lockfile_digest(b"# lockfile\n"), "must be deterministic");
        assert_ne!(a, lockfile_digest(b"# other\n"), "must depend on content");
        assert_eq!(a.len(), 64, "hex sha256 is 64 chars: {a}");
    }

    const LOCK_SAMPLE: &str = r#"
version = 4

[[package]]
name = "jci-audit"
version = "0.0.2"
dependencies = ["clap"]

[[package]]
name = "clap"
version = "4.6.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d91e0c145792ef73a6ad36d27c75ac09f1832222a3c209689d90f534685ee5b7"
"#;

    #[test]
    fn dependency_digest_ignores_the_workspace_version_bump() {
        // THE property this exists for: cargo-release rewrites the crate's own
        // version in Cargo.lock during the release, so the digest must not move.
        let bumped = LOCK_SAMPLE.replace(r#"version = "0.0.2""#, r#"version = "0.0.3""#);
        assert_eq!(
            dependency_set_digest(LOCK_SAMPLE).unwrap(),
            dependency_set_digest(&bumped).unwrap(),
            "the release's own version bump must not change the dependency digest"
        );
    }

    #[test]
    fn dependency_digest_tracks_external_dependencies() {
        let changed = LOCK_SAMPLE.replace(r#"version = "4.6.4""#, r#"version = "4.6.5""#);
        assert_ne!(
            dependency_set_digest(LOCK_SAMPLE).unwrap(),
            dependency_set_digest(&changed).unwrap(),
            "an external dependency change MUST change the digest"
        );
        let rechecksummed = LOCK_SAMPLE.replace("d91e0c1457", "0000000000");
        assert_ne!(
            dependency_set_digest(LOCK_SAMPLE).unwrap(),
            dependency_set_digest(&rechecksummed).unwrap(),
            "a checksum change MUST change the digest"
        );
    }

    #[test]
    fn dependency_digest_is_order_independent_and_stable() {
        let a = dependency_set_digest(LOCK_SAMPLE).unwrap();
        assert_eq!(a, dependency_set_digest(LOCK_SAMPLE).unwrap());
        assert_eq!(a.len(), 64);
        // An empty lockfile has no external packages but is still well-defined.
        assert!(
            dependency_set_digest(
                "version = 4
"
            )
            .is_ok()
        );
    }

    #[test]
    fn discovers_the_single_nested_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let checkout = dir.path().join("advisory-db-3157b0e258782691");
        std::fs::create_dir_all(&checkout).unwrap();
        assert_eq!(discover_db_checkout(dir.path()).unwrap(), checkout);
    }

    #[test]
    fn discovery_errors_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let err = discover_db_checkout(dir.path()).unwrap_err();
        assert!(err.to_string().contains("advisory-db"), "got: {err}");
    }

    #[test]
    fn discovery_errors_when_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("advisory-db-aaa")).unwrap();
        std::fs::create_dir_all(dir.path().join("advisory-db-bbb")).unwrap();
        let err = discover_db_checkout(dir.path()).unwrap_err();
        assert!(err.to_string().contains("advisory-db"), "got: {err}");
    }

    #[test]
    fn record_is_deterministic_and_omits_volatile_data() {
        let a = build_record(
            "1.2.0",
            "abc123",
            "cargo-deny 0.20.2",
            "cargo-audit 0.22.0",
            "deps1",
            "p1",
            Some("a1"),
        );
        let b = build_record(
            "1.2.0",
            "abc123",
            "cargo-deny 0.20.2",
            "cargo-audit 0.22.0",
            "deps1",
            "p1",
            Some("a1"),
        );
        assert_eq!(render_record(&a).unwrap(), render_record(&b).unwrap());
        // Both policy digests prove which exception set was in force.
        assert!(
            render_record(&a)
                .unwrap()
                .contains("\"deny_toml_sha256\": \"p1\""),
            "record must carry the policy digest"
        );
        assert!(
            render_record(&a)
                .unwrap()
                .contains("\"about_toml_sha256\": \"a1\""),
            "record must carry the license-policy digest"
        );

        let rendered = render_record(&a).unwrap();
        assert!(
            rendered.contains("\"commit\": \"abc123\""),
            "got:\n{rendered}"
        );
        assert!(
            rendered.contains("\"dependencies_sha256\": \"deps1\""),
            "got:\n{rendered}"
        );
        // Volatile data must never be recorded.
        for forbidden in ["timestamp", "date", "live", "generated_at"] {
            assert!(
                !rendered.contains(forbidden),
                "record must omit '{forbidden}':\n{rendered}"
            );
        }
    }

    #[test]
    fn version_resolution_prefers_the_explicit_value() {
        unsafe { std::env::set_var("JCI_TEST_VERSION_ENV", "9.9.9") };
        assert_eq!(
            resolve_version(Some("1.2.0"), "JCI_TEST_VERSION_ENV").unwrap(),
            "1.2.0"
        );
        // Falls back to the environment when not supplied…
        assert_eq!(
            resolve_version(None, "JCI_TEST_VERSION_ENV").unwrap(),
            "9.9.9"
        );
        // …and an empty flag is treated as absent, not as an empty version.
        assert_eq!(
            resolve_version(Some("  "), "JCI_TEST_VERSION_ENV").unwrap(),
            "9.9.9"
        );
        unsafe { std::env::remove_var("JCI_TEST_VERSION_ENV") };
    }

    #[test]
    fn version_resolution_errors_rather_than_guessing() {
        let err = resolve_version(None, "JCI_TEST_ABSENT_VERSION_ENV").unwrap_err();
        assert!(err.to_string().contains("no release version"), "got: {err}");
    }

    #[test]
    fn record_path_is_under_dot_security() {
        let p = record_path(Path::new("/repo"), "1.2.0");
        assert_eq!(p, PathBuf::from("/repo/.security/release-1.2.0.json"));
    }

    #[test]
    fn version_line_is_trimmed_to_first_line() {
        assert_eq!(
            first_line("cargo-deny 0.20.2\nextra\n"),
            "cargo-deny 0.20.2"
        );
        assert_eq!(first_line(""), "");
    }

    // ── orchestration ──────────────────────────────────────────────────────

    use std::cell::RefCell;

    use crate::check::ToolOutput;

    /// A trivial `cargo metadata` graph: one root package, no dependencies.
    /// Yields an empty crate-scoped `accepted` set, so an about.toml
    /// committed with `accepted = []` and no exceptions is already in sync.
    fn trivial_metadata_json() -> String {
        r#"{"packages":[{"name":"demo","version":"0.0.0","id":"path+file:///demo#0.0.0","license":null}],"resolve":{"root":"path+file:///demo#0.0.0","nodes":[{"id":"path+file:///demo#0.0.0","deps":[]}]}}"#.to_string()
    }

    /// Dispatches on (program, first arg) so each tool can be scripted.
    struct MockRunner {
        deny_ok: bool,
        live_json: String,
        metadata_json: String,
        about_ok: bool,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl MockRunner {
        fn new(deny_ok: bool, live_json: &str) -> Self {
            Self {
                deny_ok,
                live_json: live_json.to_string(),
                metadata_json: trivial_metadata_json(),
                about_ok: true,
                calls: RefCell::new(Vec::new()),
            }
        }
        fn with_about_ok(mut self, ok: bool) -> Self {
            self.about_ok = ok;
            self
        }
        fn ran(&self, program: &str) -> Vec<Vec<String>> {
            self.calls
                .borrow()
                .iter()
                .filter(|c| c[0] == program)
                .cloned()
                .collect()
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
            Ok(match (program, args.first().copied()) {
                ("git", _) => ok("abc1234def\n"),
                ("cargo-deny", Some("--version")) => ok("cargo-deny 0.20.2\n"),
                ("cargo-audit", Some("--version")) => ok("cargo-audit 0.22.0\n"),
                ("cargo-audit", _) => ok(&self.live_json),
                ("cargo-deny", _) => ToolOutput {
                    success: self.deny_ok,
                    stdout: "advisories ok\n".to_string(),
                    stderr: String::new(),
                },
                ("cargo", Some("metadata")) => ok(&self.metadata_json),
                ("cargo-about", _) => ToolOutput {
                    success: self.about_ok,
                    stdout: String::new(),
                    stderr: if self.about_ok {
                        String::new()
                    } else {
                        "unresolved licence".to_string()
                    },
                },
                _ => ok(""),
            })
        }
    }

    /// A repo with deny.toml + Cargo.lock, plus a db root holding the nested checkout.
    fn scenario() -> (tempfile::TempDir, tempfile::TempDir) {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("deny.toml"), DENY_WITH_PATH).unwrap();
        std::fs::write(repo.path().join("Cargo.lock"), "# lockfile\n").unwrap();
        let db = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(db.path().join("advisory-db-3157b0e258782691")).unwrap();
        (repo, db)
    }

    fn clean_audit_json() -> &'static str {
        r#"{"vulnerabilities":{"count":0,"found":false,"list":[]},"warnings":{}}"#
    }

    /// Adds `crates/demo/{Cargo.toml, about.toml}` to a `scenario()` repo,
    /// with the about.toml already in sync with an empty license policy (the
    /// exact content `merge_about_toml` would derive, computed rather than
    /// hand-typed so the fixture can't drift from the real format).
    fn add_in_sync_crate(repo: &Path) {
        let crate_dir = repo.join("crates/demo");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        let in_sync = crate::sync::merge_about_toml(
            "",
            &crate::license_scope::CrateLicenseScope::default(),
            &crate::sync::LicensePolicy::default(),
        )
        .unwrap();
        std::fs::write(crate_dir.join("about.toml"), in_sync).unwrap();
    }

    #[test]
    fn release_writes_the_record_and_locks_the_commit() {
        let (repo, db) = scenario();
        let work = repo.path().join("work");
        let runner = MockRunner::new(true, clean_audit_json());
        let outcome = release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();

        assert!(outcome.deny_passed);
        assert_eq!(outcome.db_commit, "abc1234def");
        let written = std::fs::read_to_string(&outcome.record_path).unwrap();
        assert!(
            written.contains("\"commit\": \"abc1234def\""),
            "got:\n{written}"
        );
        assert!(
            written.contains("\"version\": \"1.2.0\""),
            "got:\n{written}"
        );
        assert!(written.contains("cargo-deny 0.20.2"), "got:\n{written}");
        assert_eq!(
            outcome.record_path,
            repo.path().join(".security/release-1.2.0.json")
        );
    }

    #[test]
    fn deny_runs_with_the_derived_config_and_all_checks() {
        let (repo, db) = scenario();
        let work = repo.path().join("work");
        let runner = MockRunner::new(true, clean_audit_json());
        release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();

        let gate = runner
            .ran("cargo-deny")
            .into_iter()
            .find(|c| c.contains(&"check".to_string()))
            .expect("no cargo-deny check call");
        assert!(gate.contains(&"--config".to_string()), "call: {gate:?}");
        for check in DENY_CHECKS {
            assert!(
                gate.contains(&check.to_string()),
                "missing {check}: {gate:?}"
            );
        }
        // The derived config must point at the pinned db root, not the repo's value.
        let derived = std::fs::read_to_string(work.join("deny.toml")).unwrap();
        assert!(
            derived.contains(&db.path().display().to_string()),
            "derived config must set the pinned db-path:\n{derived}"
        );
    }

    #[test]
    fn failing_gate_writes_no_record() {
        let (repo, db) = scenario();
        let work = repo.path().join("work");
        let runner = MockRunner::new(false, clean_audit_json());
        let err = release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("release gate failed"),
            "got: {err}"
        );
        assert!(
            !repo.path().join(".security/release-1.2.0.json").exists(),
            "a failed gate must not leave a record"
        );
    }

    #[test]
    fn live_findings_are_reported_but_do_not_block() {
        let (repo, db) = scenario();
        let work = repo.path().join("work");
        let live = r#"{"vulnerabilities":{"count":1,"found":true,"list":[
             {"advisory":{"id":"RUSTSEC-2099-0001"}}]},"warnings":{}}"#;
        let runner = MockRunner::new(true, live);
        let outcome = release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();

        assert_eq!(outcome.live_findings, vec!["RUSTSEC-2099-0001"]);
        // Non-blocking: the release still succeeds and the record is written.
        assert!(outcome.record_path.exists());
        // …and the volatile live result is NOT recorded.
        let written = std::fs::read_to_string(&outcome.record_path).unwrap();
        assert!(!written.contains("RUSTSEC-2099-0001"), "got:\n{written}");
    }

    #[test]
    fn release_reruns_are_byte_identical() {
        let (repo, db) = scenario();
        let work = repo.path().join("work");
        let runner = MockRunner::new(true, clean_audit_json());
        release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
        let first =
            std::fs::read_to_string(repo.path().join(".security/release-1.2.0.json")).unwrap();
        release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
        let second =
            std::fs::read_to_string(repo.path().join(".security/release-1.2.0.json")).unwrap();
        assert_eq!(
            first, second,
            "same lockfile + commit must reproduce exactly"
        );
    }

    #[test]
    fn missing_lockfile_is_an_error() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("deny.toml"), DENY_WITH_PATH).unwrap();
        let db = tempfile::tempdir().unwrap();
        let runner = MockRunner::new(true, clean_audit_json());
        let err = release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &repo.path().join("w"),
            crate::diagnostics::Detail::Summary,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Cargo.lock"), "got: {err}");
    }

    // ── release-gate integration with about.toml (about_toml_digest itself
    // is unit-tested in sync.rs, where it now lives) ─────────────────────

    #[test]
    fn release_records_the_about_toml_digest_when_in_sync() {
        let (repo, db) = scenario();
        add_in_sync_crate(repo.path());
        let work = repo.path().join("work");
        let runner = MockRunner::new(true, clean_audit_json());
        let outcome = release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();

        let written = std::fs::read_to_string(&outcome.record_path).unwrap();
        assert!(
            written.contains("\"about_toml_sha256\":"),
            "got:\n{written}"
        );
        assert!(
            !written.contains("\"about_toml_sha256\": null"),
            "an in-sync about.toml must produce a real digest, not null:\n{written}"
        );
        // cargo-about was invoked (policy-resolution check ran).
        assert_eq!(runner.ran("cargo-about").len(), 1);
    }

    #[test]
    fn release_fails_when_about_toml_is_drifted() {
        let (repo, db) = scenario();
        let crate_dir = repo.path().join("crates/demo");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        // Drifted: asserts something the (empty) derived policy does not.
        std::fs::write(crate_dir.join("about.toml"), "accepted = [\"MIT\"]\n").unwrap();
        let work = repo.path().join("work");
        let runner = MockRunner::new(true, clean_audit_json());

        let err = release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap_err();
        assert!(err.to_string().contains("out of sync"), "got: {err}");
        assert!(
            !repo.path().join(".security/release-1.2.0.json").exists(),
            "a drifted about.toml must not leave a record"
        );
        // The expensive cargo-deny gate must not have run — caught earlier.
        assert!(runner.ran("cargo-deny").is_empty());
    }

    #[test]
    fn release_fails_when_cargo_about_cannot_resolve() {
        let (repo, db) = scenario();
        add_in_sync_crate(repo.path());
        let work = repo.path().join("work");
        let runner = MockRunner::new(true, clean_audit_json()).with_about_ok(false);

        let err = release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("cargo-about could not resolve"),
            "got: {err}"
        );
        assert!(
            !repo.path().join(".security/release-1.2.0.json").exists(),
            "an unresolvable licence must not leave a record"
        );
        // The expensive cargo-deny gate must not have run — caught earlier.
        assert!(runner.ran("cargo-deny").is_empty());
    }

    #[test]
    fn release_with_no_about_toml_records_a_null_digest() {
        // scenario() alone has no crates/ directory at all.
        let (repo, db) = scenario();
        let work = repo.path().join("work");
        let runner = MockRunner::new(true, clean_audit_json());
        let outcome = release_with(
            &runner,
            repo.path(),
            "1.2.0",
            db.path(),
            &work,
            crate::diagnostics::Detail::Summary,
        )
        .unwrap();
        let written = std::fs::read_to_string(&outcome.record_path).unwrap();
        assert!(
            written.contains("\"about_toml_sha256\": null"),
            "got:\n{written}"
        );
    }
}
