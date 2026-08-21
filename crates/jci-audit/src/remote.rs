//! `verify`'s no-local-checkout fetch path (jerus-org/jci-audit#75 phase 3).
//!
//! [`crate::verify`] re-runs the gate against a checked-out `Cargo.lock` and
//! `deny.toml` — the full reproduction. This module exists for the auditor
//! who has neither: it downloads the record and its signature from the
//! **published** GitHub release (never a draft — a draft's assets can still
//! be replaced) and checks the signature against the pubkey published in
//! that release's own `Cargo.toml`, so the fetched record is provably the
//! one the release's signing key produced.
//!
//! It does **not** re-run cargo-deny — that needs the checked-out policy and
//! lockfile a bare directory doesn't have. What it proves is narrower but
//! still real: the record is authentic, not substituted in transit or by a
//! compromised release asset. An auditor who also fetches the crate source
//! (e.g. `cargo download jci-audit@<version>`) can run [`crate::verify`]
//! from within it for the full comparison; [`RemoteVerifyOutcome::unchecked`]
//! says plainly what this mode alone does not cover.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::check::CommandRunner;
use crate::verify::field;

/// Where the remote fetch path gets its bytes from — a published release's
/// named assets, and the raw `Cargo.toml` at that release's tag. A trait so
/// [`verify_remote_with`] is testable without real network access.
pub(crate) trait ReleaseAssetSource {
    /// Fetch a named asset from the **published** release for `tag`.
    fn fetch_asset(&self, tag: &str, asset_name: &str) -> Result<Vec<u8>>;
    /// Fetch the raw `crates/jci-audit/Cargo.toml` as it stood at `tag`, to
    /// extract the historical signing pubkey.
    fn fetch_manifest(&self, tag: &str) -> Result<String>;
}

/// What a remote (no-checkout) verification concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteVerifyOutcome {
    /// The release version verified.
    pub(crate) version: String,
    /// The advisory-db commit the record attests it was locked to.
    pub(crate) db_commit: String,
    /// The record's own attested verdict — not re-derived, only authenticated.
    pub(crate) recorded_pass: bool,
    /// What this mode does not check, so an auditor sees exactly the limits
    /// of a signature-only verification rather than an implied full pass.
    pub(crate) unchecked: Vec<String>,
}

/// A required boolean field, erroring rather than silently defaulting to a
/// pass. Unlike the local `verify::verify_with` path — where a missing/
/// malformed `checks.deny.passed` still gets caught by comparing against a
/// freshly re-run gate — this mode never re-runs the gate, so a wrong
/// default here would be the final, unchecked answer. Fail closed instead.
fn bool_field(record: &Value, path: &[&str]) -> Result<bool> {
    let mut cur = record;
    for key in path {
        cur = cur
            .get(key)
            .with_context(|| format!("release record has no '{}'", path.join(".")))?;
    }
    cur.as_bool()
        .with_context(|| format!("release record '{}' is not a boolean", path.join(".")))
}

/// Extract `[package.metadata.binstall.signing].pubkey` from a crate
/// manifest's text. This is where the release pipeline publishes each
/// release's ephemeral minisign public key (see `docs/RELEASING.md`).
pub(crate) fn extract_pubkey(cargo_toml: &str) -> Result<String> {
    let doc: toml_edit::DocumentMut = cargo_toml.parse().context("failed to parse Cargo.toml")?;
    doc.get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("binstall"))
        .and_then(|b| b.get("signing"))
        .and_then(|s| s.get("pubkey"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .context(
            "Cargo.toml has no [package.metadata.binstall.signing].pubkey \
             — cannot verify the record's signature",
        )
}

/// Re-verify a published release's record from its release assets alone, no
/// checkout required. `tag` is the full release tag (e.g. `jci-audit-v1.2.0`).
pub(crate) fn verify_remote_with<R: CommandRunner, S: ReleaseAssetSource>(
    runner: &R,
    source: &S,
    version: &str,
    tag: &str,
    work_dir: &Path,
) -> Result<RemoteVerifyOutcome> {
    let record_name = format!("release-{version}.json");
    let sig_name = format!("{record_name}.sig");

    let record_bytes = source
        .fetch_asset(tag, &record_name)
        .with_context(|| format!("failed to fetch '{record_name}' from release '{tag}'"))?;
    let sig_bytes = source
        .fetch_asset(tag, &sig_name)
        .with_context(|| format!("failed to fetch '{sig_name}' from release '{tag}'"))?;
    let manifest = source
        .fetch_manifest(tag)
        .with_context(|| format!("failed to fetch Cargo.toml at '{tag}'"))?;
    let pubkey = extract_pubkey(&manifest)?;

    std::fs::create_dir_all(work_dir)
        .with_context(|| format!("failed to create '{}'", work_dir.display()))?;
    let record_path = work_dir.join(&record_name);
    let sig_path = work_dir.join(&sig_name);
    std::fs::write(&record_path, &record_bytes)
        .with_context(|| format!("failed to write '{}'", record_path.display()))?;
    std::fs::write(&sig_path, &sig_bytes)
        .with_context(|| format!("failed to write '{}'", sig_path.display()))?;

    let record_path_str = record_path.to_str().unwrap_or_default();
    let sig_path_str = sig_path.to_str().unwrap_or_default();
    let verify = runner.run(
        "rsign",
        &["verify", "-P", &pubkey, "-x", sig_path_str, record_path_str],
        work_dir,
    )?;
    if !verify.success {
        bail!(
            "signature verification failed for '{record_name}' from release '{tag}': {}",
            verify.stderr.trim()
        );
    }

    let record: Value = serde_json::from_slice(&record_bytes)
        .with_context(|| format!("failed to parse '{record_name}' as JSON"))?;
    let db_commit = field(&record, &["advisory_db", "commit"])?.to_string();
    let recorded_pass = bool_field(&record, &["checks", "deny", "passed"])?;

    Ok(RemoteVerifyOutcome {
        version: version.to_string(),
        db_commit,
        recorded_pass,
        unchecked: vec![
            "no local Cargo.lock/deny.toml — the dependency-set and policy digests were not \
             re-verified; fetch the crate source (e.g. `cargo download` from crates.io) and run \
             `jci-audit verify` from within it for the full comparison"
                .to_string(),
            "the gate was not re-run — the recorded verdict is authenticated, not reproduced"
                .to_string(),
        ],
    })
}

/// The crate's own repository, e.g. `https://github.com/jerus-org/jci-audit`
/// — `CARGO_PKG_REPOSITORY` at compile time, so this only ever tracks the
/// real value in `Cargo.toml`, never a value that can drift from it.
pub(crate) const REPOSITORY_URL: &str = env!("CARGO_PKG_REPOSITORY");

/// This repo's release tag prefix — fixed, like the rest of this crate's
/// hardcoded self-knowledge (`release::DEFAULT_VERSION_ENV`, the
/// `.security/release-<VERSION>.json` path). `verify` only ever verifies
/// jci-audit's own releases, not an arbitrary repo's.
pub(crate) const TAG_PREFIX: &str = "jci-audit-v";

/// Where the release pipeline publishes this crate's manifest, relative to
/// the repo root — this repo's workspace layout, not a general convention.
const MANIFEST_PATH: &str = "crates/jci-audit/Cargo.toml";

/// Split a GitHub repository URL into `(owner, repo)`.
///
/// Accepts the exact form `CARGO_PKG_REPOSITORY` publishes
/// (`https://github.com/<owner>/<repo>`), with or without a trailing `.git`
/// or slash.
pub(crate) fn owner_repo_from_repository_url(url: &str) -> Result<(String, String)> {
    let path = url
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .strip_prefix("https://github.com/")
        .with_context(|| format!("'{url}' is not a github.com repository URL"))?;
    let mut parts = path.splitn(2, '/');
    let owner = parts.next().filter(|s| !s.is_empty());
    let repo = parts.next().filter(|s| !s.is_empty());
    match (owner, repo) {
        (Some(owner), Some(repo)) => Ok((owner.to_string(), repo.to_string())),
        _ => bail!("'{url}' is missing an owner or repo segment"),
    }
}

/// The raw-content URL for this repo's `Cargo.toml` as it stood at `tag`.
fn raw_manifest_url(owner: &str, repo: &str, tag: &str) -> String {
    format!("https://raw.githubusercontent.com/{owner}/{repo}/refs/tags/{tag}/{MANIFEST_PATH}")
}

/// Real [`ReleaseAssetSource`], backed by `pcu-release-assets` for the
/// record + signature and a plain HTTPS fetch for the raw `Cargo.toml` at
/// the release tag — `pcu-release-assets` only fetches release *assets*,
/// not arbitrary repo file contents.
pub(crate) struct PcuAssetSource {
    client: pcu_release_assets::ReleaseAssetClient,
    owner: String,
    repo: String,
    // pcu-release-assets' ReleaseAssetClient doesn't expose the token it was
    // built with (no getter), and fetch_manifest needs it too — for the same
    // repo, an authenticated request avoids the unauthenticated rate limit
    // and works if the repo is ever made private.
    github_token: String,
}

/// How long the manifest fetch waits before giving up. Without this, an
/// unresponsive `raw.githubusercontent.com` hangs the whole CLI invocation
/// indefinitely inside the single-threaded runtime below.
const MANIFEST_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl PcuAssetSource {
    pub(crate) fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        github_token: impl Into<String>,
    ) -> Self {
        let owner = owner.into();
        let repo = repo.into();
        let github_token = github_token.into();
        let client = pcu_release_assets::ReleaseAssetClient::new(
            owner.clone(),
            repo.clone(),
            github_token.clone(),
        );
        Self {
            client,
            owner,
            repo,
            github_token,
        }
    }

    /// One call, one runtime — this is an occasional CLI invocation, not a
    /// server; there is no benefit to keeping a runtime alive across calls.
    fn block_on<F: std::future::Future>(fut: F) -> Result<F::Output> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to start an async runtime for the release-asset fetch")
            .map(|rt| rt.block_on(fut))
    }
}

impl ReleaseAssetSource for PcuAssetSource {
    fn fetch_asset(&self, tag: &str, asset_name: &str) -> Result<Vec<u8>> {
        Self::block_on(self.client.download_release_asset(tag, asset_name))?
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn fetch_manifest(&self, tag: &str) -> Result<String> {
        let url = raw_manifest_url(&self.owner, &self.repo, tag);
        Self::block_on(async {
            let client = reqwest::Client::builder()
                .timeout(MANIFEST_FETCH_TIMEOUT)
                .build()
                .context("failed to build an HTTP client")?;
            let resp = client
                .get(&url)
                .bearer_auth(&self.github_token)
                .send()
                .await
                .with_context(|| format!("failed to fetch '{url}'"))?;
            if !resp.status().is_success() {
                bail!("failed to fetch '{url}': HTTP {}", resp.status());
            }
            resp.text()
                .await
                .with_context(|| format!("failed to read body of '{url}'"))
        })?
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use serde_json::json;

    use super::*;
    use crate::check::ToolOutput;

    const PUBKEY: &str = "RWSImK6yfWBJsXrcL0Pj4rGeuKAZBAHz1LtaE677qZGJ4Pd/O+L2A9vl";

    #[test]
    fn owner_repo_parses_the_standard_github_url() {
        let (owner, repo) =
            owner_repo_from_repository_url("https://github.com/jerus-org/jci-audit").unwrap();
        assert_eq!(owner, "jerus-org");
        assert_eq!(repo, "jci-audit");
    }

    #[test]
    fn owner_repo_tolerates_a_trailing_git_suffix_and_slash() {
        let (owner, repo) =
            owner_repo_from_repository_url("https://github.com/jerus-org/jci-audit.git/").unwrap();
        assert_eq!(owner, "jerus-org");
        assert_eq!(repo, "jci-audit");
    }

    #[test]
    fn owner_repo_rejects_a_non_github_url() {
        let err =
            owner_repo_from_repository_url("https://gitlab.com/jerus-org/jci-audit").unwrap_err();
        assert!(err.to_string().contains("github.com"), "got: {err}");
    }

    #[test]
    fn the_compiled_in_repository_matches_this_crates_manifest() {
        // A drift here would silently point verify's remote fetch at the
        // wrong repository.
        let (owner, repo) = owner_repo_from_repository_url(REPOSITORY_URL).unwrap();
        assert_eq!(owner, "jerus-org");
        assert_eq!(repo, "jci-audit");
    }

    #[test]
    fn raw_manifest_url_targets_this_repos_crate_layout() {
        let url = raw_manifest_url("jerus-org", "jci-audit", "jci-audit-v1.2.0");
        assert_eq!(
            url,
            "https://raw.githubusercontent.com/jerus-org/jci-audit/refs/tags/\
             jci-audit-v1.2.0/crates/jci-audit/Cargo.toml"
        );
    }

    fn manifest_with(pubkey: &str) -> String {
        format!(
            "[package]\nname = \"jci-audit\"\n\n[package.metadata.binstall.signing]\n\
             algorithm = \"minisign\"\npubkey = \"{pubkey}\"\n"
        )
    }

    #[test]
    fn extract_pubkey_reads_the_binstall_signing_table() {
        let manifest = manifest_with(PUBKEY);
        assert_eq!(extract_pubkey(&manifest).unwrap(), PUBKEY);
    }

    #[test]
    fn extract_pubkey_errors_when_the_table_is_absent() {
        let err = extract_pubkey("[package]\nname = \"jci-audit\"\n").unwrap_err();
        assert!(err.to_string().contains("pubkey"), "got: {err}");
    }

    struct MockSource {
        assets: HashMap<(String, String), Vec<u8>>,
        manifest: String,
    }

    impl MockSource {
        fn new(version: &str, record: &Value) -> Self {
            let mut assets = HashMap::new();
            let record_bytes = serde_json::to_vec(record).unwrap();
            assets.insert(
                (
                    "jci-audit-v1.2.0".to_string(),
                    format!("release-{version}.json"),
                ),
                record_bytes,
            );
            assets.insert(
                (
                    "jci-audit-v1.2.0".to_string(),
                    format!("release-{version}.json.sig"),
                ),
                b"untrusted comment: signature\nfake-signature-bytes\n".to_vec(),
            );
            Self {
                assets,
                manifest: manifest_with(PUBKEY),
            }
        }
    }

    impl ReleaseAssetSource for MockSource {
        fn fetch_asset(&self, tag: &str, asset_name: &str) -> Result<Vec<u8>> {
            self.assets
                .get(&(tag.to_string(), asset_name.to_string()))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no such asset '{asset_name}' on '{tag}'"))
        }

        fn fetch_manifest(&self, _tag: &str) -> Result<String> {
            Ok(self.manifest.clone())
        }
    }

    struct MockRunner {
        rsign_ok: bool,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl MockRunner {
        fn new(rsign_ok: bool) -> Self {
            Self {
                rsign_ok,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str], _cwd: &Path) -> Result<ToolOutput> {
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|s| s.to_string()));
            self.calls.borrow_mut().push(call);
            Ok(ToolOutput {
                success: self.rsign_ok,
                stdout: String::new(),
                stderr: if self.rsign_ok {
                    String::new()
                } else {
                    "signature verification failed".to_string()
                },
            })
        }
    }

    fn record_v4(db_commit: &str, pass: bool) -> Value {
        json!({
            "schema_version": 4,
            "version": "1.2.0",
            "advisory_db": { "commit": db_commit },
            "tools": { "cargo_deny": "cargo-deny 0.20.2", "cargo_audit": "cargo-audit 0.22.0" },
            "lockfile": { "dependencies_sha256": "deps-sha" },
            "policy": { "deny_toml_sha256": "policy-sha", "about_toml_sha256": "about-sha" },
            "checks": { "deny": { "passed": pass, "checks": ["advisories"] } },
        })
    }

    #[test]
    fn a_valid_signature_reproduces_the_recorded_verdict() {
        let rec = record_v4("abc1234def", true);
        let source = MockSource::new("1.2.0", &rec);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        let out =
            verify_remote_with(&runner, &source, "1.2.0", "jci-audit-v1.2.0", work.path()).unwrap();

        assert_eq!(out.db_commit, "abc1234def");
        assert!(out.recorded_pass);
        assert_eq!(out.unchecked.len(), 2, "got {:?}", out.unchecked);
    }

    #[test]
    fn rsign_is_invoked_with_the_fetched_pubkey_and_files() {
        let rec = record_v4("abc1234def", true);
        let source = MockSource::new("1.2.0", &rec);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        verify_remote_with(&runner, &source, "1.2.0", "jci-audit-v1.2.0", work.path()).unwrap();

        let calls = runner.calls.borrow();
        let call = calls
            .iter()
            .find(|c| c[0] == "rsign")
            .expect("must call rsign");
        assert!(call.contains(&"verify".to_string()));
        assert!(call.contains(&PUBKEY.to_string()), "call: {call:?}");
        assert!(
            call.iter().any(|a| a.ends_with("release-1.2.0.json.sig")),
            "call: {call:?}"
        );
        assert!(
            call.iter().any(
                |a| a.ends_with("release-1.2.0.json") && !a.ends_with("release-1.2.0.json.sig")
            ),
            "call: {call:?}"
        );
    }

    #[test]
    fn a_failing_signature_check_is_an_error_not_a_reported_mismatch() {
        // Unlike the local `verify_with` path, a bad signature here means the
        // record cannot be trusted at all — there is nothing left to report.
        let rec = record_v4("abc1234def", true);
        let source = MockSource::new("1.2.0", &rec);
        let runner = MockRunner::new(false);
        let work = tempfile::tempdir().unwrap();

        let err = verify_remote_with(&runner, &source, "1.2.0", "jci-audit-v1.2.0", work.path())
            .unwrap_err();
        assert!(
            err.to_string().contains("signature verification failed"),
            "got: {err}"
        );
    }

    #[test]
    fn a_missing_asset_is_a_clear_error() {
        let rec = record_v4("abc1234def", true);
        let source = MockSource::new("1.2.0", &rec);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        let err = verify_remote_with(&runner, &source, "9.9.9", "jci-audit-v1.2.0", work.path())
            .unwrap_err();
        assert!(err.to_string().contains("release-9.9.9.json"), "got: {err}");
    }

    #[test]
    fn a_record_missing_the_verdict_field_fails_closed_not_open() {
        // A validly-signed record whose `checks.deny.passed` is absent (a
        // future/older schema variant) must not be silently treated as a
        // pass — this mode has no gate re-run to catch a wrong default, so
        // the default itself must be "unverifiable", not "true".
        let rec = json!({
            "schema_version": 4,
            "version": "1.2.0",
            "advisory_db": { "commit": "abc1234def" },
            "checks": { "deny": {} },
        });
        let source = MockSource::new("1.2.0", &rec);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        let err = verify_remote_with(&runner, &source, "1.2.0", "jci-audit-v1.2.0", work.path())
            .unwrap_err();
        assert!(err.to_string().contains("checks.deny.passed"), "got: {err}");
    }
}
