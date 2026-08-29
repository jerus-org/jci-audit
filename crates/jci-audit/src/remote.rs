//! `verify`'s no-local-checkout fetch path (jerus-org/jci-audit#75 phase 3).
//!
//! [`crate::verify`] re-runs the gate against a checked-out `Cargo.lock` and
//! `deny.toml` — the full reproduction. This module exists for the auditor
//! who has neither: it downloads the record and its signature from the
//! **published** GitHub release (never a draft — a draft's assets can still
//! be replaced), finds the pubkey that signed it from one of several
//! [`PubkeySource`]s, and checks that the signature matches, so a record
//! that doesn't match its accompanying signature fails closed instead of
//! being silently trusted.
//!
//! **Why more than one pubkey source.** The long-term intent
//! (jerus-org/jci-audit#75) is for the pubkey to be published as its own
//! release asset (`release-<VERSION>.json.pub`) — [`AssetPubkeySource`] —
//! needing nothing beyond the release's own assets, and the only source
//! generally available to a non-Rust/non-crates.io consumer. But the CI
//! wiring that uploads it is a separate, not-yet-shipped piece, and until it
//! ships every real release still only has its pubkey where it always has:
//! injected into `Cargo.toml` by the existing tarball-signing step —
//! [`ManifestPubkeySource`]. `verify_remote_with` takes an ordered list of
//! sources and tries each in turn ([`fetch_pubkey_from_sources`]) with no
//! built-in preference of its own; the *caller* decides the order.
//! `cli.rs::run_verify_remote` puts [`ManifestPubkeySource`] first — today
//! that's the only source with real data, **not** because it's
//! independently stronger (see below). Deliberately built as a small trait
//! rather than hardcoded fetches: a future source (a different registry, a
//! different language's convention) is just another implementation, not a
//! change to this flow.
//!
//! **Be honest about what the signature check does and doesn't buy**,
//! because it differs by source, and neither is as strong as it might
//! sound. For [`AssetPubkeySource`]: unless a given release's pubkey *also*
//! has an anchor independent of the release itself, anyone with only
//! release-asset-upload access can mint their own key, sign a forged
//! record, and upload a self-consistent fake triple — the check alone
//! doesn't rule that out. For [`ManifestPubkeySource`]: **do not assume
//! this is that independent anchor.** In jci-audit's own release pipeline
//! (see `docs/RELEASING.md`), the same CI job that injects the pubkey into
//! `Cargo.toml` and pushes the tag is also the job that (once #75 phase 2
//! lands) uploads the record and its signature as release assets — one
//! job, one credential set. Compromising that job's credentials compromises
//! both at once; there is no separately-operated second channel to also
//! break. It also trusts a **mutable** git ref (`refs/tags/<tag>`) with no
//! platform-enforced immutability, unlike the published-release-only
//! guarantee [`AssetPubkeySource`] gets from GitHub Immutable Releases — a
//! force-moved tag silently changes what this source fetches. A genuinely
//! independent, stronger anchor would need the git-push and
//! release-asset-upload credentials to actually be separate; today they
//! aren't. See `docs/assurance-case.md`'s T9 entry for the full accounting.
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
/// named assets. A trait so [`verify_remote_with`] is testable without real
/// network access.
pub(crate) trait ReleaseAssetSource {
    /// Fetch a named asset from the **published** release for `tag`.
    fn fetch_asset(&self, tag: &str, asset_name: &str) -> Result<Vec<u8>>;
}

/// One place `verify`'s remote path might find a release's signing pubkey.
/// See the module-level docs for why there's more than one implementation.
/// Dyn-compatible and minimal on purpose — adding a source later means
/// implementing this trait, not touching [`verify_remote_with`] itself.
pub(crate) trait PubkeySource {
    /// Fetch the pubkey for this release, or fail — including "not
    /// available from this source", which is a normal outcome
    /// [`fetch_pubkey_from_sources`] handles by trying the next one, not a
    /// caller-visible error on its own.
    fn fetch_pubkey(&self, tag: &str, version: &str) -> Result<String>;
    /// Short label identifying this source in a combined failure message.
    fn name(&self) -> &str;
}

/// Try each source in order, returning the first success. If all of them
/// fail, bail with every source's name and reason so a real outage is
/// diagnosable — not just "no pubkey found," with no way to tell whether
/// that's because none exists yet or because a fetch is genuinely broken.
fn fetch_pubkey_from_sources(
    sources: &[&dyn PubkeySource],
    tag: &str,
    version: &str,
) -> Result<String> {
    let mut failures = Vec::new();
    for source in sources {
        match source.fetch_pubkey(tag, version) {
            Ok(pubkey) => return Ok(pubkey),
            Err(e) => failures.push(format!("{}: {e}", source.name())),
        }
    }
    bail!(
        "could not find a pubkey for release '{tag}' from any source:\n  {}",
        failures.join("\n  ")
    );
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

/// Extract the bare minisign pubkey from a fetched or freshly-generated
/// `.pub` file's text. Tolerates either a bare single-line key or the full
/// `rsign`/minisign pubkey-file format (an `untrusted comment: ...` line
/// followed by the key) — the same `grep -v '^untrusted'` extraction
/// `circleci-toolkit`'s own `generate_signing_key` command already applies
/// for the tarball's pubkey, so this doesn't assume whatever produces the
/// `.pub` asset has pre-stripped it. Shared with [`crate::publish_record`],
/// which reads the same file shape straight out of `rsign generate -W`.
pub(crate) fn parse_pubkey_asset(text: &str) -> Result<String> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("untrusted"));
    let key = lines
        .next()
        .context("no key line found (only comment/blank lines)")?;
    if lines.next().is_some() {
        bail!("more than one non-comment line — ambiguous which is the key");
    }
    Ok(key.to_string())
}

/// Extract `[package.metadata.binstall.signing].pubkey` from a crate
/// manifest's text. This is where the release pipeline publishes each
/// release's ephemeral minisign public key (see `docs/RELEASING.md`).
fn extract_pubkey_from_manifest(cargo_toml: &str) -> Result<String> {
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
/// `pubkey_sources` are tried in the order given — the caller decides that
/// order, deliberately: this function has no built-in opinion on which
/// source to prefer. Callers should put the strongest available source
/// first (e.g. [`ManifestPubkeySource`] before [`AssetPubkeySource`] — see
/// the module docs for why the manifest source is the stronger one) rather
/// than defaulting to whichever is more convenient to construct.
pub(crate) fn verify_remote_with<R: CommandRunner, S: ReleaseAssetSource>(
    runner: &R,
    source: &S,
    pubkey_sources: &[&dyn PubkeySource],
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

    let pubkey = fetch_pubkey_from_sources(pubkey_sources, tag, version)?;

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

/// [`PubkeySource`] that fetches the pubkey as its own release asset
/// (`release-<VERSION>.json.pub`) via the same [`ReleaseAssetSource`]
/// already used for the record and signature — the intended long-term path,
/// and the only source generally available to a non-Rust/non-crates.io
/// consumer. Weaker than [`ManifestPubkeySource`] when both exist for the
/// same release — see the module docs.
pub(crate) struct AssetPubkeySource<'a, S: ReleaseAssetSource>(&'a S);

impl<'a, S: ReleaseAssetSource> AssetPubkeySource<'a, S> {
    pub(crate) fn new(source: &'a S) -> Self {
        Self(source)
    }
}

impl<S: ReleaseAssetSource> PubkeySource for AssetPubkeySource<'_, S> {
    fn fetch_pubkey(&self, tag: &str, version: &str) -> Result<String> {
        let pub_name = format!("release-{version}.json.pub");
        let pub_bytes = self
            .0
            .fetch_asset(tag, &pub_name)
            .with_context(|| format!("failed to fetch '{pub_name}' from release '{tag}'"))?;
        let pub_text = String::from_utf8(pub_bytes)
            .with_context(|| format!("'{pub_name}' from release '{tag}' is not valid UTF-8"))?;
        parse_pubkey_asset(&pub_text)
            .with_context(|| format!("failed to extract a pubkey from '{pub_name}'"))
    }

    fn name(&self) -> &str {
        "release asset (release-<VERSION>.json.pub)"
    }
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

/// How long the manifest fetch waits before giving up. Without this, an
/// unresponsive `raw.githubusercontent.com` hangs the whole CLI invocation
/// indefinitely inside the single-threaded runtime below.
const MANIFEST_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// [`PubkeySource`] that fetches the release tag's raw `Cargo.toml` and
/// reads the pubkey `inject_pubkey_and_amend` already writes there.
/// Currently the **only** source that actually has data for any real
/// jci-audit release, since the CI wiring to also upload a `.pub` asset
/// (jerus-org/jci-audit#75) hasn't shipped yet — that alone is why a caller
/// should try this source before [`AssetPubkeySource`], not any assumed
/// independence between the two (see the module docs' "be honest" section —
/// in jci-audit's own pipeline both sources' trust currently traces back to
/// the same CI job and credentials). Also trusts a **mutable** git tag ref,
/// with no immutability guarantee — see the module docs.
/// This reads exactly the content crates.io itself received for that
/// release: `cargo publish` packages the commit at the pushed tag verbatim,
/// so the tag's `Cargo.toml` and the one crates.io has are byte-identical.
/// Fetched via the git tag rather than crates.io's own API because
/// crates.io has no endpoint that serves raw file contents — only package
/// metadata and the packed `.crate` tarball.
pub(crate) struct ManifestPubkeySource {
    owner: String,
    repo: String,
    // reqwest's client doesn't need a matching getter on anything else here
    // — this is the only place in the module that makes an authenticated
    // HTTP call outside pcu-release-assets, so the token is just stored
    // plainly rather than threaded through a shared client.
    github_token: String,
}

impl ManifestPubkeySource {
    pub(crate) fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        github_token: impl Into<String>,
    ) -> Self {
        Self {
            owner: owner.into(),
            repo: repo.into(),
            github_token: github_token.into(),
        }
    }

    /// One call, one runtime — this is an occasional CLI invocation, not a
    /// server; there is no benefit to keeping a runtime alive across calls.
    fn block_on<F: std::future::Future>(fut: F) -> Result<F::Output> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to start an async runtime for the manifest fetch")
            .map(|rt| rt.block_on(fut))
    }
}

impl PubkeySource for ManifestPubkeySource {
    fn fetch_pubkey(&self, tag: &str, _version: &str) -> Result<String> {
        let url = raw_manifest_url(&self.owner, &self.repo, tag);
        let manifest: String = Self::block_on(async {
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
            let body = resp
                .bytes()
                .await
                .with_context(|| format!("failed to read body of '{url}'"))?;
            // `.bytes()` + an explicit UTF-8 check, not `.text()` — `.text()`
            // lossy-replaces invalid bytes instead of erroring, which would
            // let corrupted transport silently produce a wrong-but-parseable
            // manifest instead of failing closed (matches AssetPubkeySource's
            // explicit `String::from_utf8` check on the same failure class).
            String::from_utf8(body.to_vec())
                .with_context(|| format!("body of '{url}' is not valid UTF-8"))
        })??;
        extract_pubkey_from_manifest(&manifest)
    }

    fn name(&self) -> &str {
        "Cargo.toml at the release tag"
    }
}

/// Real [`ReleaseAssetSource`], backed by `pcu-release-assets`.
pub(crate) struct PcuAssetSource {
    client: pcu_release_assets::ReleaseAssetClient,
}

impl PcuAssetSource {
    pub(crate) fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        github_token: impl Into<String>,
    ) -> Self {
        let client = pcu_release_assets::ReleaseAssetClient::new(owner, repo, github_token);
        Self { client }
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
    fn extract_pubkey_from_manifest_reads_the_binstall_signing_table() {
        let manifest = manifest_with(PUBKEY);
        assert_eq!(extract_pubkey_from_manifest(&manifest).unwrap(), PUBKEY);
    }

    #[test]
    fn extract_pubkey_from_manifest_errors_when_the_table_is_absent() {
        let err = extract_pubkey_from_manifest("[package]\nname = \"jci-audit\"\n").unwrap_err();
        assert!(err.to_string().contains("pubkey"), "got: {err}");
    }

    #[test]
    fn parse_pubkey_asset_accepts_a_bare_key() {
        assert_eq!(parse_pubkey_asset(PUBKEY).unwrap(), PUBKEY);
        // Trailing newline, as a real uploaded asset would have.
        assert_eq!(parse_pubkey_asset(&format!("{PUBKEY}\n")).unwrap(), PUBKEY);
    }

    #[test]
    fn parse_pubkey_asset_strips_the_rsign_comment_line() {
        // The exact shape `rsign generate`/circleci-toolkit's
        // generate_signing_key command produce: an `untrusted comment: ...`
        // line above the key, matching what a future upload step might
        // publish verbatim if it doesn't pre-strip it itself.
        let raw = format!("untrusted comment: minisign public key ABCDEF\n{PUBKEY}\n");
        assert_eq!(parse_pubkey_asset(&raw).unwrap(), PUBKEY);
    }

    #[test]
    fn parse_pubkey_asset_errors_on_comment_only_input() {
        let err = parse_pubkey_asset("untrusted comment: nothing else\n").unwrap_err();
        assert!(err.to_string().contains("no key line"), "got: {err}");
    }

    #[test]
    fn parse_pubkey_asset_errors_on_multiple_key_lines() {
        let raw = format!("{PUBKEY}\nsome-other-line\n");
        let err = parse_pubkey_asset(&raw).unwrap_err();
        assert!(err.to_string().contains("more than one"), "got: {err}");
    }

    struct MockSource {
        assets: HashMap<(String, String), Vec<u8>>,
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
            assets.insert(
                (
                    "jci-audit-v1.2.0".to_string(),
                    format!("release-{version}.json.pub"),
                ),
                // A trailing newline, as a real published pubkey file would
                // have — trimmed by parse_pubkey_asset, not passed through
                // raw.
                format!("{PUBKEY}\n").into_bytes(),
            );
            Self { assets }
        }
    }

    impl ReleaseAssetSource for MockSource {
        fn fetch_asset(&self, tag: &str, asset_name: &str) -> Result<Vec<u8>> {
            self.assets
                .get(&(tag.to_string(), asset_name.to_string()))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no such asset '{asset_name}' on '{tag}'"))
        }
    }

    /// A [`PubkeySource`] under direct test control — succeeds with a fixed
    /// key, or fails with a fixed message, so fallback ordering can be
    /// tested without any real network/manifest-fetch machinery.
    struct StubPubkeySource {
        result: Result<String>,
        name: &'static str,
        calls: RefCell<u32>,
    }

    impl StubPubkeySource {
        fn ok(key: &str, name: &'static str) -> Self {
            Self {
                result: Ok(key.to_string()),
                name,
                calls: RefCell::new(0),
            }
        }

        fn err(message: &str, name: &'static str) -> Self {
            Self {
                result: Err(anyhow::anyhow!(message.to_string())),
                name,
                calls: RefCell::new(0),
            }
        }
    }

    impl PubkeySource for StubPubkeySource {
        fn fetch_pubkey(&self, _tag: &str, _version: &str) -> Result<String> {
            *self.calls.borrow_mut() += 1;
            match &self.result {
                Ok(key) => Ok(key.clone()),
                Err(e) => Err(anyhow::anyhow!(e.to_string())),
            }
        }

        fn name(&self) -> &str {
            self.name
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
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        let out = verify_remote_with(
            &runner,
            &source,
            &[&asset_source],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap();

        assert_eq!(out.db_commit, "abc1234def");
        assert!(out.recorded_pass);
        assert_eq!(out.unchecked.len(), 2, "got {:?}", out.unchecked);
    }

    #[test]
    fn rsign_is_invoked_with_the_fetched_pubkey_and_files() {
        let rec = record_v4("abc1234def", true);
        let source = MockSource::new("1.2.0", &rec);
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        verify_remote_with(
            &runner,
            &source,
            &[&asset_source],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap();

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
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(false);
        let work = tempfile::tempdir().unwrap();

        let err = verify_remote_with(
            &runner,
            &source,
            &[&asset_source],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
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
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        let err = verify_remote_with(
            &runner,
            &source,
            &[&asset_source],
            "9.9.9",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("release-9.9.9.json"), "got: {err}");
    }

    #[test]
    fn no_pubkey_source_available_is_a_combined_clear_error() {
        // The record and signature alone aren't enough — a release with no
        // pubkey asset AND no extra fallback source configured must fail
        // clearly rather than trying to verify against an empty/garbage key.
        let rec = record_v4("abc1234def", true);
        let mut source = MockSource::new("1.2.0", &rec);
        source.assets.remove(&(
            "jci-audit-v1.2.0".to_string(),
            "release-1.2.0.json.pub".to_string(),
        ));
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        let err = verify_remote_with(
            &runner,
            &source,
            &[&asset_source],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("release-1.2.0.json.pub"),
            "got: {err}"
        );
    }

    #[test]
    fn falls_back_to_the_next_pubkey_source_when_the_asset_is_missing() {
        // The exact "next jci-audit release" scenario the maintainer flagged
        // on PR #105: no .pub asset yet (CI wiring hasn't shipped), but a
        // fallback source (standing in for ManifestPubkeySource) has it.
        let rec = record_v4("abc1234def", true);
        let mut source = MockSource::new("1.2.0", &rec);
        source.assets.remove(&(
            "jci-audit-v1.2.0".to_string(),
            "release-1.2.0.json.pub".to_string(),
        ));
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();
        let fallback = StubPubkeySource::ok(PUBKEY, "stub fallback");

        let out = verify_remote_with(
            &runner,
            &source,
            &[&asset_source, &fallback],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap();

        assert!(out.recorded_pass);
        assert_eq!(*fallback.calls.borrow(), 1, "fallback must be tried");
    }

    #[test]
    fn does_not_try_the_fallback_when_the_asset_source_succeeds() {
        // A working fallback must not be consulted when the source ahead of
        // it in the caller-chosen order already succeeded.
        let rec = record_v4("abc1234def", true);
        let source = MockSource::new("1.2.0", &rec);
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();
        let fallback = StubPubkeySource::ok("a-different-key-entirely", "stub fallback");

        verify_remote_with(
            &runner,
            &source,
            &[&asset_source, &fallback],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap();

        assert_eq!(
            *fallback.calls.borrow(),
            0,
            "fallback must not be tried when an earlier source already succeeded"
        );
    }

    #[test]
    fn all_pubkey_sources_failing_names_every_attempt() {
        let rec = record_v4("abc1234def", true);
        let mut source = MockSource::new("1.2.0", &rec);
        source.assets.remove(&(
            "jci-audit-v1.2.0".to_string(),
            "release-1.2.0.json.pub".to_string(),
        ));
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();
        let fallback = StubPubkeySource::err("network unreachable", "stub fallback");

        let err = verify_remote_with(
            &runner,
            &source,
            &[&asset_source, &fallback],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("release asset"), "got: {msg}");
        assert!(msg.contains("stub fallback"), "got: {msg}");
        assert!(msg.contains("network unreachable"), "got: {msg}");
    }

    #[test]
    fn a_non_utf8_pub_asset_is_a_clear_error() {
        let rec = record_v4("abc1234def", true);
        let mut source = MockSource::new("1.2.0", &rec);
        source.assets.insert(
            (
                "jci-audit-v1.2.0".to_string(),
                "release-1.2.0.json.pub".to_string(),
            ),
            vec![0xff, 0xfe, 0xfd],
        );
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        let err = verify_remote_with(
            &runner,
            &source,
            &[&asset_source],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not valid UTF-8"), "got: {err}");
    }

    #[test]
    fn end_to_end_accepts_a_pub_asset_in_the_full_rsign_file_format() {
        // Not just parse_pubkey_asset in isolation: a future upload step that
        // publishes the raw rsign-generated pubkey file (comment line and
        // all) must still work through the whole verify_remote_with flow,
        // not just the unit-level parser.
        let rec = record_v4("abc1234def", true);
        let mut source = MockSource::new("1.2.0", &rec);
        source.assets.insert(
            (
                "jci-audit-v1.2.0".to_string(),
                "release-1.2.0.json.pub".to_string(),
            ),
            format!("untrusted comment: minisign public key ABCDEF\n{PUBKEY}\n").into_bytes(),
        );
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        let out = verify_remote_with(
            &runner,
            &source,
            &[&asset_source],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap();
        assert!(out.recorded_pass);

        let calls = runner.calls.borrow();
        let call = calls
            .iter()
            .find(|c| c[0] == "rsign")
            .expect("must call rsign");
        assert!(
            call.contains(&PUBKEY.to_string()),
            "rsign must be called with the bare key, not the raw file text: {call:?}"
        );
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
        let asset_source = AssetPubkeySource::new(&source);
        let runner = MockRunner::new(true);
        let work = tempfile::tempdir().unwrap();

        let err = verify_remote_with(
            &runner,
            &source,
            &[&asset_source],
            "1.2.0",
            "jci-audit-v1.2.0",
            work.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("checks.deny.passed"), "got: {err}");
    }
}
