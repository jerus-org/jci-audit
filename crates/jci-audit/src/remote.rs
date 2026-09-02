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
//! **Why more than one pubkey source.** [`AssetPubkeySource`] reads the
//! release's own `.pub` asset (`release-<VERSION>.json.pub`,
//! jerus-org/jci-audit#75 phase 2) — needing nothing beyond the release's
//! own assets, so it works regardless of how the release was published.
//! [`ManifestPubkeySource`] reads the pubkey `inject_pubkey_and_amend`
//! injects into `Cargo.toml` at the release tag — the
//! `[package.metadata.binstall.signing]` convention `cargo binstall` itself
//! defines, so it has data for any crates.io release that uses it, jci-audit's
//! own release pipeline included. `verify_remote_with` takes an ordered list
//! of sources and tries each in turn ([`fetch_pubkey_from_sources`]) with no
//! built-in preference of its own; the *caller* decides the order.
//! `cli.rs::run_verify_remote` always tries [`AssetPubkeySource`] first,
//! since it depends on nothing about how the release was published, then
//! [`ManifestPubkeySource`] — but only when the caller opts in with
//! `--manifest-path` (jerus-org/jci-audit#124): there is no general
//! convention for where a crate's manifest lives, so this source is never
//! tried by default. Deliberately built as a small trait rather than
//! hardcoded fetches: a future source (a different registry, a different
//! language's convention) is just another implementation, not a change to
//! this flow.
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
//! `Cargo.toml` and pushes the tag is also the job that uploads the record
//! and its signature as release assets — one job, one credential set.
//! Compromising that job's credentials compromises both at once; there is
//! no separately-operated second channel to also break. It also trusts a
//! **mutable** git ref (`refs/tags/<tag>`) with no platform-enforced
//! immutability, unlike the published-release-only guarantee
//! [`AssetPubkeySource`] gets from GitHub Immutable Releases — a
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

/// What of a full local re-verification's two prerequisites are present.
/// Only affects which "not checked" reason is reported, not which path runs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LocalCheckoutState {
    pub(crate) deny_toml: bool,
    pub(crate) cargo_lock: bool,
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

/// Extract `[package].name` from a manifest's text, or `None` for a
/// workspace root with no package of its own.
fn extract_package_name(cargo_toml: &str) -> Option<String> {
    let doc: toml_edit::DocumentMut = cargo_toml.parse().ok()?;
    doc.get("package")?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

/// Extract `[workspace].members` from a manifest's text, or empty when
/// there is no workspace table or no members array.
fn extract_workspace_members(cargo_toml: &str) -> Vec<String> {
    let Ok(doc) = cargo_toml.parse::<toml_edit::DocumentMut>() else {
        return Vec::new();
    };
    doc.get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// True for a `[workspace.members]` entry that names a glob rather than a
/// literal directory. Resolving a glob needs a directory listing, which
/// `raw.githubusercontent.com` cannot provide — every repo in this org lists
/// members explicitly rather than by glob, so this is the unsupported case,
/// not the common one.
fn is_glob_member(member: &str) -> bool {
    member.contains(['*', '?', '['])
}

/// Find the manifest, among the workspace root and its members, whose
/// `[package].name` is `package` — cargo's own `-p`/`--package` semantics
/// (jerus-org/jci-audit#124), rather than asking the caller for a raw path.
/// `fetch_member` fetches one member's `Cargo.toml` by its workspace-relative
/// directory; kept as a closure so this resolution logic is unit-testable
/// without a network call.
fn resolve_package_manifest(
    root_manifest: &str,
    package: &str,
    fetch_member: impl Fn(&str) -> Result<String>,
) -> Result<String> {
    if extract_package_name(root_manifest).as_deref() == Some(package) {
        return Ok(root_manifest.to_string());
    }
    let members = extract_workspace_members(root_manifest);
    let mut skipped_globs = Vec::new();
    for member in &members {
        if is_glob_member(member) {
            skipped_globs.push(member.clone());
            continue;
        }
        let content = fetch_member(member)?;
        if extract_package_name(&content).as_deref() == Some(package) {
            return Ok(content);
        }
    }
    let mut msg = format!(
        "package '{package}' not found in the workspace (checked root + members: {})",
        members.join(", ")
    );
    if !skipped_globs.is_empty() {
        msg += &format!(
            " — skipped glob member(s), not resolvable without a directory listing: {}",
            skipped_globs.join(", ")
        );
    }
    bail!(msg)
}

/// Re-verify a published release's record from its release assets alone, no
/// checkout required. `tag` is the full release tag (e.g. `jci-audit-v1.2.0`).
/// `pubkey_sources` are tried in the order given — the caller decides that
/// order, deliberately: this function has no built-in opinion on which
/// source to prefer. `cli.rs::run_verify_remote` puts [`AssetPubkeySource`]
/// first, since it depends on nothing about how the release was published,
/// then [`ManifestPubkeySource`] when the caller opted into it — see the
/// module docs; neither is independently stronger for jci-audit's own
/// releases (`docs/assurance-case.md` T9 has the full accounting).
pub(crate) fn verify_remote_with<R: CommandRunner, S: ReleaseAssetSource>(
    runner: &R,
    source: &S,
    pubkey_sources: &[&dyn PubkeySource],
    version: &str,
    tag: &str,
    work_dir: &Path,
    local_checkout: LocalCheckoutState,
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

    let no_reverify_reason = match (local_checkout.deny_toml, local_checkout.cargo_lock) {
        (true, true) => {
            "no local record for this version — .security/release-<VERSION>.json isn't \
             committed to git (jerus-org/jci-audit#75); the dependency-set and policy digests \
             were not re-verified against it, and there is no local way to reproduce a past \
             release's record — this authenticates the release's own signed record instead"
                .to_string()
        }
        (true, false) => {
            "deny.toml is present but Cargo.lock is not — the dependency-set and policy \
             digests were not re-verified; run `cargo generate-lockfile` (or fetch the crate \
             source and run `jci-audit verify` from within it) for the full comparison"
                .to_string()
        }
        (false, _) => {
            "no local Cargo.lock/deny.toml — the dependency-set and policy digests were not \
             re-verified; fetch the crate source (e.g. `cargo download` from crates.io) and run \
             `jci-audit verify` from within it for the full comparison"
                .to_string()
        }
    };

    Ok(RemoteVerifyOutcome {
        version: version.to_string(),
        db_commit,
        recorded_pass,
        unchecked: vec![
            no_reverify_reason,
            "the gate was not re-run — the recorded verdict is authenticated, not reproduced"
                .to_string(),
        ],
    })
}

/// [`PubkeySource`] that fetches the pubkey as its own release asset
/// (`release-<VERSION>.json.pub`) via the same [`ReleaseAssetSource`]
/// already used for the record and signature — the intended long-term path,
/// and the only source generally available to a non-Rust/non-crates.io
/// consumer. Always tried, unlike the opt-in [`ManifestPubkeySource`] — see
/// the module docs for how the two compare.
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

/// The raw-content URL for a file at the given repo-relative `path` as it
/// stood at `tag` — used for both the workspace root `Cargo.toml` and, when
/// resolving a workspace member, its `Cargo.toml` too.
fn raw_manifest_url(owner: &str, repo: &str, tag: &str, path: &str) -> String {
    format!("https://raw.githubusercontent.com/{owner}/{repo}/refs/tags/{tag}/{path}")
}

/// How long the manifest fetch waits before giving up. Without this, an
/// unresponsive `raw.githubusercontent.com` hangs the whole CLI invocation
/// indefinitely inside the single-threaded runtime below.
const MANIFEST_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// [`PubkeySource`] that fetches the release tag's raw `Cargo.toml` (and, in
/// a workspace, whichever member's manifest matches `package`) and reads the
/// pubkey `inject_pubkey_and_amend` writes there under
/// `[package.metadata.binstall.signing]` — the convention `cargo binstall`
/// itself defines. `package` is caller-supplied, cargo's own `-p`/`--package`
/// convention (jerus-org/jci-audit#124) — this source only runs when the
/// caller opts in. Also trusts a **mutable** git tag ref, with no
/// immutability guarantee — see the module docs. This reads exactly the
/// content crates.io itself received for that release: `cargo publish`
/// packages the commit at the pushed tag verbatim, so the tag's `Cargo.toml`
/// and the one crates.io has are byte-identical. Fetched via the git tag
/// rather than crates.io's own API because crates.io has no endpoint that
/// serves raw file contents — only package metadata and the packed
/// `.crate` tarball.
pub(crate) struct ManifestPubkeySource {
    owner: String,
    repo: String,
    package: String,
    // `None` sends no Authorization header at all (jerus-org/jci-audit#103)
    // — GitHub treats an *empty* bearer token as invalid credentials, not
    // as anonymous, so an empty string here would be the wrong "no token".
    github_token: Option<String>,
}

impl ManifestPubkeySource {
    pub(crate) fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        package: impl Into<String>,
        github_token: Option<String>,
    ) -> Self {
        Self {
            owner: owner.into(),
            repo: repo.into(),
            package: package.into(),
            github_token,
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

    /// Fetch one raw file's text content at `tag`, relative to the repo root.
    fn fetch_raw(&self, tag: &str, path: &str) -> Result<String> {
        let url = raw_manifest_url(&self.owner, &self.repo, tag, path);
        let token = self.github_token.clone();
        Self::block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(MANIFEST_FETCH_TIMEOUT)
                .build()
                .context("failed to build an HTTP client")?;
            let mut req = client.get(&url);
            if let Some(token) = &token {
                req = req.bearer_auth(token);
            }
            let resp = req
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
        })?
    }
}

impl PubkeySource for ManifestPubkeySource {
    fn fetch_pubkey(&self, tag: &str, _version: &str) -> Result<String> {
        let root = self.fetch_raw(tag, "Cargo.toml")?;
        let matched = resolve_package_manifest(&root, &self.package, |member| {
            self.fetch_raw(tag, &format!("{member}/Cargo.toml"))
        })?;
        extract_pubkey_from_manifest(&matched)
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
    /// `github_token: None` builds an unauthenticated client
    /// (jerus-org/jci-audit#103) — fine here since [`Self::fetch_asset`]
    /// only ever calls `download_release_asset`, the one entry point that
    /// works unauthenticated for a public repo (it never needs draft
    /// visibility, which is what requires a token).
    pub(crate) fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        github_token: Option<String>,
    ) -> Self {
        let client = match github_token {
            Some(token) => pcu_release_assets::ReleaseAssetClient::new(owner, repo, token),
            None => pcu_release_assets::ReleaseAssetClient::new_unauthenticated(owner, repo),
        };
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
    fn manifest_pubkey_source_builds_without_a_token() {
        // Constructibility only (jerus-org/jci-audit#103) — the actual
        // unauthenticated fetch needs a live network call.
        let _source = ManifestPubkeySource::new("jerus-org", "jci-audit", "jci-audit", None);
    }

    #[test]
    fn pcu_asset_source_builds_without_a_token() {
        let _source = PcuAssetSource::new("jerus-org", "jci-audit", None);
    }

    #[test]
    fn raw_manifest_url_uses_the_given_path() {
        let url = raw_manifest_url(
            "jerus-org",
            "jci-audit",
            "jci-audit-v1.2.0",
            "crates/jci-audit/Cargo.toml",
        );
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

    // ── #124 round 2: resolve a workspace package by name, cargo-style ─────

    #[test]
    fn extract_package_name_reads_the_package_table() {
        assert_eq!(
            extract_package_name("[package]\nname = \"jci-audit\"\n"),
            Some("jci-audit".to_string())
        );
    }

    #[test]
    fn extract_package_name_is_none_without_a_package_table() {
        assert_eq!(
            extract_package_name("[workspace]\nmembers = [\"crates/foo\"]\n"),
            None
        );
    }

    #[test]
    fn extract_workspace_members_reads_the_members_array() {
        assert_eq!(
            extract_workspace_members("[workspace]\nmembers = [\"crates/foo\", \"crates/bar\"]\n"),
            vec!["crates/foo".to_string(), "crates/bar".to_string()]
        );
    }

    #[test]
    fn extract_workspace_members_is_empty_without_a_workspace_table() {
        assert!(extract_workspace_members("[package]\nname = \"solo\"\n").is_empty());
    }

    #[test]
    fn is_glob_member_detects_wildcards() {
        assert!(is_glob_member("crates/*"));
        assert!(is_glob_member("crates/pkg-?"));
        assert!(!is_glob_member("crates/jci-audit"));
    }

    #[test]
    fn resolve_package_manifest_matches_the_root_package() {
        let root = "[package]\nname = \"solo\"\n";
        let matched =
            resolve_package_manifest(root, "solo", |_member| unreachable!("no members to fetch"))
                .unwrap();
        assert_eq!(matched, root);
    }

    #[test]
    fn resolve_package_manifest_checks_each_member_in_order() {
        let root = "[workspace]\nmembers = [\"crates/foo\", \"crates/bar\"]\n";
        let bar_manifest = "[package]\nname = \"bar\"\n";
        let matched = resolve_package_manifest(root, "bar", |member| match member {
            "crates/foo" => Ok("[package]\nname = \"foo\"\n".to_string()),
            "crates/bar" => Ok(bar_manifest.to_string()),
            other => panic!("unexpected member: {other}"),
        })
        .unwrap();
        assert_eq!(matched, bar_manifest);
    }

    #[test]
    fn resolve_package_manifest_skips_glob_members_and_errors_naming_them() {
        let root = "[workspace]\nmembers = [\"crates/*\"]\n";
        let err = resolve_package_manifest(root, "anything", |_member| {
            unreachable!("glob members must never be fetched")
        })
        .unwrap_err();
        assert!(err.to_string().contains("crates/*"), "got: {err}");
    }

    #[test]
    fn resolve_package_manifest_errors_naming_the_package_and_checked_members() {
        let root = "[workspace]\nmembers = [\"crates/foo\"]\n";
        let err = resolve_package_manifest(root, "missing", |_member| {
            Ok("[package]\nname = \"foo\"\n".to_string())
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("missing"), "got: {msg}");
        assert!(msg.contains("crates/foo"), "got: {msg}");
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
        )
        .unwrap();

        assert_eq!(out.db_commit, "abc1234def");
        assert!(out.recorded_pass);
        assert_eq!(out.unchecked.len(), 2, "got {:?}", out.unchecked);
    }

    #[test]
    fn unchecked_message_blames_missing_checkout_when_there_is_none() {
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
        )
        .unwrap();

        assert!(
            out.unchecked[0].contains("no local Cargo.lock/deny.toml"),
            "got {:?}",
            out.unchecked
        );
    }

    /// Records are never committed (jerus-org/jci-audit#75), so this is the
    /// normal case, not an edge case.
    #[test]
    fn unchecked_message_blames_the_missing_record_when_a_checkout_is_present() {
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
            LocalCheckoutState {
                deny_toml: true,
                cargo_lock: true,
            },
        )
        .unwrap();

        assert!(
            !out.unchecked[0].contains("Cargo.lock/deny.toml"),
            "got {:?}",
            out.unchecked
        );
        assert!(
            out.unchecked[0].contains("record"),
            "got {:?}",
            out.unchecked
        );
    }

    #[test]
    fn unchecked_message_names_only_the_file_actually_missing() {
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
            LocalCheckoutState {
                deny_toml: true,
                cargo_lock: false,
            },
        )
        .unwrap();

        assert!(
            out.unchecked[0].contains("Cargo.lock is not"),
            "got {:?}",
            out.unchecked
        );
        assert!(
            !out.unchecked[0].contains("no local Cargo.lock/deny.toml"),
            "got {:?}",
            out.unchecked
        );
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
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
            LocalCheckoutState {
                deny_toml: false,
                cargo_lock: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("checks.deny.passed"), "got: {err}");
    }
}
