//! Derive `.cargo/audit.toml` and each crate's `about.toml` from the
//! canonical `deny.toml`.
//!
//! `deny.toml` `[advisories].ignore` is the **single source of truth** for
//! advisory ignores. `cargo audit`, when run without cargo-deny, reads its own
//! `.cargo/audit.toml` — so this module projects the deny.toml ignore set (with
//! its justification comments) into that file. Likewise, `deny.toml`
//! `[licenses]` is canonical for license policy: each `crates/*/about.toml`
//! is derived from it, scoped to that crate's own dependency graph (see
//! [`crate::license_scope`]) rather than copied verbatim, since a workspace
//! can hold more than one crate and each crate's notices should reflect only
//! what it actually ships. `jci-audit sync` writes both; `jci-audit sync
//! --check` fails on drift without writing.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use crate::release::lockfile_digest;

/// One advisory ignore: its id plus any justification comment carried from
/// `deny.toml` so the derived file explains itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IgnoreEntry {
    pub(crate) id: String,
    pub(crate) comment: Option<String>,
}

/// Result of a sync operation, so the CLI can report and set an exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncOutcome {
    /// `.cargo/audit.toml` already matched the derived content.
    InSync,
    /// The file was (or would be) written with this many ignore entries.
    Wrote(usize),
    /// `--check` mode: the file differs from the derived content.
    Drift,
}

/// Extract the advisory ignore entries from a `deny.toml` string.
///
/// Reads `[advisories].ignore`, accepting both plain-string entries
/// (`"RUSTSEC-…"`) and inline-table entries (`{ id = "RUSTSEC-…", reason = …
/// }`), and captures any `#` comment written immediately above each entry. A
/// missing `[advisories]` table or `ignore` key yields an empty list (not an
/// error).
pub(crate) fn extract_ignores(deny_toml: &str) -> Result<Vec<IgnoreEntry>> {
    let doc = deny_toml
        .parse::<DocumentMut>()
        .context("failed to parse deny.toml")?;

    let array = match doc
        .get("advisories")
        .and_then(|a| a.get("ignore"))
        .and_then(Item::as_array)
    {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };

    let mut entries = Vec::with_capacity(array.len());
    for value in array.iter() {
        let id = match value_id(value) {
            Some(id) => id,
            None => bail!("deny.toml [advisories].ignore has an entry with no advisory id"),
        };
        let comment = value
            .decor()
            .prefix()
            .and_then(|p| p.as_str())
            .and_then(first_comment);
        entries.push(IgnoreEntry { id, comment });
    }
    Ok(entries)
}

/// Extract the advisory id from an ignore array value: either a bare string or
/// an inline table with an `id` key (cargo-deny's richer form).
fn value_id(value: &Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        return Some(s.to_string());
    }
    value
        .as_inline_table()
        .and_then(|t| t.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Pull the first `#` comment out of a toml_edit decor prefix, stripped of the
/// leading `#` and surrounding whitespace.
fn first_comment(prefix: &str) -> Option<String> {
    prefix.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix('#')
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
    })
}

/// Render the derived `.cargo/audit.toml` content for the given ignore set.
///
/// Always emits a `[advisories]` table with an `ignore` array (empty when there
/// are no entries) and a header marking the file as generated.
pub(crate) fn render_audit_toml(ignores: &[IgnoreEntry]) -> String {
    const HEADER: &str = "\
# DERIVED FILE — do not edit by hand.
# Regenerated from the canonical deny.toml [advisories].ignore by
# `jci-audit sync`. deny.toml is the single source of truth for advisory
# ignores; this file lets `cargo audit` (run without cargo-deny) honour the
# same ignore set.
[advisories]
";
    let mut out = String::from(HEADER);
    if ignores.is_empty() {
        out.push_str("ignore = []\n");
        return out;
    }
    out.push_str("ignore = [\n");
    for entry in ignores {
        if let Some(comment) = &entry.comment {
            out.push_str(&format!("    # {comment}\n"));
        }
        out.push_str(&format!("    \"{}\",\n", entry.id));
    }
    out.push_str("]\n");
    out
}

/// The workspace-wide license policy read from `deny.toml`: the global
/// `[licenses].allow` set, plus each `[[licenses.exceptions]]` entry's own
/// name and allow list. Unfiltered — which exceptions actually apply to a
/// given crate is [`crate::license_scope`]'s job, not this parser's.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct LicensePolicy {
    pub(crate) allow: BTreeSet<String>,
    pub(crate) exceptions: Vec<(String, Vec<String>)>,
}

/// Read an `Item`'s value as an array of strings, or an empty vec/set if the
/// item or array is absent. Shared by both the top-level `allow` list and
/// each exception's own `allow` list below, which have the identical shape.
fn string_array<T: FromIterator<String>>(item: Option<&Item>) -> T {
    item.and_then(Item::as_array)
        .into_iter()
        .flat_map(|arr| arr.iter().filter_map(Value::as_str).map(str::to_string))
        .collect()
}

/// Extract the license policy from a `deny.toml` string. A missing
/// `[licenses]` table, `allow` key, or `exceptions` array yields empty
/// results (not an error) — mirrors [`extract_ignores`]'s handling of a
/// missing `[advisories]`.
pub(crate) fn extract_license_policy(deny_toml: &str) -> Result<LicensePolicy> {
    let doc = deny_toml
        .parse::<DocumentMut>()
        .context("failed to parse deny.toml")?;

    let licenses = doc.get("licenses");
    let allow = string_array(licenses.and_then(|l| l.get("allow")));

    let mut exceptions = Vec::new();
    if let Some(array_of_tables) = licenses
        .and_then(|l| l.get("exceptions"))
        .and_then(Item::as_array_of_tables)
    {
        for table in array_of_tables.iter() {
            let Some(name) = table.get("name").and_then(Item::as_str) else {
                continue;
            };
            let allow_list = string_array(table.get("allow"));
            exceptions.push((name.to_string(), allow_list));
        }
    }

    Ok(LicensePolicy { allow, exceptions })
}

/// Build a TOML array with one element per line, trailing comma included —
/// matching this repo's existing hand-authored style (the same shape
/// `render_audit_toml` produces for `.cargo/audit.toml`, by hand-formatting a
/// string there since that file is rendered from scratch; here the array is
/// inserted into an existing document via `toml_edit`, so the formatting has
/// to be set on the `Array`/`Value` decor directly instead).
fn multiline_array<I: IntoIterator<Item = String>>(items: I) -> Array {
    let mut arr = Array::new();
    for item in items {
        let mut v = Value::from(item);
        v.decor_mut().set_prefix("\n    ");
        arr.push_formatted(v);
    }
    if !arr.is_empty() {
        arr.set_trailing("\n");
    }
    arr.set_trailing_comma(true);
    arr
}

/// Merge a crate's precise, already-scoped license set into its existing
/// `about.toml` document, preserving everything the derivation doesn't own:
/// hand-authored `[crate.clarify]` attribution pins, comments, and
/// `ignore-dev-dependencies`. Not a wholesale rewrite (unlike
/// [`render_audit_toml`]) because `about.toml` carries real hand-maintained
/// content `deny.toml` has no equivalent for.
pub(crate) fn merge_about_toml(
    existing: &str,
    scope: &crate::license_scope::CrateLicenseScope,
    policy: &LicensePolicy,
) -> Result<String> {
    let mut doc = if existing.trim().is_empty() {
        DocumentMut::new()
    } else {
        existing
            .parse::<DocumentMut>()
            .context("failed to parse existing about.toml content")?
    };

    doc["accepted"] = Item::Value(Value::Array(multiline_array(
        scope.accepted.iter().cloned(),
    )));

    for (name, allow_list) in &policy.exceptions {
        if !scope.reachable_exception_crates.contains(name) {
            continue;
        }
        let entry = doc.entry(name).or_insert_with(|| Item::Table(Table::new()));
        let table = entry
            .as_table_mut()
            .with_context(|| format!("'{name}' in about.toml is not a table"))?;
        table["accepted"] = Item::Value(Value::Array(multiline_array(allow_list.iter().cloned())));
    }

    let qualifying: BTreeSet<&str> = policy
        .exceptions
        .iter()
        .filter(|(name, _)| scope.reachable_exception_crates.contains(name))
        .map(|(name, _)| name.as_str())
        .collect();
    let stale: Vec<String> = doc
        .iter()
        .filter_map(|(key, item)| {
            let table = item.as_table()?;
            (table.contains_key("accepted") && !qualifying.contains(key)).then(|| key.to_string())
        })
        .collect();
    for name in stale {
        if let Some(table) = doc.get_mut(&name).and_then(Item::as_table_mut) {
            table.remove("accepted");
        }
        if doc
            .get(&name)
            .and_then(Item::as_table)
            .is_some_and(Table::is_empty)
        {
            doc.remove(&name);
        }
    }

    Ok(doc.to_string())
}

/// Locate the workspace `deny.toml` and the derived `.cargo/audit.toml`,
/// walking up from `start` until a directory containing `deny.toml` is found.
pub(crate) fn locate_paths(start: &Path) -> Result<(PathBuf, PathBuf)> {
    let start = start
        .canonicalize()
        .with_context(|| format!("cannot access '{}'", start.display()))?;
    let mut dir = start.as_path();
    loop {
        let deny = dir.join("deny.toml");
        if deny.is_file() {
            let audit = dir.join(".cargo").join("audit.toml");
            return Ok((deny, audit));
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => bail!(
                "could not find deny.toml in '{}' or any parent directory",
                start.display()
            ),
        }
    }
}

/// What [`decide_and_write`] found and did, before the caller attaches its
/// own count (ignores derived, or licenses accepted) to make a [`SyncOutcome`].
enum WriteDecision {
    InSync,
    Drift,
    Wrote,
}

/// The shared "does the derived content match what's on disk, and if not,
/// write it (unless `check`)" decision both [`sync_at`] and
/// [`sync_about_toml_at`] make — `render_audit_toml` and `merge_about_toml`
/// differ, but what happens with the result once derived does not. Creates
/// `path`'s parent directory first, so this also covers `.cargo/` not
/// existing yet for `audit.toml`.
fn decide_and_write(
    path: &Path,
    existing: Option<&str>,
    desired: &str,
    check: bool,
) -> Result<WriteDecision> {
    if existing == Some(desired) {
        return Ok(WriteDecision::InSync);
    }
    if check {
        return Ok(WriteDecision::Drift);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create '{}'", parent.display()))?;
    }
    std::fs::write(path, desired)
        .with_context(|| format!("failed to write '{}'", path.display()))?;
    Ok(WriteDecision::Wrote)
}

/// Run the sync from `start` (the directory to search from). In `check` mode,
/// returns `Drift`/`InSync` without writing; otherwise writes the file and
/// returns `Wrote(n)`.
pub(crate) fn sync_at(start: &Path, check: bool) -> Result<SyncOutcome> {
    let (deny_path, audit_path) = locate_paths(start)?;
    let deny = std::fs::read_to_string(&deny_path)
        .with_context(|| format!("failed to read '{}'", deny_path.display()))?;
    let ignores = extract_ignores(&deny)?;
    let desired = render_audit_toml(&ignores);

    let existing = match std::fs::read_to_string(&audit_path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(e).with_context(|| format!("failed to read '{}'", audit_path.display()));
        }
    };

    Ok(
        match decide_and_write(&audit_path, existing.as_deref(), &desired, check)? {
            WriteDecision::InSync => SyncOutcome::InSync,
            WriteDecision::Drift => SyncOutcome::Drift,
            WriteDecision::Wrote => SyncOutcome::Wrote(ignores.len()),
        },
    )
}

/// Every workspace member's `about.toml`, sorted so the result is
/// deterministic. A member with no `about.toml` is skipped — not every
/// crate need publish third-party notices. Reads `packages[].manifest_path`
/// from `cargo metadata --no-deps` output — the workspace's own declared
/// membership (`[workspace].members` in `Cargo.toml`), not an assumption
/// that every crate lives under `crates/*/` (jerus-org/jci-audit#100).
pub(crate) fn about_toml_paths_from_metadata(metadata_json: &str) -> Result<Vec<PathBuf>> {
    let doc: serde_json::Value =
        serde_json::from_str(metadata_json).context("failed to parse cargo metadata JSON")?;
    let packages = doc
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .context("cargo metadata JSON has no 'packages' array")?;
    let mut paths: Vec<PathBuf> = packages
        .iter()
        .filter_map(|pkg| pkg.get("manifest_path").and_then(serde_json::Value::as_str))
        .filter_map(|manifest_path| Path::new(manifest_path).parent())
        .map(|crate_dir| crate_dir.join("about.toml"))
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    Ok(paths)
}

/// Every workspace member's `about.toml` under `workspace_root` — the single
/// place [`sync_about_toml_at`] and [`about_toml_digest`] both walk from,
/// rather than each re-implementing the `cargo metadata` call.
pub(crate) fn find_about_toml_paths<R: crate::check::CommandRunner>(
    runner: &R,
    workspace_root: &Path,
) -> Result<Vec<PathBuf>> {
    let manifest = workspace_root.join("Cargo.toml");
    let manifest_str = manifest.to_string_lossy();
    let out = runner.run(
        "cargo",
        &[
            "metadata",
            "--manifest-path",
            &manifest_str,
            "--no-deps",
            "--format-version",
            "1",
        ],
        workspace_root,
    )?;
    if !out.success {
        bail!("cargo metadata failed for '{manifest_str}': {}", out.stderr);
    }
    about_toml_paths_from_metadata(&out.stdout)
}

/// The result of syncing one crate's `about.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AboutSyncResult {
    pub(crate) about_toml_path: PathBuf,
    pub(crate) outcome: SyncOutcome,
}

/// Sync every `crates/*/about.toml` found under the workspace root (located
/// via the same `deny.toml` search as [`sync_at`]) against its own
/// crate-scoped derivation.
pub(crate) fn sync_about_toml_at<R: crate::check::CommandRunner>(
    runner: &R,
    start: &Path,
    check: bool,
) -> Result<Vec<AboutSyncResult>> {
    let (deny_path, _) = locate_paths(start)?;
    let workspace_root = deny_path
        .parent()
        .context("deny.toml has no parent directory")?;
    let deny = std::fs::read_to_string(&deny_path)
        .with_context(|| format!("failed to read '{}'", deny_path.display()))?;
    let policy = extract_license_policy(&deny)?;
    let exception_names: BTreeSet<String> =
        policy.exceptions.iter().map(|(n, _)| n.clone()).collect();

    let mut results = Vec::new();
    for about_path in find_about_toml_paths(runner, workspace_root)? {
        let crate_dir = about_path
            .parent()
            .context("about.toml path has no parent directory")?;
        let manifest_path = crate_dir.join("Cargo.toml");
        let scope = crate::license_scope::scope_for_crate(
            runner,
            &manifest_path,
            &policy.allow,
            &exception_names,
        )?;
        let existing = std::fs::read_to_string(&about_path)
            .with_context(|| format!("failed to read '{}'", about_path.display()))?;
        // merge_about_toml only sees the content, not the path (it's tested
        // against fixture strings) — name which crate's about.toml failed
        // here, at the one call site that knows, since a workspace can hold
        // more than one.
        let desired = merge_about_toml(&existing, &scope, &policy)
            .with_context(|| format!("while deriving '{}'", about_path.display()))?;

        let outcome = match decide_and_write(&about_path, Some(&existing), &desired, check)? {
            WriteDecision::InSync => SyncOutcome::InSync,
            WriteDecision::Drift => SyncOutcome::Drift,
            WriteDecision::Wrote => SyncOutcome::Wrote(scope.accepted.len()),
        };
        results.push(AboutSyncResult {
            about_toml_path: about_path,
            outcome,
        });
    }
    Ok(results)
}

/// Digest of every workspace member's `about.toml`. `None` when the
/// workspace has no `about.toml` at all — nothing to attest. Digests the
/// **policy file**, not the rendered `THIRD-PARTY-LICENSES.md`: the notices
/// are not reproducible across machines (see `scripts/licenses.sh`'s own
/// comment on this), so a value that could differ between the machine that
/// generated the committed copy and the release container would make
/// `verify` unable to reproduce it.
pub(crate) fn about_toml_digest<R: crate::check::CommandRunner>(
    runner: &R,
    workspace_root: &Path,
) -> Result<Option<String>> {
    let paths = find_about_toml_paths(runner, workspace_root)?;
    about_toml_digest_from_paths(&paths, workspace_root)
}

/// Same digest as [`about_toml_digest`], computed directly from an
/// already-known set of `about.toml` paths — for callers (like
/// `release_with`) that have already enumerated them via
/// [`sync_about_toml_at`] and shouldn't pay for a second `cargo metadata`
/// call to re-derive the identical list.
pub(crate) fn about_toml_digest_from_paths(
    paths: &[PathBuf],
    workspace_root: &Path,
) -> Result<Option<String>> {
    if paths.is_empty() {
        return Ok(None);
    }

    let mut blob = String::new();
    for path in paths {
        let rel = path.strip_prefix(workspace_root).unwrap_or(path);
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        blob.push_str(&rel.display().to_string());
        blob.push('\n');
        blob.push_str(&content);
        blob.push_str("\n---\n");
    }
    Ok(Some(lockfile_digest(blob.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY_WITH_TWO: &str = r#"
[advisories]
db-path = "~/.cargo/advisory-db"
unmaintained = "all"
ignore = [
    # RUSTSEC-2023-0071: Marvin Attack timing side-channel in rsa.
    "RUSTSEC-2023-0071",
    "RUSTSEC-2024-0001",
]

[licenses]
allow = ["MIT"]
"#;

    const DENY_EMPTY_IGNORE: &str = r#"
[advisories]
ignore = []
"#;

    const DENY_NO_ADVISORIES: &str = r#"
[licenses]
allow = ["MIT"]
"#;

    #[test]
    fn extract_two_ids_in_order() {
        let entries = extract_ignores(DENY_WITH_TWO).unwrap();
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["RUSTSEC-2023-0071", "RUSTSEC-2024-0001"]);
    }

    #[test]
    fn extract_captures_comment() {
        let entries = extract_ignores(DENY_WITH_TWO).unwrap();
        assert!(
            entries[0]
                .comment
                .as_deref()
                .unwrap_or("")
                .contains("Marvin Attack"),
            "expected the justification comment to be captured, got {:?}",
            entries[0].comment
        );
        assert_eq!(entries[1].comment, None);
    }

    #[test]
    fn extract_empty_and_missing_yield_no_entries() {
        assert!(extract_ignores(DENY_EMPTY_IGNORE).unwrap().is_empty());
        assert!(extract_ignores(DENY_NO_ADVISORIES).unwrap().is_empty());
    }

    #[test]
    fn extract_accepts_inline_table_entries() {
        let deny = r#"
[advisories]
ignore = [
    { id = "RUSTSEC-2023-0071", reason = "no fix upstream" },
]
"#;
        let entries = extract_ignores(deny).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "RUSTSEC-2023-0071");
    }

    #[test]
    fn render_empty_has_advisories_and_empty_array() {
        let out = render_audit_toml(&[]);
        assert!(out.contains("[advisories]"), "got:\n{out}");
        assert!(out.contains("ignore = []"), "got:\n{out}");
    }

    #[test]
    fn render_includes_ids_and_comments() {
        let entries = vec![
            IgnoreEntry {
                id: "RUSTSEC-2023-0071".into(),
                comment: Some("Marvin Attack".into()),
            },
            IgnoreEntry {
                id: "RUSTSEC-2024-0001".into(),
                comment: None,
            },
        ];
        let out = render_audit_toml(&entries);
        assert!(out.contains("\"RUSTSEC-2023-0071\""), "got:\n{out}");
        assert!(out.contains("\"RUSTSEC-2024-0001\""), "got:\n{out}");
        assert!(out.contains("Marvin Attack"), "got:\n{out}");
    }

    #[test]
    fn render_is_idempotent_through_extract() {
        // render -> parse back -> same ids
        let entries = vec![
            IgnoreEntry {
                id: "RUSTSEC-2023-0071".into(),
                comment: Some("reason".into()),
            },
            IgnoreEntry {
                id: "RUSTSEC-2024-0001".into(),
                comment: None,
            },
        ];
        let rendered = render_audit_toml(&entries);
        let reparsed = extract_ignores(&rendered).unwrap();
        let ids: Vec<&str> = reparsed.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["RUSTSEC-2023-0071", "RUSTSEC-2024-0001"]);
    }

    #[test]
    fn sync_writes_then_is_in_sync_and_detects_drift() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("deny.toml"), DENY_WITH_TWO).unwrap();

        // First write derives the file.
        let outcome = sync_at(root, false).unwrap();
        assert_eq!(outcome, SyncOutcome::Wrote(2));
        let audit = root.join(".cargo/audit.toml");
        assert!(audit.exists());

        // Now --check reports in-sync.
        assert_eq!(sync_at(root, true).unwrap(), SyncOutcome::InSync);

        // Corrupt the derived file → drift detected, and --check does not rewrite.
        std::fs::write(&audit, "[advisories]\nignore = []\n").unwrap();
        assert_eq!(sync_at(root, true).unwrap(), SyncOutcome::Drift);
        assert_eq!(
            std::fs::read_to_string(&audit).unwrap(),
            "[advisories]\nignore = []\n",
            "--check must not modify the file"
        );
    }

    #[test]
    fn sync_check_on_missing_file_is_drift() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("deny.toml"), DENY_WITH_TWO).unwrap();
        // No .cargo/audit.toml yet.
        assert_eq!(sync_at(root, true).unwrap(), SyncOutcome::Drift);
    }

    // --- license policy extraction + about.toml merge -----------------

    const DENY_WITH_LICENSE_POLICY: &str = r#"
[licenses]
allow = ["MIT", "Apache-2.0"]

# MPL-2.0 (file-level copyleft): transitive config/dirs helper.
[[licenses.exceptions]]
name = "option-ext"
allow = ["MPL-2.0"]
"#;

    #[test]
    fn extract_license_policy_reads_allow_and_exceptions() {
        let policy = extract_license_policy(DENY_WITH_LICENSE_POLICY).unwrap();
        assert_eq!(
            policy.allow,
            ["MIT".to_string(), "Apache-2.0".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            policy.exceptions,
            vec![("option-ext".to_string(), vec!["MPL-2.0".to_string()])]
        );
    }

    #[test]
    fn extract_license_policy_missing_sections_yield_empty() {
        let policy = extract_license_policy("").unwrap();
        assert!(policy.allow.is_empty());
        assert!(policy.exceptions.is_empty());
    }

    fn scope(
        accepted: &[&str],
        reachable_exceptions: &[&str],
    ) -> crate::license_scope::CrateLicenseScope {
        crate::license_scope::CrateLicenseScope {
            accepted: accepted.iter().map(|s| s.to_string()).collect(),
            reachable_exception_crates: reachable_exceptions
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    fn policy_with_option_ext() -> LicensePolicy {
        LicensePolicy {
            allow: ["MIT".to_string(), "Apache-2.0".to_string()]
                .into_iter()
                .collect(),
            exceptions: vec![("option-ext".to_string(), vec!["MPL-2.0".to_string()])],
        }
    }

    #[test]
    fn merge_about_toml_sets_top_level_accepted() {
        let out = merge_about_toml("", &scope(&["MIT"], &[]), &LicensePolicy::default()).unwrap();
        let reparsed = out.parse::<DocumentMut>().unwrap();
        let accepted: Vec<&str> = reparsed["accepted"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(accepted, vec!["MIT"]);
    }

    #[test]
    fn merge_about_toml_renders_accepted_one_per_line() {
        // Matches this repo's existing hand-authored about.toml style.
        let out = merge_about_toml(
            "",
            &scope(&["MIT", "Apache-2.0"], &[]),
            &LicensePolicy::default(),
        )
        .unwrap();
        assert!(
            out.contains("accepted = [\n    \"Apache-2.0\",\n    \"MIT\",\n]\n"),
            "expected one license per line, got:\n{out}"
        );
    }

    #[test]
    fn merge_about_toml_preserves_clarify_block_when_crate_also_gains_accepted() {
        let existing = r#"
accepted = ["MIT"]

[libgit2-sys.clarify]
license = "MIT"
[[libgit2-sys.clarify.files]]
path = "LICENSE-MIT"
checksum = "abc"
"#;
        let policy = LicensePolicy {
            allow: ["MIT".to_string()].into_iter().collect(),
            exceptions: vec![("libgit2-sys".to_string(), vec!["MIT".to_string()])],
        };
        let out = merge_about_toml(existing, &scope(&["MIT"], &["libgit2-sys"]), &policy).unwrap();
        let reparsed = out.parse::<DocumentMut>().unwrap();
        let table = reparsed["libgit2-sys"].as_table().unwrap();
        assert!(
            table.get("clarify").is_some(),
            "the hand-authored clarify block must survive: {out}"
        );
        let accepted: Vec<&str> = table["accepted"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(accepted, vec!["MIT"]);
    }

    #[test]
    fn merge_about_toml_removes_stale_exception_table_entirely() {
        let existing = r#"
accepted = ["MIT"]

[option-ext]
accepted = ["MPL-2.0"]
"#;
        // option-ext is no longer reachable — its exception no longer qualifies.
        let out =
            merge_about_toml(existing, &scope(&["MIT"], &[]), &policy_with_option_ext()).unwrap();
        let reparsed = out.parse::<DocumentMut>().unwrap();
        assert!(
            reparsed.get("option-ext").is_none(),
            "a table left with nothing but a stale accepted key must be dropped entirely: {out}"
        );
    }

    #[test]
    fn merge_about_toml_removes_stale_key_but_keeps_other_content() {
        let existing = r#"
accepted = ["MIT"]

[option-ext.clarify]
license = "MPL-2.0"

[option-ext]
accepted = ["MPL-2.0"]
"#;
        let out =
            merge_about_toml(existing, &scope(&["MIT"], &[]), &policy_with_option_ext()).unwrap();
        let reparsed = out.parse::<DocumentMut>().unwrap();
        let table = reparsed["option-ext"].as_table().unwrap();
        assert!(
            table.get("accepted").is_none(),
            "the stale accepted key must be removed: {out}"
        );
        assert!(
            table.get("clarify").is_some(),
            "other content under the same table must survive: {out}"
        );
    }

    #[test]
    fn merge_about_toml_is_idempotent() {
        let once = merge_about_toml(
            "",
            &scope(&["MIT", "Apache-2.0"], &["option-ext"]),
            &policy_with_option_ext(),
        )
        .unwrap();
        let twice = merge_about_toml(
            &once,
            &scope(&["MIT", "Apache-2.0"], &["option-ext"]),
            &policy_with_option_ext(),
        )
        .unwrap();
        assert_eq!(once, twice);
    }

    // --- sync_about_toml_at (mocked cargo metadata) --------------------

    use crate::check::{CommandRunner, ToolOutput};
    use std::{cell::RefCell, collections::VecDeque};

    struct MockRunner {
        responses: RefCell<VecDeque<ToolOutput>>,
    }

    impl MockRunner {
        fn new(responses: Vec<ToolOutput>) -> Self {
            Self {
                responses: RefCell::new(responses.into_iter().collect()),
            }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, _program: &str, _args: &[&str], _cwd: &Path) -> Result<ToolOutput> {
            Ok(self
                .responses
                .borrow_mut()
                .pop_front()
                .expect("no more mock cargo-metadata responses"))
        }
    }

    fn ok(json: String) -> ToolOutput {
        ToolOutput {
            success: true,
            stdout: json,
            stderr: String::new(),
        }
    }

    fn metadata_json(root_id: &str, dep_name: &str, dep_id: &str, dep_license: &str) -> String {
        format!(
            r#"{{
              "packages": [
                {{ "name": "root", "version": "0.0.0", "id": "{root_id}", "license": null }},
                {{ "name": "{dep_name}", "version": "1.0.0", "id": "{dep_id}", "license": "{dep_license}" }}
              ],
              "resolve": {{
                "root": "{root_id}",
                "nodes": [
                  {{ "id": "{root_id}", "deps": [
                    {{ "name": "{dep_name}", "pkg": "{dep_id}", "dep_kinds": [ {{ "kind": null, "target": null }} ] }}
                  ] }},
                  {{ "id": "{dep_id}", "deps": [] }}
                ]
              }}
            }}"#
        )
    }

    fn metadata_json_no_deps(root_id: &str) -> String {
        format!(
            r#"{{
              "packages": [
                {{ "name": "root", "version": "0.0.0", "id": "{root_id}", "license": null }}
              ],
              "resolve": {{
                "root": "{root_id}",
                "nodes": [ {{ "id": "{root_id}", "deps": [] }} ]
              }}
            }}"#
        )
    }

    // --- find_about_toml_paths (#100: cargo metadata, not a crates/ scan) --

    fn workspace_metadata_json(manifest_paths: &[String]) -> String {
        let packages: Vec<String> = manifest_paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                format!(
                    r#"{{"name":"crate{i}","version":"0.0.0","id":"id{i}","manifest_path":"{p}"}}"#
                )
            })
            .collect();
        format!(r#"{{"packages":[{}]}}"#, packages.join(","))
    }

    #[test]
    fn about_toml_paths_from_metadata_finds_existing_about_tomls() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("packages/a");
        let b = dir.path().join("libs/b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("about.toml"), "").unwrap();
        // b has no about.toml — must be skipped, not every crate publishes one.
        let json = workspace_metadata_json(&[
            a.join("Cargo.toml").to_string_lossy().into_owned(),
            b.join("Cargo.toml").to_string_lossy().into_owned(),
        ]);
        let paths = about_toml_paths_from_metadata(&json).unwrap();
        assert_eq!(paths, vec![a.join("about.toml")]);
    }

    /// The whole point of #100: any workspace layout works, not just
    /// `crates/*/` — including a package living at the workspace root.
    #[test]
    fn about_toml_paths_from_metadata_is_not_limited_to_a_crates_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("about.toml"), "").unwrap();
        let json = workspace_metadata_json(&[dir
            .path()
            .join("Cargo.toml")
            .to_string_lossy()
            .into_owned()]);
        let paths = about_toml_paths_from_metadata(&json).unwrap();
        assert_eq!(paths, vec![dir.path().join("about.toml")]);
    }

    #[test]
    fn about_toml_paths_from_metadata_is_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let z = dir.path().join("crates/z-crate");
        let a = dir.path().join("crates/a-crate");
        std::fs::create_dir_all(&z).unwrap();
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(z.join("about.toml"), "").unwrap();
        std::fs::write(a.join("about.toml"), "").unwrap();
        let json = workspace_metadata_json(&[
            z.join("Cargo.toml").to_string_lossy().into_owned(),
            a.join("Cargo.toml").to_string_lossy().into_owned(),
        ]);
        let paths = about_toml_paths_from_metadata(&json).unwrap();
        assert_eq!(paths, vec![a.join("about.toml"), z.join("about.toml")]);
    }

    #[test]
    fn about_toml_paths_from_metadata_errors_on_malformed_json() {
        assert!(about_toml_paths_from_metadata("not json").is_err());
    }

    #[test]
    fn find_about_toml_paths_runs_cargo_metadata_against_the_workspace_root() {
        let dir = tempfile::tempdir().unwrap();
        let crate_dir = dir.path().join("crates/demo");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("about.toml"), "").unwrap();
        let json =
            workspace_metadata_json(&[crate_dir.join("Cargo.toml").to_string_lossy().into_owned()]);
        let runner = MockRunner::new(vec![ok(json)]);
        let paths = find_about_toml_paths(&runner, dir.path()).unwrap();
        assert_eq!(paths, vec![crate_dir.join("about.toml")]);
    }

    #[test]
    fn sync_about_toml_writes_then_is_in_sync_and_detects_drift() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("deny.toml"), DENY_WITH_LICENSE_POLICY).unwrap();
        let crate_dir = root.join("crates/demo");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(crate_dir.join("about.toml"), "").unwrap();

        let workspace = || {
            ok(workspace_metadata_json(&[crate_dir
                .join("Cargo.toml")
                .to_string_lossy()
                .into_owned()]))
        };
        let json = metadata_json(
            "path+file:///demo#0.0.0",
            "anyhow",
            "registry+https://x#anyhow@1.0.0",
            "MIT",
        );
        let runner = MockRunner::new(vec![workspace(), ok(json)]);
        let results = sync_about_toml_at(&runner, root, false).unwrap();
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].outcome, SyncOutcome::Wrote(_)));

        // Now --check reports in-sync without consuming a metadata call
        // beyond the ones it needs.
        let json = metadata_json(
            "path+file:///demo#0.0.0",
            "anyhow",
            "registry+https://x#anyhow@1.0.0",
            "MIT",
        );
        let runner = MockRunner::new(vec![workspace(), ok(json)]);
        let results = sync_about_toml_at(&runner, root, true).unwrap();
        assert_eq!(results[0].outcome, SyncOutcome::InSync);

        // Corrupt the file → drift, and --check must not rewrite it.
        let about_path = crate_dir.join("about.toml");
        std::fs::write(&about_path, "accepted = []\n").unwrap();
        let json = metadata_json(
            "path+file:///demo#0.0.0",
            "anyhow",
            "registry+https://x#anyhow@1.0.0",
            "MIT",
        );
        let runner = MockRunner::new(vec![workspace(), ok(json)]);
        let results = sync_about_toml_at(&runner, root, true).unwrap();
        assert_eq!(results[0].outcome, SyncOutcome::Drift);
        assert_eq!(
            std::fs::read_to_string(&about_path).unwrap(),
            "accepted = []\n",
            "--check must not modify the file"
        );
    }

    #[test]
    fn sync_about_toml_scopes_exceptions_per_crate() {
        // Two crates: crate-a reaches option-ext (MPL-2.0), crate-b doesn't.
        // Only crate-a's about.toml should gain the exception's override.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("deny.toml"), DENY_WITH_LICENSE_POLICY).unwrap();

        for name in ["crate-a", "crate-b"] {
            let crate_dir = root.join("crates").join(name);
            std::fs::create_dir_all(&crate_dir).unwrap();
            std::fs::write(
                crate_dir.join("Cargo.toml"),
                format!("[package]\nname = \"{name}\"\n"),
            )
            .unwrap();
            std::fs::write(crate_dir.join("about.toml"), "").unwrap();
        }

        // Directories are visited in sorted order: crate-a, then crate-b.
        let a_json = metadata_json(
            "path+file:///a#0.0.0",
            "option-ext",
            "registry+https://x#option-ext@0.2.0",
            "MPL-2.0",
        );
        let b_json = metadata_json_no_deps("path+file:///b#0.0.0");
        let workspace = ok(workspace_metadata_json(&[
            root.join("crates/crate-a/Cargo.toml")
                .to_string_lossy()
                .into_owned(),
            root.join("crates/crate-b/Cargo.toml")
                .to_string_lossy()
                .into_owned(),
        ]));
        let runner = MockRunner::new(vec![workspace, ok(a_json), ok(b_json)]);

        let results = sync_about_toml_at(&runner, root, false).unwrap();
        assert_eq!(results.len(), 2);

        let a_content = std::fs::read_to_string(root.join("crates/crate-a/about.toml")).unwrap();
        let b_content = std::fs::read_to_string(root.join("crates/crate-b/about.toml")).unwrap();
        assert!(
            a_content.contains("[option-ext]") && a_content.contains("MPL-2.0"),
            "crate-a reaches option-ext and must carry its exception: {a_content}"
        );
        assert!(
            !b_content.contains("option-ext"),
            "crate-b never reaches option-ext and must not carry its exception: {b_content}"
        );
    }

    // --- about_toml_digest ---------------------------------------------

    #[test]
    fn about_toml_digest_is_none_without_any_about_toml() {
        let repo = tempfile::tempdir().unwrap();
        let runner = MockRunner::new(vec![ok(workspace_metadata_json(&[]))]);
        assert_eq!(about_toml_digest(&runner, repo.path()).unwrap(), None);
    }

    #[test]
    fn about_toml_digest_is_deterministic_and_content_sensitive() {
        let repo = tempfile::tempdir().unwrap();
        let crate_dir = repo.path().join("crates/demo");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("about.toml"), "accepted = [\"MIT\"]\n").unwrap();
        let manifest = crate_dir.join("Cargo.toml").to_string_lossy().into_owned();

        let runner = MockRunner::new(vec![ok(workspace_metadata_json(std::slice::from_ref(
            &manifest,
        )))]);
        let a = about_toml_digest(&runner, repo.path()).unwrap().unwrap();
        let runner = MockRunner::new(vec![ok(workspace_metadata_json(std::slice::from_ref(
            &manifest,
        )))]);
        let b = about_toml_digest(&runner, repo.path()).unwrap().unwrap();
        assert_eq!(a, b, "must be deterministic");

        std::fs::write(
            crate_dir.join("about.toml"),
            "accepted = [\"MIT\", \"Apache-2.0\"]\n",
        )
        .unwrap();
        let runner = MockRunner::new(vec![ok(workspace_metadata_json(&[manifest]))]);
        let c = about_toml_digest(&runner, repo.path()).unwrap().unwrap();
        assert_ne!(a, c, "must depend on content");
    }
}
