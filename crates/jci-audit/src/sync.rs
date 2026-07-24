//! Derive `.cargo/audit.toml` from the canonical `deny.toml`.
//!
//! `deny.toml` `[advisories].ignore` is the **single source of truth** for
//! advisory ignores. `cargo audit`, when run without cargo-deny, reads its own
//! `.cargo/audit.toml` — so this module projects the deny.toml ignore set (with
//! its justification comments) into that file. `jci-audit sync` writes it;
//! `jci-audit sync --check` fails on drift without writing.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use toml_edit::{DocumentMut, Item, Value};

/// One advisory ignore: its id plus any justification comment carried from
/// `deny.toml` so the derived file explains itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreEntry {
    pub id: String,
    pub comment: Option<String>,
}

/// Result of a sync operation, so the CLI can report and set an exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
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
pub fn extract_ignores(deny_toml: &str) -> Result<Vec<IgnoreEntry>> {
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
pub fn render_audit_toml(ignores: &[IgnoreEntry]) -> String {
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

/// Locate the workspace `deny.toml` and the derived `.cargo/audit.toml`,
/// walking up from `start` until a directory containing `deny.toml` is found.
pub fn locate_paths(start: &Path) -> Result<(PathBuf, PathBuf)> {
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

/// Run the sync from `start` (the directory to search from). In `check` mode,
/// returns `Drift`/`InSync` without writing; otherwise writes the file and
/// returns `Wrote(n)`.
pub fn sync_at(start: &Path, check: bool) -> Result<SyncOutcome> {
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

    if existing.as_deref() == Some(desired.as_str()) {
        return Ok(SyncOutcome::InSync);
    }
    if check {
        return Ok(SyncOutcome::Drift);
    }

    if let Some(parent) = audit_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create '{}'", parent.display()))?;
    }
    std::fs::write(&audit_path, &desired)
        .with_context(|| format!("failed to write '{}'", audit_path.display()))?;
    Ok(SyncOutcome::Wrote(ignores.len()))
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
}
