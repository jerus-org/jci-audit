//! Scaffold a standard `deny.toml` plus a derived `.cargo/audit.toml`.
//!
//! The template is the "Style-B" cargo-deny policy: vulnerabilities always
//! denied, `unmaintained`/`yanked` surfaced, a permissive license allow-list
//! with weak-copyleft licenses admitted only per-crate via
//! `[[licenses.exceptions]]`, and pinned advisory-db sources.
//! `.cargo/audit.toml` is derived from it so cargo-audit honours the same
//! (initially empty) ignore set. See [`crate::sync`] for the derivation.

use std::path::Path;

use anyhow::{Context, Result};

use toml_edit::{DocumentMut, Item, Table};

use crate::sync::{extract_ignores, render_audit_toml};

/// The standard Style-B `deny.toml` written by `jci-audit init`.
pub(crate) const DENY_TEMPLATE: &str = r#"[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
# Vulnerabilities are always denied by cargo-deny. unmaintained/unsound are
# scope selectors ("all" | "workspace" | "transitive" | "none"); "all" checks
# every crate in the graph and reports them as warnings.
unmaintained = "all"
yanked = "warn"
# Canonical source of truth for advisory ignores. `.cargo/audit.toml` is
# derived from this list via `jci-audit sync`. Give each entry a written
# justification.
ignore = []

[licenses]
# All licenses are denied unless explicitly allowed. Permissive licenses are
# allowed globally; weak-copyleft licenses are NOT — scope them to the specific
# transitive crates that carry them via [[licenses.exceptions]], so a new
# copyleft dependency fails the check until consciously reviewed.
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
    "BSL-1.0",
    "CDLA-Permissive-2.0",
]

# Example: admit a weak-copyleft license only for the crate that carries it.
# [[licenses.exceptions]]
# name = "some-crate"
# allow = ["MPL-2.0"]

[bans]
multiple-versions = "warn"
wildcards = "allow"

[sources]
unknown-registry = "warn"
unknown-git = "warn"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
"#;

/// What `init` did to `deny.toml`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DenyOutcome {
    /// No `deny.toml` existed; the template was written.
    Created,
    /// `--force`: an existing file was replaced by the template.
    Replaced,
    /// An existing file was missing these template keys, now added. Each entry
    /// reads `[table] key`.
    Merged { added: Vec<String> },
    /// An existing file already carried every template key; not rewritten.
    Unchanged,
}

/// What `init` did to `.cargo/audit.toml`, which it always derives from
/// `deny.toml`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuditOutcome {
    Created,
    /// A file that differed from the derived content was replaced.
    Overwritten,
    /// The file already matched the derived content.
    Unchanged,
}

/// What `init` did to each file it manages.
#[derive(Debug)]
pub(crate) struct InitOutcome {
    pub(crate) deny: DenyOutcome,
    pub(crate) audit: AuditOutcome,
}

/// An existing `deny.toml` with the template's missing keys added.
#[derive(Debug)]
pub(crate) struct MergeOutcome {
    pub(crate) text: String,
    /// Each key added, as `[table] key`.
    pub(crate) added: Vec<String>,
}

/// Add every table and key of `template` that `existing` lacks, leaving all
/// existing content (values, comments, entries, order) untouched.
///
/// A key the user already set is never compared or altered, whatever its
/// value; the template is a starting point, not a schema.
pub(crate) fn merge_deny_toml(existing: &str, template: &str) -> Result<MergeOutcome> {
    let mut doc = existing
        .parse::<DocumentMut>()
        .context("failed to parse deny.toml")?;
    let template = template
        .parse::<DocumentMut>()
        .context("failed to parse the deny.toml template")?;

    let mut added = Vec::new();
    for (table_name, template_item) in template.iter() {
        let Some(template_table) = template_item.as_table() else {
            continue;
        };
        let item = doc.entry(table_name).or_insert_with(|| {
            let mut table = Table::new();
            *table.decor_mut() = template_table.decor().clone();
            Item::Table(table)
        });
        for (key, template_value) in template_table {
            let present = item
                .as_table_like()
                .with_context(|| format!("deny.toml [{table_name}] is not a table"))?
                .contains_key(key);
            if present {
                continue;
            }
            insert_key(item, template_table, key, template_value.clone());
            added.push(format!("[{table_name}] {key}"));
        }
    }

    let mut text = doc.to_string();
    if !added.is_empty() && !existing.is_empty() && !existing.ends_with('\n') {
        text = text.replacen(existing, &format!("{existing}\n"), 1);
    }
    Ok(MergeOutcome { text, added })
}

/// Insert `key` into `target` (already known to be table-like). A standard
/// table keeps the template's leading comment, which lives on the key's decor;
/// an inline table has no room for comments, so it takes the bare value.
fn insert_key(target: &mut Item, template_table: &Table, key: &str, value: Item) {
    if let Some(table) = target.as_table_mut() {
        match template_table.get_key_value(key) {
            Some((template_key, _)) => {
                table.insert_formatted(template_key, value);
            }
            None => {
                table.insert(key, value);
            }
        }
    } else if let Some(table) = target.as_table_like_mut() {
        table.insert(key, value);
    }
}

/// Write `deny.toml` and the derived `.cargo/audit.toml` into `dir`.
///
/// With no `deny.toml`, writes the template. With one, adds the template keys
/// it lacks and changes nothing else, so a user's ignores, license exceptions
/// and comments survive; `force` instead replaces it with the template. The
/// audit file is derived from the resulting `deny.toml`, so existing ignores
/// carry through; an existing one that differs is overwritten (the outcome
/// says so, since the file is kept in sync with `deny.toml` from then on).
///
/// See `tests::init_creates_deny_and_derived_audit` for a real,
/// currently-passing exercise of this function.
pub(crate) fn init_at(dir: &Path, force: bool) -> Result<InitOutcome> {
    let deny_path = dir.join("deny.toml");
    let existing = match std::fs::read_to_string(&deny_path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(e).with_context(|| format!("failed to read '{}'", deny_path.display()));
        }
    };

    let (deny, outcome) = match existing {
        None => (DENY_TEMPLATE.to_string(), DenyOutcome::Created),
        Some(_) if force => (DENY_TEMPLATE.to_string(), DenyOutcome::Replaced),
        Some(text) => {
            let merge = merge_deny_toml(&text, DENY_TEMPLATE)?;
            let outcome = if merge.added.is_empty() {
                DenyOutcome::Unchanged
            } else {
                DenyOutcome::Merged { added: merge.added }
            };
            (merge.text, outcome)
        }
    };
    if outcome != DenyOutcome::Unchanged {
        crate::fs_atomic::write_atomically(&deny_path, &deny)?;
    }

    // Derive .cargo/audit.toml from the resulting deny.toml so the two stay
    // consistent from the start (the same projection `jci-audit sync` performs).
    let ignores = extract_ignores(&deny)?;
    let audit_path = dir.join(".cargo").join("audit.toml");
    if let Some(parent) = audit_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create '{}'", parent.display()))?;
    }
    let derived = render_audit_toml(&ignores);
    let audit = match std::fs::read_to_string(&audit_path) {
        Ok(current) if current == derived => AuditOutcome::Unchanged,
        Ok(_) => AuditOutcome::Overwritten,
        Err(_) => AuditOutcome::Created,
    };
    if audit != AuditOutcome::Unchanged {
        crate::fs_atomic::write_atomically(&audit_path, &derived)?;
    }
    Ok(InitOutcome {
        deny: outcome,
        audit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_is_valid_and_has_empty_ignore() {
        // The embedded template must parse and start with no ignores.
        let ignores = extract_ignores(DENY_TEMPLATE).unwrap();
        assert_eq!(ignores, [] as [crate::sync::IgnoreEntry; 0]);
        assert!(DENY_TEMPLATE.contains("[advisories]"));
        assert!(DENY_TEMPLATE.contains("[licenses]"));
        assert!(DENY_TEMPLATE.contains("[bans]"));
        assert!(DENY_TEMPLATE.contains("[sources]"));
    }

    #[test]
    fn init_creates_deny_and_derived_audit() {
        let dir = tempfile::tempdir().unwrap();
        init_at(dir.path(), false).unwrap();

        let deny = std::fs::read_to_string(dir.path().join("deny.toml")).unwrap();
        assert_eq!(deny, DENY_TEMPLATE);

        let audit = std::fs::read_to_string(dir.path().join(".cargo/audit.toml")).unwrap();
        assert!(audit.contains("[advisories]"));
        assert!(audit.contains("ignore = []"));
        // The derived file matches what sync would produce for the template.
        assert_eq!(
            audit,
            render_audit_toml(&extract_ignores(DENY_TEMPLATE).unwrap())
        );
    }

    #[test]
    fn init_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deny.toml"), "# existing\n").unwrap();
        init_at(dir.path(), true).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("deny.toml")).unwrap(),
            DENY_TEMPLATE
        );
    }

    const USER_DENY: &str = r#"# my policy
[advisories]
# kept: reviewed 2026-01
ignore = [
    # transitive, no fix
    "RUSTSEC-2024-0001",
]
yanked = "deny"

[licenses]
allow = ["MIT"]

[[licenses.exceptions]]
name = "some-crate"
allow = ["MPL-2.0"]

[bans]
multiple-versions = "deny"

[[bans.skip]]
crate = "syn"
reason = "two majors"
"#;

    fn merged(existing: &str) -> MergeOutcome {
        merge_deny_toml(existing, DENY_TEMPLATE).unwrap()
    }

    #[test]
    fn merge_into_an_empty_file_adds_every_template_key() {
        let out = merged("");
        assert_eq!(out.text, DENY_TEMPLATE);
        assert_eq!(
            out.added,
            [
                "[advisories] db-path",
                "[advisories] db-urls",
                "[advisories] unmaintained",
                "[advisories] yanked",
                "[advisories] ignore",
                "[licenses] allow",
                "[bans] multiple-versions",
                "[bans] wildcards",
                "[sources] unknown-registry",
                "[sources] unknown-git",
                "[sources] allow-registry",
            ]
        );
    }

    #[test]
    fn merge_leaves_a_file_that_already_has_every_key_unchanged() {
        let out = merged(DENY_TEMPLATE);
        assert_eq!(out.text, DENY_TEMPLATE);
        assert!(out.added.is_empty(), "got: {:?}", out.added);
    }

    #[test]
    fn merge_is_idempotent() {
        let first = merged(USER_DENY);
        let second = merged(&first.text);
        assert_eq!(second.text, first.text);
        assert!(second.added.is_empty(), "got: {:?}", second.added);
    }

    #[test]
    fn merge_keeps_every_existing_line_in_order() {
        let out = merged(USER_DENY);
        let mut rest = out.text.lines();
        for line in USER_DENY.lines() {
            assert!(
                rest.any(|l| l == line),
                "line lost or reordered: {line:?}\n--- merged ---\n{}",
                out.text
            );
        }
    }

    #[test]
    fn merge_never_changes_the_value_of_a_key_the_user_set() {
        let doc = merged(USER_DENY).text.parse::<DocumentMut>().unwrap();
        assert_eq!(doc["advisories"]["yanked"].as_str(), Some("deny"));
        assert_eq!(doc["bans"]["multiple-versions"].as_str(), Some("deny"));
        let allow: Vec<_> = doc["licenses"]["allow"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(allow, ["MIT"]);
    }

    #[test]
    fn merge_adds_only_the_keys_the_user_lacks() {
        let out = merged(USER_DENY);
        assert_eq!(
            out.added,
            [
                "[advisories] db-path",
                "[advisories] db-urls",
                "[advisories] unmaintained",
                "[bans] wildcards",
                "[sources] unknown-registry",
                "[sources] unknown-git",
                "[sources] allow-registry",
            ]
        );
    }

    #[test]
    fn merge_carries_the_template_comment_with_an_added_key() {
        let out = merged("[advisories]\nignore = []\n");
        assert!(
            out.text.contains("# Vulnerabilities are always denied"),
            "got:\n{}",
            out.text
        );
    }

    #[test]
    fn merge_keeps_user_ignores_and_exceptions_readable_by_the_tool() {
        let text = merged(USER_DENY).text;
        let ignores = extract_ignores(&text).unwrap();
        assert_eq!(ignores.len(), 1);
        assert_eq!(ignores[0].id, "RUSTSEC-2024-0001");
        let policy = crate::sync::extract_license_policy(&text).unwrap();
        assert_eq!(
            policy.exceptions,
            [("some-crate".to_string(), vec!["MPL-2.0".to_string()])]
        );
        assert_eq!(
            crate::exceptions::extract_bans_skips(&text).unwrap().len(),
            1
        );
    }

    #[test]
    fn merge_rejects_a_template_table_that_is_not_a_table() {
        let err = merge_deny_toml("advisories = 1\n", DENY_TEMPLATE).unwrap_err();
        assert!(err.to_string().contains("[advisories]"), "got: {err}");
    }

    #[test]
    fn merge_rejects_invalid_toml() {
        let err = merge_deny_toml("[advisories\n", DENY_TEMPLATE).unwrap_err();
        assert!(err.to_string().contains("parse"), "got: {err}");
    }

    #[test]
    fn merge_fills_a_inline_table_section() {
        let out = merged("advisories = { ignore = [] }\n");
        let doc = out.text.parse::<DocumentMut>().unwrap();
        assert_eq!(doc["advisories"]["yanked"].as_str(), Some("warn"));
    }

    #[test]
    fn init_without_force_merges_into_an_existing_deny_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deny.toml"), USER_DENY).unwrap();

        let outcome = init_at(dir.path(), false).unwrap().deny;

        let DenyOutcome::Merged { added } = outcome else {
            panic!("expected Merged, got {outcome:?}");
        };
        assert!(added.contains(&"[sources] allow-registry".to_string()));
        let deny = std::fs::read_to_string(dir.path().join("deny.toml")).unwrap();
        assert!(deny.contains("# kept: reviewed 2026-01"), "got:\n{deny}");
        assert!(deny.contains("[[bans.skip]]"), "got:\n{deny}");
    }

    #[test]
    fn init_derives_audit_toml_from_the_users_existing_ignores() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deny.toml"), USER_DENY).unwrap();

        init_at(dir.path(), false).unwrap();

        let audit = std::fs::read_to_string(dir.path().join(".cargo/audit.toml")).unwrap();
        assert!(audit.contains("RUSTSEC-2024-0001"), "got:\n{audit}");
    }

    #[test]
    fn init_does_not_rewrite_a_deny_toml_that_already_has_every_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.toml");
        std::fs::write(&path, DENY_TEMPLATE).unwrap();
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();

        let outcome = init_at(dir.path(), false).unwrap().deny;

        assert_eq!(outcome, DenyOutcome::Unchanged);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
    }

    #[test]
    fn init_leaves_an_unparseable_deny_toml_and_audit_toml_untouched() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deny.toml"), "[advisories\n").unwrap();

        assert!(init_at(dir.path(), false).is_err());

        assert_eq!(
            std::fs::read_to_string(dir.path().join("deny.toml")).unwrap(),
            "[advisories\n"
        );
        assert!(!dir.path().join(".cargo/audit.toml").exists());
    }

    #[test]
    fn init_reports_a_new_audit_toml_as_created() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            init_at(dir.path(), false).unwrap().audit,
            AuditOutcome::Created
        );
    }

    #[test]
    fn init_reports_overwriting_a_different_audit_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".cargo")).unwrap();
        std::fs::write(dir.path().join(".cargo/audit.toml"), "# hand edited\n").unwrap();

        let outcome = init_at(dir.path(), false).unwrap();

        assert_eq!(outcome.audit, AuditOutcome::Overwritten);
        let audit = std::fs::read_to_string(dir.path().join(".cargo/audit.toml")).unwrap();
        assert!(!audit.contains("hand edited"), "got:\n{audit}");
    }

    #[test]
    fn init_reports_an_audit_toml_already_in_sync_as_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        init_at(dir.path(), false).unwrap();
        assert_eq!(
            init_at(dir.path(), false).unwrap().audit,
            AuditOutcome::Unchanged
        );
    }

    /// Dropping any one template key (by deletion or by commenting it out) must
    /// not stop jci-audit's own readers: the template is a recommendation, not
    /// a schema.
    #[test]
    fn every_template_key_is_optional_for_jci_audit_readers() {
        let template = DENY_TEMPLATE.parse::<DocumentMut>().unwrap();
        let mut checked = 0;
        for (table, item) in template.iter() {
            for (key, _) in item.as_table().unwrap() {
                let mut doc = template.clone();
                doc[table].as_table_mut().unwrap().remove(key);
                let text = doc.to_string();
                let ctx = format!("without [{table}] {key}");

                extract_ignores(&text).unwrap_or_else(|e| panic!("{ctx}: {e}"));
                crate::sync::extract_license_policy(&text).unwrap_or_else(|e| panic!("{ctx}: {e}"));
                crate::exceptions::extract_bans_skips(&text)
                    .unwrap_or_else(|e| panic!("{ctx}: {e}"));
                crate::exceptions::as_warn_without_skip(&text)
                    .unwrap_or_else(|e| panic!("{ctx}: {e}"));
                crate::release::with_db_path(&text, Path::new("/x"))
                    .unwrap_or_else(|e| panic!("{ctx}: {e}"));
                checked += 1;
            }
        }
        assert_eq!(checked, 11);
    }
}
