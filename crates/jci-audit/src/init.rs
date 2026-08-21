//! Scaffold a standard `deny.toml` plus a derived `.cargo/audit.toml`.
//!
//! The template is the "Style-B" cargo-deny policy: vulnerabilities always
//! denied, `unmaintained`/`yanked` surfaced, a permissive license allow-list
//! with weak-copyleft licenses admitted only per-crate via
//! `[[licenses.exceptions]]`, and pinned advisory-db sources.
//! `.cargo/audit.toml` is derived from it so cargo-audit honours the same
//! (initially empty) ignore set. See [`crate::sync`] for the derivation.

use std::path::Path;

use anyhow::{Context, Result, bail};

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

/// Write the `deny.toml` template and derived `.cargo/audit.toml` into `dir`.
/// Refuses to overwrite an existing `deny.toml` unless `force` is set.
pub(crate) fn init_at(dir: &Path, force: bool) -> Result<()> {
    let deny_path = dir.join("deny.toml");
    if deny_path.exists() && !force {
        bail!(
            "'{}' already exists; use --force to overwrite",
            deny_path.display()
        );
    }
    std::fs::write(&deny_path, DENY_TEMPLATE)
        .with_context(|| format!("failed to write '{}'", deny_path.display()))?;

    // Derive .cargo/audit.toml from the template so the two stay consistent
    // from the start (the same projection `jci-audit sync` performs).
    let ignores = extract_ignores(DENY_TEMPLATE)?;
    let audit_path = dir.join(".cargo").join("audit.toml");
    if let Some(parent) = audit_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create '{}'", parent.display()))?;
    }
    std::fs::write(&audit_path, render_audit_toml(&ignores))
        .with_context(|| format!("failed to write '{}'", audit_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_is_valid_and_has_empty_ignore() {
        // The embedded template must parse and start with no ignores.
        let ignores = extract_ignores(DENY_TEMPLATE).unwrap();
        assert!(ignores.is_empty());
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
    fn init_refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deny.toml"), "# existing\n").unwrap();

        let err = init_at(dir.path(), false).unwrap_err();
        assert!(err.to_string().contains("already exists"), "got: {err}");
        // Original content preserved.
        assert_eq!(
            std::fs::read_to_string(dir.path().join("deny.toml")).unwrap(),
            "# existing\n"
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
}
