//! Visibility for cargo-deny's native `[[bans.skip]]` exceptions.
//!
//! `multiple-versions = "deny"` plus a named `[[bans.skip]]` entry already gives
//! cargo-deny exactly the policy jerus-org/jci-audit#49 wants: deny by default,
//! pass cleanly for a named exception. What it does not give is visibility — a
//! skip entry that matches a genuine duplicate is completely silent, so nobody
//! reading a CI log or a release record can tell what was actually tolerated.
//! This module reads the configured exceptions straight out of `deny.toml` (the
//! same file cargo-deny itself reads — nothing here needs its own config
//! surface) and cross-references them against cargo-deny's own
//! `warning[unmatched-skip]:` diagnostic, which fires for free whenever a
//! configured skip no longer matches anything.

use anyhow::{Context, Result};
use toml_edit::{DocumentMut, Item, TableLike, Value};

/// One `[[bans.skip]]` entry, as configured in `deny.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkipEntry {
    pub(crate) name: String,
    pub(crate) version: Option<String>,
    pub(crate) reason: Option<String>,
}

/// Parse every `[[bans.skip]]` entry out of a `deny.toml` string.
///
/// `skip` accepts every form cargo-deny's own PackageSpec docs describe
/// (<https://embarkstudios.github.io/cargo-deny/checks/cfg.html#package-specs>,
/// verified live against cargo-deny 0.20.2 — a customer follows that page, not
/// this crate) and can be written either as a plain array (`skip = [...]`,
/// mixing bare strings and inline tables freely — cargo-deny's own
/// `skip-tree` doc example does exactly this) or as `[[bans.skip]]` block
/// syntax (always full tables). Both are handled uniformly here.
///
/// A missing `[bans]` table or `skip` key yields an empty list, not an error —
/// mirrors [`crate::sync::extract_ignores`]'s convention for `[advisories].ignore`.
/// An entry this crate can't make sense of is skipped rather than erroring,
/// since cargo-deny itself would already have rejected genuinely invalid
/// config before jci-audit ever runs.
pub(crate) fn extract_bans_skips(deny_toml: &str) -> Result<Vec<SkipEntry>> {
    let doc = deny_toml
        .parse::<DocumentMut>()
        .context("failed to parse deny.toml")?;

    let Some(skip) = doc.get("bans").and_then(|b| b.get("skip")) else {
        return Ok(Vec::new());
    };

    // `[[bans.skip]]` block syntax: an ArrayOfTables, entries are always
    // `Table`s.
    if let Some(array) = skip.as_array_of_tables() {
        return Ok(array.iter().filter_map(|t| entry_from_table(t)).collect());
    }

    // `skip = [...]` inline syntax: an Array of Values, each either a bare
    // string or an inline table.
    let Some(array) = skip.as_array() else {
        return Ok(Vec::new());
    };
    Ok(array.iter().filter_map(entry_from_value).collect())
}

/// One `skip = [...]` array element: a bare PackageSpec string, or an inline
/// table (`{ crate = "..." }` or the deprecated `{ name = "...", version =
/// "..." }`).
fn entry_from_value(value: &Value) -> Option<SkipEntry> {
    if let Some(spec) = value.as_str() {
        let (name, version) = split_package_spec(spec);
        return Some(SkipEntry {
            name: name.to_string(),
            version,
            reason: None,
        });
    }
    entry_from_table(value.as_inline_table()?)
}

/// One `[[bans.skip]]` block entry, or one inline table from a `skip = [...]`
/// array — both are `TableLike`, so a single function handles the `crate=`
/// (recommended) and deprecated `name=`/`version=` forms for either syntax.
fn entry_from_table(table: &dyn TableLike) -> Option<SkipEntry> {
    let reason = table
        .get("reason")
        .and_then(Item::as_str)
        .map(str::to_string);

    if let Some(spec) = table.get("crate").and_then(Item::as_str) {
        let (name, version) = split_package_spec(spec);
        return Some(SkipEntry {
            name: name.to_string(),
            version,
            reason,
        });
    }

    let name = table.get("name")?.as_str()?.to_string();
    let version = table
        .get("version")
        .and_then(Item::as_str)
        .map(str::to_string);
    Some(SkipEntry {
        name,
        version,
        reason,
    })
}

/// The crate-name prefix of a PackageSpec-shaped string (`"simple"`,
/// `"simple:<=0.1,>0.2"`, `"simple@0.1.0"`, or — matching cargo-deny's own
/// `skip-tree` doc example, which omits the documented `:` separator
/// entirely — `"windows-sys<=0.52"`). All four forms were verified live: a
/// crate name is only ASCII alphanumerics, `-`, and `_` (crates.io's own
/// naming rule), so the first character outside that set always marks the
/// end of the name, regardless of which separator (or none) follows it. Also
/// used to read the name back out of cargo-deny's `unmatched-skip`
/// diagnostic text, which echoes the same shapes (see [`unmatched_skip_name`]).
fn spec_name(spec: &str) -> &str {
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or(spec.len());
    &spec[..end]
}

/// Split a bare PackageSpec string into its name and, if present, the raw
/// text of whatever version requirement follows — kept verbatim (not
/// reinterpreted as semver) for the release record and notices. The `:`/`@`
/// separator, if any, is dropped; the requirement text itself is not, since
/// jci-audit only needs to identify *which crate* an exception names, not
/// evaluate the requirement — cargo-deny already does that.
fn split_package_spec(spec: &str) -> (&str, Option<String>) {
    let name = spec_name(spec);
    let rest = spec[name.len()..].trim_start_matches([':', '@']);
    (name, (!rest.is_empty()).then(|| rest.to_string()))
}

/// Crate names named in `warning[unmatched-skip]:` lines this run — configured
/// skips that matched nothing, so cargo-deny itself already flagged them.
///
/// Only the `unmatched-skip` code counts: `unmatched-skip-root`/`unmatched-root`
/// belong to `bans.skip-tree`, a different (and for now unsupported) exception
/// shape.
pub(crate) fn unmatched_skip_names(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .map(strip_ansi)
        .filter_map(|line| unmatched_skip_name(&line))
        .collect()
}

/// The crate name of one `warning[unmatched-skip]:` line, if this line opens
/// one. cargo-deny renders the skipped spec differently depending on how it
/// was configured — a bare `skip = ["name..."]` string echoes verbatim (e.g.
/// `'windows-sys<=0.52'`), while a `crate=`/`name=` table-form entry is
/// re-rendered as `'name = requirement'` with spaces (e.g. `'windows-sys =
/// ^0.52'`) — verified live for every form. [`spec_name`] handles both: a
/// crate name can't contain a space, `<`, `>`, `=`, `^`, `~`, `,`, or `@`, so
/// the first such character always marks the end of the name regardless of
/// rendering.
///
/// This means two `[[bans.skip]]` entries for the same crate name at
/// different versions cannot be told apart by this alone — cargo-deny's own
/// diagnostic doesn't give a name-only match anything more specific to key
/// on, and reconstructing its exact requirement rendering to disambiguate
/// would couple this to internals (the `semver` crate's `VersionReq` Display
/// format) rather than the documented diagnostic text. Narrow in practice —
/// revisit only if a real config needs two skips for the same crate name.
fn unmatched_skip_name(line: &str) -> Option<String> {
    let rest = line.strip_prefix("warning[unmatched-skip]:")?;
    let rest = rest.trim().strip_prefix("skipped crate '")?;
    let (spec, _) = rest.split_once('\'')?;
    Some(spec_name(spec).to_string())
}

/// Drop ANSI escapes so colourised output is still matched.
///
/// Duplicated from `crate::diagnostics`'s private `strip_ansi` rather than
/// exposed across the module boundary — four lines, and classification here
/// is policy, not the counting `diagnostics` already owns.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        for c in chars.by_ref() {
            if c.is_ascii_alphabetic() {
                break;
            }
        }
    }
    out
}

/// Configured skips split by whether they fired `unmatched-skip` this run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct AcceptedWarnings {
    /// Configured skips NOT flagged unmatched this run — presumed still in force.
    pub(crate) in_force: Vec<SkipEntry>,
    /// Configured skips flagged `unmatched-skip` this run — safe to remove.
    pub(crate) stale: Vec<SkipEntry>,
}

/// Split `configured` by whether each entry's name appears in
/// [`unmatched_skip_names`] for `stderr`. Matches by crate name only — see
/// [`unmatched_skip_name`] for why two skip entries naming the same crate at
/// different versions aren't disambiguated.
pub(crate) fn accepted_warnings(configured: Vec<SkipEntry>, stderr: &str) -> AcceptedWarnings {
    let unmatched = unmatched_skip_names(stderr);
    let mut out = AcceptedWarnings::default();
    for entry in configured {
        if unmatched.contains(&entry.name) {
            out.stale.push(entry);
        } else {
            out.in_force.push(entry);
        }
    }
    out
}

/// Print a notice for `deny.toml`'s accepted duplicate exceptions — cargo-deny
/// itself is silent about a skip that's actively suppressing a real
/// duplicate, so this is the only place that visibility comes from. Shared by
/// `check`, `release-prep`, and `verify` — the one thing all three would
/// otherwise print identically.
pub(crate) fn print_notice(accepted: &AcceptedWarnings) {
    if !accepted.in_force.is_empty() {
        println!(
            "  {} accepted duplicate exception(s) in force:",
            accepted.in_force.len()
        );
        for entry in &accepted.in_force {
            match &entry.reason {
                Some(reason) => println!("    - {} ({reason})", entry.name),
                None => println!("    - {}", entry.name),
            }
        }
    }
    if !accepted.stale.is_empty() {
        println!(
            "  {} stale accepted exception(s) — no longer needed, safe to remove from deny.toml:",
            accepted.stale.len()
        );
        for entry in &accepted.stale {
            println!("    - {}", entry.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY_TOML: &str = "\
[bans]
multiple-versions = \"deny\"

[[bans.skip]]
name = \"syn\"
reason = \"genuinely duplicates today; drop once deps converge\"

[[bans.skip]]
name = \"windows-sys\"
version = \"0.52\"
";

    #[test]
    fn extracts_every_skip_entry_with_its_fields() {
        let entries = extract_bans_skips(DENY_TOML).unwrap();
        assert_eq!(
            entries,
            vec![
                SkipEntry {
                    name: "syn".to_string(),
                    version: None,
                    reason: Some("genuinely duplicates today; drop once deps converge".to_string()),
                },
                SkipEntry {
                    name: "windows-sys".to_string(),
                    version: Some("0.52".to_string()),
                    reason: None,
                },
            ]
        );
    }

    // Every PackageSpec form cargo-deny's own docs document
    // (https://embarkstudios.github.io/cargo-deny/checks/cfg.html#package-specs),
    // verified live against cargo-deny 0.20.2 — a customer writes these by
    // following that page, not this crate's assumptions about it. `skip =
    // [...]` is a plain TOML array, not `[[bans.skip]]` block syntax, and can
    // freely mix bare strings with inline tables (cargo-deny's own
    // `skip-tree` doc example does exactly this).
    const MIXED_SPEC_FORMS: &str = "\
[bans]
skip = [
    \"simple\",
    \"simple-colon:<=0.1,>0.2\",
    \"simple-at@0.1.0\",
    \"simple-bare<=0.52\",
    { crate = \"crate-form@1.2.3\", reason = \"table crate form\" },
    { crate = \"crate-form-no-version\" },
    { name = \"old-form\", version = \"*\", reason = \"deprecated table form\" },
    { name = \"old-form-bare\" },
]
";

    #[test]
    fn extracts_every_documented_package_spec_form() {
        let entries = extract_bans_skips(MIXED_SPEC_FORMS).unwrap();
        assert_eq!(
            entries,
            vec![
                SkipEntry {
                    name: "simple".to_string(),
                    version: None,
                    reason: None,
                },
                SkipEntry {
                    name: "simple-colon".to_string(),
                    version: Some("<=0.1,>0.2".to_string()),
                    reason: None,
                },
                SkipEntry {
                    name: "simple-at".to_string(),
                    version: Some("0.1.0".to_string()),
                    reason: None,
                },
                SkipEntry {
                    name: "simple-bare".to_string(),
                    version: Some("<=0.52".to_string()),
                    reason: None,
                },
                SkipEntry {
                    name: "crate-form".to_string(),
                    version: Some("1.2.3".to_string()),
                    reason: Some("table crate form".to_string()),
                },
                SkipEntry {
                    name: "crate-form-no-version".to_string(),
                    version: None,
                    reason: None,
                },
                SkipEntry {
                    name: "old-form".to_string(),
                    version: Some("*".to_string()),
                    reason: Some("deprecated table form".to_string()),
                },
                SkipEntry {
                    name: "old-form-bare".to_string(),
                    version: None,
                    reason: None,
                },
            ]
        );
    }

    #[test]
    fn block_header_syntax_also_supports_the_crate_form() {
        // [[bans.skip]] is the OTHER valid TOML syntax for the same `skip`
        // array — verified live that `crate =` works there too, not just
        // `name =`/`version =`.
        let deny_toml = "\
[[bans.skip]]
crate = \"blocked@2.0.0\"
reason = \"block syntax crate form\"
";
        let entries = extract_bans_skips(deny_toml).unwrap();
        assert_eq!(
            entries,
            vec![SkipEntry {
                name: "blocked".to_string(),
                version: Some("2.0.0".to_string()),
                reason: Some("block syntax crate form".to_string()),
            }]
        );
    }

    #[test]
    fn missing_bans_table_yields_no_entries() {
        assert!(
            extract_bans_skips("[licenses]\nallow = []\n")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn bans_table_without_skip_yields_no_entries() {
        assert!(
            extract_bans_skips("[bans]\nmultiple-versions = \"deny\"\n")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_malformed_toml() {
        assert!(extract_bans_skips("not = [valid").is_err());
    }

    const STDERR_WITH_UNMATCHED: &str = "\
warning[unmatched-skip]: skipped crate 'totally-nonexistent-crate-xyz' was not encountered
   ┌─ deny.toml:63:9
   │
63 │ name = \"totally-nonexistent-crate-xyz\"
   │         ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ unmatched skip configuration
";

    #[test]
    fn finds_the_unmatched_skip_crate_name() {
        let names = unmatched_skip_names(STDERR_WITH_UNMATCHED);
        assert_eq!(names, vec!["totally-nonexistent-crate-xyz".to_string()]);
    }

    #[test]
    fn a_matching_skip_produces_no_unmatched_name() {
        // syn genuinely duplicates and is skip-listed — cargo-deny is silent
        // about it, so there is nothing in stderr naming it at all.
        let stderr = "warning[duplicate]: found 2 duplicate entries for crate 'reqwest'\n";
        assert!(unmatched_skip_names(stderr).is_empty());
    }

    #[test]
    fn colour_codes_do_not_hide_an_unmatched_skip() {
        let stderr = "\u{1b}[33mwarning\u{1b}[0m[unmatched-skip]: skipped crate 'widget' was not encountered\n";
        assert_eq!(unmatched_skip_names(stderr), vec!["widget".to_string()]);
    }

    #[test]
    fn no_configured_skips_means_nothing_in_force_or_stale() {
        let result = accepted_warnings(Vec::new(), STDERR_WITH_UNMATCHED);
        assert!(result.in_force.is_empty());
        assert!(result.stale.is_empty());
    }

    #[test]
    fn splits_in_force_from_stale_by_name() {
        let configured = extract_bans_skips(DENY_TOML).unwrap();
        // 'syn' is not named in this stderr, so it's presumed in force;
        // 'windows-sys' IS named — with its configured version rendered as a
        // caret requirement, exactly as cargo-deny actually emits it for a
        // versioned skip entry (verified live: `version = "0.52"` renders as
        // `'windows-sys = ^0.52'`) — so it's stale.
        let stderr = "\
warning[unmatched-skip]: skipped crate 'windows-sys = ^0.52' was not encountered
";
        let result = accepted_warnings(configured, stderr);
        assert_eq!(result.in_force.len(), 1);
        assert_eq!(result.in_force[0].name, "syn");
        assert_eq!(result.stale.len(), 1);
        assert_eq!(result.stale[0].name, "windows-sys");
    }

    #[test]
    fn unmatched_skip_name_strips_the_version_requirement() {
        // A versioned skip's unmatched line names the crate as `name =
        // <requirement>`, not bare `name` — verified live against cargo-deny
        // 0.20.2. Only the name is meaningful for matching against a
        // configured SkipEntry.
        let stderr = "warning[unmatched-skip]: skipped crate 'syn = ^0.52' was not encountered\n";
        assert_eq!(unmatched_skip_names(stderr), vec!["syn".to_string()]);
    }

    #[test]
    fn unmatched_skip_name_handles_every_rendering_cargo_deny_actually_produces() {
        // Captured from one live run mixing every PackageSpec form: bare
        // string entries echo verbatim (no spaces), while `crate=`/`name=`
        // table-form entries are re-rendered by cargo-deny as `name =
        // <requirement>` (with spaces around `=`). All must reduce to the
        // bare crate name.
        let cases = [
            ("unmatched-bare-a", "unmatched-bare-a"),
            ("unmatched-bare-b = <=0.1, >0.2", "unmatched-bare-b"),
            ("unmatched-bare-c<=0.52", "unmatched-bare-c"),
            ("unmatched-bare-d = =1.2.3", "unmatched-bare-d"),
            ("unmatched-crate-e = =1.2.3", "unmatched-crate-e"),
            ("unmatched-crate-f", "unmatched-crate-f"),
            ("unmatched-old-g = *", "unmatched-old-g"),
            ("unmatched-old-h", "unmatched-old-h"),
        ];
        for (rendered, expected_name) in cases {
            let stderr = format!(
                "warning[unmatched-skip]: skipped crate '{rendered}' was not encountered\n"
            );
            assert_eq!(
                unmatched_skip_names(&stderr),
                vec![expected_name.to_string()],
                "rendered form: {rendered}"
            );
        }
    }

    #[test]
    fn everything_stale_when_every_configured_skip_is_unmatched() {
        let configured = extract_bans_skips(DENY_TOML).unwrap();
        let stderr = "\
warning[unmatched-skip]: skipped crate 'syn' was not encountered
warning[unmatched-skip]: skipped crate 'windows-sys' was not encountered
";
        let result = accepted_warnings(configured, stderr);
        assert!(result.in_force.is_empty());
        assert_eq!(result.stale.len(), 2);
    }
}
