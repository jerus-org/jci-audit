//! Wire the generated `jerus-org/jci-audit` orb job into a consumer's
//! `.circleci/config.yml` — `jci-audit wire-ci`.
//!
//! Two files, one merged intent:
//!
//! - **`jci-audit.toml`'s `[ci]` table** is the persistent, git-committed
//!   record of what should be wired — mirroring `gen-circleci-orb.toml`'s own
//!   `[ci]` table role for that tool's wiring of a repo's CI. It is fully
//!   independent of `gen-circleci-orb.toml`: a `wire-ci` consumer need not use
//!   gen-circleci-orb at all.
//! - **`.circleci/config.yml`** (or wherever `--config` points) is patched to
//!   match it: an `orbs:` pin plus one job entry in the named workflow.
//!
//! Every CLI flag is an *optional override* layered onto whatever
//! `jci-audit.toml` already declares ([`merge_ci_config`]) — running with no
//! flags at all resyncs from the existing config, the same shape
//! `gen-circleci-orb update` uses for its own `[ci]` table.
//!
//! The YAML file is patched with plain line/text-splicing (bounded by
//! indentation), never a `serde_yaml` parse+reserialize — mirroring
//! `gen-circleci-orb`'s own `ci_patcher` precedent, which avoids that
//! specifically to preserve a consumer's comments and formatting outside what
//! it manages. The inserted job entry is wrapped in a managed-marker comment
//! pair; the `orbs:` pin (a single line) and any `--required-by` append (a
//! mutation inside a job this tool did not create) are **not** marker-wrapped
//! — wrapping either would either add noise for one line or misleadingly
//! claim ownership of a job jci-audit didn't create.
//!
//! Both files are written atomically ([`crate::fs_atomic`]), and validation
//! for `--required-by` targets runs to completion before either file is
//! touched — a failure there leaves both byte-identical to their originals.
//!
//! This module wires exactly one job into one workflow (PR 1 of
//! jerus-org/jci-audit#101). The release workflow's multi-job chain
//! (`release_prep`/`publish_record`) is deferred to a follow-on issue.

use std::path::Path;

use anyhow::{Context, Result, bail};
use toml_edit::{DocumentMut, Item, Table, Value};

use crate::{fs_atomic, sync};

/// A `- job:` entry's own indent inside a workflow's `jobs:` list.
const JOB_ENTRY_INDENT: usize = 6;
/// A job entry's continuation keys (`name:`, `requires:`, …).
const JOB_PARAM_INDENT: usize = 10;

pub(crate) const MANAGED_BEGIN: &str =
    "# >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')";
pub(crate) const MANAGED_END: &str = "# <<< jci-audit wire-ci";

// ---------------------------------------------------------------------
// jci-audit.toml's [ci] table
// ---------------------------------------------------------------------

/// The `[ci]` table's own shape. `Default` means nothing configured yet — a
/// consumer running `wire-ci` for the first time, not an error.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CiConfig {
    pub(crate) workflow: Option<String>,
    pub(crate) orb_job: Option<String>,
    pub(crate) orb_version: Option<String>,
    pub(crate) job_name: Option<String>,
    pub(crate) requires: Vec<String>,
    pub(crate) required_by: Vec<String>,
}

/// Read `jci-audit.toml`'s `[ci]` table. Neither the file nor the table
/// existing is `Ok(CiConfig::default())`, not an error.
pub(crate) fn read_ci_config(jci_audit_toml: &str) -> Result<CiConfig> {
    if jci_audit_toml.trim().is_empty() {
        return Ok(CiConfig::default());
    }
    let doc = jci_audit_toml
        .parse::<DocumentMut>()
        .context("failed to parse jci-audit.toml")?;
    let Some(ci) = doc.get("ci").and_then(Item::as_table) else {
        return Ok(CiConfig::default());
    };

    let str_field = |key: &str| {
        ci.get(key)
            .and_then(Item::as_str)
            .map(str::to_string)
            .filter(|s| !s.is_empty())
    };

    Ok(CiConfig {
        workflow: str_field("workflow"),
        orb_job: str_field("orb_job"),
        orb_version: str_field("orb_version"),
        job_name: str_field("job_name"),
        requires: string_list(ci.get("requires")),
        required_by: string_list(ci.get("required_by")),
    })
}

fn string_list(item: Option<&Item>) -> Vec<String> {
    item.and_then(Item::as_array)
        .into_iter()
        .flat_map(|arr| arr.iter().filter_map(Value::as_str).map(str::to_string))
        .collect()
}

/// Write `config` into `jci-audit.toml`'s `[ci]` table, preserving everything
/// else in the file byte-for-byte. Scalar fields are always present (empty
/// string when unset) and list fields always present (`[]` when empty) —
/// matches this codebase's "always present, never omitted" convention for
/// schema fields (e.g. release.rs's `package` field).
pub(crate) fn write_ci_config(jci_audit_toml: &str, config: &CiConfig) -> Result<String> {
    let mut doc = if jci_audit_toml.trim().is_empty() {
        DocumentMut::new()
    } else {
        jci_audit_toml
            .parse::<DocumentMut>()
            .context("failed to parse jci-audit.toml")?
    };

    let ci = doc
        .entry("ci")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .context("jci-audit.toml [ci] is not a table")?;

    ci["workflow"] = toml_edit::value(config.workflow.as_deref().unwrap_or(""));
    ci["orb_job"] = toml_edit::value(config.orb_job.as_deref().unwrap_or(""));
    ci["orb_version"] = toml_edit::value(config.orb_version.as_deref().unwrap_or(""));
    ci["job_name"] = toml_edit::value(config.job_name.as_deref().unwrap_or(""));
    ci["requires"] = Item::Value(Value::Array(sync::multiline_array(
        config.requires.iter().cloned(),
    )));
    ci["required_by"] = Item::Value(Value::Array(sync::multiline_array(
        config.required_by.iter().cloned(),
    )));

    Ok(doc.to_string())
}

// ---------------------------------------------------------------------
// CLI overrides layered onto the config file
// ---------------------------------------------------------------------

/// One CLI invocation's flag overrides — all optional, layered onto
/// `jci-audit.toml`'s existing `[ci]` table. `requires`/`required_by` are
/// `Option<Vec<String>>`, not bare `Vec<String>`: `None` means "flag not
/// given, keep the config's existing list"; `Some(_)` (including
/// `Some(vec![])`) REPLACES the existing list outright.
#[derive(Debug, Clone, Default)]
pub(crate) struct WireCiOverrides {
    pub(crate) workflow: Option<String>,
    pub(crate) orb_job: Option<String>,
    pub(crate) orb_version: Option<String>,
    pub(crate) job_name: Option<String>,
    pub(crate) requires: Option<Vec<String>>,
    pub(crate) required_by: Option<Vec<String>>,
}

/// `overrides` layered onto `existing` — pure, independently testable.
pub(crate) fn merge_ci_config(existing: &CiConfig, overrides: &WireCiOverrides) -> CiConfig {
    CiConfig {
        workflow: overrides
            .workflow
            .clone()
            .or_else(|| existing.workflow.clone()),
        orb_job: overrides
            .orb_job
            .clone()
            .or_else(|| existing.orb_job.clone()),
        orb_version: overrides
            .orb_version
            .clone()
            .or_else(|| existing.orb_version.clone()),
        job_name: overrides
            .job_name
            .clone()
            .or_else(|| existing.job_name.clone()),
        requires: overrides
            .requires
            .clone()
            .unwrap_or_else(|| existing.requires.clone()),
        required_by: overrides
            .required_by
            .clone()
            .unwrap_or_else(|| existing.required_by.clone()),
    }
}

// ---------------------------------------------------------------------
// Outcome reporting
// ---------------------------------------------------------------------

/// Outcome for one of the two files `wire-ci` may touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteOutcome {
    InSync,
    Wrote,
    Drift,
}

/// Both files' outcomes, so the CLI can report — and gate `--check`'s exit
/// code on — either independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WireCiOutcome {
    pub(crate) config_record: WriteOutcome,
    pub(crate) ci_file: WriteOutcome,
}

// ---------------------------------------------------------------------
// Line-splicing core (pure — no I/O)
// ---------------------------------------------------------------------

/// Strip one layer of matching `'…'`/`"…"` quoting, if present.
fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    if s.len() >= 2
        && ((bytes[0] == b'"' && bytes[s.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[s.len() - 1] == b'\''))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Locate a top-level (0-indent) section header line (e.g. `"orbs:"`) and
/// return the index immediately after its last member — the insertion point
/// for a new entry — or `None` if the header itself isn't present.
fn find_section_end(lines: &[String], header: &str) -> Option<usize> {
    let start = lines.iter().position(|l| l.trim_end() == header)?;
    let mut end = start + 1;
    while end < lines.len() {
        let line = &lines[end];
        if line.trim().is_empty() {
            end += 1;
            continue;
        }
        if indent_of(line) == 0 {
            break;
        }
        end += 1;
    }
    Some(end)
}

/// The line index of the named workflow's own `jobs:` key line, or `None` if
/// the workflow (or its `jobs:` key) isn't found.
fn find_workflow_jobs_line(lines: &[String], workflow: &str) -> Option<usize> {
    let header = format!("  {workflow}:");
    let start = lines.iter().position(|l| l.trim_end() == header)?;
    let mut i = start + 1;
    while i < lines.len() {
        let line = &lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        let indent = indent_of(line);
        if indent <= 2 {
            return None;
        }
        if indent == 4 && line.trim() == "jobs:" {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The insertion point for a new job entry: the line index immediately after
/// the named workflow's last existing job entry (bounded by indent dropping
/// to ≤4 — leaving the `jobs:` list).
fn find_workflow_jobs_end(lines: &[String], workflow: &str) -> Option<usize> {
    let jobs_line = find_workflow_jobs_line(lines, workflow)?;
    let mut end = jobs_line + 1;
    while end < lines.len() {
        let line = &lines[end];
        if line.trim().is_empty() {
            end += 1;
            continue;
        }
        if indent_of(line) <= 4 {
            break;
        }
        end += 1;
    }
    Some(end)
}

/// One job list entry, located purely by line range — never parsed into a
/// generic tree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct JobEntry {
    start: usize,
    end: usize,
}

/// Walk the named workflow's `jobs:` list, bounded by indentation, and return
/// each entry's own line range.
fn list_workflow_job_entries(lines: &[String], workflow: &str) -> Result<Vec<JobEntry>> {
    let jobs_line = find_workflow_jobs_line(lines, workflow)
        .with_context(|| format!("workflow '{workflow}' not found (or has no jobs: key)"))?;
    let jobs_end = find_workflow_jobs_end(lines, workflow).unwrap_or(lines.len());

    let mut entries = Vec::new();
    let mut i = jobs_line + 1;
    while i < jobs_end {
        let line = &lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        let indent = indent_of(line);
        if indent == JOB_ENTRY_INDENT && line.trim_start().starts_with("- ") {
            let start = i;
            let mut end = i + 1;
            while end < jobs_end {
                let l = &lines[end];
                if l.trim().is_empty() {
                    end += 1;
                    continue;
                }
                if indent_of(l) <= JOB_ENTRY_INDENT {
                    break;
                }
                end += 1;
            }
            entries.push(JobEntry { start, end });
            i = end;
        } else {
            i += 1;
        }
    }
    Ok(entries)
}

/// An entry's `name:` override if it declares one, else its own bare/orb-job
/// string — the matching rule for `--requires`/`--required-by`/idempotency.
/// Exact, case-sensitive.
fn effective_name(lines: &[String], entry: &JobEntry) -> String {
    for line in &lines[entry.start..entry.end] {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name:") {
            return unquote(rest.trim());
        }
    }
    lines[entry.start]
        .trim_start()
        .trim_start_matches("- ")
        .trim()
        .trim_end_matches(':')
        .to_string()
}

/// The new job's own effective name (what other jobs' `requires:` should
/// name it as): its configured `job_name` if non-empty, else its orb-job
/// string.
fn new_job_effective_name(config: &CiConfig) -> String {
    config
        .job_name
        .as_deref()
        .filter(|n| !n.is_empty())
        .map_or_else(
            || config.orb_job.clone().unwrap_or_default(),
            str::to_string,
        )
}

/// The marker-wrapped lines for the new job entry. `requires:` is always
/// rendered inline (`requires: [a, b]`) when non-empty — this tool never
/// emits the block-list form itself, only recognises it on existing jobs.
fn render_new_job_block(config: &CiConfig) -> Vec<String> {
    let orb_job = config.orb_job.as_deref().unwrap_or_default();
    let entry_indent = " ".repeat(JOB_ENTRY_INDENT);
    let param_indent = " ".repeat(JOB_PARAM_INDENT);

    let mut lines = vec![format!("{entry_indent}{MANAGED_BEGIN}")];

    let job_name = config.job_name.as_deref().filter(|n| !n.is_empty());
    let has_params = job_name.is_some() || !config.requires.is_empty();

    if has_params {
        lines.push(format!("{entry_indent}- {orb_job}:"));
        if let Some(name) = job_name {
            lines.push(format!("{param_indent}name: {name}"));
        }
        if !config.requires.is_empty() {
            lines.push(format!(
                "{param_indent}requires: [{}]",
                config.requires.join(", ")
            ));
        }
    } else {
        lines.push(format!("{entry_indent}- {orb_job}"));
    }

    lines.push(format!("{entry_indent}{MANAGED_END}"));
    lines
}

/// An existing job's `requires:` key, classified by shape. Only `Inline` and
/// `Block` are safe to append to; `Absent` is deliberately NOT auto-created
/// (mutating a job jci-audit doesn't own by inventing a new key on it is
/// exactly the risk this tool avoids) and `Unrecognized` covers anything this
/// tool cannot safely rewrite (anchors, flow maps, trailing comments,
/// non-contiguous block items).
#[derive(Debug, Clone, PartialEq, Eq)]
enum RequiresShape {
    Absent,
    Inline {
        line_idx: usize,
        indent: usize,
        items: Vec<String>,
    },
    Block {
        header_idx: usize,
        item_indent: usize,
        last_item_idx: usize,
    },
    Unrecognized,
}

fn shape_position(shape: &RequiresShape) -> usize {
    match shape {
        RequiresShape::Inline { line_idx, .. } => *line_idx,
        RequiresShape::Block { header_idx, .. } => *header_idx,
        RequiresShape::Absent | RequiresShape::Unrecognized => 0,
    }
}

/// Classify an existing job's `requires:` (if any) by scanning only that
/// entry's own line range.
fn find_requires_shape(lines: &[String], entry: &JobEntry) -> RequiresShape {
    for i in entry.start..entry.end {
        let line = &lines[i];
        let trimmed = line.trim_start();
        let indent = indent_of(line);
        let Some(rest) = trimmed.strip_prefix("requires:") else {
            continue;
        };
        let rest = rest.trim();

        if rest.is_empty() {
            // Block form: a bare "requires:" key followed immediately (no
            // interleaved blank/comment lines) by "- item" lines at
            // indent + 2.
            let item_indent = indent + 2;
            let mut last_item_idx = None;
            let mut j = i + 1;
            while j < entry.end {
                let l = &lines[j];
                if l.trim().is_empty() {
                    break;
                }
                if indent_of(l) == item_indent && l.trim_start().starts_with("- ") {
                    last_item_idx = Some(j);
                    j += 1;
                } else {
                    break;
                }
            }
            return match last_item_idx {
                Some(last) => RequiresShape::Block {
                    header_idx: i,
                    item_indent,
                    last_item_idx: last,
                },
                None => RequiresShape::Unrecognized,
            };
        }

        // Inline form: "requires: [a, b]", no trailing comment.
        if rest.contains('#') {
            return RequiresShape::Unrecognized;
        }
        let Some(inner) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
            return RequiresShape::Unrecognized;
        };
        let mut items = Vec::new();
        for raw in inner.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            if raw.contains(['[', ']', '{', '}']) {
                return RequiresShape::Unrecognized;
            }
            items.push(unquote(raw));
        }
        return RequiresShape::Inline {
            line_idx: i,
            indent,
            items,
        };
    }
    RequiresShape::Absent
}

/// Append `new_req` to an existing `requires:` list in place. Idempotent: a
/// no-op if `new_req` is already present.
fn append_requires(lines: &mut Vec<String>, shape: &RequiresShape, new_req: &str) {
    match shape {
        RequiresShape::Inline {
            line_idx,
            indent,
            items,
        } => {
            if items.iter().any(|i| i == new_req) {
                return;
            }
            let mut new_items = items.clone();
            new_items.push(new_req.to_string());
            lines[*line_idx] = format!(
                "{}requires: [{}]",
                " ".repeat(*indent),
                new_items.join(", ")
            );
        }
        RequiresShape::Block {
            header_idx,
            item_indent,
            last_item_idx,
        } => {
            let already_present = lines[header_idx + 1..=*last_item_idx]
                .iter()
                .any(|l| unquote(l.trim_start().trim_start_matches("- ").trim()) == new_req);
            if already_present {
                return;
            }
            lines.insert(
                last_item_idx + 1,
                format!("{}- {new_req}", " ".repeat(*item_indent)),
            );
        }
        RequiresShape::Absent | RequiresShape::Unrecognized => {}
    }
}

/// Validate every `--required-by` target BEFORE any mutation: each must
/// exist in the workflow (matched by [`effective_name`]) and have a
/// `requires:` in `Inline` or `Block` form. Aggregates every failure into one
/// error rather than stopping at the first.
fn validate_required_by_targets(
    lines: &[String],
    entries: &[JobEntry],
    required_by: &[String],
) -> Result<Vec<RequiresShape>> {
    let mut results = Vec::new();
    let mut failures = Vec::new();

    for target in required_by {
        let Some(entry) = entries.iter().find(|e| effective_name(lines, e) == *target) else {
            failures.push(format!("  - \"{target}\": not found in workflow"));
            continue;
        };
        match find_requires_shape(lines, entry) {
            RequiresShape::Absent => {
                failures.push(format!(
                    "  - \"{target}\": has no `requires:` key — add `requires: []` to it by hand, then re-run"
                ));
            }
            RequiresShape::Unrecognized => {
                failures.push(format!(
                    "  - \"{target}\": has a `requires:` key jci-audit doesn't recognise \
                     (anchors, flow maps, or a trailing comment) — rewrite it to a plain \
                     inline or block list, then re-run"
                ));
            }
            shape @ (RequiresShape::Inline { .. } | RequiresShape::Block { .. }) => {
                results.push(shape);
            }
        }
    }

    if !failures.is_empty() {
        bail!(
            "required-by target(s) cannot be safely wired:\n{}\nno changes written.",
            failures.join("\n")
        );
    }

    Ok(results)
}

/// The pure whole-function core: patch `content` (a `.circleci/config.yml`-
/// shaped string) to match `config`. Order: validate every `--required-by`
/// target first (bail with zero mutation on any failure); skip-or-insert the
/// `orbs:` pin; skip-or-insert the new job entry; apply each validated
/// `--required-by` append; rejoin, preserving the original trailing-newline
/// convention.
fn wire_job_into(content: &str, config: &CiConfig) -> Result<String> {
    let workflow = config
        .workflow
        .as_deref()
        .context("no workflow configured")?;
    let orb_job = config.orb_job.as_deref().context("no orb_job configured")?;

    let trailing_newline = content.ends_with('\n');
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();

    // Fail fast, zero mutation: prove every --required-by target is safe to
    // touch before changing anything.
    let entries = list_workflow_job_entries(&lines, workflow)?;
    validate_required_by_targets(&lines, &entries, &config.required_by)?;

    // orbs: pin (presence-only idempotency — no version-bump resync, see the
    // module's Decisions Deferred note in the design plan).
    let orb_name = orb_job.split('/').next().unwrap_or(orb_job);
    let pin_key = format!("  {orb_name}:");
    let already_pinned = lines.iter().any(|l| l.trim_end().starts_with(&pin_key));
    if !already_pinned {
        let version = config.orb_version.as_deref().unwrap_or(orb_job);
        let pin_line = format!("  {orb_name}: {version}");
        let Some(end) = find_section_end(&lines, "orbs:") else {
            bail!("no top-level 'orbs:' section found in the CI config file");
        };
        lines.insert(end, pin_line);
    }

    // job entry — matched by effective name within the target workflow only,
    // never a raw substring match (avoids a false positive against a
    // same-named job in a different workflow).
    let new_name = new_job_effective_name(config);
    let entries_after_pin = list_workflow_job_entries(&lines, workflow)?;
    let already_wired = entries_after_pin
        .iter()
        .any(|e| effective_name(&lines, e) == new_name);
    if !already_wired {
        let insert_at =
            find_workflow_jobs_end(&lines, workflow).context("workflow jobs: end not found")?;
        for (offset, line) in render_new_job_block(config).into_iter().enumerate() {
            lines.insert(insert_at + offset, line);
        }
    }

    // --required-by appends. The new job entry is always inserted AFTER every
    // pre-existing entry in the jobs: list (at find_workflow_jobs_end), so it
    // never shifts an existing target's position — but the orbs: pin (above
    // workflows: in every realistic file) can shift everything below it by
    // one line. Recomputing fresh here, rather than reusing the pre-mutation
    // positions from the validation pass above, stays correct either way.
    if !config.required_by.is_empty() {
        let entries_final = list_workflow_job_entries(&lines, workflow)?;
        let mut shapes = validate_required_by_targets(&lines, &entries_final, &config.required_by)?;
        shapes.sort_by_key(|shape| std::cmp::Reverse(shape_position(shape)));
        for shape in &shapes {
            append_requires(&mut lines, shape, &new_name);
        }
    }

    let mut out = lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Top-level entry point
// ---------------------------------------------------------------------

/// Locate the workspace, read `jci-audit.toml`, merge in `overrides`, patch
/// `config_path` to match, and report both files' outcomes independently.
/// Under `check`, neither file is written regardless of either outcome.
pub(crate) fn wire_ci_at(
    start: &Path,
    config_path: &Path,
    overrides: &WireCiOverrides,
    check: bool,
) -> Result<WireCiOutcome> {
    let (deny_path, _) = sync::locate_paths(start)?;
    let root = deny_path
        .parent()
        .context("deny.toml has no parent directory")?;
    let jci_audit_toml_path = root.join("jci-audit.toml");

    let existing_config_text = if jci_audit_toml_path.is_file() {
        std::fs::read_to_string(&jci_audit_toml_path)
            .with_context(|| format!("failed to read '{}'", jci_audit_toml_path.display()))?
    } else {
        String::new()
    };
    let existing = read_ci_config(&existing_config_text)?;
    let merged = merge_ci_config(&existing, overrides);

    if merged.workflow.is_none() || merged.orb_job.is_none() {
        bail!(
            "no CI wiring configured in jci-audit.toml — run with --workflow/--orb-job \
             (and --requires/--required-by as needed) to establish it"
        );
    }

    if !config_path.is_file() {
        bail!(
            "'{}' not found — run from a repo with .circleci/config.yml, or pass --config",
            config_path.display()
        );
    }
    let existing_ci_text = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read '{}'", config_path.display()))?;

    // Compute both desired outputs before writing either: wire_job_into can
    // fail (an invalid --required-by target), and neither file should be
    // touched when it does, even though the config-record write alone would
    // otherwise have already succeeded.
    let desired_config_text = write_ci_config(&existing_config_text, &merged)?;
    let desired_ci_text = wire_job_into(&existing_ci_text, &merged)?;

    let config_record = decide(
        &jci_audit_toml_path,
        &existing_config_text,
        &desired_config_text,
        check,
    )?;
    let ci_file = decide(config_path, &existing_ci_text, &desired_ci_text, check)?;

    Ok(WireCiOutcome {
        config_record,
        ci_file,
    })
}

/// The shared "does the desired content match what's on disk, and if not,
/// write it (unless `check`)" decision — mirrors `sync::decide_and_write`'s
/// shape, duplicated rather than shared: it's ~10 lines, and keeps
/// `wire_ci.rs` decoupled from `sync.rs`, consistent with this codebase's
/// existing preference for small duplication over premature cross-module
/// sharing.
fn decide(path: &Path, existing: &str, desired: &str, check: bool) -> Result<WriteOutcome> {
    if existing == desired {
        return Ok(WriteOutcome::InSync);
    }
    if check {
        return Ok(WriteOutcome::Drift);
    }
    fs_atomic::write_atomically(path, desired)?;
    Ok(WriteOutcome::Wrote)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- CiConfig / jci-audit.toml -----------------------------------

    fn full_config() -> CiConfig {
        CiConfig {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            orb_version: Some("jerus-org/jci-audit@1.0".to_string()),
            job_name: Some("audit".to_string()),
            requires: vec!["toolkit/common_tests".to_string()],
            required_by: vec!["deploy".to_string()],
        }
    }

    #[test]
    fn read_ci_config_empty_input_is_default_not_error() {
        assert_eq!(read_ci_config("").unwrap(), CiConfig::default());
    }

    #[test]
    fn read_ci_config_no_ci_table_is_default_not_error() {
        assert_eq!(
            read_ci_config("[other]\nkey = \"x\"\n").unwrap(),
            CiConfig::default()
        );
    }

    #[test]
    fn read_ci_config_reads_every_field() {
        let toml = r#"
[ci]
workflow = "validation"
orb_job = "jci-audit/check"
orb_version = "jerus-org/jci-audit@1.0"
job_name = "audit"
requires = ["toolkit/common_tests"]
required_by = ["deploy"]
"#;
        assert_eq!(read_ci_config(toml).unwrap(), full_config());
    }

    #[test]
    fn read_ci_config_partial_fixture_defaults_lists_to_empty() {
        let toml = "[ci]\nworkflow = \"validation\"\norb_job = \"jci-audit/check\"\n";
        let got = read_ci_config(toml).unwrap();
        assert_eq!(got.workflow.as_deref(), Some("validation"));
        assert_eq!(got.orb_job.as_deref(), Some("jci-audit/check"));
        assert!(got.requires.is_empty());
        assert!(got.required_by.is_empty());
    }

    #[test]
    fn write_ci_config_inserts_a_fresh_table_into_an_empty_file() {
        let out = write_ci_config("", &full_config()).unwrap();
        assert_eq!(read_ci_config(&out).unwrap(), full_config());
    }

    #[test]
    fn write_ci_config_preserves_unrelated_content() {
        let existing = "[other]\nkept = true\n\n[ci]\nworkflow = \"old\"\n";
        let out = write_ci_config(existing, &full_config()).unwrap();
        assert!(out.contains("[other]"));
        assert!(out.contains("kept = true"));
        assert_eq!(read_ci_config(&out).unwrap(), full_config());
    }

    #[test]
    fn write_ci_config_empty_lists_render_as_empty_array_not_omitted() {
        let mut config = full_config();
        config.requires = Vec::new();
        config.required_by = Vec::new();
        let out = write_ci_config("", &config).unwrap();
        assert!(out.contains("requires = []"));
        assert!(out.contains("required_by = []"));
    }

    #[test]
    fn write_ci_config_round_trips_minimal_config() {
        let config = CiConfig {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            ..CiConfig::default()
        };
        let out = write_ci_config("", &config).unwrap();
        assert_eq!(read_ci_config(&out).unwrap(), config);
    }

    // -- merge_ci_config -----------------------------------------------

    #[test]
    fn merge_ci_config_no_overrides_returns_existing_unchanged() {
        let existing = full_config();
        assert_eq!(
            merge_ci_config(&existing, &WireCiOverrides::default()),
            existing
        );
    }

    #[test]
    fn merge_ci_config_scalar_override_replaces_existing() {
        let existing = full_config();
        let overrides = WireCiOverrides {
            workflow: Some("release".to_string()),
            ..Default::default()
        };
        let merged = merge_ci_config(&existing, &overrides);
        assert_eq!(merged.workflow.as_deref(), Some("release"));
        assert_eq!(merged.orb_job, existing.orb_job);
    }

    #[test]
    fn merge_ci_config_list_override_replaces_outright_not_merge() {
        let existing = full_config();
        let overrides = WireCiOverrides {
            requires: Some(vec!["other/job".to_string()]),
            ..Default::default()
        };
        let merged = merge_ci_config(&existing, &overrides);
        assert_eq!(merged.requires, vec!["other/job".to_string()]);
    }

    #[test]
    fn merge_ci_config_some_empty_vec_clears_the_list() {
        let existing = full_config();
        let overrides = WireCiOverrides {
            required_by: Some(Vec::new()),
            ..Default::default()
        };
        let merged = merge_ci_config(&existing, &overrides);
        assert!(merged.required_by.is_empty());
    }

    // -- fixtures for the line-splicing core ----------------------------

    const CONFIG_BASE: &str = "\
version: 2.1
orbs:
  toolkit: jerus-org/circleci-toolkit@7.4.0
workflows:
  validation:
    jobs:
      - toolkit/common_tests
  release:
    jobs:
      - toolkit/release_crate
";

    const CONFIG_WITH_REQUIRES_INLINE: &str = "\
version: 2.1
orbs:
  toolkit: jerus-org/circleci-toolkit@7.4.0
workflows:
  validation:
    jobs:
      - toolkit/common_tests
      - deploy:
          requires: [toolkit/common_tests]
";

    const CONFIG_WITH_REQUIRES_BLOCK: &str = "\
version: 2.1
orbs:
  toolkit: jerus-org/circleci-toolkit@7.4.0
workflows:
  validation:
    jobs:
      - toolkit/common_tests
      - deploy:
          requires:
            - toolkit/common_tests
";

    const CONFIG_WITH_REQUIRES_ABSENT: &str = "\
version: 2.1
orbs:
  toolkit: jerus-org/circleci-toolkit@7.4.0
workflows:
  validation:
    jobs:
      - toolkit/common_tests
      - deploy
";

    const CONFIG_WITH_REQUIRES_UNRECOGNIZED: &str = "\
version: 2.1
orbs:
  toolkit: jerus-org/circleci-toolkit@7.4.0
workflows:
  validation:
    jobs:
      - toolkit/common_tests
      - deploy:
          requires: [toolkit/common_tests] # trailing comment
";

    fn lines_of(s: &str) -> Vec<String> {
        s.lines().map(str::to_string).collect()
    }

    fn base_config() -> CiConfig {
        CiConfig {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            orb_version: Some("jerus-org/jci-audit@1.0".to_string()),
            job_name: None,
            requires: Vec::new(),
            required_by: Vec::new(),
        }
    }

    // -- find_section_end / find_workflow_jobs_line / find_workflow_jobs_end

    #[test]
    fn find_section_end_finds_the_end_of_a_top_level_section() {
        let lines = lines_of(CONFIG_BASE);
        let end = find_section_end(&lines, "orbs:").unwrap();
        assert_eq!(lines[end].trim_end(), "workflows:");
    }

    #[test]
    fn find_section_end_none_when_header_absent() {
        let lines = lines_of(CONFIG_BASE);
        assert_eq!(find_section_end(&lines, "no-such-section:"), None);
    }

    #[test]
    fn find_workflow_jobs_line_distinguishes_similarly_named_workflows() {
        let lines = lines_of(CONFIG_BASE);
        let validation = find_workflow_jobs_line(&lines, "validation").unwrap();
        let release = find_workflow_jobs_line(&lines, "release").unwrap();
        assert_ne!(validation, release);
        assert_eq!(lines[validation].trim_end(), "    jobs:");
        assert_eq!(lines[release].trim_end(), "    jobs:");
    }

    #[test]
    fn find_workflow_jobs_line_none_when_workflow_absent() {
        let lines = lines_of(CONFIG_BASE);
        assert_eq!(find_workflow_jobs_line(&lines, "deploy"), None);
    }

    #[test]
    fn find_workflow_jobs_end_stops_at_next_workflow() {
        let lines = lines_of(CONFIG_BASE);
        let end = find_workflow_jobs_end(&lines, "validation").unwrap();
        assert_eq!(lines[end].trim_end(), "  release:");
    }

    // -- list_workflow_job_entries / effective_name ----------------------

    #[test]
    fn list_workflow_job_entries_finds_bare_and_map_entries() {
        let lines = lines_of(CONFIG_WITH_REQUIRES_INLINE);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(effective_name(&lines, &entries[0]), "toolkit/common_tests");
        assert_eq!(effective_name(&lines, &entries[1]), "deploy");
    }

    #[test]
    fn list_workflow_job_entries_errs_when_workflow_absent() {
        let lines = lines_of(CONFIG_BASE);
        assert!(list_workflow_job_entries(&lines, "no-such-workflow").is_err());
    }

    #[test]
    fn effective_name_prefers_name_override() {
        let content = "\
workflows:
  validation:
    jobs:
      - jci-audit/check:
          name: audit
";
        let lines = lines_of(content);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        assert_eq!(effective_name(&lines, &entries[0]), "audit");
    }

    // -- find_requires_shape ---------------------------------------------

    #[test]
    fn find_requires_shape_inline() {
        let lines = lines_of(CONFIG_WITH_REQUIRES_INLINE);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        let shape = find_requires_shape(&lines, &entries[1]);
        assert_eq!(
            shape,
            RequiresShape::Inline {
                line_idx: entries[1].start + 1,
                indent: 10,
                items: vec!["toolkit/common_tests".to_string()],
            }
        );
    }

    #[test]
    fn find_requires_shape_block() {
        let lines = lines_of(CONFIG_WITH_REQUIRES_BLOCK);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        let shape = find_requires_shape(&lines, &entries[1]);
        assert_eq!(
            shape,
            RequiresShape::Block {
                header_idx: entries[1].start + 1,
                item_indent: 12,
                last_item_idx: entries[1].start + 2,
            }
        );
    }

    #[test]
    fn find_requires_shape_absent() {
        let lines = lines_of(CONFIG_WITH_REQUIRES_ABSENT);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        assert_eq!(
            find_requires_shape(&lines, &entries[1]),
            RequiresShape::Absent
        );
    }

    #[test]
    fn find_requires_shape_unrecognized_trailing_comment() {
        let lines = lines_of(CONFIG_WITH_REQUIRES_UNRECOGNIZED);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        assert_eq!(
            find_requires_shape(&lines, &entries[1]),
            RequiresShape::Unrecognized
        );
    }

    #[test]
    fn find_requires_shape_unrecognized_anchor() {
        let content = "\
workflows:
  validation:
    jobs:
      - deploy:
          requires: *anchor
";
        let lines = lines_of(content);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        assert_eq!(
            find_requires_shape(&lines, &entries[0]),
            RequiresShape::Unrecognized
        );
    }

    // -- append_requires ---------------------------------------------------

    #[test]
    fn append_requires_rewrites_inline() {
        let mut lines = lines_of(CONFIG_WITH_REQUIRES_INLINE);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        let shape = find_requires_shape(&lines, &entries[1]);
        append_requires(&mut lines, &shape, "jci-audit/check");
        assert_eq!(
            lines[entries[1].start + 1].trim(),
            "requires: [toolkit/common_tests, jci-audit/check]"
        );
    }

    #[test]
    fn append_requires_inserts_block_item() {
        let mut lines = lines_of(CONFIG_WITH_REQUIRES_BLOCK);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        let shape = find_requires_shape(&lines, &entries[1]);
        let before_len = lines.len();
        append_requires(&mut lines, &shape, "jci-audit/check");
        assert_eq!(lines.len(), before_len + 1);
        assert_eq!(lines[entries[1].start + 3].trim(), "- jci-audit/check");
    }

    #[test]
    fn append_requires_is_idempotent() {
        let mut lines = lines_of(CONFIG_WITH_REQUIRES_INLINE);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        let shape = find_requires_shape(&lines, &entries[1]);
        append_requires(&mut lines, &shape, "toolkit/common_tests");
        assert_eq!(
            lines[entries[1].start + 1].trim(),
            "requires: [toolkit/common_tests]"
        );
    }

    // -- render_new_job_block ----------------------------------------------

    #[test]
    fn render_new_job_block_bare() {
        let config = base_config();
        let block = render_new_job_block(&config);
        assert_eq!(
            block,
            vec![
                format!("      {MANAGED_BEGIN}"),
                "      - jci-audit/check".to_string(),
                format!("      {MANAGED_END}"),
            ]
        );
    }

    #[test]
    fn render_new_job_block_with_name_and_requires() {
        let mut config = base_config();
        config.job_name = Some("audit".to_string());
        config.requires = vec!["toolkit/common_tests".to_string()];
        let block = render_new_job_block(&config);
        assert_eq!(
            block,
            vec![
                format!("      {MANAGED_BEGIN}"),
                "      - jci-audit/check:".to_string(),
                "          name: audit".to_string(),
                "          requires: [toolkit/common_tests]".to_string(),
                format!("      {MANAGED_END}"),
            ]
        );
    }

    // -- wire_job_into -------------------------------------------------------

    #[test]
    fn wire_job_into_inserts_pin_and_job_when_neither_present() {
        let out = wire_job_into(CONFIG_BASE, &base_config()).unwrap();
        assert!(out.contains("  jci-audit: jerus-org/jci-audit@1.0"));
        assert!(out.contains(MANAGED_BEGIN));
        assert!(out.contains("      - jci-audit/check"));
    }

    #[test]
    fn wire_job_into_skips_pin_when_already_present_but_still_inserts_job() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@0.1
workflows:
  validation:
    jobs:
      - toolkit/common_tests
";
        let out = wire_job_into(content, &base_config()).unwrap();
        assert_eq!(out.matches("jci-audit:").count(), 1);
        assert!(out.contains(MANAGED_BEGIN));
    }

    #[test]
    fn wire_job_into_is_a_no_op_when_already_wired() {
        let first = wire_job_into(CONFIG_BASE, &base_config()).unwrap();
        let second = wire_job_into(&first, &base_config()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn wire_job_into_errs_when_workflow_absent() {
        let mut config = base_config();
        config.workflow = Some("no-such-workflow".to_string());
        assert!(wire_job_into(CONFIG_BASE, &config).is_err());
    }

    #[test]
    fn wire_job_into_errs_on_missing_orbs_section() {
        let content = "\
version: 2.1
workflows:
  validation:
    jobs:
      - toolkit/common_tests
";
        assert!(wire_job_into(content, &base_config()).is_err());
    }

    #[test]
    fn wire_job_into_aggregates_all_required_by_failures() {
        let mut config = base_config();
        config.required_by = vec![
            "missing-job".to_string(),
            "toolkit/common_tests".to_string(),
        ];
        let err = wire_job_into(CONFIG_WITH_REQUIRES_ABSENT, &config)
            .unwrap_err()
            .to_string();
        assert!(err.contains("\"missing-job\": not found"));
        assert!(err.contains("\"toolkit/common_tests\": has no `requires:` key"));
    }

    #[test]
    fn wire_job_into_required_by_leaves_content_untouched_on_failure() {
        let mut config = base_config();
        config.required_by = vec!["deploy".to_string()];
        let err = wire_job_into(CONFIG_WITH_REQUIRES_ABSENT, &config);
        assert!(err.is_err());
    }

    #[test]
    fn wire_job_into_required_by_appends_to_inline_target() {
        let mut config = base_config();
        config.required_by = vec!["deploy".to_string()];
        let out = wire_job_into(CONFIG_WITH_REQUIRES_INLINE, &config).unwrap();
        assert!(out.contains("requires: [toolkit/common_tests, jci-audit/check]"));
    }

    #[test]
    fn wire_job_into_required_by_appends_to_block_target() {
        let mut config = base_config();
        config.required_by = vec!["deploy".to_string()];
        let out = wire_job_into(CONFIG_WITH_REQUIRES_BLOCK, &config).unwrap();
        assert!(out.contains("- jci-audit/check"));
        assert!(out.contains("- toolkit/common_tests"));
    }

    #[test]
    fn wire_job_into_required_by_is_idempotent() {
        let mut config = base_config();
        config.required_by = vec!["deploy".to_string()];
        let first = wire_job_into(CONFIG_WITH_REQUIRES_INLINE, &config).unwrap();
        let second = wire_job_into(&first, &config).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn wire_job_into_preserves_unrelated_workflow_and_comments() {
        let content = "\
version: 2.1
orbs:
  toolkit: jerus-org/circleci-toolkit@7.4.0
workflows:
  # a comment that must survive
  validation:
    jobs:
      - toolkit/common_tests
  release:
    jobs:
      - toolkit/release_crate
";
        let out = wire_job_into(content, &base_config()).unwrap();
        assert!(out.contains("# a comment that must survive"));
        assert!(out.contains("- toolkit/release_crate"));
    }

    #[test]
    fn wire_job_into_preserves_trailing_newline_convention() {
        let no_trailing = CONFIG_BASE.trim_end();
        let out = wire_job_into(no_trailing, &base_config()).unwrap();
        assert!(!out.ends_with('\n'));

        let out = wire_job_into(CONFIG_BASE, &base_config()).unwrap();
        assert!(out.ends_with('\n'));
    }

    // -- wire_ci_at (integration) --------------------------------------------

    fn write_workspace(
        dir: &std::path::Path,
        config_yml: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        std::fs::write(dir.join("deny.toml"), "[advisories]\n").unwrap();
        let circleci_dir = dir.join(".circleci");
        std::fs::create_dir_all(&circleci_dir).unwrap();
        let config_path = circleci_dir.join("config.yml");
        std::fs::write(&config_path, config_yml).unwrap();
        (dir.join("jci-audit.toml"), config_path)
    }

    #[test]
    fn wire_ci_at_first_run_writes_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);
        let overrides = WireCiOverrides {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            orb_version: Some("jerus-org/jci-audit@1.0".to_string()),
            ..Default::default()
        };

        let outcome = wire_ci_at(dir.path(), &config_path, &overrides, false).unwrap();
        assert_eq!(outcome.config_record, WriteOutcome::Wrote);
        assert_eq!(outcome.ci_file, WriteOutcome::Wrote);
        assert!(toml_path.is_file());
        let ci_text = std::fs::read_to_string(&config_path).unwrap();
        assert!(ci_text.contains(MANAGED_BEGIN));
    }

    #[test]
    fn wire_ci_at_second_run_no_flags_is_in_sync() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);
        let overrides = WireCiOverrides {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            ..Default::default()
        };
        wire_ci_at(dir.path(), &config_path, &overrides, false).unwrap();
        let toml_after_first = std::fs::read_to_string(&toml_path).unwrap();
        let ci_after_first = std::fs::read_to_string(&config_path).unwrap();

        let outcome =
            wire_ci_at(dir.path(), &config_path, &WireCiOverrides::default(), false).unwrap();
        assert_eq!(outcome.config_record, WriteOutcome::InSync);
        assert_eq!(outcome.ci_file, WriteOutcome::InSync);
        assert_eq!(
            std::fs::read_to_string(&toml_path).unwrap(),
            toml_after_first
        );
        assert_eq!(
            std::fs::read_to_string(&config_path).unwrap(),
            ci_after_first
        );
    }

    #[test]
    fn wire_ci_at_config_only_change_is_independent_of_ci_file_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let (_, config_path) = write_workspace(dir.path(), CONFIG_WITH_REQUIRES_INLINE);
        let overrides = WireCiOverrides {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            ..Default::default()
        };
        wire_ci_at(dir.path(), &config_path, &overrides, false).unwrap();

        let overrides_with_required_by = WireCiOverrides {
            required_by: Some(vec!["deploy".to_string()]),
            ..Default::default()
        };
        let outcome =
            wire_ci_at(dir.path(), &config_path, &overrides_with_required_by, false).unwrap();
        assert_eq!(outcome.config_record, WriteOutcome::Wrote);
        assert_eq!(outcome.ci_file, WriteOutcome::Wrote);
    }

    #[test]
    fn wire_ci_at_check_detects_drift_without_writing_either_file() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);
        let overrides = WireCiOverrides {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            ..Default::default()
        };
        wire_ci_at(dir.path(), &config_path, &overrides, false).unwrap();
        // Hand-revert the CI file only.
        std::fs::write(&config_path, CONFIG_BASE).unwrap();
        let toml_before = std::fs::read_to_string(&toml_path).unwrap();

        let outcome =
            wire_ci_at(dir.path(), &config_path, &WireCiOverrides::default(), true).unwrap();
        assert_eq!(outcome.config_record, WriteOutcome::InSync);
        assert_eq!(outcome.ci_file, WriteOutcome::Drift);
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), CONFIG_BASE);
        assert_eq!(std::fs::read_to_string(&toml_path).unwrap(), toml_before);
    }

    #[test]
    fn wire_ci_at_no_flags_and_no_existing_config_errs_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);
        let err = wire_ci_at(dir.path(), &config_path, &WireCiOverrides::default(), false);
        assert!(err.is_err());
        assert!(!toml_path.is_file());
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), CONFIG_BASE);
    }

    #[test]
    fn wire_ci_at_required_by_failure_leaves_both_files_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_WITH_REQUIRES_ABSENT);
        let overrides = WireCiOverrides {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            required_by: Some(vec!["deploy".to_string()]),
            ..Default::default()
        };
        let err = wire_ci_at(dir.path(), &config_path, &overrides, false);
        assert!(err.is_err());
        assert!(!toml_path.is_file(), "jci-audit.toml must not be created");
        assert_eq!(
            std::fs::read_to_string(&config_path).unwrap(),
            CONFIG_WITH_REQUIRES_ABSENT
        );
    }
}
