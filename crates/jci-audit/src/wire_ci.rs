//! Wire the generated `jerus-org/jci-audit` orb job(s) into a consumer's
//! `CircleCI` config — `jci-audit wire-ci`.
//!
//! **`jci-audit.toml`'s `[ci]` table is the required, authoritative spec —
//! not CLI flags.** `[ci].file` names the `CircleCI` config file to patch
//! (default `.circleci/config.yml`, resolved relative to `jci-audit.toml`'s
//! own directory), and each `[[ci.jobs]]` entry describes one job to wire
//! into one workflow (`workflow`, `orb_job`, `orb_version`, `job_name`,
//! `requires`, `required_by` — the same fields PR 1 of
//! jerus-org/jci-audit#101 started with, now array elements instead of a
//! single flat table). This mirrors `gen-circleci-orb.toml`'s own `[ci]`
//! table role for that tool's wiring of a repo's CI, and stays fully
//! independent of it: a `wire-ci` consumer need not use gen-circleci-orb at
//! all. `--config` only says WHICH file to read as this spec (default
//! `jci-audit.toml` at the discovered workspace root) — it carries no
//! per-job settings itself.
//!
//! **Why array-of-tables, not CLI flags for each field**: an early version of
//! this module took `--workflow`/`--orb-job`/`--requires`/etc. as CLI
//! overrides merged onto a single-job `[ci]` table. Review feedback on PR
//! jerus-org/jci-audit#163 pushed back — the release workflow (tracked by the
//! follow-on issue jerus-org/jci-audit#164) needs a three-job chain
//! (`release_prep`/the consumer's own release job/`publish_record`), which
//! would have meant a pile of new/renamed CLI flags to add a second job. A
//! `[[ci.jobs]]` array needs none of that: #164 adds a second array entry
//! (`workflow = "release"`, plus new fields on `JobSpec` like `context`/
//! `attach_workspace`/`post_steps` as they're needed) without touching this
//! module's CLI surface or its existing entries at all. `wire-ci` itself also
//! gets simpler: with no per-field flags, a fresh run just reads whatever
//! `jci-audit.toml` already says. On first run — nothing configured yet — it
//! scaffolds ONE example `[[ci.jobs]]` entry (this repo's own dogfooded
//! `jci-audit/check` in `validation`) for the consumer to review and adapt by
//! hand, mirroring `jci-audit init`'s role for `deny.toml`. An interactive,
//! call-and-response config generator is a further, explicitly deferred step
//! — not attempted here.
//!
//! Detecting drift in a job's *specification* as the orb itself evolves
//! (e.g. a newer `jci-audit/check` gaining a newly-required parameter) is
//! also out of scope for this module — `--check` only detects drift between
//! `jci-audit.toml`'s current content and the CI file, not whether that
//! content itself is stale relative to a newer orb version.
//!
//! The YAML file is patched with plain line/text-splicing (bounded by
//! indentation), never a `serde_yaml` parse+reserialize — mirroring
//! `gen-circleci-orb`'s own `ci_patcher` precedent, which avoids that
//! specifically to preserve a consumer's comments and formatting outside what
//! it manages. Each inserted job entry is wrapped in a managed-marker comment
//! pair; the `orbs:` pin (a single line) and any `required_by` append (a
//! mutation inside a job this tool did not create) are **not** marker-wrapped
//! — wrapping either would either add noise for one line or misleadingly
//! claim ownership of a job jci-audit didn't create.
//!
//! Both files are written atomically ([`crate::fs_atomic`]). Jobs are wired
//! in array order into one shared, growing line buffer, and nothing reaches
//! disk unless every job in the list succeeds — a later job's `required_by`
//! validation failing discards the whole in-memory buffer, including any
//! earlier jobs' now-uncommitted insertions, leaving the CI file
//! byte-identical to what it was on disk.
//!
//! **In CI, always pass `--check`.** Review feedback on
//! jerus-org/jci-audit#163 drew the same line `gen-circleci-orb`'s own
//! `update` job draws: a pipeline job is only ever useful here to detect
//! wiring drift and tell a human how to fix it — a CI run must never rewrite
//! the very `CircleCI` config that is currently executing it. Write mode
//! (the default, no `--check`) is for a human running `jci-audit wire-ci`
//! locally to apply `jci-audit.toml`'s spec, then committing the result —
//! never for a pipeline step. The orb job's `check` parameter cannot default
//! to `true` yet without corrupting its own type (`gen-circleci-orb`'s
//! `[subcommand.*.param.*]` default-override always renders as a quoted YAML
//! string, breaking a `type: boolean` parameter's default — see
//! jerus-org/gen-circleci-orb#347); until that lands, every `jci-audit/wire_ci`
//! job wired into a workflow **must** set `check: true` explicitly.

use std::path::Path;

use anyhow::{Context, Result, bail};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, Value};

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

/// One `[[ci.jobs]]` entry's shape. `Default` means an entry with nothing
/// set — not itself a valid job (see [`wire_one_job`]'s required-field
/// checks), but a legitimate empty starting point for a hand-edited scaffold.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct JobSpec {
    pub(crate) workflow: Option<String>,
    pub(crate) orb_job: Option<String>,
    pub(crate) orb_version: Option<String>,
    pub(crate) job_name: Option<String>,
    pub(crate) requires: Vec<String>,
    pub(crate) required_by: Vec<String>,
}

/// `jci-audit.toml`'s `[ci]` table as a whole: which `CircleCI` config file to
/// patch, and the ordered list of jobs to wire into it. `Default` (no file
/// set, no jobs) means nothing configured yet — a consumer running
/// `wire-ci` for the first time, not an error.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CiFile {
    pub(crate) file: Option<String>,
    pub(crate) jobs: Vec<JobSpec>,
}

/// Read `jci-audit.toml`'s `[ci]` table: `[ci].file` plus every
/// `[[ci.jobs]]` entry, in order. Neither the file, the `[ci]` table, nor
/// any `[[ci.jobs]]` entries existing is `Ok(CiFile::default())`, not an
/// error.
pub(crate) fn read_ci_file(jci_audit_toml: &str) -> Result<CiFile> {
    if jci_audit_toml.trim().is_empty() {
        return Ok(CiFile::default());
    }
    let doc = jci_audit_toml
        .parse::<DocumentMut>()
        .context("failed to parse jci-audit.toml")?;
    let Some(ci) = doc.get("ci").and_then(Item::as_table) else {
        return Ok(CiFile::default());
    };

    let file = ci
        .get("file")
        .and_then(Item::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty());

    let mut jobs = Vec::new();
    if let Some(array) = ci.get("jobs").and_then(Item::as_array_of_tables) {
        for table in array {
            let str_field = |key: &str| {
                table
                    .get(key)
                    .and_then(Item::as_str)
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
            };
            jobs.push(JobSpec {
                workflow: str_field("workflow"),
                orb_job: str_field("orb_job"),
                orb_version: str_field("orb_version"),
                job_name: str_field("job_name"),
                requires: string_list(table.get("requires")),
                required_by: string_list(table.get("required_by")),
            });
        }
    }

    Ok(CiFile { file, jobs })
}

fn string_list(item: Option<&Item>) -> Vec<String> {
    item.and_then(Item::as_array)
        .into_iter()
        .flat_map(|arr| arr.iter().filter_map(Value::as_str).map(str::to_string))
        .collect()
}

/// Insert one example `[[ci.jobs]]` entry (this repo's own dogfooded
/// `jci-audit/check` in `validation`) plus a `[ci].file` default into
/// `jci-audit.toml`, preserving everything else in the file byte-for-byte.
/// Only called when [`CiFile::jobs`] is empty — never touches an existing
/// `[[ci.jobs]]` entry.
pub(crate) fn write_scaffold(jci_audit_toml: &str) -> Result<String> {
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

    if !ci.contains_key("file") {
        ci["file"] = toml_edit::value(".circleci/config.yml");
    }

    let mut job = Table::new();
    job["workflow"] = toml_edit::value("validation");
    job["orb_job"] = toml_edit::value("jci-audit/check");
    job["orb_version"] = toml_edit::value("jerus-org/jci-audit@1.0");
    job["job_name"] = toml_edit::value("");
    job["requires"] = Item::Value(Value::Array(sync::multiline_array(std::iter::empty())));
    job["required_by"] = Item::Value(Value::Array(sync::multiline_array(std::iter::empty())));

    let mut jobs = ArrayOfTables::new();
    jobs.push(job);
    ci["jobs"] = Item::ArrayOfTables(jobs);

    Ok(doc.to_string())
}

// ---------------------------------------------------------------------
// Outcome reporting
// ---------------------------------------------------------------------

/// Outcome for the `CircleCI` config file `wire-ci` patches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteOutcome {
    InSync,
    Wrote,
    Drift,
}

/// [`wire_ci_at`]'s result: whether `jci-audit.toml` already had jobs to
/// apply, or had to be scaffolded with an example first — a single enum
/// rather than a status-plus-optional-payload struct, so a resolved
/// `ci_file` outcome existing is only representable together with
/// `Configured`, not something a caller has to `.expect()` at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WireCiOutcome {
    /// At least one `[[ci.jobs]]` entry existed: the resolved `CircleCI`
    /// config path, and what was (or would be) done to it.
    Configured {
        ci_file_path: std::path::PathBuf,
        ci_file: WriteOutcome,
    },
    /// No `[[ci.jobs]]` entries existed — an example was scaffolded into
    /// `jci-audit.toml` (or, under `--check`, nothing was written at all;
    /// see [`wire_ci_at`]). The `CircleCI` config file was not touched
    /// either way.
    Scaffolded,
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
/// the index immediately after its last member — the insertion point for a
/// new entry — or `None` if the header itself isn't present. Also the
/// header's own line index, so a caller can bound a scan to just that
/// section's body (e.g. the orb-pin idempotency check below, which must
/// never match an unrelated same-named key elsewhere in the file).
fn find_section_bounds(lines: &[String], header: &str) -> Option<(usize, usize)> {
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
    Some((start, end))
}

/// Locate a top-level (0-indent) section header line (e.g. `"orbs:"`) and
/// return the index immediately after its last member — the insertion point
/// for a new entry — or `None` if the header itself isn't present.
fn find_section_end(lines: &[String], header: &str) -> Option<usize> {
    find_section_bounds(lines, header).map(|(_, end)| end)
}

/// The line index of the named workflow's own `jobs:` key line, or `None` if
/// the workflow (or its `jobs:` key) isn't found.
fn find_workflow_jobs_line(lines: &[String], workflow: &str) -> Option<usize> {
    // Scoped to after the top-level `workflows:` key, not searched anywhere
    // in the file — a top-level reusable `jobs:` template can share a name
    // with a workflow, and must never be mistaken for it.
    let workflows_start = lines.iter().position(|l| l.trim_end() == "workflows:")?;
    let header = format!("  {workflow}:");
    let start = lines[workflows_start + 1..]
        .iter()
        .position(|l| l.trim_end() == header)?
        + workflows_start
        + 1;
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

/// The line index immediately after one job entry's own block: scanning
/// forward from `start + 1`, bounded by `jobs_end` — a blank line doesn't
/// end the entry, any line back at (or above) `JOB_ENTRY_INDENT` does.
fn find_job_entry_end(lines: &[String], start: usize, jobs_end: usize) -> usize {
    let mut end = start + 1;
    while end < jobs_end {
        let line = &lines[end];
        if line.trim().is_empty() {
            end += 1;
            continue;
        }
        if indent_of(line) <= JOB_ENTRY_INDENT {
            break;
        }
        end += 1;
    }
    end
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
        if indent_of(line) == JOB_ENTRY_INDENT && line.trim_start().starts_with("- ") {
            let end = find_job_entry_end(lines, i, jobs_end);
            entries.push(JobEntry { start: i, end });
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
    // Only the job's own direct param level — a nested step further down
    // (e.g. `steps: - run: name: "Run tests"`) has its own unrelated
    // `name:` at a deeper indent and must not be mistaken for the job's
    // identity.
    for line in &lines[entry.start..entry.end] {
        if indent_of(line) != JOB_PARAM_INDENT {
            continue;
        }
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
fn new_job_effective_name(job: &JobSpec) -> String {
    job.job_name
        .as_deref()
        .filter(|n| !n.is_empty())
        .map_or_else(|| job.orb_job.clone().unwrap_or_default(), str::to_string)
}

/// The marker-wrapped lines for the new job entry. `requires:` is always
/// rendered inline (`requires: [a, b]`) when non-empty — this tool never
/// emits the block-list form itself, only recognises it on existing jobs.
fn render_new_job_block(job: &JobSpec) -> Vec<String> {
    let orb_job = job.orb_job.as_deref().unwrap_or_default();
    let entry_indent = " ".repeat(JOB_ENTRY_INDENT);
    let param_indent = " ".repeat(JOB_PARAM_INDENT);

    let mut lines = vec![format!("{entry_indent}{MANAGED_BEGIN}")];

    let job_name = job.job_name.as_deref().filter(|n| !n.is_empty());
    let has_params = job_name.is_some() || !job.requires.is_empty();

    if has_params {
        lines.push(format!("{entry_indent}- {orb_job}:"));
        if let Some(name) = job_name {
            lines.push(format!("{param_indent}name: {name}"));
        }
        if !job.requires.is_empty() {
            lines.push(format!(
                "{param_indent}requires: [{}]",
                job.requires.join(", ")
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

        return if rest.is_empty() {
            classify_requires_block(lines, i, indent, entry.end)
        } else {
            classify_requires_inline(i, indent, rest)
        };
    }
    RequiresShape::Absent
}

/// Block form: a bare `requires:` key at `header_idx` (own indent
/// `header_indent`), followed immediately — no interleaved blank/comment
/// lines — by one or more `- item` lines at `header_indent + 2`.
fn classify_requires_block(
    lines: &[String],
    header_idx: usize,
    header_indent: usize,
    entry_end: usize,
) -> RequiresShape {
    let item_indent = header_indent + 2;
    let mut last_item_idx = None;
    let mut j = header_idx + 1;
    while j < entry_end {
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
    match last_item_idx {
        Some(last_item_idx) => RequiresShape::Block {
            header_idx,
            item_indent,
            last_item_idx,
        },
        None => RequiresShape::Unrecognized,
    }
}

/// Inline form: `requires: [a, b]` — no trailing comment, no item
/// containing a nested bracket/brace.
fn classify_requires_inline(line_idx: usize, indent: usize, rest: &str) -> RequiresShape {
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
    RequiresShape::Inline {
        line_idx,
        indent,
        items,
    }
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

/// Patch one job's own entry into `lines` in place. Order: validate this
/// job's own `required_by` targets first (bail with zero mutation to `lines`
/// on any failure); skip-or-insert the `orbs:` pin; skip-or-insert the job
/// entry; apply each validated `required_by` append.
fn wire_one_job(lines: &mut Vec<String>, job: &JobSpec) -> Result<()> {
    let workflow = job.workflow.as_deref().context("no workflow configured")?;
    let orb_job = job.orb_job.as_deref().context("no orb_job configured")?;

    // Deduped once, up front: append_requires's Block-form idempotency check
    // reads a position captured before any mutation, so two identical
    // targets in one job's own required_by list would both see "not present
    // yet" and each insert their own duplicate line — a literal duplicate
    // string in a hand-edited jci-audit.toml is a realistic mistake, not a
    // contrived input.
    let required_by = dedupe_preserving_order(&job.required_by);

    // Fail fast, zero mutation: prove every required_by target is safe to
    // touch before changing anything.
    let entries = list_workflow_job_entries(lines, workflow)?;
    validate_required_by_targets(lines, &entries, &required_by)?;

    // orbs: pin (presence-only idempotency — no version-bump resync, see the
    // module doc's deferred-concerns note).
    let orb_name = orb_job.split('/').next().unwrap_or(orb_job);
    let pin_key = format!("  {orb_name}:");
    // Scoped to the orbs: section's own body — an unrelated same-named key
    // elsewhere in the file (e.g. a workflow that happens to be named after
    // the orb) must never be mistaken for an existing pin.
    let already_pinned = find_section_bounds(lines, "orbs:").is_some_and(|(start, end)| {
        lines[start + 1..end]
            .iter()
            .any(|l| l.trim_end().starts_with(&pin_key))
    });
    if !already_pinned {
        // No fallback to orb_job here: that would silently pin
        // "jci-audit: jci-audit/check" — a job path, not a version — which
        // is invalid `CircleCI` YAML and (since the pin is then presence-only
        // idempotent) would never self-correct on a later run.
        let version = job.orb_version.as_deref().context(
            "no orb version configured — set orb_version (e.g. \
             \"jerus-org/jci-audit@1.0\") on this job in jci-audit.toml",
        )?;
        let pin_line = format!("  {orb_name}: {version}");
        let Some(end) = find_section_end(lines, "orbs:") else {
            bail!("no top-level 'orbs:' section found in the CI config file");
        };
        lines.insert(end, pin_line);
    }

    // job entry — matched by effective name within the target workflow only,
    // never a raw substring match (avoids a false positive against a
    // same-named job in a different workflow).
    let new_name = new_job_effective_name(job);
    let entries_after_pin = list_workflow_job_entries(lines, workflow)?;
    let already_wired = entries_after_pin
        .iter()
        .any(|e| effective_name(lines, e) == new_name);
    if !already_wired {
        let insert_at =
            find_workflow_jobs_end(lines, workflow).context("workflow jobs: end not found")?;
        for (offset, line) in render_new_job_block(job).into_iter().enumerate() {
            lines.insert(insert_at + offset, line);
        }
    }

    // required_by appends. This job's own entry is always inserted AFTER
    // every pre-existing entry in the jobs: list (at
    // find_workflow_jobs_end), so it never shifts an existing target's
    // position — but the orbs: pin (above workflows: in every realistic
    // file) can shift everything below it by one line. Recomputing fresh
    // here, rather than reusing the pre-mutation positions from the
    // validation pass above, stays correct either way.
    if !required_by.is_empty() {
        let entries_final = list_workflow_job_entries(lines, workflow)?;
        let mut shapes = validate_required_by_targets(lines, &entries_final, &required_by)?;
        shapes.sort_by_key(|shape| std::cmp::Reverse(shape_position(shape)));
        for shape in &shapes {
            append_requires(lines, shape, &new_name);
        }
    }

    Ok(())
}

/// `items` with exact duplicates removed, keeping each item's first
/// occurrence. `required_by` lists are always short, so a plain `Vec` scan
/// is simpler than a set here.
fn dedupe_preserving_order(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if !out.contains(item) {
            out.push(item.clone());
        }
    }
    out
}

/// The pure whole-function core: patch `content` (a `CircleCI`-config-shaped
/// string) to match every job in `jobs`, in order, in one shared line
/// buffer. Nothing reaches the caller unless every job succeeds — a later
/// job's failure discards the whole buffer, including any earlier jobs'
/// now-uncommitted insertions.
fn wire_jobs_into(content: &str, jobs: &[JobSpec]) -> Result<String> {
    // `str::lines()` treats a "\r\n" pair as one line terminator and strips
    // both bytes, so a CRLF file's line endings must be restored explicitly
    // on rejoin — joining with a bare "\n" would silently convert the whole
    // file (not just the lines actually touched) to LF, and `decide`'s
    // byte-for-byte comparison would then report permanent drift even when
    // the wiring itself is already correct.
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let trailing_newline = content.ends_with('\n');
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();

    for (index, job) in jobs.iter().enumerate() {
        wire_one_job(&mut lines, job).with_context(|| format!("ci.jobs[{index}]"))?;
    }

    let mut out = lines.join(newline);
    if trailing_newline {
        out.push_str(newline);
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Top-level entry point
// ---------------------------------------------------------------------

/// Locate `jci-audit.toml` (an explicit `config_override`, used as given —
/// mirrors `resolve_publish_record_path`'s "override short-circuits before
/// any discovery" precedent — or `jci-audit.toml` at the workspace root
/// discovered from `deny.toml`), read its `[ci]` table, and either scaffold
/// an example `[[ci.jobs]]` entry (nothing configured yet) or patch the
/// `[ci].file` it names — resolved relative to `jci-audit.toml`'s own
/// directory, not the workspace root — to match every job in order. Under
/// `check`, nothing is ever written, on either path.
pub(crate) fn wire_ci_at(
    start: &Path,
    config_override: Option<&Path>,
    check: bool,
) -> Result<WireCiOutcome> {
    let config_path = if let Some(p) = config_override {
        p.to_path_buf()
    } else {
        let (deny_path, _) = sync::locate_paths(start)?;
        let root = deny_path
            .parent()
            .context("deny.toml has no parent directory")?;
        root.join("jci-audit.toml")
    };
    let spec_dir = config_path.parent().unwrap_or_else(|| Path::new("."));

    let existing_config_text = if config_path.is_file() {
        std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read '{}'", config_path.display()))?
    } else {
        String::new()
    };
    let spec = read_ci_file(&existing_config_text)?;

    if spec.jobs.is_empty() {
        if check {
            bail!(
                "'{}' has no [[ci.jobs]] entries — run `jci-audit wire-ci` (without --check) to \
                 scaffold one, edit it to match your CI, then re-run",
                config_path.display()
            );
        }
        let scaffolded = write_scaffold(&existing_config_text)?;
        fs_atomic::write_atomically(&config_path, &scaffolded)?;
        return Ok(WireCiOutcome::Scaffolded);
    }

    let ci_file_path = spec_dir.join(spec.file.as_deref().unwrap_or(".circleci/config.yml"));
    if !ci_file_path.is_file() {
        bail!(
            "'{}' not found — run from a repo with .circleci/config.yml, or set [ci].file in \
             '{}'",
            ci_file_path.display(),
            config_path.display()
        );
    }
    let existing_ci_text = std::fs::read_to_string(&ci_file_path)
        .with_context(|| format!("failed to read '{}'", ci_file_path.display()))?;
    let desired_ci_text = wire_jobs_into(&existing_ci_text, &spec.jobs)?;
    let ci_file = decide(&ci_file_path, &existing_ci_text, &desired_ci_text, check)?;

    Ok(WireCiOutcome::Configured {
        ci_file_path,
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

    // -- JobSpec / CiFile / jci-audit.toml -------------------------------

    fn full_job() -> JobSpec {
        JobSpec {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            orb_version: Some("jerus-org/jci-audit@1.0".to_string()),
            job_name: Some("audit".to_string()),
            requires: vec!["toolkit/common_tests".to_string()],
            required_by: vec!["deploy".to_string()],
        }
    }

    #[test]
    fn read_ci_file_empty_input_is_default_not_error() {
        assert_eq!(read_ci_file("").unwrap(), CiFile::default());
    }

    #[test]
    fn read_ci_file_no_ci_table_is_default_not_error() {
        assert_eq!(
            read_ci_file("[other]\nkey = \"x\"\n").unwrap(),
            CiFile::default()
        );
    }

    #[test]
    fn read_ci_file_reads_file_and_all_job_fields() {
        let toml = r#"
[ci]
file = ".circleci/config.yml"

[[ci.jobs]]
workflow = "validation"
orb_job = "jci-audit/check"
orb_version = "jerus-org/jci-audit@1.0"
job_name = "audit"
requires = ["toolkit/common_tests"]
required_by = ["deploy"]
"#;
        let got = read_ci_file(toml).unwrap();
        assert_eq!(got.file.as_deref(), Some(".circleci/config.yml"));
        assert_eq!(got.jobs, vec![full_job()]);
    }

    #[test]
    fn read_ci_file_partial_job_defaults_lists_to_empty() {
        let toml = "[[ci.jobs]]\nworkflow = \"validation\"\norb_job = \"jci-audit/check\"\n";
        let got = read_ci_file(toml).unwrap();
        assert_eq!(got.jobs.len(), 1);
        assert_eq!(got.jobs[0].workflow.as_deref(), Some("validation"));
        assert_eq!(got.jobs[0].orb_job.as_deref(), Some("jci-audit/check"));
        assert!(got.jobs[0].requires.is_empty());
        assert!(got.jobs[0].required_by.is_empty());
    }

    #[test]
    fn read_ci_file_jobs_only_no_explicit_ci_header() {
        // `[[ci.jobs]]` alone creates an implicit `ci` table — no `[ci]`
        // header line required.
        let toml = "[[ci.jobs]]\nworkflow = \"validation\"\norb_job = \"jci-audit/check\"\n";
        let got = read_ci_file(toml).unwrap();
        assert_eq!(got.file, None);
        assert_eq!(got.jobs.len(), 1);
    }

    #[test]
    fn read_ci_file_multiple_jobs_in_order() {
        let toml = r#"
[[ci.jobs]]
workflow = "validation"
orb_job = "jci-audit/check"

[[ci.jobs]]
workflow = "release"
orb_job = "jci-audit/publish_record"
"#;
        let got = read_ci_file(toml).unwrap();
        assert_eq!(got.jobs.len(), 2);
        assert_eq!(got.jobs[0].workflow.as_deref(), Some("validation"));
        assert_eq!(got.jobs[1].workflow.as_deref(), Some("release"));
    }

    #[test]
    fn write_scaffold_inserts_file_default_and_example_job_into_empty_file() {
        let out = write_scaffold("").unwrap();
        let got = read_ci_file(&out).unwrap();
        assert_eq!(got.file.as_deref(), Some(".circleci/config.yml"));
        assert_eq!(got.jobs.len(), 1);
        assert_eq!(got.jobs[0].workflow.as_deref(), Some("validation"));
        assert_eq!(got.jobs[0].orb_job.as_deref(), Some("jci-audit/check"));
        assert_eq!(
            got.jobs[0].orb_version.as_deref(),
            Some("jerus-org/jci-audit@1.0")
        );
    }

    #[test]
    fn write_scaffold_preserves_unrelated_content() {
        let existing = "[other]\nkept = true\n";
        let out = write_scaffold(existing).unwrap();
        assert!(out.contains("[other]"));
        assert!(out.contains("kept = true"));
        assert_eq!(read_ci_file(&out).unwrap().jobs.len(), 1);
    }

    #[test]
    fn write_scaffold_does_not_overwrite_an_existing_file_key() {
        let existing = "[ci]\nfile = \"custom.yml\"\n";
        let out = write_scaffold(existing).unwrap();
        assert_eq!(
            read_ci_file(&out).unwrap().file.as_deref(),
            Some("custom.yml")
        );
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

    fn base_job() -> JobSpec {
        JobSpec {
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
    fn find_workflow_jobs_line_ignores_a_same_named_job_template_before_workflows() {
        // A top-level reusable job template can share a name with a
        // workflow — the search must not match it before reaching the
        // actual `workflows:` section.
        let content = "\
version: 2.1
jobs:
  validation:
    steps:
      - checkout
workflows:
  validation:
    jobs:
      - toolkit/common_tests
";
        let lines = lines_of(content);
        let jobs_line = find_workflow_jobs_line(&lines, "validation").unwrap();
        assert_eq!(lines[jobs_line].trim(), "jobs:");
        assert_eq!(lines[jobs_line - 1].trim_end(), "  validation:");
        // the correct "  validation:" is the SECOND one, under workflows:
        assert!(
            jobs_line
                > lines
                    .iter()
                    .position(|l| l.trim_end() == "workflows:")
                    .unwrap()
        );
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

    #[test]
    fn effective_name_ignores_a_nested_steps_own_name_field() {
        let content = "\
workflows:
  validation:
    jobs:
      - build-and-test:
          steps:
            - run:
                name: \"Run tests\"
";
        let lines = lines_of(content);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        assert_eq!(effective_name(&lines, &entries[0]), "build-and-test");
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
        let job = base_job();
        let block = render_new_job_block(&job);
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
        let mut job = base_job();
        job.job_name = Some("audit".to_string());
        job.requires = vec!["toolkit/common_tests".to_string()];
        let block = render_new_job_block(&job);
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

    // -- wire_jobs_into / wire_one_job ---------------------------------------

    #[test]
    fn wire_jobs_into_inserts_pin_and_job_when_neither_present() {
        let out = wire_jobs_into(CONFIG_BASE, &[base_job()]).unwrap();
        assert!(out.contains("  jci-audit: jerus-org/jci-audit@1.0"));
        assert!(out.contains(MANAGED_BEGIN));
        assert!(out.contains("      - jci-audit/check"));
    }

    #[test]
    fn wire_jobs_into_does_not_mistake_a_same_named_workflow_for_an_existing_pin() {
        // A workflow literally named after the orb must not be mistaken for
        // an orbs: pin — the idempotency check has to stay scoped to the
        // orbs: section's own body.
        let content = "\
version: 2.1
orbs:
  toolkit: jerus-org/circleci-toolkit@7.4.0
workflows:
  jci-audit:
    jobs:
      - toolkit/common_tests
  validation:
    jobs:
      - toolkit/common_tests
";
        let out = wire_jobs_into(content, &[base_job()]).unwrap();
        assert!(
            out.contains("  jci-audit: jerus-org/jci-audit@1.0"),
            "the real orb pin must still be inserted: {out}"
        );
    }

    #[test]
    fn wire_jobs_into_skips_pin_when_already_present_but_still_inserts_job() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@0.1
workflows:
  validation:
    jobs:
      - toolkit/common_tests
";
        let out = wire_jobs_into(content, &[base_job()]).unwrap();
        assert_eq!(out.matches("jci-audit:").count(), 1);
        assert!(out.contains(MANAGED_BEGIN));
    }

    #[test]
    fn wire_jobs_into_is_a_no_op_when_already_wired() {
        let first = wire_jobs_into(CONFIG_BASE, &[base_job()]).unwrap();
        let second = wire_jobs_into(&first, &[base_job()]).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn wire_jobs_into_errs_when_workflow_absent() {
        let mut job = base_job();
        job.workflow = Some("no-such-workflow".to_string());
        assert!(wire_jobs_into(CONFIG_BASE, &[job]).is_err());
    }

    #[test]
    fn wire_jobs_into_errs_on_missing_orbs_section() {
        let content = "\
version: 2.1
workflows:
  validation:
    jobs:
      - toolkit/common_tests
";
        assert!(wire_jobs_into(content, &[base_job()]).is_err());
    }

    #[test]
    fn wire_jobs_into_errs_instead_of_pinning_an_invalid_placeholder_version() {
        let mut job = base_job();
        job.orb_version = None;
        let err = format!("{:?}", wire_jobs_into(CONFIG_BASE, &[job]).unwrap_err());
        assert!(err.contains("no orb version configured"), "got: {err}");
        assert!(!CONFIG_BASE.contains("jci-audit"));
    }

    #[test]
    fn wire_jobs_into_error_names_the_failing_job_index() {
        let mut second = base_job();
        second.workflow = Some("no-such-workflow".to_string());
        let err = wire_jobs_into(CONFIG_BASE, &[base_job(), second])
            .unwrap_err()
            .to_string();
        assert!(err.contains("ci.jobs[1]"), "got: {err}");
    }

    #[test]
    fn wire_jobs_into_a_later_jobs_failure_discards_an_earlier_jobs_insertion() {
        let mut second = base_job();
        second.workflow = Some("no-such-workflow".to_string());
        assert!(wire_jobs_into(CONFIG_BASE, &[base_job(), second]).is_err());
        // The pure function returns Err with no output at all — the caller
        // (wire_ci_at) never sees a partially-applied string to write.
    }

    #[test]
    fn wire_jobs_into_aggregates_all_required_by_failures() {
        let mut job = base_job();
        job.required_by = vec![
            "missing-job".to_string(),
            "toolkit/common_tests".to_string(),
        ];
        let err = format!(
            "{:?}",
            wire_jobs_into(CONFIG_WITH_REQUIRES_ABSENT, &[job]).unwrap_err()
        );
        assert!(err.contains("\"missing-job\": not found"));
        assert!(err.contains("\"toolkit/common_tests\": has no `requires:` key"));
    }

    #[test]
    fn wire_jobs_into_required_by_leaves_content_untouched_on_failure() {
        let mut job = base_job();
        job.required_by = vec!["deploy".to_string()];
        assert!(wire_jobs_into(CONFIG_WITH_REQUIRES_ABSENT, &[job]).is_err());
    }

    #[test]
    fn wire_jobs_into_required_by_appends_to_inline_target() {
        let mut job = base_job();
        job.required_by = vec!["deploy".to_string()];
        let out = wire_jobs_into(CONFIG_WITH_REQUIRES_INLINE, &[job]).unwrap();
        assert!(out.contains("requires: [toolkit/common_tests, jci-audit/check]"));
    }

    #[test]
    fn wire_jobs_into_required_by_appends_to_block_target() {
        let mut job = base_job();
        job.required_by = vec!["deploy".to_string()];
        let out = wire_jobs_into(CONFIG_WITH_REQUIRES_BLOCK, &[job]).unwrap();
        assert!(out.contains("- jci-audit/check"));
        assert!(out.contains("- toolkit/common_tests"));
    }

    #[test]
    fn wire_jobs_into_required_by_duplicate_target_appends_only_once() {
        // append_requires's Block-form idempotency check reads a position
        // captured before any mutation — two identical entries in one job's
        // own required_by list must not each insert their own duplicate
        // line.
        let mut job = base_job();
        job.required_by = vec!["deploy".to_string(), "deploy".to_string()];
        let out = wire_jobs_into(CONFIG_WITH_REQUIRES_BLOCK, &[job]).unwrap();
        // The appended block item, at its own 12-space indent — distinct
        // from the new job entry's own 6-space "- jci-audit/check" line.
        assert_eq!(
            out.matches("            - jci-audit/check").count(),
            1,
            "got: {out}"
        );
    }

    #[test]
    fn wire_jobs_into_required_by_is_idempotent() {
        let mut job = base_job();
        job.required_by = vec!["deploy".to_string()];
        let first = wire_jobs_into(CONFIG_WITH_REQUIRES_INLINE, &[job.clone()]).unwrap();
        let second = wire_jobs_into(&first, &[job]).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn wire_jobs_into_preserves_unrelated_workflow_and_comments() {
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
        let out = wire_jobs_into(content, &[base_job()]).unwrap();
        assert!(out.contains("# a comment that must survive"));
        assert!(out.contains("- toolkit/release_crate"));
    }

    #[test]
    fn wire_jobs_into_preserves_trailing_newline_convention() {
        let no_trailing = CONFIG_BASE.trim_end();
        let out = wire_jobs_into(no_trailing, &[base_job()]).unwrap();
        assert!(!out.ends_with('\n'));

        let out = wire_jobs_into(CONFIG_BASE, &[base_job()]).unwrap();
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn wire_jobs_into_preserves_crlf_line_endings() {
        let crlf = CONFIG_BASE.replace('\n', "\r\n");
        let out = wire_jobs_into(&crlf, &[base_job()]).unwrap();
        assert!(out.contains("\r\n"), "expected CRLF endings preserved");
        assert!(
            !out.replace("\r\n", "").contains('\n'),
            "no bare LF should remain: {out:?}"
        );
        assert!(out.contains(MANAGED_BEGIN));
    }

    #[test]
    fn wire_jobs_into_applies_two_jobs_into_two_workflows() {
        let mut release_job = JobSpec {
            workflow: Some("release".to_string()),
            orb_job: Some("jci-audit/publish_record".to_string()),
            orb_version: None,
            job_name: None,
            requires: Vec::new(),
            required_by: Vec::new(),
        };
        release_job.orb_version = Some("jerus-org/jci-audit@1.0".to_string());

        let out = wire_jobs_into(CONFIG_BASE, &[base_job(), release_job]).unwrap();
        assert!(out.contains("      - jci-audit/check"));
        assert!(out.contains("      - jci-audit/publish_record"));
        // Only ONE orb pin — both jobs share the same orb.
        assert_eq!(
            out.matches("  jci-audit: jerus-org/jci-audit@1.0").count(),
            1
        );
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

    const CONFIGURED_JOB_TOML: &str = "\
[ci]
file = \".circleci/config.yml\"

[[ci.jobs]]
workflow = \"validation\"
orb_job = \"jci-audit/check\"
orb_version = \"jerus-org/jci-audit@1.0\"
";

    #[test]
    fn wire_ci_at_first_run_scaffolds_an_example_and_touches_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);

        let outcome = wire_ci_at(dir.path(), None, false).unwrap();
        assert_eq!(outcome, WireCiOutcome::Scaffolded);

        assert!(toml_path.is_file());
        let scaffolded = read_ci_file(&std::fs::read_to_string(&toml_path).unwrap()).unwrap();
        assert_eq!(scaffolded.jobs.len(), 1);
        assert_eq!(scaffolded.jobs[0].workflow.as_deref(), Some("validation"));
        // Nothing applied yet — the CI file is untouched.
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), CONFIG_BASE);
    }

    #[test]
    fn wire_ci_at_check_with_no_config_errs_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);

        let err = wire_ci_at(dir.path(), None, true);
        assert!(err.is_err());
        assert!(!toml_path.is_file());
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), CONFIG_BASE);
    }

    #[test]
    fn wire_ci_at_applies_configured_jobs_and_never_rewrites_the_spec() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);
        std::fs::write(&toml_path, CONFIGURED_JOB_TOML).unwrap();

        let outcome = wire_ci_at(dir.path(), None, false).unwrap();
        assert_eq!(
            outcome,
            WireCiOutcome::Configured {
                ci_file_path: config_path.clone(),
                ci_file: WriteOutcome::Wrote,
            }
        );

        let ci_text = std::fs::read_to_string(&config_path).unwrap();
        assert!(ci_text.contains(MANAGED_BEGIN));
        // jci-audit.toml is read-only on this path — never rewritten.
        assert_eq!(
            std::fs::read_to_string(&toml_path).unwrap(),
            CONFIGURED_JOB_TOML
        );
    }

    #[test]
    fn wire_ci_at_second_run_is_in_sync() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);
        std::fs::write(&toml_path, CONFIGURED_JOB_TOML).unwrap();

        wire_ci_at(dir.path(), None, false).unwrap();
        let ci_after_first = std::fs::read_to_string(&config_path).unwrap();

        let outcome = wire_ci_at(dir.path(), None, false).unwrap();
        let WireCiOutcome::Configured { ci_file, .. } = outcome else {
            panic!("expected Configured, got {outcome:?}");
        };
        assert_eq!(ci_file, WriteOutcome::InSync);
        assert_eq!(
            std::fs::read_to_string(&config_path).unwrap(),
            ci_after_first
        );
    }

    #[test]
    fn wire_ci_at_check_detects_drift_without_writing_anything() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);
        std::fs::write(&toml_path, CONFIGURED_JOB_TOML).unwrap();

        wire_ci_at(dir.path(), None, false).unwrap();
        // Hand-revert the CI file only.
        std::fs::write(&config_path, CONFIG_BASE).unwrap();
        let toml_before = std::fs::read_to_string(&toml_path).unwrap();

        let outcome = wire_ci_at(dir.path(), None, true).unwrap();
        let WireCiOutcome::Configured { ci_file, .. } = outcome else {
            panic!("expected Configured, got {outcome:?}");
        };
        assert_eq!(ci_file, WriteOutcome::Drift);
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), CONFIG_BASE);
        assert_eq!(std::fs::read_to_string(&toml_path).unwrap(), toml_before);
    }

    #[test]
    fn wire_ci_at_ci_file_missing_errs_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deny.toml"), "[advisories]\n").unwrap();
        std::fs::write(dir.path().join("jci-audit.toml"), CONFIGURED_JOB_TOML).unwrap();

        let err = wire_ci_at(dir.path(), None, false);
        assert!(err.is_err());
        assert!(!dir.path().join(".circleci/config.yml").exists());
    }

    #[test]
    fn wire_ci_at_required_by_failure_leaves_the_ci_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_WITH_REQUIRES_ABSENT);
        let toml = "\
[[ci.jobs]]
workflow = \"validation\"
orb_job = \"jci-audit/check\"
orb_version = \"jerus-org/jci-audit@1.0\"
required_by = [\"deploy\"]
";
        std::fs::write(&toml_path, toml).unwrap();

        let err = wire_ci_at(dir.path(), None, false);
        assert!(err.is_err());
        assert_eq!(
            std::fs::read_to_string(&config_path).unwrap(),
            CONFIG_WITH_REQUIRES_ABSENT
        );
        assert_eq!(std::fs::read_to_string(&toml_path).unwrap(), toml);
    }

    #[test]
    fn wire_ci_at_explicit_config_override_bypasses_deny_toml_discovery() {
        // Must not even need a deny.toml when an override is given — mirrors
        // resolve_publish_record_path's identical precedent.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".circleci-config.yml"), CONFIG_BASE).unwrap();
        let spec_path = dir.path().join("my-wiring.toml");
        std::fs::write(
            &spec_path,
            "[ci]\nfile = \".circleci-config.yml\"\n\n[[ci.jobs]]\nworkflow = \"validation\"\norb_job = \"jci-audit/check\"\norb_version = \"jerus-org/jci-audit@1.0\"\n",
        )
        .unwrap();

        let outcome = wire_ci_at(dir.path(), Some(&spec_path), false).unwrap();
        let WireCiOutcome::Configured {
            ci_file_path,
            ci_file,
        } = outcome
        else {
            panic!("expected Configured, got {outcome:?}");
        };
        assert_eq!(ci_file_path, dir.path().join(".circleci-config.yml"));
        assert_eq!(ci_file, WriteOutcome::Wrote);
    }

    #[test]
    fn wire_ci_at_applies_multiple_jobs_into_different_workflows() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_BASE);
        let toml = "\
[[ci.jobs]]
workflow = \"validation\"
orb_job = \"jci-audit/check\"
orb_version = \"jerus-org/jci-audit@1.0\"

[[ci.jobs]]
workflow = \"release\"
orb_job = \"jci-audit/publish_record\"
orb_version = \"jerus-org/jci-audit@1.0\"
";
        std::fs::write(&toml_path, toml).unwrap();

        wire_ci_at(dir.path(), None, false).unwrap();
        let ci_text = std::fs::read_to_string(&config_path).unwrap();
        assert!(ci_text.contains("      - jci-audit/check"));
        assert!(ci_text.contains("      - jci-audit/publish_record"));
    }
}
