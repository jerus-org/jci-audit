//! Wire the generated `jerus-org/jci-audit` orb job(s) into a consumer's
//! `CircleCI` config — `jci-audit wire-ci` (apply, local-only) and
//! `jci-audit check-ci-wiring` (verify, CI-facing).
//!
//! **`jci-audit.toml`'s `[ci]` table is the required, authoritative spec —
//! not CLI flags.** `[ci].file` names the `CircleCI` config file to patch
//! (default `.circleci/config.yml`, resolved relative to `jci-audit.toml`'s
//! own directory), and each `[[ci.jobs]]` entry describes one job to wire
//! into one workflow — see [`JobSpec`] for the full field list, including
//! `params` for the orb job's own extra parameters (e.g. `jci-audit/check`'s
//! `deny_unused_licenses`). This mirrors `gen-circleci-orb.toml`'s own `[ci]`
//! table role for that tool's wiring of a repo's CI, and stays fully
//! independent of it: a `wire-ci` consumer need not use gen-circleci-orb at
//! all. `--config` only says WHICH file to read as this spec (default
//! `jci-audit.toml` at the discovered workspace root) — it carries no
//! per-job settings itself.
//!
//! A `[ci.jobs.params]` table (or an inline `params = {...}`) belongs to
//! whichever `[[ci.jobs]]` entry it's written directly under — ordinary TOML
//! table nesting, so with two jobs only the first gets `deny_unused_licenses`:
//!
//! ```toml
//! [[ci.jobs]]
//! workflow = "validation"
//! orb_job = "jci-audit/check"
//!
//! [ci.jobs.params]
//! deny_unused_licenses = "true"
//!
//! [[ci.jobs]]
//! workflow = "validation"
//! orb_job = "jci-audit/check_ci_wiring"
//! ```
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
//! also out of scope for this module — `check-ci-wiring` only detects drift
//! between `jci-audit.toml`'s current content and the CI file, not whether
//! that content itself is stale relative to a newer orb version.
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
//! **`wire-ci` and `check-ci-wiring` are two separate subcommands, not one
//! subcommand with a `--check` flag.** Review feedback on
//! jerus-org/jci-audit#163 drew the same line `gen-circleci-orb`'s own
//! `generate` job draws for its `check_ci_wiring` switch (a hardcoded,
//! non-parameterized `update --check` step, never a forwarded flag a
//! consumer could get wrong): a pipeline job must only ever be able to
//! detect wiring drift and tell a human how to fix it, never rewrite the
//! very `CircleCI` config that is currently executing it. An earlier version
//! of this module put that choice behind `wire-ci --check`, which asked
//! every consumer's workflow to remember to set `check: true` — a
//! documentation-enforced convention, not a guarantee. Splitting the verbs
//! removes the unsafe option from `check-ci-wiring`'s CLI surface entirely:
//! it has no flag that could make it write, so the orb job the generator
//! produces for it can't be wired in a way that regresses to write mode —
//! the same construction gen-circleci-orb's own hardcoded step achieves,
//! reached here without needing a generator change (tracked upstream as a
//! future generalization, jerus-org/gen-circleci-orb#350). `wire-ci` itself
//! is excluded from orb generation altogether (`[subcommand.wire-ci]
//! interactive = true` in `gen-circleci-orb.toml`) — it only ever runs
//! locally, for a human to apply `jci-audit.toml`'s spec and commit the
//! result.

use std::path::Path;

use anyhow::{Context, Result, bail};
use toml_edit::{ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

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

/// One `[[ci.jobs]]` entry's shape. `params` holds the orb job's own extra
/// parameters (`[ci.jobs.params]` nested under that same entry, or an
/// inline `params = {...}` — e.g. `jci-audit/check`'s
/// `deny_unused_licenses`/`deny_stale_exceptions`); see [`scalar_to_string`]
/// for exactly how a value renders. `Default` means an entry with nothing
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
    pub(crate) params: Vec<(String, String)>,
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
/// `[[ci.jobs]]` entry, in order. A `[ci.jobs.params]` header (or an inline
/// `params = {...}`) belongs to whichever `[[ci.jobs]]` entry it's written
/// directly under — ordinary TOML table nesting, not something this
/// function resolves itself: each array element already carries its own
/// `params` key by the time `toml_edit` hands it to the loop below. Neither
/// the file, the `[ci]` table, nor any `[[ci.jobs]]` entries existing is
/// `Ok(CiFile::default())`, not an error. Errors if any `[ci.jobs.params]`
/// value isn't a string/boolean/integer, or reuses a key (`name`,
/// `requires`) the job's own dedicated fields already own.
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
        for (index, table) in array.iter().enumerate() {
            let str_field = |key: &str| {
                table
                    .get(key)
                    .and_then(Item::as_str)
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
            };
            let params = key_value_pairs(table.get("params"))
                .with_context(|| format!("ci.jobs[{index}]"))?;
            // `name`/`requires` already have dedicated top-level fields —
            // TOML itself rejects a literal duplicate key within one table,
            // so this only ever needs to guard the reserved names.
            for (key, _) in &params {
                if matches!(key.as_str(), "name" | "requires") {
                    bail!(
                        "ci.jobs[{index}].params.{key}: reserved key — 'name' and \
                         'requires' are set via the job's own top-level fields, not params"
                    );
                }
            }
            jobs.push(JobSpec {
                workflow: str_field("workflow"),
                orb_job: str_field("orb_job"),
                orb_version: str_field("orb_version"),
                job_name: str_field("job_name"),
                requires: string_list(table.get("requires")),
                required_by: string_list(table.get("required_by")),
                params,
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

/// `[ci.jobs.params]`, in declaration order. `as_table_like` (not
/// `as_table`) so a standalone `[ci.jobs.params]` header and an inline
/// `params = { a = "1" }` both read identically — a hand-authored
/// `jci-audit.toml` may reasonably use either.
fn key_value_pairs(item: Option<&Item>) -> Result<Vec<(String, String)>> {
    let Some(item) = item else {
        return Ok(Vec::new());
    };
    // `params` present but the wrong shape (e.g. a bare string typo instead
    // of a table) must fail loudly — treating it the same as "absent" would
    // silently wire the job with none of its params, the exact "vanished
    // with no indication why" failure this module elsewhere fails loudly to
    // avoid.
    let table = item.as_table_like().with_context(
        || "ci.jobs.params: not a table — use `[ci.jobs.params]` or `params = { ... }`",
    )?;
    table
        .iter()
        .map(|(key, value)| {
            let rendered = value
                .as_value()
                .and_then(scalar_to_string)
                .with_context(|| {
                    format!(
                        "ci.jobs.params.{key}: unsupported value — use a string, boolean, or \
                         integer"
                    )
                })?;
            Ok((key.to_string(), rendered))
        })
        .collect()
}

/// A string, boolean, or integer TOML value rendered as it should appear on
/// the right of a `key: value` YAML line — a boolean or integer renders
/// unquoted (`true`, `3`), a string renders verbatim with NO quoting or
/// escaping added: its own content is exactly what ends up after the colon.
/// This is deliberate, not an oversight — it's what lets a boolean/integer
/// TOML value render as the bare YAML scalar it names, and lets a caller who
/// wants a literal quoted string (or one that would otherwise be
/// misinterpreted — a value containing `: `, or itself a YAML-reserved word
/// like `yes`/`null`) embed the quote characters themselves in
/// `jci-audit.toml`, e.g. `param = "\"a: b\""` renders `param: "a: b"`. Only
/// a value type with no sensible single-line YAML rendering at all (array,
/// table, float, datetime) is rejected: a param that silently vanished from
/// the rendered job with no indication why is worse than a loud parse error.
fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.value().clone()),
        Value::Boolean(b) => Some(b.value().to_string()),
        Value::Integer(i) => Some(i.value().to_string()),
        _ => None,
    }
}

/// Render one `JobSpec` as a `[[ci.jobs]]` table — the shared builder behind
/// both `write_scaffold`'s one canned example and `append_discovered_jobs`'s
/// real, `jci-audit.toml`-writing entries (jerus-org/jci-audit#171). Empty
/// `orb_version`/`job_name` and empty `requires`/`required_by` arrays are
/// always written explicitly (never omitted), matching this codebase's
/// established "always present, never omitted" schema-field convention.
fn job_spec_to_table(job: &JobSpec) -> Table {
    let mut table = Table::new();
    table["workflow"] = toml_edit::value(job.workflow.as_deref().unwrap_or_default());
    table["orb_job"] = toml_edit::value(job.orb_job.as_deref().unwrap_or_default());
    table["orb_version"] = toml_edit::value(job.orb_version.as_deref().unwrap_or_default());
    table["job_name"] = toml_edit::value(job.job_name.as_deref().unwrap_or_default());
    table["requires"] = Item::Value(Value::Array(sync::multiline_array(
        job.requires.iter().cloned(),
    )));
    table["required_by"] = Item::Value(Value::Array(sync::multiline_array(
        job.required_by.iter().cloned(),
    )));
    if !job.params.is_empty() {
        let mut params = InlineTable::new();
        for (key, value) in &job.params {
            params.insert(key, value.clone().into());
        }
        table["params"] = Item::Value(Value::InlineTable(params));
    }
    table
}

/// Insert one example `[[ci.jobs]]` entry (this repo's own dogfooded
/// `jci-audit/check` in `validation`) plus a `[ci].file` default into
/// `jci-audit.toml`, preserving everything else in the file byte-for-byte.
/// Only called when [`CiFile::jobs`] is empty AND nothing was discoverable
/// in the `CircleCI` config either (see [`wire_ci_at`]) — never touches an
/// existing `[[ci.jobs]]` entry.
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

    // A real, working example — jci-audit/check's own two flags — shows the
    // shape without requiring the reader to invent a plausible one. Left
    // empty: a job namespaced under jci-audit/ falls back to the running
    // binary's own crate version when orb_version is unset (see
    // resolve_orb_version) — set it only to pin a different orb, or a
    // specific jci-audit version other than the one that wrote this file.
    let example = JobSpec {
        workflow: Some("validation".to_string()),
        orb_job: Some("jci-audit/check".to_string()),
        params: vec![
            ("deny_unused_licenses".to_string(), "true".to_string()),
            ("deny_stale_exceptions".to_string(), "true".to_string()),
        ],
        ..JobSpec::default()
    };

    let mut jobs = ArrayOfTables::new();
    jobs.push(job_spec_to_table(&example));
    ci["jobs"] = Item::ArrayOfTables(jobs);

    Ok(doc.to_string())
}

/// Append one real `[[ci.jobs]]` entry per discovered job (see
/// [`discover_undeclared_jobs`]) to `jci-audit.toml`, preserving everything
/// else in the file byte-for-byte — the ongoing counterpart to
/// [`write_scaffold`]'s one-time canned example. Creates `[ci]`/`[ci].file`/
/// `[ci].jobs` if any are missing, but never touches an existing
/// `[[ci.jobs]]` entry (only pushes new ones onto the end).
fn append_discovered_jobs(jci_audit_toml: &str, discovered: &[JobSpec]) -> Result<String> {
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

    let jobs = ci
        .entry("jobs")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .context("jci-audit.toml [[ci.jobs]] is not an array of tables")?;
    for job in discovered {
        jobs.push(job_spec_to_table(job));
    }

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
    /// At least one `[[ci.jobs]]` entry existed, or one was discoverable in
    /// the `CircleCI` config (jerus-org/jci-audit#171): both files' own
    /// resolved paths and what was (or would be) done to each, plus a
    /// human-readable note per concrete change either direction makes —
    /// a param/requires drift correction, a job adopted into managed
    /// markers, or a newly-discovered job appended to `jci-audit.toml`.
    /// Printed by the CLI in both check and write mode, so `check-ci-wiring`
    /// states the effect of alignment *before* anything is changed.
    Configured {
        toml_path: std::path::PathBuf,
        toml: WriteOutcome,
        ci_file_path: std::path::PathBuf,
        ci_file: WriteOutcome,
        notes: Vec<String>,
    },
    /// No `[[ci.jobs]]` entries existed in `jci-audit.toml`, AND nothing
    /// *usable* was discoverable in the `CircleCI` config either — an
    /// example was scaffolded into `jci-audit.toml` instead. Only reachable
    /// when `check` is `false` (`wire-ci`): under `check-ci-wiring`, this
    /// same situation is an `Err` instead — see [`wire_ci_at`]. The
    /// `CircleCI` config file is never touched either way. `notes` still
    /// carries one entry per `jci-audit/*` job discovery found but couldn't
    /// safely capture (an unrecognized `requires:` shape) — "nothing
    /// discoverable" means nothing *usable*, not that the config has no
    /// jci-audit orb jobs at all.
    Scaffolded { notes: Vec<String> },
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

/// Every workflow name declared under the top-level `workflows:` key, in
/// file order — the entry point for scanning the whole file for
/// `jci-audit/*` jobs (jerus-org/jci-audit#171's discovery pass), rather
/// than one named workflow at a time like every other scanner here.
fn all_workflow_names(lines: &[String]) -> Vec<String> {
    let Some(start) = lines.iter().position(|l| l.trim_end() == "workflows:") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for line in &lines[start + 1..] {
        if line.trim().is_empty() {
            continue;
        }
        if indent_of(line) != 2 {
            // Anything shallower ends the workflows: section; anything
            // deeper is that workflow's own body, not another workflow.
            if indent_of(line) < 2 {
                break;
            }
            continue;
        }
        if let Some(name) = line.trim().strip_suffix(':') {
            names.push(name.to_string());
        }
    }
    names
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

/// An entry's own explicit `name:` override, if it declares one — `None`
/// when it's identified only by its bare orb-job string. Only the job's own
/// direct param level counts: a nested step further down (e.g. `steps: -
/// run: name: "Run tests"`) has its own unrelated `name:` at a deeper
/// indent and must not be mistaken for the job's identity.
fn entry_explicit_name(lines: &[String], entry: &JobEntry) -> Option<String> {
    lines[entry.start..entry.end].iter().find_map(|line| {
        if indent_of(line) != JOB_PARAM_INDENT {
            return None;
        }
        line.trim()
            .strip_prefix("name:")
            .map(|rest| unquote(rest.trim()))
    })
}

/// An entry's `name:` override if it declares one, else its own bare/orb-job
/// string — the matching rule for `--requires`/`--required-by`/idempotency.
/// Exact, case-sensitive.
fn effective_name(lines: &[String], entry: &JobEntry) -> String {
    entry_explicit_name(lines, entry).unwrap_or_else(|| entry_bare_job(lines, entry))
}

/// An entry's own bare orb-job (or plain job template) string — its `- `
/// line's own identifier, regardless of whether it also declares a `name:`
/// override. This is the job actually invoked; a `name:` override is a
/// separate, optional label for it, not a substitute.
fn entry_bare_job(lines: &[String], entry: &JobEntry) -> String {
    lines[entry.start]
        .trim_start()
        .trim_start_matches("- ")
        .trim()
        .trim_end_matches(':')
        .to_string()
}

/// An entry's own current custom params — any `key: value` line at
/// `JOB_PARAM_INDENT` other than `name:`/`requires:`, in file order.
/// Mirrors [`effective_name`]'s indent-scoped scan.
fn entry_current_params(lines: &[String], entry: &JobEntry) -> Vec<(String, String)> {
    lines[entry.start..entry.end]
        .iter()
        .filter(|line| indent_of(line) == JOB_PARAM_INDENT)
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("name:") || trimmed.starts_with("requires:") {
                return None;
            }
            let (key, value) = trimmed.split_once(':')?;
            Some((
                key.trim().to_string(),
                strip_trailing_comment(value.trim()).to_string(),
            ))
        })
        .collect()
}

/// Strip a trailing ` # comment` from a YAML scalar, if one is present
/// outside of matching quotes — a `#` inside a quoted value (`"a # b"`) is
/// part of the value, not a comment, and must survive. Without this, a
/// hand-added comment on a param line (`deny_unused_licenses: true # keep`)
/// would read as part of the *value* (`"true # keep"`), never match toml's
/// declared `"true"`, and get silently rewritten away on the very next
/// resync — deleting the user's comment with a misleading "changed from...
/// to..." note that isn't actually about the value at all.
fn strip_trailing_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    let (mut in_single, mut in_double) = (false, false);
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single
                && !in_double
                && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') =>
            {
                return value[..i].trim_end();
            }
            _ => {}
        }
    }
    value
}

/// Whether `entry` is already wrapped in jci-audit's own managed markers —
/// both sit immediately outside the entry's own `start..end` range, at the
/// same indent as the `- job:` line itself (confirmed by
/// [`find_job_entry_end`]'s own stop condition: a marker comment line's
/// indent matches `JOB_ENTRY_INDENT`, so it's never absorbed into the entry
/// it wraps).
fn entry_is_marked(lines: &[String], entry: &JobEntry) -> bool {
    let begin = format!("{}{MANAGED_BEGIN}", " ".repeat(JOB_ENTRY_INDENT));
    let end = format!("{}{MANAGED_END}", " ".repeat(JOB_ENTRY_INDENT));
    let before_is_begin = entry.start > 0 && lines[entry.start - 1] == begin;
    let after_is_end = entry.end < lines.len() && lines[entry.end] == end;
    before_is_begin && after_is_end
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

/// The marker-wrapped lines for the new job entry: `name:`, then `params`
/// (in declaration order), then `requires:` last. `requires:` is always
/// rendered inline (`requires: [a, b]`) when non-empty — this tool never
/// emits the block-list form itself, only recognises it on existing jobs.
fn render_new_job_block(job: &JobSpec) -> Vec<String> {
    let entry_indent = " ".repeat(JOB_ENTRY_INDENT);
    let mut lines = vec![format!("{entry_indent}{MANAGED_BEGIN}")];
    lines.extend(render_job_body(job, None));
    lines.push(format!("{entry_indent}{MANAGED_END}"));
    lines
}

/// The job entry's own lines — `- orb_job:`, then `name:`, then `params` (in
/// declaration order), then `requires:` last — with no marker wrapping.
/// `existing_name` is rendered as the job's `name:` only when `job.job_name`
/// is empty: an existing entry's own identity is preserved on resync rather
/// than cleared, since other jobs' `requires:` elsewhere in the workflow may
/// reference it by that name (a much bigger blast radius than dropping one
/// param — see jerus-org/jci-audit#171). `requires:` is always rendered
/// inline (`requires: [a, b]`) when non-empty — this tool never emits the
/// block-list form itself, only recognises it on an existing job it's not
/// touching.
fn render_job_body(job: &JobSpec, existing_name: Option<&str>) -> Vec<String> {
    let orb_job = job.orb_job.as_deref().unwrap_or_default();
    let entry_indent = " ".repeat(JOB_ENTRY_INDENT);
    let param_indent = " ".repeat(JOB_PARAM_INDENT);

    let job_name = job
        .job_name
        .as_deref()
        .filter(|n| !n.is_empty())
        .or(existing_name);
    let has_params = job_name.is_some() || !job.requires.is_empty() || !job.params.is_empty();

    let mut lines = Vec::new();
    if has_params {
        lines.push(format!("{entry_indent}- {orb_job}:"));
        if let Some(name) = job_name {
            lines.push(format!("{param_indent}name: {name}"));
        }
        for (key, value) in &job.params {
            lines.push(format!("{param_indent}{key}: {value}"));
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
            // A trailing comment makes the item unsafe to read back as a
            // plain string (jerus-org/jci-audit#171: entry_current_requires
            // reuses this shape's items as real `requires` data, not just
            // an append target — matches classify_requires_inline's own
            // coarse "any `#` at all" refusal for the identical reason).
            if l.contains('#') {
                return RequiresShape::Unrecognized;
            }
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

/// The entry's own current `requires:` items — `Some(vec![])` when it has
/// none, `None` when its shape can't be safely read at all
/// (`Unrecognized`: anchors, a trailing comment, nested flow). Callers
/// decide what "no safe read" means for their own operation: a resync
/// against toml's own explicit intent bails outright, while discovery skips
/// just that one job rather than aborting entirely.
fn entry_current_requires(lines: &[String], entry: &JobEntry) -> Option<Vec<String>> {
    match find_requires_shape(lines, entry) {
        RequiresShape::Absent => Some(Vec::new()),
        RequiresShape::Inline { items, .. } => Some(items),
        RequiresShape::Block {
            header_idx,
            item_indent,
            last_item_idx,
        } => Some(
            lines[header_idx + 1..=last_item_idx]
                .iter()
                .filter(|l| indent_of(l) == item_indent)
                .map(|l| unquote(l.trim_start().trim_start_matches("- ").trim()))
                .collect(),
        ),
        RequiresShape::Unrecognized => None,
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

/// Version to write when the `orbs:` key doesn't exist yet — an explicit
/// `declared` value always wins (needed for any orb other than jci-audit's
/// own, and still available as a manual override for it). Omitting it on one
/// of jci-audit's own jobs falls back to the running binary's own crate
/// version: this repo's Renovate-tracked pin needs *some* value the moment
/// the job it's wiring in is added, and jci-audit's own release always
/// carries that job by construction — there's no reason to also hand-type
/// and then maintain a duplicate of it in `jci-audit.toml`, where it would go
/// stale the instant Renovate bumps the real pin (jerus-org/jci-audit#167).
/// No fallback like this exists for another orb (nothing here knows what
/// version of, say, `other-org/tool` is correct), so that case still errors
/// rather than silently pinning something wrong that — since the pin is
/// presence-only idempotent — would never self-correct on a later run.
fn resolve_orb_version(orb_name: &str, declared: Option<&str>) -> Result<String> {
    if let Some(version) = declared {
        return Ok(version.to_string());
    }
    if orb_name == "jci-audit" {
        return Ok(format!("jerus-org/jci-audit@{}", env!("CARGO_PKG_VERSION")));
    }
    bail!(
        "no orb version configured for '{orb_name}' — set orb_version (e.g. \
         \"jerus-org/{orb_name}@1.0\") on this job in jci-audit.toml"
    );
}

/// One note per param removed, changed, or added between an entry's current
/// declared params and what `jci-audit.toml` now says — comparison is by
/// key, existing order otherwise ignored. A param present in the config but
/// not declared in toml is reported for removal (jerus-org/jci-audit#171:
/// toml is a full, authoritative mirror) rather than silently kept.
fn diff_params_notes(
    job_label: &str,
    existing: &[(String, String)],
    desired: &[(String, String)],
) -> Vec<String> {
    let mut notes = Vec::new();
    for (key, value) in existing {
        match desired.iter().find(|(k, _)| k == key) {
            None => notes.push(format!(
                "{job_label}: removing param '{key}: {value}' — not declared in \
                 jci-audit.toml; add it there to keep it"
            )),
            Some((_, new_value)) if new_value != value => notes.push(format!(
                "{job_label}: param '{key}' changing from '{value}' to '{new_value}' to \
                 match jci-audit.toml"
            )),
            Some(_) => {}
        }
    }
    for (key, value) in desired {
        if !existing.iter().any(|(k, _)| k == key) {
            notes.push(format!(
                "{job_label}: adding param '{key}: {value}' from jci-audit.toml"
            ));
        }
    }
    notes
}

/// Resync an existing job entry (matched by effective name) against `job`'s
/// declared spec — the counterpart to a fresh insert for a job that's
/// already there, marked or not (jerus-org/jci-audit#171). `params` and
/// `requires` are a full, authoritative mirror of what `jci-audit.toml`
/// declares: anything present in the entry but not declared there is
/// dropped, with a note. An unrecognisable existing `requires:` shape
/// (anchors, a trailing comment, nested flow) bails with zero mutation
/// instead of guessing at rewriting it — the same refusal
/// `validate_required_by_targets` already applies to a required-by
/// *target*'s unsafe shape, now applied to the job's own `requires:` too.
/// A job's own identity (`name:`) is preserved when toml doesn't declare
/// one, never cleared — unlike a custom param, it may be referenced by
/// other jobs' `requires:` elsewhere in the workflow.
fn resync_job_entry(
    lines: &mut Vec<String>,
    job: &JobSpec,
    entry: &JobEntry,
    job_label: &str,
    notes: &mut Vec<String>,
) -> Result<()> {
    let Some(existing_requires) = entry_current_requires(lines, entry) else {
        bail!(
            "'{job_label}': existing `requires:` is in a shape jci-audit can't safely \
             rewrite (anchors, a trailing comment, or nested flow) — rewrite it to a \
             plain inline or block list, then re-run"
        );
    };
    let existing_name = entry_explicit_name(lines, entry);
    let existing_params = entry_current_params(lines, entry);
    let is_marked = entry_is_marked(lines, entry);

    let desired_body = render_job_body(job, existing_name.as_deref());
    let actual_body = &lines[entry.start..entry.end];
    if actual_body == desired_body.as_slice() && is_marked {
        return Ok(());
    }

    let notes_before = notes.len();
    notes.extend(diff_params_notes(job_label, &existing_params, &job.params));
    if existing_requires != job.requires {
        notes.push(format!(
            "{job_label}: requires updated to match jci-audit.toml"
        ));
    }
    if !is_marked {
        notes.push(format!(
            "{job_label}: wrapping in jci-audit managed markers (was unmarked)"
        ));
    }
    // The entry is about to be rewritten (we're past the identical-content
    // early return above) but none of the specific checks above explain
    // why — e.g. the same params in a different declared order. Say so
    // rather than rewriting silently with zero explanation.
    if notes.len() == notes_before {
        notes.push(format!(
            "{job_label}: reordering to match jci-audit.toml's declared order"
        ));
    }

    let body_len = desired_body.len();
    lines.splice(entry.start..entry.end, desired_body);
    if !is_marked {
        let entry_indent = " ".repeat(JOB_ENTRY_INDENT);
        lines.insert(entry.start, format!("{entry_indent}{MANAGED_BEGIN}"));
        lines.insert(
            entry.start + 1 + body_len,
            format!("{entry_indent}{MANAGED_END}"),
        );
    }
    Ok(())
}

/// Whether `job`'s declared identity refers to `entry` — the one identity
/// rule used everywhere a declared job needs matching against a real config
/// entry (jerus-org/jci-audit#171): exact effective-name match first (an
/// entry already carrying the exact name toml declares, or — when toml
/// declares none — an entry with no override, whose fallback name is its
/// own bare orb-job string), falling back to the same bare orb-job
/// invocation regardless of what name (if any) the entry currently
/// carries. That fallback is what lets a single, unambiguous entry be
/// recognised as the same job across it gaining, losing, or keeping a
/// `name:` override relative to what toml currently says — this is a
/// pairwise yes/no check; see [`find_matching_entry`] for the version that
/// also detects when the fallback is ambiguous across several entries.
fn job_identifies_entry(lines: &[String], job: &JobSpec, entry: &JobEntry) -> bool {
    if effective_name(lines, entry) == new_job_effective_name(job) {
        return true;
    }
    job.orb_job
        .as_deref()
        .is_some_and(|orb_job| entry_bare_job(lines, entry) == orb_job)
}

/// Find the single entry in `entries` that `job` refers to, per
/// [`job_identifies_entry`]. An exact effective-name match always wins;
/// otherwise every entry sharing `job`'s bare orb-job invocation is a
/// candidate — exactly one is an unambiguous match (renaming or preserving
/// its current name as appropriate), but more than one is refused outright
/// rather than silently resyncing whichever happened to be found first —
/// the same "never touch the wrong thing" discipline
/// `validate_required_by_targets` already applies elsewhere. Used by both
/// `wire_one_job`'s own resync-or-insert decision and
/// `discover_undeclared_jobs`'s already-declared check (via
/// `job_identifies_entry` directly, for its own simpler yes/no need), so
/// the two can never disagree about whether a given entry is "already
/// declared."
fn find_matching_entry<'a>(
    lines: &[String],
    job: &JobSpec,
    entries: &'a [JobEntry],
) -> Result<Option<&'a JobEntry>> {
    let new_name = new_job_effective_name(job);
    if let Some(entry) = entries
        .iter()
        .find(|e| effective_name(lines, e) == new_name)
    {
        return Ok(Some(entry));
    }
    let Some(orb_job) = job.orb_job.as_deref() else {
        return Ok(None);
    };
    let candidates: Vec<&JobEntry> = entries
        .iter()
        .filter(|e| entry_bare_job(lines, e) == orb_job)
        .collect();
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(Some(candidates[0])),
        _ => {
            let names: Vec<String> = candidates
                .iter()
                .map(|e| effective_name(lines, e))
                .collect();
            bail!(
                "multiple '{orb_job}' jobs already exist in this workflow ({}) — set job_name \
                 in jci-audit.toml to say which one this entry refers to",
                names.join(", ")
            );
        }
    }
}

/// Whether `name` (in `workflow`) is itself one of `all_jobs`' own declared
/// `[[ci.jobs]]` entries — the dividing line between two different ways a
/// `required_by` relationship gets realised (see
/// [`required_by_contributors`] and [`wire_one_job`]).
fn is_declared_job(workflow: &str, name: &str, all_jobs: &[JobSpec]) -> bool {
    all_jobs
        .iter()
        .any(|j| j.workflow.as_deref() == Some(workflow) && new_job_effective_name(j) == name)
}

/// Every other job in `all_jobs` (same workflow) whose own `required_by`
/// names `job` — the effective names to merge into `job`'s own desired
/// `requires:` so the relationship survives even when `job` is itself
/// resynced on its own turn, regardless of declaration order. Without this,
/// a required-by contribution applied via the old in-place
/// [`append_requires`] mechanism would be silently discarded the moment its
/// target's own `[[ci.jobs]]` entry is next resynced — resync's "toml is a
/// full mirror" rule (jerus-org/jci-audit#171) only knows about `job`'s own
/// declared `requires`, not a sibling job's `required_by`, unless it's
/// folded in here first. Only relevant when the *source* names a target
/// that's itself declared — [`wire_one_job`] keeps using the in-place
/// append for a target that's some other, unmanaged job in the config
/// (never resynced, so there's nothing to discard it).
fn required_by_contributors(job: &JobSpec, all_jobs: &[JobSpec]) -> Vec<String> {
    let Some(workflow) = job.workflow.as_deref() else {
        return Vec::new();
    };
    let new_name = new_job_effective_name(job);
    all_jobs
        .iter()
        .filter(|other| other.workflow.as_deref() == Some(workflow))
        .filter(|other| other.required_by.contains(&new_name))
        .map(new_job_effective_name)
        .collect()
}

/// Patch one job's own entry into `lines` in place. Order: merge in any
/// required-by contributions from sibling jobs in `all_jobs` (see
/// [`required_by_contributors`]); validate this job's own *external*
/// `required_by` targets (bail with zero mutation to `lines` on any
/// failure); skip-or-insert the `orbs:` pin; skip-or-insert or resync the
/// job entry; apply each validated external `required_by` append.
fn wire_one_job(
    lines: &mut Vec<String>,
    job: &JobSpec,
    all_jobs: &[JobSpec],
    notes: &mut Vec<String>,
) -> Result<()> {
    let workflow = job.workflow.as_deref().context("no workflow configured")?;
    let orb_job = job.orb_job.as_deref().context("no orb_job configured")?;
    let new_name = new_job_effective_name(job);

    // This job's own desired `requires:` also carries any *other* declared
    // job's `required_by` naming it — see `required_by_contributors`.
    let mut effective_job = job.clone();
    for contributor in required_by_contributors(job, all_jobs) {
        if !effective_job.requires.contains(&contributor) {
            effective_job.requires.push(contributor);
        }
    }

    // Deduped once, up front: append_requires's Block-form idempotency check
    // reads a position captured before any mutation, so two identical
    // targets in one job's own required_by list would both see "not present
    // yet" and each insert their own duplicate line — a literal duplicate
    // string in a hand-edited jci-audit.toml is a realistic mistake, not a
    // contrived input. Targets that are themselves declared jobs are
    // excluded here — they're realised entirely via the merge above, on
    // that target's own turn, not by mutating it in place from here.
    let required_by: Vec<String> = dedupe_preserving_order(&job.required_by)
        .into_iter()
        .filter(|target| !is_declared_job(workflow, target, all_jobs))
        .collect();

    // Fail fast, zero mutation: prove every (external) required_by target
    // is safe to touch before changing anything.
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
        let version = resolve_orb_version(orb_name, job.orb_version.as_deref())?;
        let pin_line = format!("  {orb_name}: {version}");
        let Some(end) = find_section_end(lines, "orbs:") else {
            bail!("no top-level 'orbs:' section found in the CI config file");
        };
        lines.insert(end, pin_line);
    }

    // job entry — matched within the target workflow only, via the one
    // shared identity rule (see `find_matching_entry`) also used by
    // `discover_undeclared_jobs`'s already-declared check, so the two can
    // never disagree about whether a given entry is "already declared."
    let entries_after_pin = list_workflow_job_entries(lines, workflow)?;
    let existing_entry = find_matching_entry(lines, job, &entries_after_pin)?.cloned();
    match existing_entry {
        None => {
            let insert_at =
                find_workflow_jobs_end(lines, workflow).context("workflow jobs: end not found")?;
            for (offset, line) in render_new_job_block(&effective_job).into_iter().enumerate() {
                lines.insert(insert_at + offset, line);
            }
        }
        Some(entry) => resync_job_entry(lines, &effective_job, &entry, &new_name, notes)?,
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

/// Scan every workflow in `lines` for `jci-audit/*` job entries `declared`
/// doesn't already account for (matched the same way `wire_one_job` matches
/// — `(workflow, effective_name)`), and synthesize a `JobSpec` reflecting
/// each one's current, real content: `jci-audit.toml` becomes canonical in
/// both directions, not just "config catches up to toml"
/// (jerus-org/jci-audit#171). `orb_version` is left `None` — the
/// self-referential fallback already covers a `jci-audit/*` job (see
/// `resolve_orb_version`), so there's nothing worth hand-capturing.
///
/// A job whose `requires:` can't be safely read (`Unrecognized`) is skipped
/// with a note rather than aborting discovery entirely — this is a
/// *softer* failure than `resync_job_entry`'s hard bail: there's no
/// conflicting, already-declared toml intent here to protect, just one
/// job's own introspection limits, which must not block every other
/// independent job's discovery. The second return value carries one note
/// per job either way — discovered or skipped — surfaced by the caller
/// alongside every other change (jerus-org/jci-audit#171): a skip that's
/// silently swallowed on the `Scaffolded` path (nothing else discoverable)
/// would otherwise leave a customer with no idea a real job already exists
/// that jci-audit couldn't capture.
fn discover_undeclared_jobs(lines: &[String], declared: &[JobSpec]) -> (Vec<JobSpec>, Vec<String>) {
    let mut discovered = Vec::new();
    let mut notes = Vec::new();

    for workflow in all_workflow_names(lines) {
        let Ok(entries) = list_workflow_job_entries(lines, &workflow) else {
            continue;
        };
        for entry in &entries {
            let orb_job = entry_bare_job(lines, entry);
            if !orb_job.starts_with("jci-audit/") {
                continue;
            }
            let name = effective_name(lines, entry);
            let already_declared = declared.iter().any(|d| {
                d.workflow.as_deref() == Some(workflow.as_str())
                    && job_identifies_entry(lines, d, entry)
            });
            if already_declared {
                continue;
            }
            let Some(requires) = entry_current_requires(lines, entry) else {
                notes.push(format!(
                    "'{name}' in workflow '{workflow}': existing `requires:` is in a shape \
                     jci-audit can't safely capture — add a [[ci.jobs]] entry for it to \
                     jci-audit.toml by hand"
                ));
                continue;
            };
            notes.push(format!(
                "'{name}' in workflow '{workflow}': discovered — appending a new [[ci.jobs]] \
                 entry for it to jci-audit.toml"
            ));
            discovered.push(JobSpec {
                workflow: Some(workflow.clone()),
                orb_job: Some(orb_job),
                orb_version: None,
                job_name: entry_explicit_name(lines, entry),
                requires,
                required_by: Vec::new(),
                params: entry_current_params(lines, entry),
            });
        }
    }

    (discovered, notes)
}

/// Test-only convenience over [`wire_jobs_into_with_notes`] for the many
/// tests that only care about the resulting text, not the notes —
/// production code (`wire_ci_at`) always wants the notes, so it calls the
/// full function directly.
#[cfg(test)]
fn wire_jobs_into(content: &str, jobs: &[JobSpec]) -> Result<String> {
    let mut notes = Vec::new();
    wire_jobs_into_with_notes(content, jobs, &mut notes)
}

/// The pure whole-function core: patch `content` (a `CircleCI`-config-shaped
/// string) to match every job in `jobs`, in order, in one shared line
/// buffer. Nothing reaches the caller unless every job succeeds — a later
/// job's failure discards the whole buffer, including any earlier jobs'
/// now-uncommitted insertions. Also appends one human-readable note per
/// concrete change a resync makes (a removed/changed/added param, a
/// `requires:` update, or adding managed markers to a previously-unmarked
/// entry) — surfaced by `check-ci-wiring` *before* anything is written, and
/// again by `wire-ci` as an audit trail when it actually happens
/// (jerus-org/jci-audit#171).
fn wire_jobs_into_with_notes(
    content: &str,
    jobs: &[JobSpec],
    notes: &mut Vec<String>,
) -> Result<String> {
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
        wire_one_job(&mut lines, job, jobs, notes).with_context(|| format!("ci.jobs[{index}]"))?;
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

/// `path`, shown relative to `start` when it's actually under it — a CI
/// job's cwd (or a local run from a different directory) would otherwise
/// show a meaningless, container-internal absolute path like
/// `/home/circleci/project/jci-audit.toml` in every message (jerus-org/
/// jci-audit#174). Falls back to the absolute path unchanged when it isn't
/// under `start` at all (an explicit `--config` pointing elsewhere).
pub(crate) fn display_path(path: &Path, start: &Path) -> String {
    match path.strip_prefix(start) {
        Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
        Ok(rel) => rel.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

/// Locate `jci-audit.toml` (an explicit `config_override`, used as given —
/// mirrors `resolve_publish_record_path`'s "override short-circuits before
/// any discovery" precedent — or `jci-audit.toml` at the workspace root
/// discovered from `deny.toml`), read its `[ci]` table, and reconcile it
/// against the `CircleCI` config it names (resolved relative to
/// `jci-audit.toml`'s own directory, not the workspace root) in both
/// directions (jerus-org/jci-audit#171): every declared `[[ci.jobs]]` entry
/// is applied to the config (inserted, or resynced/adopted if a matching
/// job already exists there — see [`wire_one_job`]), and every
/// `jci-audit/*` job already in the config that toml doesn't yet declare is
/// discovered and appended to `jci-audit.toml` itself (see
/// [`discover_undeclared_jobs`]). Only when there's truly nothing on either
/// side — no declared jobs, nothing discoverable — does this fall back to
/// scaffolding the one canned example. Under `check`, nothing is ever
/// written, on any path.
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

    let existing_toml_text = if config_path.is_file() {
        std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read '{}'", display_path(&config_path, start)))?
    } else {
        String::new()
    };
    let spec = read_ci_file(&existing_toml_text)?;

    let ci_file_path = spec_dir.join(spec.file.as_deref().unwrap_or(".circleci/config.yml"));
    let existing_ci_text =
        if ci_file_path.is_file() {
            Some(std::fs::read_to_string(&ci_file_path).with_context(|| {
                format!("failed to read '{}'", display_path(&ci_file_path, start))
            })?)
        } else {
            None
        };

    let (discovered, mut notes) = match &existing_ci_text {
        Some(text) => {
            let lines: Vec<String> = text.lines().map(str::to_string).collect();
            discover_undeclared_jobs(&lines, &spec.jobs)
        }
        None => (Vec::new(), Vec::new()),
    };

    if spec.jobs.is_empty() && discovered.is_empty() {
        if check {
            let mut message = format!(
                "'{}' has no [[ci.jobs]] entries — run `jci-audit wire-ci` to scaffold one, edit \
                 it to match your CI, then re-run",
                display_path(&config_path, start)
            );
            if !notes.is_empty() {
                message.push_str("\n\nAlso found in the CircleCI config but not captured:\n");
                message.push_str(&notes.join("\n"));
            }
            bail!(message);
        }
        let scaffolded = write_scaffold(&existing_toml_text)?;
        fs_atomic::write_atomically(&config_path, &scaffolded)?;
        return Ok(WireCiOutcome::Scaffolded { notes });
    }

    let Some(existing_ci_text) = existing_ci_text else {
        bail!(
            "'{}' not found — run from a repo with .circleci/config.yml, or set [ci].file in \
             '{}'",
            display_path(&ci_file_path, start),
            display_path(&config_path, start)
        );
    };

    // Both desired texts are computed — and any failure (an unrecognized
    // `requires:` shape on some *other* already-declared job, say) has a
    // chance to surface — before either file is touched on disk. Writing
    // jci-audit.toml here first and only then discovering the CI file's own
    // update fails would leave a newly-appended, not-yet-reviewed toml entry
    // persisted with nothing applied to match it — exactly the half-applied
    // state this module's own atomicity guarantee (jerus-org/jci-audit#171)
    // exists to rule out.
    let desired_toml_text = if discovered.is_empty() {
        existing_toml_text.clone()
    } else {
        append_discovered_jobs(&existing_toml_text, &discovered)?
    };
    let all_jobs: Vec<JobSpec> = spec.jobs.iter().cloned().chain(discovered).collect();
    let desired_ci_text = wire_jobs_into_with_notes(&existing_ci_text, &all_jobs, &mut notes)?;

    let toml = decide(&config_path, &existing_toml_text, &desired_toml_text, check)?;
    let ci_file = decide(&ci_file_path, &existing_ci_text, &desired_ci_text, check)?;

    Ok(WireCiOutcome::Configured {
        toml_path: config_path,
        toml,
        ci_file_path,
        ci_file,
        notes,
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

    #[test]
    fn display_path_strips_the_start_prefix() {
        let start = Path::new("/home/circleci/project");
        let path = Path::new("/home/circleci/project/jci-audit.toml");
        assert_eq!(display_path(path, start), "jci-audit.toml");
    }

    #[test]
    fn display_path_strips_a_nested_prefix() {
        let start = Path::new("/home/circleci/project");
        let path = Path::new("/home/circleci/project/.circleci/config.yml");
        assert_eq!(display_path(path, start), ".circleci/config.yml");
    }

    #[test]
    fn display_path_falls_back_to_the_full_path_when_not_under_start() {
        let start = Path::new("/home/circleci/project");
        let path = Path::new("/somewhere/else/jci-audit.toml");
        assert_eq!(display_path(path, start), "/somewhere/else/jci-audit.toml");
    }

    /// A bare empty string is a more confusing message than the input was
    /// to begin with — show "." (the shell convention for "here") instead,
    /// even though no caller of this function can currently trigger it
    /// (`read_ci_file` already normalizes an empty `[ci].file` to `None`
    /// before it ever reaches path-joining).
    #[test]
    fn display_path_shows_dot_when_path_equals_start() {
        let start = Path::new("/home/circleci/project");
        assert_eq!(display_path(start, start), ".");
    }

    // -- JobSpec / CiFile / jci-audit.toml -------------------------------

    fn full_job() -> JobSpec {
        JobSpec {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            orb_version: Some("jerus-org/jci-audit@1.0".to_string()),
            job_name: Some("audit".to_string()),
            requires: vec!["toolkit/common_tests".to_string()],
            required_by: vec!["deploy".to_string()],
            params: vec![("deny_unused_licenses".to_string(), "true".to_string())],
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

[ci.jobs.params]
deny_unused_licenses = "true"
"#;
        let got = read_ci_file(toml).unwrap();
        assert_eq!(got.file.as_deref(), Some(".circleci/config.yml"));
        assert_eq!(got.jobs, vec![full_job()]);
    }

    /// A hand-authored `jci-audit.toml` may reasonably use the inline-table
    /// form instead of a standalone `[ci.jobs.params]` header — both must
    /// read identically.
    #[test]
    fn read_ci_file_reads_inline_table_params() {
        let toml = r#"
[[ci.jobs]]
workflow = "validation"
orb_job = "jci-audit/check"
params = { deny_unused_licenses = "true", deny_stale_exceptions = "true" }
"#;
        let got = read_ci_file(toml).unwrap();
        assert_eq!(
            got.jobs[0].params,
            vec![
                ("deny_unused_licenses".to_string(), "true".to_string()),
                ("deny_stale_exceptions".to_string(), "true".to_string()),
            ]
        );
    }

    /// A boolean or integer is the natural way to write most orb params
    /// (`deny_unused_licenses`'s real type is boolean) — coerced to its
    /// unquoted string form rather than forcing every value through a TOML
    /// string just to satisfy the schema.
    #[test]
    fn read_ci_file_coerces_boolean_and_integer_param_values() {
        let toml = r#"
[[ci.jobs]]
workflow = "validation"
orb_job = "jci-audit/check"
params = { deny_unused_licenses = true, max_attempts = 3 }
"#;
        let got = read_ci_file(toml).unwrap();
        assert_eq!(
            got.jobs[0].params,
            vec![
                ("deny_unused_licenses".to_string(), "true".to_string()),
                ("max_attempts".to_string(), "3".to_string()),
            ]
        );
    }

    /// A value type with no sensible single-line YAML rendering (array,
    /// table, float, datetime) must fail loudly — a param that silently
    /// vanished from the rendered job with no indication why is worse than
    /// a parse error naming exactly which key is unsupported.
    #[test]
    fn read_ci_file_errs_on_unsupported_param_value_type() {
        let toml = r#"
[[ci.jobs]]
workflow = "validation"
orb_job = "jci-audit/check"
params = { targets = ["a", "b"] }
"#;
        let err = format!("{:?}", read_ci_file(toml).unwrap_err());
        assert!(err.contains("params.targets"), "got: {err}");
        assert!(err.contains("unsupported value"), "got: {err}");
    }

    /// A `params` key present but not table-shaped (a typo — a bare string
    /// instead of `{ ... }`) must fail loudly rather than be treated the
    /// same as "no params at all", which would silently wire the job with
    /// none of them.
    #[test]
    fn read_ci_file_errs_when_params_is_not_a_table() {
        let toml = r#"
[[ci.jobs]]
workflow = "validation"
orb_job = "jci-audit/check"
params = "deny_unused_licenses"
"#;
        let err = format!("{:?}", read_ci_file(toml).unwrap_err());
        assert!(err.contains("ci.jobs.params"), "got: {err}");
        assert!(err.contains("not a table"), "got: {err}");
    }

    /// `name`/`requires` already have dedicated top-level fields —
    /// redeclaring either inside `params` would render two conflicting
    /// `name:`/`requires:` lines in the same job entry.
    #[test]
    fn read_ci_file_errs_when_params_reuses_a_reserved_key() {
        for key in ["name", "requires"] {
            let toml = format!(
                "[[ci.jobs]]\nworkflow = \"validation\"\norb_job = \"jci-audit/check\"\n\n\
                 [ci.jobs.params]\n{key} = \"x\"\n"
            );
            let err = format!("{:?}", read_ci_file(&toml).unwrap_err());
            assert!(err.contains("reserved key"), "key {key}, got: {err}");
        }
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
        assert!(got.jobs[0].params.is_empty());
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
        // Left unset: jci-audit/* falls back to the running binary's own
        // crate version (resolve_orb_version) — nothing to hand-maintain.
        assert_eq!(got.jobs[0].orb_version.as_deref(), None);
        // A real, working example of jci-audit/check's own two params,
        // round-tripping through the inline-table form write_scaffold uses.
        assert_eq!(
            got.jobs[0].params,
            vec![
                ("deny_unused_licenses".to_string(), "true".to_string()),
                ("deny_stale_exceptions".to_string(), "true".to_string()),
            ]
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

    /// `jci-audit/check`, hand-drafted before `wire-ci` existed: pinned,
    /// present, carrying real params — but never wrapped in managed markers.
    const CONFIG_WITH_UNMARKED_CHECK_JOB: &str = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      - jci-audit/check:
          deny_unused_licenses: true
";

    /// `jci-audit/check`, already managed, but its params have drifted from
    /// what `jci-audit.toml` now declares — `deny_stale_exceptions` is
    /// config-only (not in `full_check_job()`'s params below), and
    /// `deny_unused_licenses` has the wrong value.
    const CONFIG_WITH_MARKED_CHECK_JOB_DRIFTED: &str = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check:
          deny_unused_licenses: false
          deny_stale_exceptions: true
      # <<< jci-audit wire-ci
";

    /// `jci-audit/check`, already managed, with a block-form `requires:`
    /// naming a job toml no longer declares.
    const CONFIG_WITH_MARKED_CHECK_JOB_REQUIRES_BLOCK: &str = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check:
          requires:
            - toolkit/common_tests
      # <<< jci-audit wire-ci
";

    /// Same job, marked, with a `requires:` this tool can't safely rewrite.
    const CONFIG_WITH_MARKED_CHECK_JOB_UNRECOGNIZED_REQUIRES: &str = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check:
          requires: [toolkit/common_tests] # trailing comment
      # <<< jci-audit wire-ci
";

    /// A `[[ci.jobs]]` entry for `jci-audit/check` declaring
    /// `deny_unused_licenses = "true"` only — matches
    /// `CONFIG_WITH_UNMARKED_CHECK_JOB`'s content exactly (adoption should
    /// be markers-only), but not `CONFIG_WITH_MARKED_CHECK_JOB_DRIFTED`'s.
    fn check_job_with_one_param() -> JobSpec {
        let mut job = base_job();
        job.params = vec![("deny_unused_licenses".to_string(), "true".to_string())];
        job
    }

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
            params: Vec::new(),
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

    /// A trailing comment on a block-form item is unsafe to read back as
    /// plain data — the same reason `find_requires_shape_unrecognized_*`
    /// already refuses an inline `requires:` with one
    /// (jerus-org/jci-audit#171: `entry_current_requires` reuses these
    /// items as real `requires` values, not just an append target).
    #[test]
    fn find_requires_shape_unrecognized_block_item_trailing_comment() {
        let content = "\
version: 2.1
orbs:
  toolkit: jerus-org/circleci-toolkit@7.4.0
workflows:
  validation:
    jobs:
      - toolkit/common_tests
      - deploy:
          requires:
            - toolkit/common_tests # trailing comment
";
        let lines = lines_of(content);
        let entries = list_workflow_job_entries(&lines, "validation").unwrap();
        let shape = find_requires_shape(&lines, &entries[1]);
        assert_eq!(shape, RequiresShape::Unrecognized);
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

    #[test]
    fn render_new_job_block_with_params_only() {
        let mut job = base_job();
        job.params = vec![
            ("deny_unused_licenses".to_string(), "true".to_string()),
            ("deny_stale_exceptions".to_string(), "true".to_string()),
        ];
        let block = render_new_job_block(&job);
        assert_eq!(
            block,
            vec![
                format!("      {MANAGED_BEGIN}"),
                "      - jci-audit/check:".to_string(),
                "          deny_unused_licenses: true".to_string(),
                "          deny_stale_exceptions: true".to_string(),
                format!("      {MANAGED_END}"),
            ]
        );
    }

    /// Params sit between `name:` and `requires:` — config values before
    /// dependency wiring.
    #[test]
    fn render_new_job_block_with_name_params_and_requires() {
        let mut job = base_job();
        job.job_name = Some("audit".to_string());
        job.params = vec![("deny_unused_licenses".to_string(), "true".to_string())];
        job.requires = vec!["toolkit/common_tests".to_string()];
        let block = render_new_job_block(&job);
        assert_eq!(
            block,
            vec![
                format!("      {MANAGED_BEGIN}"),
                "      - jci-audit/check:".to_string(),
                "          name: audit".to_string(),
                "          deny_unused_licenses: true".to_string(),
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
    fn wire_jobs_into_inserts_a_brand_new_job_with_its_own_params() {
        let mut job = base_job();
        job.params = vec![
            ("deny_unused_licenses".to_string(), "true".to_string()),
            ("deny_stale_exceptions".to_string(), "true".to_string()),
        ];
        let out = wire_jobs_into(CONFIG_BASE, &[job]).unwrap();
        assert!(out.contains("      - jci-audit/check:"));
        assert!(out.contains("          deny_unused_licenses: true"));
        assert!(out.contains("          deny_stale_exceptions: true"));
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

    /// Wiring one of jci-audit's own orb jobs with no `orb_version` declared
    /// doesn't need a placeholder in `jci-audit.toml` at all — the running
    /// binary's own crate version is a correct, always-current answer, and
    /// never goes stale the way a hand-typed value would once Renovate bumps
    /// the pin (jerus-org/jci-audit#167).
    #[test]
    fn wire_jobs_into_pins_jci_audit_using_its_own_crate_version_when_orb_version_omitted() {
        let mut job = base_job();
        job.orb_version = None;
        let out = wire_jobs_into(CONFIG_BASE, &[job]).unwrap();
        assert!(
            out.contains(&format!(
                "  jci-audit: jerus-org/jci-audit@{}",
                env!("CARGO_PKG_VERSION")
            )),
            "got: {out}"
        );
    }

    /// Any other orb has no self-reference to fall back to — omitting
    /// `orb_version` there must still fail loudly rather than silently pin
    /// something jci-audit's own version has no relation to.
    #[test]
    fn wire_jobs_into_errs_when_orb_version_missing_for_a_non_self_referential_orb() {
        let mut job = base_job();
        job.orb_job = Some("other-org/tool".to_string());
        job.orb_version = None;
        let err = format!("{:?}", wire_jobs_into(CONFIG_BASE, &[job]).unwrap_err());
        assert!(err.contains("no orb version configured"), "got: {err}");
        assert!(!CONFIG_BASE.contains("other-org"));
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

    /// A `required_by` target that's *itself* a declared, resync-managed
    /// job must not lose the contribution the moment its own turn resyncs
    /// it — regardless of which job comes first in `[[ci.jobs]]`'s own
    /// order (jerus-org/jci-audit#171 review feedback).
    #[test]
    fn wire_jobs_into_required_by_survives_the_targets_own_resync() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check
      - jci-audit/publish_record
      # <<< jci-audit wire-ci
";
        let mut source = base_job();
        source.required_by = vec!["jci-audit/publish_record".to_string()];
        let mut target = base_job();
        target.orb_job = Some("jci-audit/publish_record".to_string());

        // Source (with the required_by) declared BEFORE its target — the
        // exact ordering that silently discarded the contribution before
        // this fix, since the target's own resync ran after the append and
        // overwrote it.
        let out = wire_jobs_into(content, &[source, target]).unwrap();
        assert!(out.contains("requires: [jci-audit/check]"), "got: {out}");
    }

    /// Same relationship, target declared first — must work either way,
    /// proving the fix isn't just reordering the bug.
    #[test]
    fn wire_jobs_into_required_by_survives_the_targets_own_resync_reverse_order() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check
      - jci-audit/publish_record
      # <<< jci-audit wire-ci
";
        let mut source = base_job();
        source.required_by = vec!["jci-audit/publish_record".to_string()];
        let mut target = base_job();
        target.orb_job = Some("jci-audit/publish_record".to_string());

        let out = wire_jobs_into(content, &[target, source]).unwrap();
        assert!(out.contains("requires: [jci-audit/check]"), "got: {out}");
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
            params: Vec::new(),
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

    // -- resync_job_entry / wire_one_job adopt+resync (jerus-org/jci-audit#171) --

    #[test]
    fn wire_jobs_into_adopts_an_unmarked_entry_matching_toml() {
        let mut notes = Vec::new();
        let out = wire_jobs_into_with_notes(
            CONFIG_WITH_UNMARKED_CHECK_JOB,
            &[check_job_with_one_param()],
            &mut notes,
        )
        .unwrap();
        assert!(out.contains(MANAGED_BEGIN), "got: {out}");
        assert!(out.contains(MANAGED_END), "got: {out}");
        assert!(out.contains("deny_unused_licenses: true"), "got: {out}");
        // Content already matched — the only note is the adoption itself.
        assert_eq!(notes.len(), 1, "got: {notes:?}");
        assert!(notes[0].contains("wrapping in jci-audit managed markers"));
        // No duplicate job entry inserted.
        assert_eq!(out.matches("jci-audit/check").count(), 1, "got: {out}");
    }

    #[test]
    fn wire_jobs_into_resyncs_a_marked_entrys_drifted_params() {
        let mut notes = Vec::new();
        let out = wire_jobs_into_with_notes(
            CONFIG_WITH_MARKED_CHECK_JOB_DRIFTED,
            &[check_job_with_one_param()],
            &mut notes,
        )
        .unwrap();
        assert!(out.contains("deny_unused_licenses: true"), "got: {out}");
        assert!(
            !out.contains("deny_stale_exceptions"),
            "config-only param must be removed: {out}"
        );
        assert!(
            notes
                .iter()
                .any(|n| n.contains("removing param 'deny_stale_exceptions: true'")),
            "got: {notes:?}"
        );
        assert!(
            notes
                .iter()
                .any(|n| n.contains("changing from 'false' to 'true'")),
            "got: {notes:?}"
        );
    }

    #[test]
    fn strip_trailing_comment_removes_a_bare_comment() {
        assert_eq!(strip_trailing_comment("true # keep this"), "true");
    }

    #[test]
    fn strip_trailing_comment_preserves_a_hash_inside_quotes() {
        assert_eq!(strip_trailing_comment("\"a # b\""), "\"a # b\"");
    }

    /// A hand-added comment on an existing param line must not be read as
    /// part of its *value* — otherwise it never matches toml's declared
    /// value and gets silently rewritten away as if it had actually
    /// changed.
    #[test]
    fn entry_current_params_strips_a_trailing_comment_from_the_value() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      - jci-audit/check:
          deny_unused_licenses: true # keep this
";
        let mut notes = Vec::new();
        let out =
            wire_jobs_into_with_notes(content, &[check_job_with_one_param()], &mut notes).unwrap();
        // Already matches toml (modulo the comment) plus needs markers —
        // the only note should be the adoption, not a spurious value change.
        assert_eq!(notes.len(), 1, "got: {notes:?}");
        assert!(notes[0].contains("wrapping in jci-audit managed markers"));
        let _ = out;
    }

    /// The same params in a different declared order still triggers a
    /// rewrite (the file changes), but must not do so with zero
    /// explanation — the whole point of `notes` is to say why.
    #[test]
    fn wire_jobs_into_resync_notes_a_pure_reorder() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check:
          deny_stale_exceptions: true
          deny_unused_licenses: true
      # <<< jci-audit wire-ci
";
        let mut job = base_job();
        job.params = vec![
            ("deny_unused_licenses".to_string(), "true".to_string()),
            ("deny_stale_exceptions".to_string(), "true".to_string()),
        ];
        let mut notes = Vec::new();
        let out = wire_jobs_into_with_notes(content, &[job], &mut notes).unwrap();
        assert_ne!(out, content, "the declared order must be applied");
        assert_eq!(notes.len(), 1, "got: {notes:?}");
        assert!(notes[0].contains("reordering"), "got: {notes:?}");
    }

    #[test]
    fn wire_jobs_into_resync_is_a_no_op_when_already_marked_and_matching() {
        let first = wire_jobs_into(
            CONFIG_WITH_UNMARKED_CHECK_JOB,
            &[check_job_with_one_param()],
        )
        .unwrap();
        let mut notes = Vec::new();
        let second =
            wire_jobs_into_with_notes(&first, &[check_job_with_one_param()], &mut notes).unwrap();
        assert_eq!(first, second, "byte-identical: no reflow nobody caused");
        assert!(notes.is_empty(), "got: {notes:?}");
    }

    #[test]
    fn wire_jobs_into_resync_replaces_block_requires_with_toml_inline_list() {
        let mut job = base_job();
        job.requires = vec!["toolkit/idiomatic_rust".to_string()];
        let out = wire_jobs_into(CONFIG_WITH_MARKED_CHECK_JOB_REQUIRES_BLOCK, &[job]).unwrap();
        assert!(
            out.contains("requires: [toolkit/idiomatic_rust]"),
            "got: {out}"
        );
        assert!(
            !out.contains("- toolkit/common_tests"),
            "a requires item not declared in toml must be dropped: {out}"
        );
    }

    #[test]
    fn wire_jobs_into_resync_bails_on_unrecognized_requires() {
        let err = format!(
            "{:?}",
            wire_jobs_into(
                CONFIG_WITH_MARKED_CHECK_JOB_UNRECOGNIZED_REQUIRES,
                &[base_job()]
            )
            .unwrap_err()
        );
        assert!(err.contains("jci-audit/check"), "got: {err}");
        assert!(err.contains("can't safely rewrite"), "got: {err}");
        assert!(
            !CONFIG_WITH_MARKED_CHECK_JOB_UNRECOGNIZED_REQUIRES.contains("nonsense"),
            "sanity: fixture unchanged"
        );
    }

    #[test]
    fn wire_jobs_into_resync_preserves_existing_name_when_toml_is_silent() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check:
          name: audit-check
          deny_unused_licenses: false
      # <<< jci-audit wire-ci
";
        let job = check_job_with_one_param(); // job_name: None
        let out = wire_jobs_into(content, &[job]).unwrap();
        assert!(out.contains("name: audit-check"), "got: {out}");
        assert_eq!(
            out.matches("jci-audit/check").count(),
            1,
            "must resync the existing named entry, not insert a duplicate: {out}"
        );
    }

    /// The matching step itself, not just the render: an entry already
    /// carrying an explicit `name:` override must still be found and
    /// resynced (not duplicated) when toml declares no `job_name` at all —
    /// matching by effective name alone never finds it, since toml's own
    /// computed identity is the bare orb-job string while the entry's is
    /// the override.
    #[test]
    fn wire_jobs_into_resync_matches_a_named_entry_when_toml_declares_no_name() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check:
          name: audit-check
      # <<< jci-audit wire-ci
";
        let out = wire_jobs_into(content, &[check_job_with_one_param()]).unwrap();
        assert_eq!(out.matches("jci-audit/check").count(), 1, "got: {out}");
        assert!(out.contains("name: audit-check"), "got: {out}");
        assert!(out.contains("deny_unused_licenses: true"), "got: {out}");
    }

    /// The mirror image: a bare, unnamed entry already exists, and toml
    /// *newly* declares a `job_name` for it — must rename the existing
    /// entry, not insert a second one alongside it.
    #[test]
    fn wire_jobs_into_resync_renames_a_bare_entry_when_toml_adds_a_name() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check
      # <<< jci-audit wire-ci
";
        let mut job = base_job();
        job.job_name = Some("audit-check".to_string());
        let out = wire_jobs_into(content, &[job]).unwrap();
        assert_eq!(out.matches("jci-audit/check").count(), 1, "got: {out}");
        assert!(out.contains("name: audit-check"), "got: {out}");
    }

    /// Two entries invoke the same orb job under different names, and toml
    /// declares no `job_name` at all — there is no way to tell which one is
    /// meant, so this must refuse outright rather than silently resyncing
    /// whichever happens to be found first.
    #[test]
    fn wire_jobs_into_resync_refuses_an_ambiguous_bare_orb_job_match() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/check:
          name: check-a
      - jci-audit/check:
          name: check-b
      # <<< jci-audit wire-ci
";
        let err = format!("{:?}", wire_jobs_into(content, &[base_job()]).unwrap_err());
        assert!(err.contains("check-a"), "got: {err}");
        assert!(err.contains("check-b"), "got: {err}");
    }

    /// `discover_undeclared_jobs` and `wire_one_job` must use the exact
    /// same identity rule — otherwise the same physical job can look
    /// "already declared" to one and "not yet declared" to the other,
    /// appending a spurious duplicate `[[ci.jobs]]` entry.
    #[test]
    fn discover_undeclared_jobs_agrees_with_wire_one_jobs_bare_orb_job_fallback() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      - jci-audit/check:
          name: audit-check
";
        let lines = lines_of(content);
        // Declared with a job_name that doesn't match the entry's current
        // name yet (a rename in flight) — still recognised as the same job
        // via the bare-orb-job fallback, so it's not "undeclared."
        let mut declared = base_job();
        declared.job_name = Some("some-other-name".to_string());
        let (discovered, _) = discover_undeclared_jobs(&lines, &[declared]);
        assert!(discovered.is_empty(), "got: {discovered:?}");
    }

    // -- discover_undeclared_jobs / append_discovered_jobs (jerus-org/jci-audit#171) --

    #[test]
    fn all_workflow_names_finds_every_workflow_in_order() {
        let lines = lines_of(CONFIG_BASE);
        assert_eq!(all_workflow_names(&lines), vec!["validation", "release"]);
    }

    #[test]
    fn discover_undeclared_jobs_synthesizes_a_job_matching_the_real_entry() {
        let lines = lines_of(CONFIG_WITH_UNMARKED_CHECK_JOB);
        let (discovered, notes) = discover_undeclared_jobs(&lines, &[]);
        assert_eq!(notes.len(), 1, "got: {notes:?}");
        assert!(notes[0].contains("discovered"), "got: {notes:?}");
        assert_eq!(
            discovered,
            vec![JobSpec {
                workflow: Some("validation".to_string()),
                orb_job: Some("jci-audit/check".to_string()),
                orb_version: None,
                job_name: None,
                requires: Vec::new(),
                required_by: Vec::new(),
                params: vec![("deny_unused_licenses".to_string(), "true".to_string())],
            }]
        );
    }

    #[test]
    fn discover_undeclared_jobs_skips_a_job_already_declared() {
        let lines = lines_of(CONFIG_WITH_UNMARKED_CHECK_JOB);
        let (discovered, _) = discover_undeclared_jobs(&lines, &[check_job_with_one_param()]);
        assert!(discovered.is_empty(), "got: {discovered:?}");
    }

    #[test]
    fn discover_undeclared_jobs_ignores_non_jci_audit_jobs() {
        let lines = lines_of(CONFIG_BASE); // toolkit/common_tests, toolkit/release_crate
        let (discovered, warnings) = discover_undeclared_jobs(&lines, &[]);
        assert!(discovered.is_empty(), "got: {discovered:?}");
        assert!(warnings.is_empty(), "got: {warnings:?}");
    }

    #[test]
    fn discover_undeclared_jobs_skips_unrecognized_requires_with_a_warning() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      - jci-audit/check:
          requires: [toolkit/common_tests] # trailing comment
";
        let lines = lines_of(content);
        let (discovered, warnings) = discover_undeclared_jobs(&lines, &[]);
        assert!(discovered.is_empty(), "got: {discovered:?}");
        assert_eq!(warnings.len(), 1, "got: {warnings:?}");
        assert!(warnings[0].contains("jci-audit/check"));
        assert!(warnings[0].contains("validation"));
    }

    /// Same refusal, block form — without it, the commented-out text would
    /// be captured as a literal `requires` value and re-rendered inline as
    /// `requires: [item # comment]`, corrupting the YAML on write.
    #[test]
    fn discover_undeclared_jobs_skips_unrecognized_block_requires_with_a_warning() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      - jci-audit/check:
          requires:
            - toolkit/common_tests # trailing comment
";
        let lines = lines_of(content);
        let (discovered, warnings) = discover_undeclared_jobs(&lines, &[]);
        assert!(discovered.is_empty(), "got: {discovered:?}");
        assert_eq!(warnings.len(), 1, "got: {warnings:?}");
        assert!(warnings[0].contains("jci-audit/check"));
    }

    #[test]
    fn append_discovered_jobs_writes_a_real_entry_preserving_the_rest() {
        let existing = "[other]\nkept = true\n";
        let discovered = vec![JobSpec {
            workflow: Some("validation".to_string()),
            orb_job: Some("jci-audit/check".to_string()),
            orb_version: None,
            job_name: None,
            requires: Vec::new(),
            required_by: Vec::new(),
            params: vec![("deny_unused_licenses".to_string(), "true".to_string())],
        }];
        let out = append_discovered_jobs(existing, &discovered).unwrap();
        assert!(out.contains("kept = true"), "got: {out}");
        let got = read_ci_file(&out).unwrap();
        assert_eq!(got.jobs, discovered);
    }

    #[test]
    fn append_discovered_jobs_never_touches_an_existing_entry() {
        let existing = "\
[ci]
file = \".circleci/config.yml\"

[[ci.jobs]]
workflow = \"validation\"
orb_job = \"jci-audit/check_ci_wiring\"
";
        let discovered = vec![JobSpec {
            workflow: Some("release".to_string()),
            orb_job: Some("jci-audit/publish_record".to_string()),
            ..JobSpec::default()
        }];
        let out = append_discovered_jobs(existing, &discovered).unwrap();
        let got = read_ci_file(&out).unwrap();
        assert_eq!(got.jobs.len(), 2, "got: {got:?}");
        assert_eq!(
            got.jobs[0].orb_job.as_deref(),
            Some("jci-audit/check_ci_wiring")
        );
        assert_eq!(
            got.jobs[1].orb_job.as_deref(),
            Some("jci-audit/publish_record")
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
        assert_eq!(outcome, WireCiOutcome::Scaffolded { notes: Vec::new() });

        assert!(toml_path.is_file());
        let scaffolded = read_ci_file(&std::fs::read_to_string(&toml_path).unwrap()).unwrap();
        assert_eq!(scaffolded.jobs.len(), 1);
        assert_eq!(scaffolded.jobs[0].workflow.as_deref(), Some("validation"));
        // Nothing applied yet — the CI file is untouched.
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), CONFIG_BASE);
    }

    /// "Nothing discoverable" must mean nothing *usable*, not that the
    /// config has no jci-audit orb jobs at all — a customer must still
    /// learn a real, unparseable job already exists, not just get the
    /// generic canned-example message with no explanation.
    const CONFIG_WITH_UNSYNTHESIZABLE_CHECK_JOB: &str = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      - jci-audit/check:
          requires: [toolkit/common_tests] # trailing comment
";

    #[test]
    fn wire_ci_at_scaffolded_still_surfaces_an_unsynthesizable_discovery() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace(dir.path(), CONFIG_WITH_UNSYNTHESIZABLE_CHECK_JOB);

        let outcome = wire_ci_at(dir.path(), None, false).unwrap();
        let WireCiOutcome::Scaffolded { notes } = outcome else {
            panic!("expected Scaffolded, got {outcome:?}");
        };
        assert_eq!(notes.len(), 1, "got: {notes:?}");
        assert!(notes[0].contains("jci-audit/check"), "got: {notes:?}");
    }

    #[test]
    fn wire_ci_at_check_scaffold_bail_message_surfaces_an_unsynthesizable_discovery() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace(dir.path(), CONFIG_WITH_UNSYNTHESIZABLE_CHECK_JOB);

        let err = wire_ci_at(dir.path(), None, true).unwrap_err().to_string();
        assert!(err.contains("jci-audit/check"), "got: {err}");
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
                toml_path: toml_path.clone(),
                toml: WriteOutcome::InSync,
                ci_file_path: config_path.clone(),
                ci_file: WriteOutcome::Wrote,
                notes: Vec::new(),
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

    /// A Gap-B discovery finding something to append to `jci-audit.toml`
    /// must not get written before a *different*, toml-declared job's own
    /// resync is confirmed to succeed — otherwise a failure on the config
    /// side leaves `jci-audit.toml` holding an appended entry nothing was
    /// ever applied to match (jerus-org/jci-audit#171 review feedback).
    #[test]
    fn wire_ci_at_leaves_toml_untouched_when_the_ci_file_computation_fails() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      - jci-audit/check:
          deny_unused_licenses: true
      # >>> jci-audit wire-ci (managed — edits overwritten by re-running 'jci-audit wire-ci')
      - jci-audit/publish_record:
          requires: [jci-audit/check] # trailing comment
      # <<< jci-audit wire-ci
";
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), content);
        let toml = "\
[[ci.jobs]]
workflow = \"validation\"
orb_job = \"jci-audit/publish_record\"
";
        std::fs::write(&toml_path, toml).unwrap();

        let err = wire_ci_at(dir.path(), None, false);
        assert!(
            err.is_err(),
            "publish_record's unrecognized requires: must bail"
        );
        assert_eq!(
            std::fs::read_to_string(&toml_path).unwrap(),
            toml,
            "jci-audit/check's Gap-B discovery must not be persisted"
        );
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), content);
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
            ..
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

    // -- wire_ci_at: Gap B discovery + combined Gap A/B (jerus-org/jci-audit#171) --

    #[test]
    fn wire_ci_at_discovers_an_undeclared_job_and_writes_it_into_toml() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, config_path) = write_workspace(dir.path(), CONFIG_WITH_UNMARKED_CHECK_JOB);
        // jci-audit.toml starts completely empty: an empty spec plus a
        // config that already has a jci-audit/* job must discover it,
        // not fall back to the canned scaffold.
        std::fs::write(&toml_path, "").unwrap();

        let outcome = wire_ci_at(dir.path(), None, false).unwrap();
        let WireCiOutcome::Configured { toml, ci_file, .. } = outcome else {
            panic!("expected Configured (discovery found a real job), not Scaffolded");
        };
        assert_eq!(toml, WriteOutcome::Wrote);
        assert_eq!(ci_file, WriteOutcome::Wrote, "adopts: adds markers");

        let toml_text = std::fs::read_to_string(&toml_path).unwrap();
        let got = read_ci_file(&toml_text).unwrap();
        assert_eq!(got.jobs.len(), 1);
        assert_eq!(got.jobs[0].orb_job.as_deref(), Some("jci-audit/check"));
        assert_eq!(
            got.jobs[0].params,
            vec![("deny_unused_licenses".to_string(), "true".to_string())]
        );

        let ci_text = std::fs::read_to_string(&config_path).unwrap();
        assert!(ci_text.contains(MANAGED_BEGIN), "got: {ci_text}");
    }

    #[test]
    fn wire_ci_at_check_reports_drift_on_toml_for_an_undeclared_job() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, _) = write_workspace(dir.path(), CONFIG_WITH_UNMARKED_CHECK_JOB);
        std::fs::write(&toml_path, "").unwrap();

        let outcome = wire_ci_at(dir.path(), None, true).unwrap();
        let WireCiOutcome::Configured { toml, ci_file, .. } = outcome else {
            panic!("expected Configured");
        };
        assert_eq!(toml, WriteOutcome::Drift);
        assert_eq!(ci_file, WriteOutcome::Drift);
        // check mode: neither file actually touched.
        assert_eq!(std::fs::read_to_string(&toml_path).unwrap(), "");
    }

    #[test]
    fn wire_ci_at_never_rediscovers_a_job_already_declared() {
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, _) = write_workspace(dir.path(), CONFIG_WITH_UNMARKED_CHECK_JOB);
        let toml = "\
[[ci.jobs]]
workflow = \"validation\"
orb_job = \"jci-audit/check\"

[ci.jobs.params]
deny_unused_licenses = \"true\"
";
        std::fs::write(&toml_path, toml).unwrap();

        let outcome = wire_ci_at(dir.path(), None, false).unwrap();
        let WireCiOutcome::Configured { toml, .. } = outcome else {
            panic!("expected Configured");
        };
        // Already declared — Gap B must not append a duplicate entry.
        assert_eq!(toml, WriteOutcome::InSync);
        let got = read_ci_file(&std::fs::read_to_string(&toml_path).unwrap()).unwrap();
        assert_eq!(got.jobs.len(), 1);
    }

    #[test]
    fn wire_ci_at_discovers_undeclared_jobs_across_multiple_workflows() {
        let content = "\
version: 2.1
orbs:
  jci-audit: jerus-org/jci-audit@1.0
workflows:
  validation:
    jobs:
      - jci-audit/check:
          deny_unused_licenses: true
  release:
    jobs:
      - jci-audit/publish_record
";
        let dir = tempfile::tempdir().unwrap();
        let (toml_path, _) = write_workspace(dir.path(), content);
        std::fs::write(&toml_path, "").unwrap();

        let outcome = wire_ci_at(dir.path(), None, false).unwrap();
        let WireCiOutcome::Configured { toml, .. } = outcome else {
            panic!("expected Configured");
        };
        assert_eq!(toml, WriteOutcome::Wrote);

        let got = read_ci_file(&std::fs::read_to_string(&toml_path).unwrap()).unwrap();
        assert_eq!(got.jobs.len(), 2, "got: {got:?}");
        assert_eq!(got.jobs[0].workflow.as_deref(), Some("validation"));
        assert_eq!(got.jobs[0].orb_job.as_deref(), Some("jci-audit/check"));
        assert_eq!(got.jobs[1].workflow.as_deref(), Some("release"));
        assert_eq!(
            got.jobs[1].orb_job.as_deref(),
            Some("jci-audit/publish_record")
        );
    }
}
