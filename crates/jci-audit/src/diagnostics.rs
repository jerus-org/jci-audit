//! Summarising the warnings the underlying tools emit.
//!
//! cargo-deny reports warnings on stderr, each trailing a dependency tree, while
//! the verdict goes to stdout. Redirecting stdout captures the verdict and loses
//! the warnings, and reading the last line reports success whatever was warned
//! about. The count belongs in the tool's own output so a captured run still says
//! what needs attention.

/// Whether a diagnostic came from cargo-deny at its default `warning[...]`
/// severity, or `error[...]` — a lint the consumer's `deny.toml` raised to
/// deny severity (e.g. `multiple-versions = "deny"`). cargo-deny already
/// fails the step outright for an `error[...]`; this only governs how it's
/// *described* here, so calling a hard failure a "warning" doesn't understate
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Severity {
    Warning,
    Error,
}

/// A diagnostic's severity, its code, and how many times it occurred.
pub(crate) type WarningCount = (Severity, String, usize);

/// Count diagnostics by severity and code, most frequent first then
/// alphabetical.
///
/// Matches only a `warning[code]:` or `error[code]:` prefix at the start of a
/// line: tree lines and prose mentioning either word must not inflate the
/// total, or the summary is not worth printing.
pub(crate) fn count_diagnostics(stderr: &str) -> Vec<WarningCount> {
    let mut counts: std::collections::BTreeMap<(Severity, String), usize> =
        std::collections::BTreeMap::default();
    for line in stderr.lines() {
        if let Some(key) = diagnostic_code(&strip_ansi(line)) {
            *counts.entry(key).or_default() += 1;
        }
    }
    let mut out: Vec<WarningCount> = counts.into_iter().map(|((s, c), n)| (s, c, n)).collect();
    out.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.cmp(&b.1)));
    out
}

/// "N warning(s)", "N error(s)", or "N warning(s), M error(s)" — never
/// collapsing an error into the word "warning".
fn severity_headline(counts: &[WarningCount]) -> String {
    let warnings: usize = counts
        .iter()
        .filter(|(s, ..)| *s == Severity::Warning)
        .map(|(.., n)| n)
        .sum();
    let errors: usize = counts
        .iter()
        .filter(|(s, ..)| *s == Severity::Error)
        .map(|(.., n)| n)
        .sum();
    match (warnings, errors) {
        (w, 0) => format!("{w} warning(s)"),
        (0, e) => format!("{e} error(s)"),
        (w, e) => format!("{w} warning(s), {e} error(s)"),
    }
}

/// One line naming the total and the codes, or `None` when there is nothing to say.
pub(crate) fn render_summary(counts: &[WarningCount]) -> Option<String> {
    if counts.is_empty() {
        return None;
    }
    let codes = counts
        .iter()
        .map(|(_, code, n)| format!("{n} {code}"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "  {}: {codes} (-v to list, -vv for full output)",
        severity_headline(counts)
    ))
}

/// How much of a tool's output to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detail {
    /// Counts by code.
    Summary,
    /// Each warning's headline, without its dependency tree.
    List,
    /// Everything the tool printed.
    Full,
}

impl Detail {
    /// Map a logging level onto how much to show.
    ///
    /// The middle step is the useful one: which warnings, without the thousands
    /// of lines of tree that justify them.
    pub(crate) fn from_level(level: tracing::level_filters::LevelFilter) -> Self {
        use tracing::level_filters::LevelFilter as L;
        if level >= L::TRACE {
            Detail::Full
        } else if level >= L::DEBUG {
            Detail::List
        } else {
            Detail::Summary
        }
    }
}

/// The headline of each diagnostic, without the dependency tree beneath it.
pub(crate) fn diagnostic_lines(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .map(strip_ansi)
        .filter(|l| is_diagnostic(l))
        .collect()
}

/// Print a tool's output and return its warning counts.
///
/// The tool's stdout is always shown — it is the one-line verdict. Its stderr
/// carries the warnings and a dependency tree for each, so how much of it appears
/// depends on `detail`.
pub(crate) fn emit(stdout: &str, stderr: &str, detail: Detail) -> Vec<WarningCount> {
    if !stdout.trim().is_empty() {
        print!("{stdout}");
    }
    if detail == Detail::Full && !stderr.trim().is_empty() {
        eprint!("{stderr}");
    }
    let counts = count_diagnostics(stderr);
    if let Some(line) = render_summary(&counts) {
        println!("{line}");
    }
    if detail == Detail::List {
        for line in diagnostic_lines(stderr) {
            println!("    {line}");
        }
    }
    counts
}

/// Fail when diagnostics are present and the caller asked for that.
///
/// An `error[...]` already fails its own step via cargo-deny's exit code
/// (see [`crate::check::CheckReport::success`]), so folding it in here too is
/// a no-op for pass/fail — this only affects the message when
/// `--deny-warnings` is what actually catches it, e.g. a `warning[...]`
/// alongside an `error[...]` in the same run.
pub(crate) fn enforce(counts: &[WarningCount], deny_warnings: bool) -> anyhow::Result<()> {
    if deny_warnings && !counts.is_empty() {
        anyhow::bail!(
            "{} reported and --deny-warnings is set",
            severity_headline(counts)
        );
    }
    Ok(())
}

/// The severity and code of a diagnostic, if this line opens one.
///
/// Only a `warning[code]:` or `error[code]:` prefix at the start of a line
/// counts. A tree line or a sentence mentioning either word must not
/// register, or the summary overstates what happened and stops being worth
/// printing.
fn diagnostic_code(line: &str) -> Option<(Severity, String)> {
    let (severity, rest) = if let Some(rest) = line.strip_prefix("warning[") {
        (Severity::Warning, rest)
    } else {
        (Severity::Error, line.strip_prefix("error[")?)
    };
    let (code, after) = rest.split_once(']')?;
    (after.starts_with(':') && !code.is_empty()).then(|| (severity, code.to_string()))
}

/// Whether the line opens a warning or error diagnostic.
fn is_diagnostic(line: &str) -> bool {
    diagnostic_code(line).is_some()
}

/// Drop ANSI escapes so colourised output is still matched.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // Skip up to and including the terminating letter of the escape.
        for c in chars.by_ref() {
            if c.is_ascii_alphabetic() {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const STDERR: &str = "\
warning[license-exception-not-encountered]: license exception was not encountered
  ┌─ deny.toml:55:9
warning[duplicate]: found 3 duplicate entries for crate 'base64'
warning[duplicate]: found 2 duplicate entries for crate 'windows-sys'
warning[license-exception-not-encountered]: license exception was not encountered
warning[no-license-field]: license expression was not specified
";

    const MIXED_STDERR: &str = "\
error[duplicate]: found 3 duplicate entries for crate 'base64'
  ┌─ deny.toml:55:9
warning[license-exception-not-encountered]: license exception was not encountered
error[duplicate]: found 2 duplicate entries for crate 'windows-sys'
";

    #[test]
    fn an_error_prefixed_diagnostic_is_counted_as_an_error() {
        let counts = count_diagnostics(MIXED_STDERR);
        assert_eq!(
            counts,
            vec![
                (Severity::Error, "duplicate".to_string(), 2),
                (
                    Severity::Warning,
                    "license-exception-not-encountered".to_string(),
                    1
                ),
            ],
            "got {counts:?}"
        );
    }

    #[test]
    fn only_the_diagnostic_prefix_counts_for_errors_too() {
        let counts = count_diagnostics("an error[thing] mid-sentence\n  └── error[x]: nested\n");
        assert!(counts.is_empty(), "got {counts:?}");
    }

    #[test]
    fn colour_codes_do_not_hide_an_error() {
        let counts = count_diagnostics("\u{1b}[31merror\u{1b}[0m[duplicate]: found 2\n");
        assert_eq!(counts, vec![(Severity::Error, "duplicate".to_string(), 1)]);
    }

    #[test]
    fn an_error_headline_says_error_not_warning() {
        let counts =
            count_diagnostics("error[duplicate]: found 2 duplicate entries for crate 'x'\n");
        let out = render_summary(&counts).expect("diagnostics present");
        assert!(out.contains("1 error(s)"), "{out}");
        assert!(!out.contains("warning(s)"), "{out}");
    }

    #[test]
    fn a_mixed_headline_names_both_severities() {
        let out = render_summary(&count_diagnostics(MIXED_STDERR)).expect("diagnostics present");
        assert!(out.contains("1 warning(s)"), "{out}");
        assert!(out.contains("2 error(s)"), "{out}");
    }

    #[test]
    fn error_lines_are_listed_verbatim_alongside_warnings() {
        let lines = diagnostic_lines(MIXED_STDERR);
        assert_eq!(lines.len(), 3, "got {lines:?}");
        assert!(
            lines.iter().any(|l| l.starts_with("error[duplicate]:")),
            "{lines:?}"
        );
    }

    #[test]
    fn enforce_fails_on_deny_severity_diagnostics_too() {
        let counts =
            count_diagnostics("error[duplicate]: found 2 duplicate entries for crate 'x'\n");
        let err = enforce(&counts, true).unwrap_err().to_string();
        assert!(err.contains("1 error(s)"), "{err}");
    }

    #[test]
    fn warnings_are_counted_by_code() {
        let counts = count_diagnostics(STDERR);
        assert_eq!(
            counts,
            vec![
                (Severity::Warning, "duplicate".to_string(), 2),
                (
                    Severity::Warning,
                    "license-exception-not-encountered".to_string(),
                    2
                ),
                (Severity::Warning, "no-license-field".to_string(), 1),
            ],
            "most frequent first, then alphabetical, so the order is stable"
        );
        assert_eq!(counts.iter().map(|(_, _, n)| n).sum::<usize>(), 5);
    }

    #[test]
    fn only_the_diagnostic_prefix_counts() {
        // A tree line or a sentence mentioning a warning must not inflate the
        // total, or the summary stops being trustworthy.
        let counts = count_diagnostics("a warning[thing] mid-sentence\n  └── warning[x]: nested\n");
        assert!(counts.is_empty(), "got {counts:?}");
    }

    #[test]
    fn colour_codes_do_not_hide_a_warning() {
        let counts = count_diagnostics("\u{1b}[33mwarning\u{1b}[0m[duplicate]: found 2\n");
        assert_eq!(
            counts,
            vec![(Severity::Warning, "duplicate".to_string(), 1)]
        );
    }

    #[test]
    fn nothing_to_report_renders_nothing() {
        assert!(render_summary(&[]).is_none());
    }

    #[test]
    fn the_warning_headlines_are_listed_without_their_trees() {
        // -v wants to know WHICH warnings, not the several thousand lines of
        // dependency tree that justify them.
        let lines = diagnostic_lines(STDERR);
        assert_eq!(lines.len(), 5, "one per warning: {lines:?}");
        assert!(lines[0].starts_with("warning[license-exception-not-encountered]"));
        assert!(
            lines.iter().any(|l| l.contains("base64")),
            "keeps the message: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("┌─")),
            "no tree lines: {lines:?}"
        );
    }

    #[test]
    fn detail_steps_up_with_verbosity() {
        use tracing::level_filters::LevelFilter as L;
        assert_eq!(Detail::from_level(L::INFO), Detail::Summary);
        assert_eq!(Detail::from_level(L::WARN), Detail::Summary);
        assert_eq!(Detail::from_level(L::DEBUG), Detail::List);
        assert_eq!(Detail::from_level(L::TRACE), Detail::Full);
    }

    #[test]
    fn deny_warnings_only_fails_when_both_hold() {
        let counts = count_diagnostics(STDERR);
        assert!(enforce(&counts, false).is_ok(), "reporting is the default");
        assert!(enforce(&[], true).is_ok(), "nothing to deny");
        let err = enforce(&counts, true).unwrap_err().to_string();
        assert!(err.contains('5'), "names the count: {err}");
    }

    #[test]
    fn the_summary_gives_the_total_and_the_codes() {
        let out = render_summary(&count_diagnostics(STDERR)).expect("warnings present");
        assert!(out.contains('5'), "the total: {out}");
        assert!(out.contains("duplicate"), "{out}");
        assert!(
            out.contains("-v to list") && out.contains("-vv"),
            "must say how to reach both levels of detail: {out}"
        );
    }
}
