//! Summarising the warnings the underlying tools emit.
//!
//! cargo-deny reports warnings on stderr, each trailing a dependency tree, while
//! the verdict goes to stdout. Redirecting stdout captures the verdict and loses
//! the warnings, and reading the last line reports success whatever was warned
//! about. The count belongs in the tool's own output so a captured run still says
//! what needs attention.

/// A warning code and how many times it occurred.
pub(crate) type WarningCount = (String, usize);

/// Count warnings by code, most frequent first then alphabetical.
///
/// Matches only the `warning[code]:` diagnostic prefix at the start of a line:
/// tree lines and prose mentioning a warning must not inflate the total, or the
/// summary is not worth printing.
pub(crate) fn count_warnings(stderr: &str) -> Vec<WarningCount> {
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for line in stderr.lines() {
        if let Some(code) = warning_code(&strip_ansi(line)) {
            *counts.entry(code).or_default() += 1;
        }
    }
    let mut out: Vec<WarningCount> = counts.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// Total warnings across all codes.
pub(crate) fn total(counts: &[WarningCount]) -> usize {
    counts.iter().map(|(_, n)| n).sum()
}

/// One line naming the total and the codes, or `None` when there is nothing to say.
pub(crate) fn render_summary(counts: &[WarningCount]) -> Option<String> {
    if counts.is_empty() {
        return None;
    }
    let codes = counts
        .iter()
        .map(|(code, n)| format!("{n} {code}"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "  {} warning(s): {codes} (-v to list, -vv for full output)",
        total(counts)
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

/// The headline of each warning, without the dependency tree beneath it.
pub(crate) fn warning_lines(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .map(strip_ansi)
        .filter(|l| is_warning(l))
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
    let counts = count_warnings(stderr);
    if let Some(line) = render_summary(&counts) {
        println!("{line}");
    }
    if detail == Detail::List {
        for line in warning_lines(stderr) {
            println!("    {line}");
        }
    }
    counts
}

/// Fail when warnings are present and the caller asked for that.
pub(crate) fn enforce(counts: &[WarningCount], deny_warnings: bool) -> anyhow::Result<()> {
    if deny_warnings && !counts.is_empty() {
        anyhow::bail!(
            "{} warning(s) reported and --deny-warnings is set",
            total(counts)
        );
    }
    Ok(())
}

/// The code of a warning diagnostic, if this line opens one.
///
/// Only the `warning[code]:` prefix at the start of a line counts. A tree line or
/// a sentence mentioning a warning must not register, or the summary overstates
/// what happened and stops being worth printing.
fn warning_code(line: &str) -> Option<String> {
    let rest = line.strip_prefix("warning[")?;
    let (code, after) = rest.split_once(']')?;
    (after.starts_with(':') && !code.is_empty()).then(|| code.to_string())
}

/// Whether the line opens a warning diagnostic.
fn is_warning(line: &str) -> bool {
    warning_code(line).is_some()
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

    #[test]
    fn warnings_are_counted_by_code() {
        let counts = count_warnings(STDERR);
        assert_eq!(
            counts,
            vec![
                ("duplicate".to_string(), 2),
                ("license-exception-not-encountered".to_string(), 2),
                ("no-license-field".to_string(), 1),
            ],
            "most frequent first, then alphabetical, so the order is stable"
        );
        assert_eq!(total(&counts), 5);
    }

    #[test]
    fn only_the_diagnostic_prefix_counts() {
        // A tree line or a sentence mentioning a warning must not inflate the
        // total, or the summary stops being trustworthy.
        let counts = count_warnings("a warning[thing] mid-sentence\n  └── warning[x]: nested\n");
        assert!(counts.is_empty(), "got {counts:?}");
    }

    #[test]
    fn colour_codes_do_not_hide_a_warning() {
        let counts = count_warnings("\u{1b}[33mwarning\u{1b}[0m[duplicate]: found 2\n");
        assert_eq!(counts, vec![("duplicate".to_string(), 1)]);
    }

    #[test]
    fn nothing_to_report_renders_nothing() {
        assert!(render_summary(&[]).is_none());
    }

    #[test]
    fn the_warning_headlines_are_listed_without_their_trees() {
        // -v wants to know WHICH warnings, not the several thousand lines of
        // dependency tree that justify them.
        let lines = warning_lines(STDERR);
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
        let counts = count_warnings(STDERR);
        assert!(enforce(&counts, false).is_ok(), "reporting is the default");
        assert!(enforce(&[], true).is_ok(), "nothing to deny");
        let err = enforce(&counts, true).unwrap_err().to_string();
        assert!(err.contains('5'), "names the count: {err}");
    }

    #[test]
    fn the_summary_gives_the_total_and_the_codes() {
        let out = render_summary(&count_warnings(STDERR)).expect("warnings present");
        assert!(out.contains('5'), "the total: {out}");
        assert!(out.contains("duplicate"), "{out}");
        assert!(
            out.contains("-v to list") && out.contains("-vv"),
            "must say how to reach both levels of detail: {out}"
        );
    }
}
