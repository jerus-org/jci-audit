//! # jci-audit
//!
//! A context-aware Rust security gate that orchestrates
//! [`cargo-audit`](https://crates.io/crates/cargo-audit) and
//! [`cargo-deny`](https://crates.io/crates/cargo-deny), leveraging the
//! complementary strengths of each:
//!
//! - **`cargo audit`** — fresh, *live* advisories from the RustSec database.
//! - **`cargo deny`** — policy enforcement (advisories, bans, licenses,
//!   sources) with **file-based** ignores that carry written justifications.
//!
//! `deny.toml` is the single source of truth for both advisory ignores and
//! license policy; `.cargo/audit.toml` and every crate's `about.toml` are
//! derived from it via `jci-audit sync`. Release validation is
//! **reproducible**: `cargo deny` locks to a pinned advisory-db commit and
//! runs offline; `cargo audit` keeps running live, as a non-blocking
//! currency check.
//!
//! `jci-audit` shells out to the `cargo audit` and `cargo deny` binaries; it
//! does not reimplement them. See [`preflight`] for the presence check every
//! shelling subcommand runs first.

pub mod check;
pub mod diagnostics;
pub mod init;
pub mod license_scope;
pub mod preflight;
pub mod prune;
pub mod release;
pub mod sync;
pub mod verify;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use crate::preflight::Tool;

/// Context-aware Rust security gate over cargo-audit and cargo-deny.
#[derive(Debug, Parser)]
#[command(name = "jci-audit")]
#[command(
    author,
    version,
    about,
    long_about = "Orchestrate cargo-audit and cargo-deny per pipeline context. \
        `check` gates PRs on both tools; `release` validates reproducibly \
        against a pinned advisory-db; `sync` derives .cargo/audit.toml from the \
        canonical deny.toml; `prune` detects stale advisory ignores; `init` \
        scaffolds a standard deny.toml."
)]
pub struct Cli {
    #[command(flatten)]
    pub logging: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,

    #[command(subcommand)]
    command: Commands,
}

/// Flags shared by the subcommands that run cargo-deny / cargo-audit.
#[derive(Debug, clap::Args)]
struct ToolOutput {
    /// Fail if the tools report any warning.
    #[arg(long)]
    deny_warnings: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// PR/dev gate: cargo-deny policy plus a live cargo-audit scan.
    ///
    /// Both blocking. Aggregates exit codes and surfaces stderr.
    Check {
        /// Path to the Cargo.toml (or its directory) to check.
        #[arg(long, default_value = ".")]
        manifest_path: std::path::PathBuf,

        #[command(flatten)]
        output: ToolOutput,
    },
    /// Release gate: reproducible, pinned-advisory-db validation.
    ///
    /// Locks `cargo-deny` to the pinned commit and runs it offline;
    /// `cargo-audit` runs live as a non-blocking currency check. Writes the
    /// record locally to `.security/release-<VERSION>.json`; see
    /// jerus-org/jci-audit#75 for how it is distributed from there.
    Release {
        /// The release version being validated (e.g. "1.2.0").
        ///
        /// Falls back to an environment variable when omitted, since release
        /// pipelines compute the version at runtime.
        #[arg(long, value_name = "VERSION")]
        release_version: Option<String>,

        /// Env var NAME holding the release version (default SEMVER).
        ///
        /// Used when --release-version is not given.
        #[arg(long)]
        version_env: Option<String>,

        /// Advisory-db root; cargo-deny's checkout lives beneath it.
        ///
        /// Its commit becomes the pin. Defaults to ~/.cargo/advisory-db.
        #[arg(long)]
        advisory_db: Option<std::path::PathBuf>,

        #[command(flatten)]
        output: ToolOutput,
    },
    /// Derive `.cargo/audit.toml` from the canonical `deny.toml`.
    ///
    /// Reads `[advisories].ignore`, keeping deny.toml the single source of
    /// truth.
    Sync {
        /// Fail (non-zero) on drift instead of rewriting the file. For CI.
        #[arg(long)]
        check: bool,
    },
    /// Stale-ignore detector for advisory ignores that no longer fire.
    ///
    /// Runs audit/deny against the naked advisory-db (no local ignores
    /// applied) to find configured ignores that no longer fire.
    Prune {
        /// Fail (non-zero) when a stale ignore is found. For CI.
        #[arg(long)]
        check: bool,
    },
    /// Re-verify a past release against its recorded advisory snapshot.
    ///
    /// Uses the policy (deny.toml) that was in force at the time. Run it
    /// from a checkout of the released tag.
    Verify {
        /// The released version to verify (e.g. "1.2.0").
        #[arg(long, value_name = "VERSION")]
        release_version: String,

        /// Advisory-db root; the checkout is moved to the recorded commit.
        ///
        /// Defaults to ~/.cargo/advisory-db.
        #[arg(long)]
        advisory_db: Option<std::path::PathBuf>,

        #[command(flatten)]
        output: ToolOutput,
    },
    /// Scaffold a standard `deny.toml` and its derived `.cargo/audit.toml`.
    ///
    /// Non-interactive — every value in the template is fixed; edit the
    /// written files afterwards for anything project-specific.
    Init {
        /// Overwrite existing files without confirmation.
        #[arg(long)]
        force: bool,
    },
}

impl Cli {
    /// How much of the tools' output to show, from the logging level.
    fn detail(&self) -> diagnostics::Detail {
        diagnostics::Detail::from_level(self.logging.tracing_level_filter())
    }

    /// Execute the selected subcommand.
    pub fn run(&self) -> Result<()> {
        let detail = self.detail();
        match &self.command {
            Commands::Check {
                manifest_path,
                output,
            } => run_check(manifest_path, output, detail),
            Commands::Release {
                release_version,
                version_env,
                advisory_db,
                output,
            } => {
                let version = release::resolve_version(
                    release_version.as_deref(),
                    version_env
                        .as_deref()
                        .unwrap_or(release::DEFAULT_VERSION_ENV),
                )?;
                run_release(&version, advisory_db.as_deref(), output, detail)
            }
            Commands::Sync { check } => run_sync(*check),
            Commands::Prune { check } => run_prune(*check),
            Commands::Verify {
                release_version,
                advisory_db,
                output,
            } => run_verify(release_version, advisory_db.as_deref(), output, detail),
            Commands::Init { force } => run_init(*force),
        }
    }
}

fn run_check(
    manifest_path: &std::path::Path,
    output: &ToolOutput,
    detail: diagnostics::Detail,
) -> Result<()> {
    // Tool::Cargo: the about.toml step shells out to `cargo metadata` per
    // crate, unlike the other two (standalone binaries, work cargo-less).
    preflight::ensure_available(&[Tool::CargoDeny, Tool::CargoAudit, Tool::Cargo])?;
    tracing::info!(?manifest_path, "check");
    let report = check::check_with(&check::SystemRunner, manifest_path, detail)?;
    diagnostics::enforce(&report.warnings, output.deny_warnings)?;
    if report.success() {
        println!("security check passed (cargo deny + cargo audit)");
        Ok(())
    } else {
        bail!("security check failed: {}", report.failures().join(", "))
    }
}

fn run_release(
    version: &str,
    advisory_db: Option<&std::path::Path>,
    output: &ToolOutput,
    detail: diagnostics::Detail,
) -> Result<()> {
    // cargo-about and (bare) cargo are only needed for the license-policy
    // checks, but release_with always runs them unconditionally alongside
    // deny/audit — so a missing one fails loudly here rather than as a raw
    // subprocess-spawn error partway through the gate.
    preflight::ensure_available(&[
        Tool::CargoDeny,
        Tool::CargoAudit,
        Tool::CargoAbout,
        Tool::Cargo,
    ])?;
    let cwd = std::env::current_dir()?;
    let db_root = advisory_db
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(release::default_db_root);
    // The derived cargo-deny config is ephemeral: deny.toml stays the single
    // source of truth, so nothing derived persists beyond this run except the
    // record itself, written locally only (see jerus-org/jci-audit#75 for how
    // it's distributed from there).
    let work = release::work_dir();
    tracing::info!(version, db = %db_root.display(), "release");

    let outcome =
        release::release_with(&check::SystemRunner, &cwd, version, &db_root, &work, detail);
    let _ = std::fs::remove_dir_all(&work);
    let outcome = outcome?;

    println!("release gate passed (cargo-deny against the local advisory-db copy)");
    println!("  advisory-db commit: {}", outcome.db_commit);
    println!("  record: {}", outcome.record_path.display());
    if outcome.live_findings.is_empty() {
        println!("  live audit (currency, non-blocking): no findings");
    } else {
        println!(
            "  live audit (currency, non-blocking) reported {} advisory(ies):",
            outcome.live_findings.len()
        );
        for id in &outcome.live_findings {
            println!("    - {id}");
        }
    }

    diagnostics::enforce(&outcome.warnings, output.deny_warnings)
}

/// Print one derived file's sync outcome and report whether it drifted.
/// `.cargo/audit.toml` and each crate's `about.toml` differ only in their
/// path and what a `Wrote` count means (`noun`), so `run_sync` shares this
/// rather than repeating the match per file.
fn report_sync_outcome(path: &str, outcome: &sync::SyncOutcome, noun: &str) -> bool {
    match outcome {
        sync::SyncOutcome::InSync => {
            println!("{path} is in sync with deny.toml");
            false
        }
        sync::SyncOutcome::Wrote(n) => {
            println!("wrote {path} ({n} {noun}) derived from deny.toml");
            false
        }
        sync::SyncOutcome::Drift => {
            eprintln!("{path} is out of sync with deny.toml");
            true
        }
    }
}

fn run_sync(check: bool) -> Result<()> {
    // The about.toml half shells out to `cargo metadata` per crate.
    preflight::ensure_available(&[Tool::Cargo])?;
    let cwd = std::env::current_dir()?;
    tracing::info!(check, dir = %cwd.display(), "sync");

    let mut drifted = report_sync_outcome(
        ".cargo/audit.toml",
        &sync::sync_at(&cwd, check)?,
        "ignore(s)",
    );

    let about_results = sync::sync_about_toml_at(&check::SystemRunner, &cwd, check)?;
    for result in &about_results {
        let path = result.about_toml_path.display().to_string();
        drifted |= report_sync_outcome(&path, &result.outcome, "accepted licence(s)");
    }

    if drifted {
        bail!(
            "one or more files are out of sync with deny.toml — run `jci-audit sync` to regenerate"
        );
    }
    Ok(())
}

fn run_prune(check: bool) -> Result<()> {
    // Only cargo-audit is shelled out to: the naked probe reads the advisory
    // database directly, and cargo-deny would apply deny.toml's own ignores.
    preflight::ensure_available(&[Tool::CargoAudit])?;
    let cwd = std::env::current_dir()?;
    tracing::info!(check, dir = %cwd.display(), "prune");

    // The naked run needs a working directory outside the repository, or cargo
    // discovers the repo's .cargo/audit.toml and applies the very suppressions
    // being tested.
    let naked_cwd = prune::naked_run_dir();
    std::fs::create_dir_all(&naked_cwd)?;
    let report = prune::prune_with(&check::SystemRunner, &cwd, &naked_cwd)?;
    let _ = std::fs::remove_dir_all(&naked_cwd);

    println!(
        "{} configured ignore(s); {} advisory(ies) firing against the naked database",
        report.configured.len(),
        report.firing.len()
    );
    if report.is_clean() {
        println!("no stale ignores — every configured ignore still fires");
        return Ok(());
    }
    println!("stale ignore(s) — no longer fire, remove from deny.toml:");
    for id in &report.stale {
        println!("  - {id}");
    }
    if check {
        bail!("{} stale ignore(s) found", report.stale.len())
    }
    Ok(())
}

fn run_verify(
    version: &str,
    advisory_db: Option<&std::path::Path>,
    output: &ToolOutput,
    detail: diagnostics::Detail,
) -> Result<()> {
    preflight::ensure_available(&[Tool::CargoDeny])?;
    let cwd = std::env::current_dir()?;
    let db_root = advisory_db
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(release::default_db_root);
    let work = release::work_dir();
    tracing::info!(version, db = %db_root.display(), "verify");

    let outcome = verify::verify_with(&check::SystemRunner, &cwd, version, &db_root, &work, detail);
    let _ = std::fs::remove_dir_all(&work);
    let outcome = outcome?;

    println!(
        "verifying release {} against advisory-db {}",
        outcome.version, outcome.db_commit
    );
    for note in &outcome.unverified {
        println!("  not verified: {note}");
    }
    for m in &outcome.mismatches {
        println!("  MISMATCH: {m}");
    }
    if outcome.is_ok() {
        println!("reproduced: the release passes the gate against its recorded snapshot");
        diagnostics::enforce(&outcome.warnings, output.deny_warnings)
    } else if !outcome.mismatches.is_empty() {
        bail!("verification failed: inputs do not match the record")
    } else {
        bail!("verification failed: the gate did not reproduce the recorded verdict")
    }
}

fn run_init(force: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    tracing::info!(force, dir = %cwd.display(), "init");
    init::init_at(&cwd, force)?;
    println!("wrote deny.toml and derived .cargo/audit.toml");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_check_defaults_manifest_to_cwd() {
        let cli = Cli::try_parse_from(["jci-audit", "check"]).expect("check parses");
        assert!(
            cli.detail() == diagnostics::Detail::Summary,
            "the tools' full output is opt-in"
        );
        match cli.command {
            Commands::Check {
                manifest_path,
                output,
            } => {
                assert_eq!(manifest_path, std::path::PathBuf::from("."));
                assert!(!output.deny_warnings, "warnings are reported, not fatal");
            }
            other => panic!("expected Check, got {other:?}"),
        }
    }

    #[test]
    fn verbosity_flags_control_the_tools_detail() {
        // -v reaches the tools' output; the default and -q stay above it. Uses the
        // organisation's clap-verbosity-flag, so -q/-vv behave as in the sibling
        // CLIs rather than being a local invention.
        let quiet = Cli::try_parse_from(["jci-audit", "-q", "check"]).expect("parses");
        let default = Cli::try_parse_from(["jci-audit", "check"]).expect("parses");
        let verbose = Cli::try_parse_from(["jci-audit", "-v", "check"]).expect("parses");
        assert_eq!(quiet.detail(), diagnostics::Detail::Summary);
        assert_eq!(default.detail(), diagnostics::Detail::Summary);
        assert_eq!(verbose.detail(), diagnostics::Detail::List);
    }

    #[test]
    fn release_version_is_optional_at_parse_time() {
        // Release pipelines compute the version at runtime, so it is resolved
        // from the environment rather than being required on the command line.
        assert!(Cli::try_parse_from(["jci-audit", "release"]).is_ok());
        let cli = Cli::try_parse_from(["jci-audit", "release", "--release-version", "1.2.0"])
            .expect("parses");
        match cli.command {
            Commands::Release {
                release_version, ..
            } => assert_eq!(release_version.as_deref(), Some("1.2.0")),
            other => panic!("expected Release, got {other:?}"),
        }

        // --version is the tool's own version, and must stay that way: naming the
        // release version the same thing made one flag mean two things depending
        // on where it sat.
        let err = Cli::try_parse_from(["jci-audit", "release", "--version", "1.2.0"]).unwrap_err();
        assert!(
            !err.to_string().contains("1.2.0"),
            "--version must not be taken as a release version: {err}"
        );
    }

    #[test]
    fn commit_and_push_flags_are_gone() {
        // The record is no longer committed to git (jerus-org/jci-audit#75);
        // these flags must not silently resurrect as unused no-ops.
        for args in [
            vec!["jci-audit", "release", "--commit"],
            vec!["jci-audit", "release", "--push"],
            vec!["jci-audit", "release", "--gpg-key-env", "X"],
            vec!["jci-audit", "release", "--gpg-trust-env", "X"],
            vec!["jci-audit", "release", "--user-name-env", "X"],
            vec!["jci-audit", "release", "--user-email-env", "X"],
            vec!["jci-audit", "release", "--sign-key-env", "X"],
        ] {
            assert!(
                Cli::try_parse_from(&args).is_err(),
                "{args:?} must be rejected"
            );
        }
    }

    #[test]
    fn parse_sync_check_flag() {
        let cli = Cli::try_parse_from(["jci-audit", "sync", "--check"]).expect("parses");
        match cli.command {
            Commands::Sync { check } => assert!(check),
            other => panic!("expected Sync, got {other:?}"),
        }
    }

    #[test]
    fn parse_prune_and_init() {
        assert!(Cli::try_parse_from(["jci-audit", "prune"]).is_ok());
        assert!(Cli::try_parse_from(["jci-audit", "init", "--force"]).is_ok());
    }

    #[test]
    fn every_subcommand_has_a_long_about_distinct_from_its_about() {
        // A doc comment without a blank-line split leaves long_about unset,
        // so clap falls back to `about` for --help too, matching -h exactly.
        // Checking rendered `-h`/`--help` byte length is not a reliable
        // proxy: clap's argument-table wrapping alone can make --help
        // render longer even when about == long_about, letting this pass
        // for a subcommand whose split is missing (caught in review on #74).
        use clap::CommandFactory;
        let cmd = Cli::command();
        for name in ["check", "release", "sync", "prune", "verify", "init"] {
            let sub = cmd
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("no '{name}' subcommand"));
            let about = sub.get_about().map(ToString::to_string);
            let long_about = sub.get_long_about().map(ToString::to_string);
            assert!(
                long_about.is_some() && long_about != about,
                "'{name}': long_about must be set and differ from about (about: {about:?})"
            );
        }
    }

    #[test]
    fn unknown_subcommand_is_error() {
        assert!(Cli::try_parse_from(["jci-audit", "bogus"]).is_err());
    }
}
