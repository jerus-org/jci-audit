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
//! `deny.toml` is the single source of truth for advisory ignores;
//! `.cargo/audit.toml` is derived from it via `jci-audit sync`. Release
//! validation is **reproducible**: it runs both tools offline against a pinned
//! advisory-db commit, then a live audit as a non-blocking warning.
//!
//! `jci-audit` shells out to the `cargo audit` and `cargo deny` binaries; it
//! does not reimplement them. See [`preflight`] for the presence check every
//! shelling subcommand runs first.

pub mod check;
pub mod init;
pub mod preflight;
pub mod prune;
pub mod sync;

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
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// PR / dev gate: run cargo-deny policy checks AND a live cargo-audit scan;
    /// both blocking. Aggregates exit codes and surfaces stderr.
    Check {
        /// Path to the Cargo.toml (or its directory) to check.
        #[arg(long, default_value = ".")]
        manifest_path: std::path::PathBuf,
    },
    /// Release gate: reproducible validation against a pinned advisory-db
    /// commit (deny + audit offline), then a non-blocking live audit. Records
    /// the run to `.security/release-<VERSION>.json`.
    Release {
        /// The release version being validated (e.g. "1.2.0").
        #[arg(long)]
        version: String,

        /// Path to a checked-out advisory-db at the pinned commit. When
        /// omitted, the pinned commit is resolved from configuration.
        #[arg(long)]
        advisory_db: Option<std::path::PathBuf>,
    },
    /// Derive `.cargo/audit.toml` from the canonical `deny.toml`
    /// `[advisories].ignore`. Makes deny.toml the single source of truth.
    Sync {
        /// Fail (non-zero) on drift instead of rewriting the file. For CI.
        #[arg(long)]
        check: bool,
    },
    /// Stale-ignore detector: run audit/deny against the naked advisory-db and
    /// report ignores that no longer fire.
    Prune {
        /// Fail (non-zero) when a stale ignore is found. For CI.
        #[arg(long)]
        check: bool,
    },
    /// Scaffold a standard `deny.toml` template and a derived
    /// `.cargo/audit.toml`.
    Init {
        /// Overwrite existing files without confirmation.
        #[arg(long)]
        force: bool,
    },
}

impl Cli {
    /// Execute the selected subcommand.
    pub fn run(&self) -> Result<()> {
        match &self.command {
            Commands::Check { manifest_path } => run_check(manifest_path),
            Commands::Release {
                version,
                advisory_db,
            } => run_release(version, advisory_db.as_deref()),
            Commands::Sync { check } => run_sync(*check),
            Commands::Prune { check } => run_prune(*check),
            Commands::Init { force } => run_init(*force),
        }
    }
}

fn run_check(manifest_path: &std::path::Path) -> Result<()> {
    preflight::ensure_available(&[Tool::CargoDeny, Tool::CargoAudit])?;
    tracing::info!(?manifest_path, "check");
    let report = check::check_with(&check::SystemRunner, manifest_path)?;
    if report.success() {
        println!("security check passed (cargo deny + cargo audit)");
        Ok(())
    } else {
        bail!("security check failed: {}", report.failures().join(", "))
    }
}

fn run_release(version: &str, advisory_db: Option<&std::path::Path>) -> Result<()> {
    preflight::ensure_available(&[Tool::CargoDeny, Tool::CargoAudit])?;
    tracing::info!(version, ?advisory_db, "release");
    bail!("`jci-audit release` is not yet implemented (P3)")
}

fn run_sync(check: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    tracing::info!(check, dir = %cwd.display(), "sync");
    match sync::sync_at(&cwd, check)? {
        sync::SyncOutcome::InSync => {
            println!(".cargo/audit.toml is in sync with deny.toml");
            Ok(())
        }
        sync::SyncOutcome::Wrote(n) => {
            println!("wrote .cargo/audit.toml ({n} ignore(s)) derived from deny.toml");
            Ok(())
        }
        sync::SyncOutcome::Drift => {
            bail!(
                ".cargo/audit.toml is out of sync with deny.toml — run `jci-audit sync` to regenerate"
            )
        }
    }
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
        match cli.command {
            Commands::Check { manifest_path } => {
                assert_eq!(manifest_path, std::path::PathBuf::from("."));
            }
            other => panic!("expected Check, got {other:?}"),
        }
    }

    #[test]
    fn parse_release_requires_version() {
        // Missing --version is a parse error.
        assert!(Cli::try_parse_from(["jci-audit", "release"]).is_err());
        let cli =
            Cli::try_parse_from(["jci-audit", "release", "--version", "1.2.0"]).expect("parses");
        match cli.command {
            Commands::Release { version, .. } => assert_eq!(version, "1.2.0"),
            other => panic!("expected Release, got {other:?}"),
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
    fn unknown_subcommand_is_error() {
        assert!(Cli::try_parse_from(["jci-audit", "bogus"]).is_err());
    }
}
