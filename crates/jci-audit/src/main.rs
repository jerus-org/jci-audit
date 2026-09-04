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
//!
//! Published as a **bin-only** crate — deliberately no importable library
//! (see [jerus-org/jci-audit#90](https://github.com/jerus-org/jci-audit/issues/90)).

mod check;
mod cli;
mod diagnostics;
mod exceptions;
mod init;
mod license_scope;
mod preflight;
mod prune;
mod publish_record;
mod release;
mod remote;
mod sync;
mod verify;

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Resolve the tracing filter directive: `RUST_LOG` wins when it is set to a
/// non-empty value; a set-but-empty `RUST_LOG` (a blank pipeline parameter, a
/// leftover export from another tool in the same shell/job) is treated the
/// same as unset, falling back to the `-v`/`-q`-derived level instead.
/// `EnvFilter::try_from_default_env()` alone only treats "unset" as absent —
/// set-but-empty succeeds with a match-nothing filter, silencing all logging
/// with no error and no indication anything changed
/// (jerus-org/jci-audit#86). A pure function, not read from the environment
/// directly, so it's unit-testable without the flakiness real env-var
/// mutation brings under a parallel test runner.
fn resolve_log_filter(rust_log: Option<&str>, derived: &str) -> String {
    match rust_log {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => derived.to_string(),
    }
}

fn main() -> Result<()> {
    // Parse first: -v/-q set the level, so the subscriber cannot be built until
    // the arguments are known. RUST_LOG still wins where it is set.
    let cli = Cli::parse();

    let derived = format!("jci_audit={}", cli.logging.tracing_level_filter());
    let filter = resolve_log_filter(std::env::var("RUST_LOG").ok().as_deref(), &derived);

    // tracing_subscriber::registry().init() wires LogTracer automatically when
    // the tracing-log feature is active; calling LogTracer::init() manually
    // beforehand would panic with SetLoggerError.
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(filter))
        .with(tracing_subscriber::fmt::layer())
        .init();

    cli.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_rust_log_falls_back_to_the_derived_filter() {
        assert_eq!(resolve_log_filter(None, "jci_audit=info"), "jci_audit=info");
    }

    #[test]
    fn empty_rust_log_falls_back_to_the_derived_filter() {
        // The exact bug from jerus-org/jci-audit#86: RUST_LOG="" must behave
        // like unset, not like a deliberate match-nothing filter.
        assert_eq!(
            resolve_log_filter(Some(""), "jci_audit=info"),
            "jci_audit=info"
        );
    }

    #[test]
    fn a_non_empty_rust_log_wins_over_the_derived_filter() {
        assert_eq!(resolve_log_filter(Some("debug"), "jci_audit=info"), "debug");
    }

    #[test]
    fn a_non_empty_rust_log_is_passed_through_verbatim() {
        assert_eq!(
            resolve_log_filter(Some("jci_audit=warn,other=trace"), "jci_audit=info"),
            "jci_audit=warn,other=trace"
        );
    }
}
