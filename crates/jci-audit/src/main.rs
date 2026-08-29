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

fn main() -> Result<()> {
    // Parse first: -v/-q set the level, so the subscriber cannot be built until
    // the arguments are known. RUST_LOG still wins where it is set.
    let cli = Cli::parse();

    // tracing_subscriber::registry().init() wires LogTracer automatically when
    // the tracing-log feature is active; calling LogTracer::init() manually
    // beforehand would panic with SetLoggerError.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("jci_audit={}", cli.logging.tracing_level_filter()).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    cli.run()
}
