use anyhow::Result;
use clap::Parser;
use jci_audit::Cli;
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
