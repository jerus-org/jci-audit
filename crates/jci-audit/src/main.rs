use anyhow::Result;
use clap::Parser;
use jci_audit::Cli;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> Result<()> {
    // tracing_subscriber::registry().init() wires LogTracer automatically when
    // the tracing-log feature is active; calling LogTracer::init() manually
    // beforehand would panic with SetLoggerError.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "jci_audit=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    cli.run()
}
