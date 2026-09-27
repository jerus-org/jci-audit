//! Single-thread tokio runtime idiom shared by every synchronous-facing
//! wrapper around an async client (jerus-org/jci-audit#235). Each caller
//! needs the same shape — build a `current_thread` runtime once, reuse it
//! for every `block_on` call rather than paying setup/teardown per call
//! (jerus-org/jci-audit#111) — previously duplicated byte-for-byte across
//! [`crate::remote::ManifestPubkeySource`], [`crate::remote::PcuAssetSource`],
//! and [`crate::publish_record::PcuAssetWriter`].

use anyhow::{Context, Result};

/// Owns a `current_thread` tokio runtime and exposes a blocking call
/// surface for it. One instance per caller, built once and reused across
/// every [`Self::block_on`] call.
pub(crate) struct SingleThreadRuntime {
    runtime: tokio::runtime::Runtime,
}

impl SingleThreadRuntime {
    /// `context` names what the runtime is for, e.g. `"the manifest
    /// fetch"` — folded into the error message on build failure, matching
    /// each call site's previous wording.
    pub(crate) fn new(context: &str) -> Result<Self> {
        Ok(Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .with_context(|| format!("failed to start an async runtime for {context}"))?,
        })
    }

    pub(crate) fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.runtime.block_on(fut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_on_runs_a_future_to_completion() {
        let rt = SingleThreadRuntime::new("a test").expect("runtime should build");

        let result = rt.block_on(async { 1 + 1 });

        assert_eq!(result, 2);
    }

    #[test]
    fn block_on_reuses_the_same_runtime_across_calls() {
        let rt = SingleThreadRuntime::new("a test").expect("runtime should build");

        let id1 = rt.block_on(async { tokio::runtime::Handle::current().id() });
        let id2 = rt.block_on(async { tokio::runtime::Handle::current().id() });

        assert_eq!(id1, id2);
    }

    // `new`'s context-message-on-build-failure path has no test:
    // `Builder::build()` only fails on OS resource exhaustion, which isn't
    // forceable from a normal test environment. A test asserting on
    // `format!(...)` directly wouldn't exercise this module at all, so it's
    // omitted rather than faked.
}
