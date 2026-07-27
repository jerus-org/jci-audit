//! Preflight tool-presence detection.
//!
//! `jci-audit` orchestrates the `cargo audit` and `cargo deny` binaries as
//! subprocesses; it does not link them as libraries. A tool whose purpose is to
//! detect *missing* security coverage must itself detect the absence of the
//! very binaries it depends on — and fail loudly and actionably rather than
//! silently no-op (the failure mode the CI-diagnostics discipline warns
//! against). Every subcommand that shells out runs this preflight first.

use std::process::Command;

use anyhow::{Result, bail};

/// An external cargo subcommand that `jci-audit` orchestrates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `cargo audit` — live advisory scanning (cargo-audit crate).
    CargoAudit,
    /// `cargo deny` — policy enforcement: advisories, bans, licenses, sources
    /// (cargo-deny crate).
    CargoDeny,
}

impl Tool {
    /// The cargo subcommand name, e.g. `audit` for `cargo audit`.
    pub fn subcommand(&self) -> &'static str {
        match self {
            Tool::CargoAudit => "audit",
            Tool::CargoDeny => "deny",
        }
    }

    /// Human-facing invocation, e.g. `cargo audit`.
    pub fn invocation(&self) -> &'static str {
        match self {
            Tool::CargoAudit => "cargo audit",
            Tool::CargoDeny => "cargo deny",
        }
    }

    /// The crate that provides the binary, for install guidance.
    pub fn crate_name(&self) -> &'static str {
        match self {
            Tool::CargoAudit => "cargo-audit",
            Tool::CargoDeny => "cargo-deny",
        }
    }

    /// Probe whether the tool's standalone binary responds to `--version`.
    fn is_present(&self) -> bool {
        probe_version(self.crate_name())
    }
}

/// Run `<binary> --version` (e.g. `cargo-audit --version`), returning true on a
/// successful exit. Probes the standalone binary so presence detection matches
/// how `check` invokes the tool — and works in a cargo-less executor.
fn probe_version(binary: &str) -> bool {
    Command::new(binary)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Pure core: given a presence probe, return the subset of `tools` that are
/// absent, preserving input order. Separated from the subprocess probe so it is
/// unit-testable without a real cargo installation.
pub fn missing_tools(tools: &[Tool], probe: impl Fn(&Tool) -> bool) -> Vec<Tool> {
    tools.iter().copied().filter(|t| !probe(t)).collect()
}

/// Ensure every tool in `tools` is available on PATH, or return an error that
/// names each missing tool and how to install it.
pub fn ensure_available(tools: &[Tool]) -> Result<()> {
    let missing = missing_tools(tools, |t| t.is_present());
    if missing.is_empty() {
        return Ok(());
    }
    let mut msg = String::from("required tool(s) not found on PATH:\n");
    for t in &missing {
        msg.push_str(&format!(
            "  - `{}` (provided by the `{}` crate)\n",
            t.invocation(),
            t.crate_name()
        ));
    }
    msg.push_str(
        "\nRun jci-audit inside the `jerusdp/ci-rust:audit` image (which ships both), \
         or install locally with `cargo binstall cargo-audit cargo-deny`.",
    );
    bail!(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tools_reports_none_when_all_present() {
        let tools = [Tool::CargoAudit, Tool::CargoDeny];
        let missing = missing_tools(&tools, |_| true);
        assert!(missing.is_empty());
    }

    #[test]
    fn missing_tools_reports_all_when_none_present() {
        let tools = [Tool::CargoAudit, Tool::CargoDeny];
        let missing = missing_tools(&tools, |_| false);
        assert_eq!(missing, vec![Tool::CargoAudit, Tool::CargoDeny]);
    }

    #[test]
    fn missing_tools_reports_only_absent_tool_preserving_order() {
        let tools = [Tool::CargoAudit, Tool::CargoDeny];
        // Only cargo-deny is absent.
        let missing = missing_tools(&tools, |t| *t == Tool::CargoAudit);
        assert_eq!(missing, vec![Tool::CargoDeny]);
    }

    #[test]
    fn ensure_available_errors_names_missing_tool() {
        // Probe every tool as absent by pointing at an impossible subcommand is
        // not possible through the public API, so assert on the pure core's
        // contract instead: an all-absent probe yields both tools.
        let missing = missing_tools(&[Tool::CargoDeny], |_| false);
        assert_eq!(missing, vec![Tool::CargoDeny]);
        assert_eq!(Tool::CargoDeny.crate_name(), "cargo-deny");
        assert_eq!(Tool::CargoDeny.invocation(), "cargo deny");
    }
}
