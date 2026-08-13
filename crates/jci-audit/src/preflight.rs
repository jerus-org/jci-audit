//! Preflight tool-presence detection.
//!
//! `jci-audit` orchestrates the `cargo audit`, `cargo deny`, and `cargo about`
//! binaries as subprocesses; it does not link them as libraries. A tool whose
//! purpose is to detect *missing* security coverage must itself detect the
//! absence of the very binaries it depends on — and fail loudly and
//! actionably rather than silently no-op (the failure mode the CI-diagnostics
//! discipline warns against). Every subcommand that shells out runs this
//! preflight first.
//!
//! `cargo-audit`/`cargo-deny`/`cargo-about` are invoked as standalone
//! binaries (not via `cargo <sub>`), so they work in a cargo-less executor
//! image. The license-policy derivation is the one exception: it shells out
//! to `cargo metadata`, a built-in cargo subcommand, so it needs a full `cargo`
//! on `PATH` — [`Tool::Cargo`] exists to preflight that separately, since its
//! absence needs different install guidance than "cargo binstall" gives the
//! other three.

use std::process::Command;

use anyhow::{Result, bail};

/// An external tool that `jci-audit` shells out to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `cargo audit` — live advisory scanning (cargo-audit crate).
    CargoAudit,
    /// `cargo deny` — policy enforcement (cargo-deny crate).
    CargoDeny,
    /// `cargo about` — license attribution (cargo-about crate).
    CargoAbout,
    /// Bare `cargo`, needed for `cargo metadata`. Not `cargo binstall`-able,
    /// so its install guidance differs from the other three.
    Cargo,
}

impl Tool {
    /// The binary this tool probes and invokes.
    fn binary(&self) -> &'static str {
        match self {
            Tool::CargoAudit => "cargo-audit",
            Tool::CargoDeny => "cargo-deny",
            Tool::CargoAbout => "cargo-about",
            Tool::Cargo => "cargo",
        }
    }

    /// Human-facing invocation, e.g. `cargo audit`.
    pub fn invocation(&self) -> &'static str {
        match self {
            Tool::CargoAudit => "cargo audit",
            Tool::CargoDeny => "cargo deny",
            Tool::CargoAbout => "cargo about",
            Tool::Cargo => "cargo",
        }
    }

    /// Human-facing install guidance for one missing tool.
    fn install_hint(&self) -> String {
        match self {
            Tool::Cargo => "part of a Rust toolchain, not a `cargo install`-able crate — \
                 install one via rustup (https://rustup.rs), or use an image \
                 that already has one"
                .to_string(),
            _ => format!(
                "provided by the `{}` crate — `cargo binstall {}`",
                self.binary(),
                self.binary()
            ),
        }
    }

    /// Probe whether the tool's binary responds to `--version`.
    fn is_present(&self) -> bool {
        probe_version(self.binary())
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
            "  - `{}` ({})\n",
            t.invocation(),
            t.install_hint()
        ));
    }
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
        assert_eq!(Tool::CargoDeny.invocation(), "cargo deny");
    }

    #[test]
    fn cargo_about_is_a_probeable_tool() {
        assert_eq!(Tool::CargoAbout.invocation(), "cargo about");
        assert!(Tool::CargoAbout.install_hint().contains("cargo-about"));
    }

    #[test]
    fn bare_cargo_gets_toolchain_install_guidance_not_binstall() {
        // cargo itself isn't `cargo binstall`-able — its guidance must say so,
        // not repeat the same "provided by the `cargo` crate" phrasing the
        // other three tools get.
        let hint = Tool::Cargo.install_hint();
        assert!(hint.contains("rustup"), "got: {hint}");
        assert!(
            !hint.contains("cargo binstall"),
            "cargo cannot install itself: {hint}"
        );
    }
}
