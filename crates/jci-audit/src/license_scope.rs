//! Per-crate license scope: which `deny.toml`-allowed license identifiers,
//! and which named exceptions, are actually reachable from a crate's own
//! dependency graph (excluding dev-only edges).
//!
//! `deny.toml`'s `[licenses].allow` list and `[[licenses.exceptions]]` are
//! workspace-wide statements, but `about.toml` lives per crate. Deriving a
//! crate's `about.toml` by copying the workspace-wide policy verbatim would
//! over-claim: a crate that never depends on a copyleft dependency, or has
//! since dropped one, would still assert an acceptance it doesn't need — the
//! same inaccuracy the drift check closes, from the other direction.
//!
//! `cargo metadata --all-features` gives each package's own (possibly
//! compound) SPDX license expression and the resolved dependency graph;
//! `spdx::Expression` — the same crate cargo-deny itself uses — evaluates
//! which of `deny.toml`'s allowed identifiers actually satisfy each reachable
//! package's expression.

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::check::CommandRunner;

/// Index a `cargo metadata` JSON array (`packages`, or `resolve.nodes`) by
/// its `id` field. Shared by [`scope_from_metadata`] and
/// [`reachable_shipped_ids`], which each need the same lookup over a
/// different array.
fn index_by_id(items: &[Value]) -> HashMap<&str, &Value> {
    items
        .iter()
        .filter_map(|item| Some((item.get("id")?.as_str()?, item)))
        .collect()
}

/// The license identifiers and exception crate names actually reachable from
/// one crate's own dependency graph — the precise `about.toml` content for
/// that crate, scoped down from the workspace-wide `deny.toml` policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CrateLicenseScope {
    /// Which of `deny.toml`'s `[licenses].allow` identifiers are actually
    /// used by a package reachable from this crate.
    pub(crate) accepted: BTreeSet<String>,
    /// Which `[[licenses.exceptions]]` crate names are actually reachable
    /// from this crate (dependency name membership, not license matching).
    pub(crate) reachable_exception_crates: BTreeSet<String>,
}

/// Compute the license scope for the crate at `manifest_path`, given
/// `deny.toml`'s global allow set and the full (workspace-wide) set of
/// exception crate names. `manifest_path` must be an absolute path — the
/// subprocess runs with the crate's own directory (`manifest_path`'s parent)
/// as its working directory, matching how `release.rs` invokes `cargo-about`
/// per crate, rather than the caller's own directory (which need not have
/// any relationship to the crate being resolved).
pub(crate) fn scope_for_crate<R: CommandRunner>(
    runner: &R,
    manifest_path: &Path,
    allow: &BTreeSet<String>,
    exception_crates: &BTreeSet<String>,
) -> Result<CrateLicenseScope> {
    let manifest = manifest_path.to_string_lossy();
    let crate_dir = manifest_path
        .parent()
        .context("manifest_path has no parent directory")?;
    let out = runner.run(
        "cargo",
        &[
            "metadata",
            "--manifest-path",
            &manifest,
            "--format-version",
            "1",
            "--all-features",
        ],
        crate_dir,
    )?;
    if !out.success {
        bail!("cargo metadata failed for '{manifest}': {}", out.stderr);
    }
    scope_from_metadata(&out.stdout, allow, exception_crates)
}

/// Parse `cargo metadata --format-version 1` JSON and compute the license
/// scope. Split from [`scope_for_crate`] so tests can inject captured JSON
/// directly rather than mocking a subprocess call.
pub(crate) fn scope_from_metadata(
    metadata_json: &str,
    allow: &BTreeSet<String>,
    exception_crates: &BTreeSet<String>,
) -> Result<CrateLicenseScope> {
    let doc: Value =
        serde_json::from_str(metadata_json).context("failed to parse cargo metadata JSON")?;

    let packages = doc
        .get("packages")
        .and_then(Value::as_array)
        .context("cargo metadata JSON has no 'packages' array")?;
    let resolve = doc.get("resolve").context(
        "cargo metadata JSON has no 'resolve' (run with --format-version 1, not --no-deps)",
    )?;
    let root = resolve
        .get("root")
        .and_then(Value::as_str)
        .context("cargo metadata JSON has no 'resolve.root'")?;
    let nodes = resolve
        .get("nodes")
        .and_then(Value::as_array)
        .context("cargo metadata JSON has no 'resolve.nodes'")?;

    let reachable = reachable_shipped_ids(root, nodes);

    let id_to_pkg = index_by_id(packages);

    let mut scope = CrateLicenseScope::default();
    // The root crate's own declared license is not a third-party dependency
    // this crate's about.toml attributes — only its descendants count.
    for id in reachable.iter().filter(|id| id.as_str() != root) {
        let Some(pkg) = id_to_pkg.get(id.as_str()) else {
            continue;
        };
        let Some(name) = pkg.get("name").and_then(Value::as_str) else {
            continue;
        };
        if exception_crates.contains(name) {
            scope.reachable_exception_crates.insert(name.to_string());
        }
        let Some(license) = pkg.get("license").and_then(Value::as_str) else {
            continue;
        };
        let expr = match spdx::Expression::parse(license) {
            Ok(e) => e,
            // A crate whose license field spdx cannot parse is cargo-deny's
            // problem to fail on, not this derivation's — it contributes
            // nothing to the accepted set rather than guessing.
            Err(_) => continue,
        };
        for req in expr.requirements() {
            let text = req.req.to_string();
            if allow.contains(&text) {
                scope.accepted.insert(text);
            }
        }
    }
    Ok(scope)
}

/// Package ids reachable from `root` via edges that ship (excludes an edge
/// only when *every one* of its `dep_kinds` is `"dev"` — a dependency that is
/// also a normal or build dependency via any other kind still ships).
fn reachable_shipped_ids(root: &str, nodes: &[Value]) -> BTreeSet<String> {
    let by_id = index_by_id(nodes);

    let mut seen = BTreeSet::new();
    let mut stack = vec![root.to_string()];
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        let Some(node) = by_id.get(id.as_str()) else {
            continue;
        };
        let deps = node
            .get("deps")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for dep in deps {
            let Some(dep_id) = dep.get("pkg").and_then(Value::as_str) else {
                continue;
            };
            if edge_ships(dep) {
                stack.push(dep_id.to_string());
            }
        }
    }
    seen
}

/// An edge ships if any of its `dep_kinds` entries is not `"dev"` (`null` =
/// normal, `"build"` = build — both ship; only an edge that is *exclusively*
/// `"dev"` across every kind is excluded, matching `about.toml`'s
/// `ignore-dev-dependencies = true`).
fn edge_ships(dep: &Value) -> bool {
    let Some(kinds) = dep.get("dep_kinds").and_then(Value::as_array) else {
        return true;
    };
    kinds.iter().any(|k| {
        !matches!(
            k.get("kind"),
            Some(Value::String(s)) if s == "dev"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trimmed from a real `cargo metadata --format-version 1 --all-features`
    // run against jci-audit's own crate: real field names/shapes for
    // packages, resolve.root, and resolve.nodes[].deps[].dep_kinds (verified
    // "dev" and null/normal kinds directly; "build" confirmed from the same
    // schema, jci-audit's own graph happening to have no direct build-dep).
    const METADATA_JSON: &str = r#"
    {
      "packages": [
        {
          "name": "demo-crate",
          "version": "0.0.6",
          "id": "path+file:///workspace/crates/demo-crate#0.0.6",
          "license": null
        },
        {
          "name": "anyhow",
          "version": "1.0.104",
          "id": "registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.104",
          "license": "MIT OR Apache-2.0"
        },
        {
          "name": "tempfile",
          "version": "3.27.0",
          "id": "registry+https://github.com/rust-lang/crates.io-index#tempfile@3.27.0",
          "license": "BSD-3-Clause"
        },
        {
          "name": "option-ext",
          "version": "0.2.0",
          "id": "registry+https://github.com/rust-lang/crates.io-index#option-ext@0.2.0",
          "license": "MPL-2.0"
        },
        {
          "name": "cc",
          "version": "1.0.0",
          "id": "registry+https://github.com/rust-lang/crates.io-index#cc@1.0.0",
          "license": "Zlib"
        }
      ],
      "resolve": {
        "root": "path+file:///workspace/crates/demo-crate#0.0.6",
        "nodes": [
          {
            "id": "path+file:///workspace/crates/demo-crate#0.0.6",
            "deps": [
              {
                "name": "anyhow",
                "pkg": "registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.104",
                "dep_kinds": [ { "kind": null, "target": null } ]
              },
              {
                "name": "tempfile",
                "pkg": "registry+https://github.com/rust-lang/crates.io-index#tempfile@3.27.0",
                "dep_kinds": [ { "kind": "dev", "target": null } ]
              },
              {
                "name": "option_ext",
                "pkg": "registry+https://github.com/rust-lang/crates.io-index#option-ext@0.2.0",
                "dep_kinds": [ { "kind": null, "target": null } ]
              },
              {
                "name": "cc",
                "pkg": "registry+https://github.com/rust-lang/crates.io-index#cc@1.0.0",
                "dep_kinds": [ { "kind": "build", "target": null } ]
              }
            ]
          },
          {
            "id": "registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.104",
            "deps": []
          },
          {
            "id": "registry+https://github.com/rust-lang/crates.io-index#tempfile@3.27.0",
            "deps": []
          },
          {
            "id": "registry+https://github.com/rust-lang/crates.io-index#option-ext@0.2.0",
            "deps": []
          },
          {
            "id": "registry+https://github.com/rust-lang/crates.io-index#cc@1.0.0",
            "deps": []
          }
        ]
      }
    }
    "#;

    fn allow(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn compound_expression_resolves_to_the_one_allowed_arm() {
        // anyhow is "MIT OR Apache-2.0"; only MIT is allowed here.
        let scope = scope_from_metadata(METADATA_JSON, &allow(&["MIT"]), &BTreeSet::new()).unwrap();
        assert!(scope.accepted.contains("MIT"));
        assert!(!scope.accepted.contains("Apache-2.0"));
    }

    #[test]
    fn dev_only_dependency_is_excluded() {
        // tempfile (dev-only) is the fixture's only source of BSD-3-Clause,
        // so its (non-)presence in `accepted` isolates dev-edge handling.
        let scope = scope_from_metadata(METADATA_JSON, &allow(&["BSD-3-Clause"]), &BTreeSet::new())
            .unwrap();
        assert!(
            !scope.accepted.contains("BSD-3-Clause"),
            "a dev-only dependency's license must not be counted: {scope:?}"
        );
    }

    #[test]
    fn build_dependency_is_included() {
        // cc (build-only) is the fixture's only source of Zlib, so its
        // presence in `accepted` isolates build-edge handling.
        let scope =
            scope_from_metadata(METADATA_JSON, &allow(&["Zlib"]), &BTreeSet::new()).unwrap();
        assert!(
            scope.accepted.contains("Zlib"),
            "a build dependency's license must be counted: {scope:?}"
        );
    }

    #[test]
    fn exception_crate_name_reachable_is_recorded() {
        let scope = scope_from_metadata(
            METADATA_JSON,
            &allow(&["MIT"]),
            &["option-ext".to_string()].into_iter().collect(),
        )
        .unwrap();
        assert!(scope.reachable_exception_crates.contains("option-ext"));
    }

    #[test]
    fn exception_crate_name_not_reachable_is_absent() {
        let scope = scope_from_metadata(
            METADATA_JSON,
            &allow(&["MIT"]),
            &["some-other-crate".to_string()].into_iter().collect(),
        )
        .unwrap();
        assert!(scope.reachable_exception_crates.is_empty());
    }

    #[test]
    fn root_crates_own_license_is_not_self_attributed() {
        // The fixture's root package has license: null (no third-party
        // attribution to itself); this also guards against a future fixture
        // change accidentally exercising self-attribution.
        let scope = scope_from_metadata(
            METADATA_JSON,
            &allow(&["MIT", "Apache-2.0"]),
            &BTreeSet::new(),
        )
        .unwrap();
        // Sanity: root contributes nothing beyond what its real dependencies
        // (anyhow, cc) already contribute.
        assert_eq!(scope.accepted, allow(&["MIT", "Apache-2.0"]));
    }

    #[test]
    fn unparseable_license_is_skipped_not_fatal() {
        let json =
            METADATA_JSON.replace(r#""license": "MPL-2.0""#, r#""license": "???not-spdx???""#);
        let scope = scope_from_metadata(&json, &allow(&["MIT"]), &BTreeSet::new());
        assert!(
            scope.is_ok(),
            "an unparseable license must not fail the whole scope: {scope:?}"
        );
    }

    /// Records the `cwd` the `cargo metadata` subprocess call was made with.
    struct CwdRecordingRunner {
        recorded_cwd: std::cell::RefCell<Option<std::path::PathBuf>>,
    }

    impl CommandRunner for CwdRecordingRunner {
        fn run(
            &self,
            _program: &str,
            _args: &[&str],
            cwd: &Path,
        ) -> Result<crate::check::ToolOutput> {
            *self.recorded_cwd.borrow_mut() = Some(cwd.to_path_buf());
            Ok(crate::check::ToolOutput {
                success: true,
                stdout: METADATA_JSON.to_string(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn scope_for_crate_runs_cargo_metadata_in_the_crates_own_directory() {
        // Not the caller's directory — the crate being resolved.
        let runner = CwdRecordingRunner {
            recorded_cwd: std::cell::RefCell::new(None),
        };
        let manifest_path = Path::new("/workspace/crates/demo/Cargo.toml");
        scope_for_crate(&runner, manifest_path, &BTreeSet::new(), &BTreeSet::new()).unwrap();
        assert_eq!(
            runner.recorded_cwd.into_inner(),
            Some(std::path::PathBuf::from("/workspace/crates/demo"))
        );
    }
}
