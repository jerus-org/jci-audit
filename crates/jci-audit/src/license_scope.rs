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

/// Which dependency-graph edges/depth a crate's `about.toml` says to include
/// when resolving its license scope — mirrors cargo-about's own
/// `ignore-dev-dependencies`/`ignore-build-dependencies`/
/// `ignore-transitive-dependencies` config fields
/// (jerus-org/jci-audit#63). cargo-about's real default for all three is
/// `false` (nothing excluded, full transitive walk) — the `Default` impl
/// here matches that, rather than the fixed "dev excluded, everything else
/// included" assumption this derivation used to hardcode regardless of what
/// a crate's own `about.toml` actually declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct DependencyScopePolicy {
    pub(crate) ignore_dev_dependencies: bool,
    pub(crate) ignore_build_dependencies: bool,
    pub(crate) ignore_transitive_dependencies: bool,
}

impl DependencyScopePolicy {
    /// The fixed policy [`reachable_dependency_versions`] (#62's per-crate
    /// dependency-digest scoping) has always used: dev-only edges excluded,
    /// everything else included, full transitive walk — "what actually
    /// ships to a consumer". Deliberately not derived from any crate's
    /// `about.toml`: that file's ignore flags are about license-notice
    /// scope, a different (if related) question from advisory/digest
    /// exposure.
    pub(crate) fn shipped() -> Self {
        Self {
            ignore_dev_dependencies: true,
            ignore_build_dependencies: false,
            ignore_transitive_dependencies: false,
        }
    }
}

/// Read the three cargo-about dependency-scope fields directly from a
/// crate's own `about.toml` content. A key that's simply absent defaults to
/// `false`, matching cargo-about's own default; unparseable TOML syntax also
/// falls back to all-`false` here — `merge_about_toml`'s own parse of the
/// same content is what surfaces *that* error to the caller, so this
/// derivation shouldn't fail twice over the same bad input. A key that IS
/// present but isn't a boolean (e.g. `ignore-dev-dependencies = "true"`,
/// a quoted string) is different: that content parses as valid TOML, so
/// `merge_about_toml` would never catch it, and silently treating it as
/// `false` would misrepresent a maintainer's explicit (if malformed) intent
/// — so this errors instead.
pub(crate) fn dependency_scope_policy_from_about_toml(
    content: &str,
) -> Result<DependencyScopePolicy> {
    let Ok(doc) = content.parse::<toml_edit::DocumentMut>() else {
        return Ok(DependencyScopePolicy::default());
    };
    let flag = |key: &str| -> Result<bool> {
        match doc.get(key) {
            None => Ok(false),
            Some(item) => item
                .as_bool()
                .with_context(|| format!("about.toml's '{key}' must be a boolean, found: {item}")),
        }
    };
    Ok(DependencyScopePolicy {
        ignore_dev_dependencies: flag("ignore-dev-dependencies")?,
        ignore_build_dependencies: flag("ignore-build-dependencies")?,
        ignore_transitive_dependencies: flag("ignore-transitive-dependencies")?,
    })
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
    policy: DependencyScopePolicy,
) -> Result<CrateLicenseScope> {
    let json = crate_metadata(runner, manifest_path)?;
    scope_from_metadata(&json, allow, exception_crates, policy)
}

/// Run `cargo metadata --all-features` scoped to one crate's own manifest,
/// from that crate's own directory — the raw JSON, shared by
/// [`scope_for_crate`] (license derivation) and `release.rs`/`verify.rs`'s
/// per-package dependency-digest scoping ([`reachable_dependency_versions`],
/// jerus-org/jci-audit#62), which each parse the same reachable graph for a
/// different purpose.
pub(crate) fn crate_metadata<R: CommandRunner>(runner: &R, manifest_path: &Path) -> Result<String> {
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
    Ok(out.stdout)
}

/// Parse `cargo metadata --format-version 1` JSON and compute the license
/// scope. Split from [`scope_for_crate`] so tests can inject captured JSON
/// directly rather than mocking a subprocess call.
pub(crate) fn scope_from_metadata(
    metadata_json: &str,
    allow: &BTreeSet<String>,
    exception_crates: &BTreeSet<String>,
    policy: DependencyScopePolicy,
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

    let reachable = reachable_shipped_ids(root, nodes, policy);

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
        // A crate whose license field spdx cannot parse is cargo-deny's
        // problem to fail on, not this derivation's — it contributes
        // nothing to the accepted set rather than guessing.
        let Ok(expr) = spdx::Expression::parse(license) else {
            continue;
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

/// `(name, version, source)` triples reachable, via edges that ship, from
/// the crate whose `cargo metadata` output this is — excluding the crate's
/// own package. `source` is `None` for a path/workspace package, `Some` for
/// a registry/git one (cargo metadata's own `source` field, matching
/// `Cargo.lock`'s). Used to scope `release.rs`/`verify.rs`'s dependency
/// digest to one crate's reachable graph instead of the whole workspace
/// `Cargo.lock` (jerus-org/jci-audit#62), reusing the exact reachability
/// rule [`scope_from_metadata`] already established for per-crate
/// `about.toml` derivation — a dev-only dependency of the crate being
/// released doesn't ship to its consumers, so it doesn't belong in that
/// crate's own advisory exposure either. Keying on the full triple, not just
/// `(name, version)`, matters because Cargo does allow two `[[package]]`
/// entries with identical name and version from different sources (e.g. a
/// git override alongside a registry entry of the same nominal version) —
/// matching on name+version alone could silently pull the wrong entry's
/// checksum into the digest.
pub(crate) fn reachable_dependency_versions(
    metadata_json: &str,
) -> Result<BTreeSet<(String, String, Option<String>)>> {
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

    let reachable = reachable_shipped_ids(root, nodes, DependencyScopePolicy::shipped());
    let id_to_pkg = index_by_id(packages);

    Ok(reachable
        .iter()
        .filter(|id| id.as_str() != root)
        .filter_map(|id| {
            let pkg = id_to_pkg.get(id.as_str())?;
            let name = pkg.get("name")?.as_str()?;
            let version = pkg.get("version")?.as_str()?;
            let source = pkg
                .get("source")
                .and_then(Value::as_str)
                .map(str::to_string);
            Some((name.to_string(), version.to_string(), source))
        })
        .collect())
}

/// Package ids reachable from `root` via edges that ship under `policy`
/// (excludes an edge only when *every one* of its `dep_kinds` is excluded —
/// a dependency that is also a normal dependency, or a non-excluded kind,
/// via any other edge still ships). When `policy.ignore_transitive_dependencies`
/// is set, only `root`'s own direct dependencies are considered — matching
/// cargo-about's "only direct dependencies... transitive dependencies are
/// ignored" semantics — rather than walking the full graph.
fn reachable_shipped_ids(
    root: &str,
    nodes: &[Value],
    policy: DependencyScopePolicy,
) -> BTreeSet<String> {
    let by_id = index_by_id(nodes);
    let mut seen = BTreeSet::new();

    let deps_of = |id: &str| -> &[Value] {
        by_id
            .get(id)
            .and_then(|node| node.get("deps"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
    };

    if policy.ignore_transitive_dependencies {
        for dep in deps_of(root) {
            if let Some(dep_id) = dep.get("pkg").and_then(Value::as_str)
                && edge_ships(dep, policy)
            {
                seen.insert(dep_id.to_string());
            }
        }
        return seen;
    }

    let mut stack = vec![root.to_string()];
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        for dep in deps_of(&id) {
            let Some(dep_id) = dep.get("pkg").and_then(Value::as_str) else {
                continue;
            };
            if edge_ships(dep, policy) {
                stack.push(dep_id.to_string());
            }
        }
    }
    seen
}

/// An edge ships under `policy` if any of its `dep_kinds` entries is a kind
/// `policy` doesn't exclude: `null` (normal) always ships; `"dev"`/`"build"`
/// ship unless `policy.ignore_dev_dependencies`/`ignore_build_dependencies`
/// says otherwise. An edge with mixed kinds (e.g. normal for one target, dev
/// for another) ships as long as at least one kind isn't excluded.
fn edge_ships(dep: &Value, policy: DependencyScopePolicy) -> bool {
    let Some(kinds) = dep.get("dep_kinds").and_then(Value::as_array) else {
        return true;
    };
    kinds.iter().any(|k| match k.get("kind") {
        Some(Value::String(s)) if s == "dev" => !policy.ignore_dev_dependencies,
        Some(Value::String(s)) if s == "build" => !policy.ignore_build_dependencies,
        _ => true,
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
          "source": null,
          "license": null
        },
        {
          "name": "anyhow",
          "version": "1.0.104",
          "id": "registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.104",
          "source": "registry+https://github.com/rust-lang/crates.io-index",
          "license": "MIT OR Apache-2.0"
        },
        {
          "name": "tempfile",
          "version": "3.27.0",
          "id": "registry+https://github.com/rust-lang/crates.io-index#tempfile@3.27.0",
          "source": "registry+https://github.com/rust-lang/crates.io-index",
          "license": "BSD-3-Clause"
        },
        {
          "name": "option-ext",
          "version": "0.2.0",
          "id": "registry+https://github.com/rust-lang/crates.io-index#option-ext@0.2.0",
          "source": "registry+https://github.com/rust-lang/crates.io-index",
          "license": "MPL-2.0"
        },
        {
          "name": "cc",
          "version": "1.0.0",
          "id": "registry+https://github.com/rust-lang/crates.io-index#cc@1.0.0",
          "source": "registry+https://github.com/rust-lang/crates.io-index",
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
        items.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn compound_expression_resolves_to_the_one_allowed_arm() {
        // anyhow is "MIT OR Apache-2.0"; only MIT is allowed here.
        let scope = scope_from_metadata(
            METADATA_JSON,
            &allow(&["MIT"]),
            &BTreeSet::new(),
            DependencyScopePolicy::default(),
        )
        .unwrap();
        assert!(scope.accepted.contains("MIT"));
        assert!(!scope.accepted.contains("Apache-2.0"));
    }

    #[test]
    fn dev_only_dependency_is_included_by_default() {
        // cargo-about's real default for ignore-dev-dependencies is false —
        // tempfile (dev-only) is the fixture's only source of BSD-3-Clause,
        // so its presence in `accepted` isolates dev-edge handling.
        let scope = scope_from_metadata(
            METADATA_JSON,
            &allow(&["BSD-3-Clause"]),
            &BTreeSet::new(),
            DependencyScopePolicy::default(),
        )
        .unwrap();
        assert!(
            scope.accepted.contains("BSD-3-Clause"),
            "a dev-only dependency must be counted when about.toml doesn't ignore it: {scope:?}"
        );
    }

    #[test]
    fn dev_only_dependency_is_excluded_when_about_toml_ignores_it() {
        let policy = DependencyScopePolicy {
            ignore_dev_dependencies: true,
            ..Default::default()
        };
        let scope = scope_from_metadata(
            METADATA_JSON,
            &allow(&["BSD-3-Clause"]),
            &BTreeSet::new(),
            policy,
        )
        .unwrap();
        assert!(
            !scope.accepted.contains("BSD-3-Clause"),
            "ignore-dev-dependencies = true must drop a dev-only dependency's license: {scope:?}"
        );
    }

    #[test]
    fn build_dependency_is_included_by_default() {
        // cc (build-only) is the fixture's only source of Zlib, so its
        // presence in `accepted` isolates build-edge handling.
        let scope = scope_from_metadata(
            METADATA_JSON,
            &allow(&["Zlib"]),
            &BTreeSet::new(),
            DependencyScopePolicy::default(),
        )
        .unwrap();
        assert!(
            scope.accepted.contains("Zlib"),
            "a build dependency's license must be counted by default: {scope:?}"
        );
    }

    #[test]
    fn build_dependency_is_excluded_when_about_toml_ignores_it() {
        let policy = DependencyScopePolicy {
            ignore_build_dependencies: true,
            ..Default::default()
        };
        let scope = scope_from_metadata(METADATA_JSON, &allow(&["Zlib"]), &BTreeSet::new(), policy)
            .unwrap();
        assert!(
            !scope.accepted.contains("Zlib"),
            "ignore-build-dependencies = true must drop a build-only dependency's license: {scope:?}"
        );
    }

    #[test]
    fn exception_crate_name_reachable_is_recorded() {
        let scope = scope_from_metadata(
            METADATA_JSON,
            &allow(&["MIT"]),
            &["option-ext".to_string()].into_iter().collect(),
            DependencyScopePolicy::default(),
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
            DependencyScopePolicy::default(),
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
            DependencyScopePolicy::default(),
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
        let scope = scope_from_metadata(
            &json,
            &allow(&["MIT"]),
            &BTreeSet::new(),
            DependencyScopePolicy::default(),
        );
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
    fn reachable_dependency_versions_excludes_root_and_dev_only_deps() {
        // Same fixture as the license-scope tests: tempfile is dev-only and
        // must be excluded; anyhow/option-ext/cc ship and must be included;
        // the root crate itself must not appear in its own dependency set.
        const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";
        let versions = reachable_dependency_versions(METADATA_JSON).unwrap();
        assert_eq!(
            versions,
            [
                (
                    "anyhow".to_string(),
                    "1.0.104".to_string(),
                    Some(REGISTRY.to_string())
                ),
                (
                    "cc".to_string(),
                    "1.0.0".to_string(),
                    Some(REGISTRY.to_string())
                ),
                (
                    "option-ext".to_string(),
                    "0.2.0".to_string(),
                    Some(REGISTRY.to_string())
                ),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn reachable_dependency_versions_distinguishes_same_name_version_different_source() {
        // Cargo does allow two [[package]] entries with identical name+version
        // from different sources (e.g. a git override alongside a registry
        // entry of the same nominal version) — matching by (name, version)
        // alone would silently conflate them.
        let json = r#"
        {
          "packages": [
            { "name": "root", "version": "0.0.1", "id": "id-root", "source": null, "license": null },
            { "name": "widget", "version": "1.0.0", "id": "id-registry",
              "source": "registry+https://github.com/rust-lang/crates.io-index", "license": "MIT" },
            { "name": "widget", "version": "1.0.0", "id": "id-git",
              "source": "git+https://example.com/widget#abc123", "license": "MIT" }
          ],
          "resolve": {
            "root": "id-root",
            "nodes": [
              { "id": "id-root", "deps": [
                  { "name": "widget", "pkg": "id-registry", "dep_kinds": [ { "kind": null, "target": null } ] }
              ] },
              { "id": "id-registry", "deps": [] },
              { "id": "id-git", "deps": [] }
            ]
          }
        }
        "#;
        let versions = reachable_dependency_versions(json).unwrap();
        assert_eq!(
            versions,
            [(
                "widget".to_string(),
                "1.0.0".to_string(),
                Some("registry+https://github.com/rust-lang/crates.io-index".to_string())
            )]
            .into_iter()
            .collect::<BTreeSet<_>>(),
            "must record the registry source actually reachable, not the git one: {versions:?}"
        );
    }

    #[test]
    fn scope_for_crate_runs_cargo_metadata_in_the_crates_own_directory() {
        // Not the caller's directory — the crate being resolved.
        let runner = CwdRecordingRunner {
            recorded_cwd: std::cell::RefCell::new(None),
        };
        let manifest_path = Path::new("/workspace/crates/demo/Cargo.toml");
        scope_for_crate(
            &runner,
            manifest_path,
            &BTreeSet::new(),
            &BTreeSet::new(),
            DependencyScopePolicy::default(),
        )
        .unwrap();
        assert_eq!(
            runner.recorded_cwd.into_inner(),
            Some(std::path::PathBuf::from("/workspace/crates/demo"))
        );
    }

    // --- ignore-transitive-dependencies ---------------------------------

    // A two-level chain: root -> direct (MIT) -> transitive (Zlib). Isolates
    // depth handling from edge-kind handling (both edges here are normal).
    const METADATA_JSON_TWO_LEVELS: &str = r#"
    {
      "packages": [
        { "name": "root", "version": "0.0.0", "id": "id-root", "source": null, "license": null },
        { "name": "direct", "version": "1.0.0", "id": "id-direct",
          "source": "registry+https://x", "license": "MIT" },
        { "name": "transitive", "version": "1.0.0", "id": "id-transitive",
          "source": "registry+https://x", "license": "Zlib" }
      ],
      "resolve": {
        "root": "id-root",
        "nodes": [
          { "id": "id-root", "deps": [
              { "name": "direct", "pkg": "id-direct", "dep_kinds": [ { "kind": null, "target": null } ] }
          ] },
          { "id": "id-direct", "deps": [
              { "name": "transitive", "pkg": "id-transitive", "dep_kinds": [ { "kind": null, "target": null } ] }
          ] },
          { "id": "id-transitive", "deps": [] }
        ]
      }
    }
    "#;

    #[test]
    fn transitive_dependency_is_included_by_default() {
        let scope = scope_from_metadata(
            METADATA_JSON_TWO_LEVELS,
            &allow(&["MIT", "Zlib"]),
            &BTreeSet::new(),
            DependencyScopePolicy::default(),
        )
        .unwrap();
        assert_eq!(scope.accepted, allow(&["MIT", "Zlib"]));
    }

    #[test]
    fn transitive_dependency_is_excluded_when_about_toml_ignores_it() {
        let policy = DependencyScopePolicy {
            ignore_transitive_dependencies: true,
            ..Default::default()
        };
        let scope = scope_from_metadata(
            METADATA_JSON_TWO_LEVELS,
            &allow(&["MIT", "Zlib"]),
            &BTreeSet::new(),
            policy,
        )
        .unwrap();
        assert_eq!(
            scope.accepted,
            allow(&["MIT"]),
            "direct dependency stays, transitive one must be dropped: {scope:?}"
        );
    }

    // --- dependency_scope_policy_from_about_toml -------------------------

    #[test]
    fn dependency_scope_policy_from_about_toml_defaults_to_all_false_when_absent() {
        let policy = dependency_scope_policy_from_about_toml("accepted = []\n").unwrap();
        assert_eq!(policy, DependencyScopePolicy::default());
    }

    #[test]
    fn dependency_scope_policy_from_about_toml_reads_declared_flags() {
        let policy = dependency_scope_policy_from_about_toml(
            "ignore-dev-dependencies = true\nignore-build-dependencies = true\n",
        )
        .unwrap();
        assert_eq!(
            policy,
            DependencyScopePolicy {
                ignore_dev_dependencies: true,
                ignore_build_dependencies: true,
                ignore_transitive_dependencies: false,
            }
        );
    }

    #[test]
    fn dependency_scope_policy_from_about_toml_falls_back_to_defaults_on_unparseable_content() {
        let policy = dependency_scope_policy_from_about_toml("not = [valid toml").unwrap();
        assert_eq!(policy, DependencyScopePolicy::default());
    }

    #[test]
    fn dependency_scope_policy_from_about_toml_errs_on_a_non_boolean_value() {
        // Valid TOML syntax (merge_about_toml's own parse would succeed), but
        // the wrong type for this key — must not be silently read as `false`.
        let result =
            dependency_scope_policy_from_about_toml("ignore-dev-dependencies = \"true\"\n");
        assert!(
            result.is_err(),
            "a non-boolean ignore-dev-dependencies must error, not silently default: {result:?}"
        );
    }
}
