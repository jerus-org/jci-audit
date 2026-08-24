//! Regression guard for jerus-org/jci-audit#90: the published crate must
//! carry no importable library target. `autolib = false` in Cargo.toml is
//! silent until something resurrects `src/lib.rs`; this catches that via the
//! same `cargo metadata` view crates.io/docs.rs would see.

use std::process::Command;

#[test]
fn crate_has_no_library_target() {
    let manifest_path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .expect("cargo metadata should run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata output should be valid JSON");
    let package = metadata["packages"]
        .as_array()
        .and_then(|pkgs| pkgs.iter().find(|p| p["name"] == "jci-audit"))
        .expect("jci-audit package should be present in metadata");

    let has_lib_target = package["targets"]
        .as_array()
        .expect("targets should be an array")
        .iter()
        .any(|t| {
            t["kind"]
                .as_array()
                .map(|kinds| kinds.iter().any(|k| k == "lib" || k == "rlib"))
                .unwrap_or(false)
        });

    assert!(
        !has_lib_target,
        "jci-audit must publish with no [lib] target (#90) — found one in `cargo metadata` output"
    );
}
