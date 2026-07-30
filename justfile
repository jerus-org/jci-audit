#!/usr/bin/env -S just --justfile
# ^ A shebang isn't required, but allows a justfile to be executed
#   like a script, with `./justfile test`, for example.

default:
    {{ just_executable() }} --list

alias t := test
alias c := check

# run all tests, clippy, including CLI tests, try building docs
test: clippy check doc unit-tests

clear-target:
    cargo clean

# Run cargo clippy on all crates, denying warnings (matches CI enforcement)
clippy *clippy-args:
    cargo clippy --all --tests --all-features {{ clippy-args }} -- -D warnings

# Build all code in suitable configurations
check:
    cargo check --all

# Run cargo doc on all crates. --document-private-items matches the toolkit's
# test_doc_build job so private-intra-doc-link errors surface locally.
doc $RUSTDOCFLAGS="-D warnings":
    cargo doc --all --no-deps --document-private-items

# run all unit + CLI (trycmd) tests
unit-tests:
    cargo test --all

# run various auditing tools to assure we are legal and safe.
# TODO (P1): replace with `jci-audit check` once implemented, for local/CI parity.
audit:
    cargo deny check advisories bans licenses sources

# verify the crate builds at its declared MSRV (rust-version) against the
# locked deps — CI's rolling toolchain never validates the true floor.
# Requires the workstation tool: cargo binstall cargo-msrv
#
# --manifest-path points at the CRATE, not the workspace root: the root declares
# rust-version under [workspace.package], where cargo-msrv does not look for it,
# and it exits 1 having verified nothing rather than falling back.
msrv:
    cargo msrv verify --manifest-path crates/jci-audit/Cargo.toml

# run nightly rustfmt for its extra features, but check that it won't upset stable rustfmt
fmt:
    cargo +nightly fmt --all -- --config-path rustfmt-nightly.toml
    cargo +stable fmt --all -- --check
    just --fmt --unstable

# Generate coverage report with cargo-llvm-cov (the tool used in CI). Uses
# --all-features so the integration tests run and the spawned-binary coverage
# is captured (tarpaulin cannot see subprocess coverage and under-reports).
cov:
    cargo llvm-cov --all-features --lcov --output-path coverage/lcov.info

# Print a coverage summary to the terminal
cov-summary:
    cargo llvm-cov --all-features --summary-only

# Regenerate the crate's third-party license notices file (cargo-about)
licenses:
    cd crates/jci-audit && cargo about generate about.hbs --output-file THIRD-PARTY-LICENSES.md

# Verify the committed license notices are current (fails if stale)
licenses-check:
    cd crates/jci-audit && cargo about generate about.hbs --output-file THIRD-PARTY-LICENSES.md
    git diff --exit-code crates/jci-audit/THIRD-PARTY-LICENSES.md
