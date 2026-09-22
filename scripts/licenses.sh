#!/usr/bin/env bash
#
# Third-party licence notices.
#
#   (no argument)  regenerate crates/jci-audit/THIRD-PARTY-LICENSES.md
#   --check        regenerate and fail if the committed copy differs
#
# Shared by the justfile recipes. `jci-audit check`/`release-prep` run the
# equivalent cargo-about resolution check natively now (jerus-org/jci-audit#80)
# — this script only regenerates/verifies the rendered notices file.
#
# THIS RUNS IN CI TOO — the `licenses-check` job in .circleci/config.yml runs
# `--check` exactly as below, in the published jerusdp/jci-audit image.
#
# It didn't always: cargo-about resolves a crate's licence partly by reading
# files from the extracted crate sources under ~/.cargo/registry/src, so on
# cargo-about 0.9.1 its output depended on what the local cargo cache
# happened to have unpacked — measured against a cold CARGO_HOME, `sigstore`
# gained an Apache-2.0 section of its own, a 208-line difference from the
# same commit and lockfile. A CI job comparing bytes would have failed on a
# correct tree. Fixed upstream in cargo-about 0.9.2
# (EmbarkStudios/cargo-about#312, closing #309); confirmed byte-identical
# against a cold cache before wiring the CI job in (jerus-org/jci-audit#36).
#
# `jci-audit check`'s own resolution check is still narrower on purpose: it
# fails only when cargo-about *errors* on a licence the policy doesn't
# accept, discarding the rendered text (jerus-org/jci-audit#80) — this
# script is still what verifies the rendered notices themselves.
set -euo pipefail

CRATE_DIR="crates/jci-audit"
NOTICES="THIRD-PARTY-LICENSES.md"
mode="${1:-write}"

# --locked so a CI run cannot quietly rewrite Cargo.lock. Deliberately not
# --frozen: that adds --offline, which fails outright on a cold cache because the
# crate sources are not there to read.
case "$mode" in
write)
    (cd "$CRATE_DIR" && cargo about generate --locked about.hbs --output-file "$NOTICES")
    ;;

--check)
    (cd "$CRATE_DIR" && cargo about generate --locked about.hbs --output-file "$NOTICES")
    if ! git diff --exit-code "$CRATE_DIR/$NOTICES"; then
        cat >&2 <<MSG

The committed licence notices do not match this machine's dependency graph.

Run 'just licenses' and commit the result if the difference is a real dependency
change. Note that some of this difference can come from the local cargo cache
rather than from the dependencies — see the comment at the top of this script.
MSG
        exit 1
    fi
    ;;

*)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac
