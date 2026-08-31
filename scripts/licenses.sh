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
# WHY THERE IS NO CI EQUIVALENT OF --check
#
# The generated text is not reproducible across machines. cargo-about resolves a
# crate's licence partly by reading files from the extracted crate sources under
# ~/.cargo/registry/src, so its output depends on what the local cargo cache
# happens to have unpacked. Measured against a cold CARGO_HOME, `sigstore` gains
# an Apache-2.0 section of its own — a 208-line difference from the same commit,
# same lockfile and same cargo-about 0.9.1. `cargo fetch` does not settle it,
# because fetching populates the archive cache and not the extracted sources.
#
# A CI job that checks out and compares bytes would therefore fail on a correct
# tree, and a gate that cries wolf is worse than no gate — this one guards
# attribution correctness, so it has to be believed. `jci-audit check`'s
# resolution check keeps what actually matters instead: it fails only when
# cargo-about *errors* on a licence the policy doesn't accept, which is
# unaffected by cache state.
#
# Making the text itself reproducible is jci-audit#36.
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
