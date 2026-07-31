#!/usr/bin/env bash
#
# Third-party licence notices.
#
#   (no argument)  regenerate crates/jci-audit/THIRD-PARTY-LICENSES.md
#   --check        regenerate and fail if the committed copy differs
#   --policy       fail only if cargo-about cannot resolve the licences at all
#
# Shared by the justfile recipes and by CI so the invocation has one definition.
# CI cannot call the recipes — `just` is not installed in the CI image — which is
# why this exists as a script rather than living in the justfile.
#
# WHY CI USES --policy AND NOT --check
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
# attribution correctness, so it has to be believed.
#
# --policy keeps what actually matters. The release that prompted all this was
# aborted by cargo-about *erroring* on a licence the policy did not accept, not
# by stale text. That error is unaffected by cache state (verified both cold and
# warm), so CI catches the release-aborting condition at PR time and leaves the
# byte comparison to maintainers, whose environment is the one that commits.
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

--policy)
    # Resolution only — the rendered text is discarded, so nothing here depends
    # on how the cache happens to be populated.
    if ! (cd "$CRATE_DIR" && cargo about generate --locked about.hbs --output-file /dev/null); then
        cat >&2 <<MSG

cargo-about could not resolve the licences of this dependency graph.

This is what aborts a release: the pre-release hook regenerates the notices, and
a licence the policy does not accept stops it there — after the approval gate and
the build, at the most expensive point in the pipeline.

A dependency has almost certainly arrived carrying a licence that is not accepted
yet. Grant it in BOTH deny.toml and $CRATE_DIR/about.toml, which state one policy
in two files and are kept in step by hand. Scope it to the crate that carries it
rather than adding it globally, so the next such dependency also stops here.
MSG
        exit 1
    fi
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
    echo "usage: $0 [--check|--policy]" >&2
    exit 2
    ;;
esac
