#!/bin/bash
set -exo pipefail
gen-changelog generate \
    --display-summaries \
    --name "CHANGELOG.md" \
    --package "jci-audit" \
    --repository-dir "../.." \
    --next-version "${NEW_VERSION:-${1}}"

# Refresh the third-party license notices so every release ships current
# attribution — the same release-time assurance exercise as the changelog above.
# Runs from the crate directory, where about.toml / about.hbs live and where
# THIRD-PARTY-LICENSES.md is packaged.
#
# Guarded until cargo-about is guaranteed in the release container — i.e. the
# ci-rust image that toolkit/release_crate runs this hook in (once cargo-about
# ships in ci-container and this repo bumps its rust_image). Once it always is,
# drop the guard so a missing tool fails the release.
if command -v cargo-about >/dev/null 2>&1; then
    cargo about generate about.hbs --output-file THIRD-PARTY-LICENSES.md
else
    echo "WARN: cargo-about not installed; skipping THIRD-PARTY-LICENSES.md refresh" >&2
fi

# Record the release's security validation: run the gate against the local
# advisory-db copy and write .security/release-<VERSION>.json at the workspace
# root. The record is COMMITTED, so it must be staged here — cargo-release
# includes tracked modifications and staged new files in the release commit, and
# an unstaged new file would be left behind, leaving the tree dirty so
# `cargo publish` refuses it.
#
# Guarded on the tools being present so it self-activates once the release
# container carries jci-audit (and the tools it orchestrates) and never breaks a
# release before then — the same approach as the cargo-about block above. The
# locally built binary is preferred when present, so jci-audit's own release
# records itself with the very build it is releasing.
VERSION="${NEW_VERSION:-${1}}"
JCI_AUDIT=""
if [ -x ../../target/release/jci-audit ]; then
    JCI_AUDIT=../../target/release/jci-audit
elif command -v jci-audit >/dev/null 2>&1; then
    JCI_AUDIT=jci-audit
fi
if [ -n "${JCI_AUDIT}" ] \
    && command -v cargo-deny >/dev/null 2>&1 \
    && command -v cargo-audit >/dev/null 2>&1; then
    "${JCI_AUDIT}" release --version "${VERSION}"
    git add "../../.security/release-${VERSION}.json"
else
    echo "WARN: jci-audit or its tools unavailable; skipping release record" >&2
fi
