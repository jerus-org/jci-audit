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
# Unguarded: `jci-audit release-prep` (record-release, earlier in this same
# pipeline) already ran cargo-about's policy-resolution check as a hard gate,
# so its presence and the policy's resolvability are already guaranteed here.
# A failure at this point means the environment changed between the two
# steps, which should fail the release loudly, not warn and ship stale
# notices.
cargo about generate about.hbs --output-file THIRD-PARTY-LICENSES.md
