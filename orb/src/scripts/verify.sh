set -- jci-audit verify
set -- "$@" --release-version "${RELEASE_VERSION}"
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ -n "${ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${ADVISORY_DB}"
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${OWNER:-}" ]] && set -- "$@" --owner "${OWNER}"
[[ -n "${REPO:-}" ]] && set -- "$@" --repo "${REPO}"
[[ -n "${TAG_PREFIX:-}" ]] && set -- "$@" --tag-prefix "${TAG_PREFIX}"
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
"$@"
