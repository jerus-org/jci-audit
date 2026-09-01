set -- jci-audit verify
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${ADVISORY_DB}"
[[ -n "${OWNER:-}" ]] && set -- "$@" --owner "${OWNER}"
[[ -n "${REPO:-}" ]] && set -- "$@" --repo "${REPO}"
[[ -n "${TAG_PREFIX:-}" ]] && set -- "$@" --tag-prefix "${TAG_PREFIX}"
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
set -- "$@" "${VERSION}"
"$@"
