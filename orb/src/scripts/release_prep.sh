set -- jci-audit release-prep
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${ADVISORY_DB}"
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
[[ -n "${VERSION:-}" ]] && set -- "$@" "${VERSION}"
"$@"
