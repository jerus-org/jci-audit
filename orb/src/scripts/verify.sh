set -- jci-audit verify
set -- "$@" --release-version "${RELEASE_VERSION}"
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ -n "${ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${ADVISORY_DB}"
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
"$@"
