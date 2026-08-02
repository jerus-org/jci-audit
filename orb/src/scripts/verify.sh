set -- jci-audit verify
set -- "$@" --version "${VERSION}"
[[ -n "${ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${ADVISORY_DB}"
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
"$@"
