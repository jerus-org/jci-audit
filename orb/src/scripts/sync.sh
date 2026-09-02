set -- jci-audit sync
[[ "${CHECK:-false}" = "true" ]] && set -- "$@" --check
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
"$@"
