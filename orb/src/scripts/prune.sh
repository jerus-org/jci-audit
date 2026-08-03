set -- jci-audit prune
[[ "${CHECK:-false}" = "true" ]] && set -- "$@" --check
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
"$@"
