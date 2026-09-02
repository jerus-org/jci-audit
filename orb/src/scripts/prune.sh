set -- jci-audit prune
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ "${CHECK:-false}" = "true" ]] && set -- "$@" --check
"$@"
