set -- jci-audit wire-ci
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${CONFIG:-}" ]] && set -- "$@" --config "${CONFIG}"
[[ "${CHECK:-false}" = "true" ]] && set -- "$@" --check
"$@"
