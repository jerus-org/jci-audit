set -- jci-audit check-ci-wiring
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${CONFIG:-}" ]] && set -- "$@" --config "${CONFIG}"
"$@"
