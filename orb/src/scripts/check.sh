set -- jci-audit check
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${MANIFEST_PATH:-}" ]] && set -- "$@" --manifest-path "${MANIFEST_PATH}"
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
"$@"
