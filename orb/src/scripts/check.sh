set -- jci-audit check
[[ -n "${MANIFEST_PATH:-}" ]] && set -- "$@" --manifest-path "${MANIFEST_PATH}"
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
"$@"
