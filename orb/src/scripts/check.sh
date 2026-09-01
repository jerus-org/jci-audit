set -- jci-audit check
[[ -n "${MANIFEST_PATH:-}" ]] && set -- "$@" --manifest-path "${MANIFEST_PATH}"
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
"$@"
