set -- jci-audit check
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${MANIFEST_PATH:-}" ]] && set -- "$@" --manifest-path "${MANIFEST_PATH}"
[[ "${DENY_STALE_EXCEPTIONS:-false}" = "true" ]] && set -- "$@" --deny-stale-exceptions
[[ "${DENY_UNUSED_LICENSES:-false}" = "true" ]] && set -- "$@" --deny-unused-licenses
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
"$@"
