set -- jci-audit check
case "${LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  verbose) set -- "$@" --verbose ;;
  verbose2) set -- "$@" --verbose --verbose ;;
  verbose3) set -- "$@" --verbose --verbose --verbose ;;
  verbose4) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
[[ -n "${MANIFEST_PATH:-}" ]] && set -- "$@" --manifest-path "${MANIFEST_PATH}"
[[ "${DENY_STALE_EXCEPTIONS:-false}" = "true" ]] && set -- "$@" --deny-stale-exceptions
[[ "${DENY_UNUSED_LICENSES:-false}" = "true" ]] && set -- "$@" --deny-unused-licenses
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
"$@"
