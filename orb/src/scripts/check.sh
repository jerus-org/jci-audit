set -- jci-audit check
case "${LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  v) set -- "$@" --verbose ;;
  vv) set -- "$@" --verbose --verbose ;;
  vvv) set -- "$@" --verbose --verbose --verbose ;;
  vvvv) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
[[ -n "${MANIFEST_PATH:-}" ]] && set -- "$@" --manifest-path "${MANIFEST_PATH}"
[[ "${DENY_STALE_EXCEPTIONS:-false}" = "true" ]] && set -- "$@" --deny-stale-exceptions
[[ "${DENY_UNUSED_LICENSES:-false}" = "true" ]] && set -- "$@" --deny-unused-licenses
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
"$@"
