set -- jci-audit check
case "${GCO_LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  v) set -- "$@" --verbose ;;
  vv) set -- "$@" --verbose --verbose ;;
  vvv) set -- "$@" --verbose --verbose --verbose ;;
  vvvv) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
[[ -n "${GCO_MANIFEST_PATH:-}" ]] && set -- "$@" --manifest-path "${GCO_MANIFEST_PATH}"
[[ "${GCO_DENY_STALE_EXCEPTIONS:-false}" = "true" ]] && set -- "$@" --deny-stale-exceptions
[[ "${GCO_DENY_UNUSED_LICENSES:-false}" = "true" ]] && set -- "$@" --deny-unused-licenses
[[ "${GCO_DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
"$@"
