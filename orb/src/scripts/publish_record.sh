set -- jci-audit publish-record
case "${LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  v) set -- "$@" --verbose ;;
  vv) set -- "$@" --verbose --verbose ;;
  vvv) set -- "$@" --verbose --verbose --verbose ;;
  vvvv) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
set -- "$@" --tag "${TAG}"
set -- "$@" --owner "${OWNER}"
set -- "$@" --repo "${REPO}"
[[ "${PUBLISH:-false}" = "true" ]] && set -- "$@" --publish
[[ -n "${RECORD_PATH:-}" ]] && set -- "$@" --record-path "${RECORD_PATH}"
set -- "$@" "${VERSION}"
"$@"
