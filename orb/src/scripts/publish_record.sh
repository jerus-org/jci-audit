set -- jci-audit publish-record
case "${LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  verbose) set -- "$@" --verbose ;;
  verbose2) set -- "$@" --verbose --verbose ;;
  verbose3) set -- "$@" --verbose --verbose --verbose ;;
  verbose4) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
set -- "$@" --tag "${TAG}"
set -- "$@" --owner "${OWNER}"
set -- "$@" --repo "${REPO}"
[[ "${PUBLISH:-false}" = "true" ]] && set -- "$@" --publish
[[ -n "${RECORD_PATH:-}" ]] && set -- "$@" --record-path "${RECORD_PATH}"
set -- "$@" "${VERSION}"
"$@"
