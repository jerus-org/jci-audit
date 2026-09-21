set -- jci-audit publish-record
case "${GCO_LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  v) set -- "$@" --verbose ;;
  vv) set -- "$@" --verbose --verbose ;;
  vvv) set -- "$@" --verbose --verbose --verbose ;;
  vvvv) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
set -- "$@" --tag "${GCO_TAG}"
set -- "$@" --owner "${GCO_OWNER}"
set -- "$@" --repo "${GCO_REPO}"
[[ "${GCO_PUBLISH:-false}" = "true" ]] && set -- "$@" --publish
[[ -n "${GCO_RECORD_PATH:-}" ]] && set -- "$@" --record-path "${GCO_RECORD_PATH}"
set -- "$@" "${GCO_VERSION}"
"$@"
