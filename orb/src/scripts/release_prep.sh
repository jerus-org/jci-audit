set -- jci-audit release-prep
case "${GCO_LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  v) set -- "$@" --verbose ;;
  vv) set -- "$@" --verbose --verbose ;;
  vvv) set -- "$@" --verbose --verbose --verbose ;;
  vvvv) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
[[ -n "${GCO_ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${GCO_ADVISORY_DB}"
[[ -n "${GCO_PACKAGE:-}" ]] && set -- "$@" --package "${GCO_PACKAGE}"
[[ "${GCO_DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
set -- "$@" "${GCO_VERSION}"
"$@"
