set -- jci-audit release-prep
case "${LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  v) set -- "$@" --verbose ;;
  vv) set -- "$@" --verbose --verbose ;;
  vvv) set -- "$@" --verbose --verbose --verbose ;;
  vvvv) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
[[ -n "${ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${ADVISORY_DB}"
[[ -n "${PACKAGE:-}" ]] && set -- "$@" --package "${PACKAGE}"
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
set -- "$@" "${VERSION}"
"$@"
