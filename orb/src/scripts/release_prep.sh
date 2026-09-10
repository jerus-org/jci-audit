set -- jci-audit release-prep
case "${LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  verbose) set -- "$@" --verbose ;;
  verbose2) set -- "$@" --verbose --verbose ;;
  verbose3) set -- "$@" --verbose --verbose --verbose ;;
  verbose4) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
[[ -n "${ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${ADVISORY_DB}"
[[ -n "${PACKAGE:-}" ]] && set -- "$@" --package "${PACKAGE}"
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
set -- "$@" "${VERSION}"
"$@"
