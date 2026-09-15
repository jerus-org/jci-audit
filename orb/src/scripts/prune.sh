set -- jci-audit prune
[[ "${CHECK:-false}" = "true" ]] && set -- "$@" --check
case "${LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  v) set -- "$@" --verbose ;;
  vv) set -- "$@" --verbose --verbose ;;
  vvv) set -- "$@" --verbose --verbose --verbose ;;
  vvvv) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
"$@"
