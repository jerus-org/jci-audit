set -- jci-audit check-ci-wiring
case "${LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  verbose) set -- "$@" --verbose ;;
  verbose2) set -- "$@" --verbose --verbose ;;
  verbose3) set -- "$@" --verbose --verbose --verbose ;;
  verbose4) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
[[ -n "${CONFIG:-}" ]] && set -- "$@" --config "${CONFIG}"
"$@"
