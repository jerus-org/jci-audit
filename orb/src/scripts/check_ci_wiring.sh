set -- jci-audit check-ci-wiring
case "${GCO_LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  v) set -- "$@" --verbose ;;
  vv) set -- "$@" --verbose --verbose ;;
  vvv) set -- "$@" --verbose --verbose --verbose ;;
  vvvv) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
[[ ! "${GCO_CONFIG:-}" =~ ^[[:space:]]*$ ]] && set -- "$@" --config "${GCO_CONFIG}"
"$@"
