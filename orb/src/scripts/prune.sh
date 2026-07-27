set -- jci-audit prune
[[ "${CHECK:-false}" = "true" ]] && set -- "$@" --check
"$@"
