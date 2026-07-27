set -- jci-audit sync
[[ "${CHECK:-false}" = "true" ]] && set -- "$@" --check
"$@"
