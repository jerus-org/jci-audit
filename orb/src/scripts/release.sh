set -- jci-audit release
set -- "$@" --version "${VERSION}"
[[ -n "${ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${ADVISORY_DB}"
"$@"
