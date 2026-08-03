set -- jci-audit verify
set -- "$@" --release-version "${RELEASE_VERSION}"
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
"$@"
