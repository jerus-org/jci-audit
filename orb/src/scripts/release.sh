set -- jci-audit release
[[ -n "${RELEASE_VERSION:-}" ]] && set -- "$@" --release-version "${RELEASE_VERSION}"
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
"$@"
