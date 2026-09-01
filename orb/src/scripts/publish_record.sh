set -- jci-audit publish-record
[[ -n "${RELEASE_VERSION:-}" ]] && set -- "$@" --release-version "${RELEASE_VERSION}"
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
set -- "$@" --tag "${TAG}"
set -- "$@" --owner "${OWNER}"
set -- "$@" --repo "${REPO}"
[[ "${PUBLISH:-false}" = "true" ]] && set -- "$@" --publish
[[ -n "${RECORD_PATH:-}" ]] && set -- "$@" --record-path "${RECORD_PATH}"
"$@"
