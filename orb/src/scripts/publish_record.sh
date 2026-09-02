set -- jci-audit publish-record
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${RELEASE_VERSION:-}" ]] && set -- "$@" --release-version "${RELEASE_VERSION}"
set -- "$@" --tag "${TAG}"
set -- "$@" --owner "${OWNER}"
set -- "$@" --repo "${REPO}"
[[ "${PUBLISH:-false}" = "true" ]] && set -- "$@" --publish
[[ -n "${RECORD_PATH:-}" ]] && set -- "$@" --record-path "${RECORD_PATH}"
"$@"
