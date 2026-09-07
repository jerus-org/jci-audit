set -- jci-audit wire-ci
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${CONFIG:-}" ]] && set -- "$@" --config "${CONFIG}"
[[ -n "${ORB_JOB:-}" ]] && set -- "$@" --orb-job "${ORB_JOB}"
[[ -n "${ORB_VERSION:-}" ]] && set -- "$@" --orb-version "${ORB_VERSION}"
[[ -n "${WORKFLOW:-}" ]] && set -- "$@" --workflow "${WORKFLOW}"
[[ -n "${JOB_NAME:-}" ]] && set -- "$@" --job-name "${JOB_NAME}"
[[ -n "${REQUIRES:-}" ]] && set -- "$@" --requires "${REQUIRES}"
[[ "${CLEAR_REQUIRES:-false}" = "true" ]] && set -- "$@" --clear-requires
[[ -n "${REQUIRED_BY:-}" ]] && set -- "$@" --required-by "${REQUIRED_BY}"
[[ "${CLEAR_REQUIRED_BY:-false}" = "true" ]] && set -- "$@" --clear-required-by
[[ "${CHECK:-false}" = "true" ]] && set -- "$@" --check
"$@"
