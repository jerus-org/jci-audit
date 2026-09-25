set -- jci-audit release-prep
case "${GCO_LOG_LEVEL:-default}" in
  quiet) set -- "$@" --quiet ;;
  v) set -- "$@" --verbose ;;
  vv) set -- "$@" --verbose --verbose ;;
  vvv) set -- "$@" --verbose --verbose --verbose ;;
  vvvv) set -- "$@" --verbose --verbose --verbose --verbose ;;
esac
[[ ! "${GCO_ADVISORY_DB:-}" =~ ^[[:space:]]*$ ]] && set -- "$@" --advisory-db "${GCO_ADVISORY_DB}"
[[ ! "${GCO_PACKAGE:-}" =~ ^[[:space:]]*$ ]] && set -- "$@" --package "${GCO_PACKAGE}"
[[ "${GCO_DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
GCO_VERSION_VALUE="${GCO_VERSION:-}"
if [[ "${GCO_VERSION_VALUE}" =~ ^[[:space:]]*$ ]]; then
  GCO_VERSION_VALUE="${GCO_VERSION_RESOLVED:-}"
fi
if [[ "${GCO_VERSION_VALUE}" =~ ^[[:space:]]*$ ]]; then
  echo "ERROR: no value for version -- set the 'version' parameter, or 'version_env_var' (with attach_workspace) to resolve one at runtime." >&2
  exit 1
fi
set -- "$@" "${GCO_VERSION_VALUE}"
"$@"
