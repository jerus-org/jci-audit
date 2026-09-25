if [[ -z "${GCO_TARGET_ENV_VAR:-}" ]]; then
  echo "ERROR: GCO_TARGET_ENV_VAR must be set to use workspace-sourced resolution" >&2
  exit 1
fi

SOURCE_FILE="${GCO_SOURCE_FILE:-${GCO_WORKSPACE_ROOT}/versions.env}"

if [[ ! -f "${SOURCE_FILE}" ]]; then
  echo "ERROR: workspace source file not found: ${SOURCE_FILE}" >&2
  echo "Did you set attach_workspace: true and persist it from an earlier job?" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "${SOURCE_FILE}"

RESOLVED="${!GCO_TARGET_ENV_VAR:-}"
if [[ -z "${RESOLVED}" ]]; then
  echo "ERROR: ${GCO_TARGET_ENV_VAR} not found (or empty) in ${SOURCE_FILE}" >&2
  exit 1
fi

echo "Resolved ${GCO_TARGET_ENV_VAR} from workspace: ${RESOLVED}"
echo "export ${GCO_OVERRIDE_VAR}=${RESOLVED}" >> "$BASH_ENV"
