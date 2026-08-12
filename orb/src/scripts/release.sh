set -- jci-audit release
[[ -n "${RELEASE_VERSION:-}" ]] && set -- "$@" --release-version "${RELEASE_VERSION}"
[[ "${VERBOSE:-false}" = "true" ]] && set -- "$@" --verbose
[[ "${QUIET:-false}" = "true" ]] && set -- "$@" --quiet
[[ -n "${ADVISORY_DB:-}" ]] && set -- "$@" --advisory-db "${ADVISORY_DB}"
[[ "${COMMIT:-false}" = "true" ]] && set -- "$@" --commit
[[ "${PUSH:-false}" = "true" ]] && set -- "$@" --push
[[ -n "${GPG_KEY_ENV:-}" ]] && set -- "$@" --gpg-key-env "${GPG_KEY_ENV}"
[[ -n "${GPG_TRUST_ENV:-}" ]] && set -- "$@" --gpg-trust-env "${GPG_TRUST_ENV}"
[[ -n "${USER_NAME_ENV:-}" ]] && set -- "$@" --user-name-env "${USER_NAME_ENV}"
[[ -n "${USER_EMAIL_ENV:-}" ]] && set -- "$@" --user-email-env "${USER_EMAIL_ENV}"
[[ -n "${SIGN_KEY_ENV:-}" ]] && set -- "$@" --sign-key-env "${SIGN_KEY_ENV}"
[[ "${DENY_WARNINGS:-false}" = "true" ]] && set -- "$@" --deny-warnings
"$@"
