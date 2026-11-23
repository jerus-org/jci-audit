#!/usr/bin/env bash
# Configure git in a Claude cloud session to author and GPG-sign commits as the
# agent identity, mirroring what CI does for the bot (toolkit/gpg_key +
# git identity): import the agent's secret key, then point git at it.
#
# Reads (all set in the cloud environment's settings, never in the repo):
#   AGENT_GPG_KEY    base64 of the ASCII-armored secret key
#   AGENT_GPG_TRUST  ownertrust line, "<FINGERPRINT>:6:"
#   AGENT_GIT_NAME   commit author/committer name
#   AGENT_GIT_EMAIL  commit author/committer email (verified on the agent's
#                    GitHub account and present as a UID on the key)
#
# No-op when AGENT_GPG_KEY is unset, so sessions without the agent identity
# (anyone else's, or a local checkout) are unaffected. Never prints a secret.
set -euo pipefail

if [[ -z "${AGENT_GPG_KEY:-}" ]]; then
  echo "agent-signing: AGENT_GPG_KEY not set; leaving git configuration unchanged"
  exit 0
fi

for var in AGENT_GPG_TRUST AGENT_GIT_NAME AGENT_GIT_EMAIL; do
  if [[ -z "${!var:-}" ]]; then
    echo "agent-signing: $var is not set" >&2
    exit 1
  fi
done

# Use only the first non-empty line of AGENT_GPG_TRUST, whitespace stripped:
# gpg rejects the whole value if any line is malformed, and a stray space or
# second line is an easy mistake when pasting into the settings form.
trust_line="$(printf '%s\n' "$AGENT_GPG_TRUST" | sed -n '/[^[:space:]]/{p;q}' | tr -d '[:space:]')"
fingerprint="${trust_line%%:*}"
if [[ ! "$fingerprint" =~ ^[0-9A-Fa-f]{40}$ ]]; then
  echo "agent-signing: AGENT_GPG_TRUST must start with a 40-character fingerprint (<FINGERPRINT>:6:)" >&2
  exit 1
fi

# Same decoding as pcu's `import_gpg_key` (which replicates toolkit/gpg_key):
# `printf '%b'` expands literal \n sequences, --ignore-garbage skips stray chars.
# gpg's own output is hidden (it can name the key); the reason is reported below.
if ! printf '%b' "$AGENT_GPG_KEY" | base64 --decode --ignore-garbage |
  gpg --batch --quiet --import 2>/dev/null; then
  echo "agent-signing: AGENT_GPG_KEY could not be decoded and imported" >&2
  echo "agent-signing: expected the base64 of an ASCII-armored secret key (gpg --export-secret-keys --armor <id> | base64 -w0)" >&2
  exit 1
fi
if ! printf '%s\n' "$trust_line" | gpg --batch --quiet --import-ownertrust 2>/dev/null; then
  echo "agent-signing: AGENT_GPG_TRUST could not be imported" >&2
  echo "agent-signing: expected a single line of the form <FINGERPRINT>:6:" >&2
  exit 1
fi

# Select the key by the fingerprint from the trust line, so a keyring holding
# other keys can never be signed with by mistake.
if ! gpg --batch --list-keys --with-colons "$fingerprint" 2>/dev/null | grep -q '^pub'; then
  echo "agent-signing: AGENT_GPG_TRUST names a key (…${fingerprint: -16}) that AGENT_GPG_KEY does not contain" >&2
  echo "agent-signing: export the key whose fingerprint is in AGENT_GPG_TRUST" >&2
  exit 1
fi
if ! gpg --batch --list-secret-keys --with-colons "$fingerprint" 2>/dev/null | grep -q '^sec'; then
  echo "agent-signing: the public key imported but no secret key did" >&2
  echo "agent-signing: the key is probably passphrase-protected; export one without a passphrase" >&2
  exit 1
fi

# Write the repository's own config when run inside one: it takes precedence
# over the global config, which the platform rewrites with its generic
# `Claude <noreply@anthropic.com>` identity between commits (observed: the
# signing settings survived but the author reverted, giving commits signed by
# the agent yet authored as the generic identity). Outside a repository fall
# back to the global config.
scope=--global
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  scope=--local
fi

# Override the platform's default SSH signing (gpg.format=ssh) with OpenPGP:
# pcu's verifier and the trust map only understand GPG keys.
git config "$scope" user.name "$AGENT_GIT_NAME"
git config "$scope" user.email "$AGENT_GIT_EMAIL"
git config "$scope" gpg.format openpgp
git config "$scope" user.signingkey "$fingerprint"
git config "$scope" commit.gpgsign true
git config "$scope" tag.gpgsign true

echo "agent-signing: git ($scope) will sign as $AGENT_GIT_NAME <$AGENT_GIT_EMAIL> with key ${fingerprint: -16}"
