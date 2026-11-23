# Agent signing hook

`agent-signing.sh` makes a Claude cloud session author and GPG-sign commits as
the agent's GitHub account, so the `verify-signatures` check can attribute them
to a known identity instead of the generic `noreply@anthropic.com`.

**Status: not wired.** Nothing runs the script automatically. Run it by hand
(`.claude/hooks/agent-signing.sh`) at the start of a session, or, only after
reading *Security* below, register it as a `SessionStart` hook.

It reads these variables from the cloud environment's settings (never from the
repository):

| Variable | Content |
|---|---|
| `AGENT_GPG_KEY` | base64 of the ASCII-armored secret key (no passphrase) |
| `AGENT_GPG_TRUST` | ownertrust line, `<FINGERPRINT>:6:` |
| `AGENT_GIT_NAME` | author/committer name |
| `AGENT_GIT_EMAIL` | author/committer email, verified on the agent's GitHub account |

The public key must be registered on the agent's GitHub account, and the
account must be a write collaborator, for the trust map to include it. With
`AGENT_GPG_KEY` unset the script does nothing.

## Security

The key is passphrase-less and stored as plain-text environment variables, and
the verifier trusts commits signed with it. Treat it as a credential that a
session can read.

**The risk.** A hook is read from whatever branch a cloud session has checked
out. A branch that edits this script or the hook registration in
`.claude/settings.json` can read `AGENT_GPG_KEY` and send it anywhere the
environment's network allows. Code-owner review on `.claude/` (the repo's
`CODEOWNERS` already covers everything) protects what gets merged, not a
branch opened in a session before it is reviewed. The script cannot defend
itself: a branch can remove any check it contains.

**The control that works is environment scoping, which is yours to enforce:**

- Put the four `AGENT_*` variables **only** in a dedicated cloud environment,
  never in the default one.
- Use that environment **only** for branches you or a trusted collaborator
  created. Never open a fork, an external contributor's branch or an
  unreviewed Renovate branch in it.
- Keep that environment's network allow-list as small as possible, so a
  tampered script has nowhere to send the key.
- Give the key a short expiry (90 days or less) and keep a revocation
  certificate offline; revoke it if a session or branch was ever exposed.
- Review any change under `.claude/` as security-sensitive.
