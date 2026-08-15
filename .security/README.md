# Release security records

Each release records the security validation it passed, as
`release-<VERSION>.json`. A record names the advisory-db commit the release was
locked to, the versions of the tools that ran, and digests of the dependency set
and of the policy (`deny.toml`) in force at the time. `jci-audit verify --release-version
<VERSION>` re-runs the gate offline against that snapshot, so a past release can
be checked later without trusting the pipeline that produced it.

Records are written only when the gate passes, and they are deterministic: no
timestamps, and live-audit results excluded, so re-running produces a
byte-identical file.

**The records below (0.0.4–0.0.7) are historical.** Starting with the release
that ships [#75](https://github.com/jerus-org/jci-audit/issues/75) phase 1,
`jci-audit release` no longer commits the record here — it's written locally
and left `.gitignore`'d, pending distribution as a signed release asset
(tracked in the same issue). This directory won't gain new entries going
forward; the files already here are kept as-is.

## 0.0.3 has no record

**Version 0.0.3 is published and no record exists for it. This is permanent.**

`jci-audit verify --release-version 0.0.3` will fail with `no release record at
'.security/release-0.0.3.json'`. That failure is correct and should not be worked
around: there is nothing to verify.

What happened: the gate ran and passed, and the record file was written — but the
step that committed it staged nothing, because it passed git an absolute path.
git resolves index entries as pathspecs against the working directory, and a
pathspec that matches nothing is not an error, so the commit was empty and was
reported as a success. Two commits on `main` claim to record 0.0.3 and both are
empty:

    0bf4e36  chore: record security validation for 0.0.3
    d153a57  chore: record security validation for 0.0.3

They cannot be reverted — there is nothing in them to revert — and they cannot be
removed, being ancestors of the published `jci-audit-v0.0.3` tag. They are
recorded here as void so that anyone reading the history is not misled by them.

The fix is in #37, which makes the paths relative and refuses to commit when
nothing was staged. The first release carrying a real record is 0.0.4.

### Why this is not back-filled

A record written now would attest to a validation run that is not the one the
release passed through. The advisory-db commit it pinned is not recoverable from
here, and a reconstruction would be indistinguishable from the genuine artefact
while carrying none of its meaning.

Fabricating it would be a worse failure than the gap: the point of a record is
that it was produced by the release it describes. A tool that back-fills its own
attestations when convenient cannot be trusted when it matters. The gap is
documented instead.
