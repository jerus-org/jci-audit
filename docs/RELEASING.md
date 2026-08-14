<!--
SPDX-FileCopyrightText: 2026 jerusdp

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Releasing & verifying releases

This document describes how jci-audit releases are produced and signed, and — most
importantly for downstream users — **how to verify a release**. It satisfies the "signed
releases with a documented verification process" expectation of the OpenSSF Best Practices
badge. Every command below was run against a real release (`jci-audit-v0.0.7`) before being
written up here.

## What is signed

A jci-audit release carries three independent, cryptographically verifiable signatures:

| Artifact | Signature | Trust anchor |
|----------|-----------|--------------|
| Git **tag** `jci-audit-v<version>` and its release commit | **GPG** signature | The project's CI signing key, published on its bot account |
| The published **`.crate`** (crates.io) | **SLSA v0.2 provenance attestation** via Sigstore *keyless* signing | Fulcio root CA + Rekor transparency log + the CircleCI OIDC build identity |
| The **binary tarball** `jci-audit-<target>.tar.gz` | **minisign/rsign** signature (`.tar.gz.sig`) | The per-release public key published in the crate's `Cargo.toml` |

## Release process (overview)

Releases run on CircleCI ([`.circleci/release.yml`](../.circleci/release.yml)):

1. `calculate-versions` — computes the next version with `nextsv`; shown for review.
2. **Manual approval** gate — a reviewer approves the calculated version before anything is
   published.
3. `build-binary` — builds the release binary from the commit being released.
4. `record-release` — runs `jci-audit release`: locks validation to a pinned advisory-db commit
   and writes `.security/release-<version>.json` locally (not committed — see
   [design.md §5–6](design.md#5-reproducibility-the-release-record) and
   [#75](https://github.com/jerus-org/jci-audit/issues/75) for how the record is distributed).
5. `release-jci-audit` — builds and **GPG-signs** the release commit + tag, generates an
   **ephemeral minisign keypair**, **signs the tarball**, injects that keypair's public key into
   `Cargo.toml` (`[package.metadata.binstall.signing]`), publishes to **crates.io**, and produces
   the **SLSA provenance attestation** (Sigstore keyless via a CircleCI `sigstore`-audience OIDC
   token → Fulcio → Rekor).
6. Pushing the `jci-audit-v*` tag triggers the tag-gated `orb-release` workflow (pack, build
   container, register + publish the `jerus-org/jci-audit` orb).

The private GPG key and the ephemeral signing key live only in CI contexts, never in the
repository.

## Verifying a release

### 1. The signed git tag

Import the CI signing key (published on the project's bot GitHub account) and verify the tag:

```bash
curl -sL https://github.com/jerus-bot.gpg | gpg --import
git verify-tag jci-audit-v<version>
git verify-commit jci-audit-v<version>^{commit}
```

GitHub also shows a **Verified** badge on the signed tag/commit.

### 2. The crate's SLSA / Sigstore attestation

Each release attaches `jci-audit-<version>.crate.sigstore.json` (the Sigstore bundle) and
`jci-audit-<version>.provenance.json` (the SLSA predicate). Verify without any extra tooling:

```bash
VER=<version>
gh release download "jci-audit-v$VER" --repo jerus-org/jci-audit \
  --pattern "*.sigstore.json"

# (a) The bundle's messageDigest must equal the crate's SHA-256
#     (download the .crate from crates.io and sha256sum it, then compare)
python3 -c "import json,base64; b=json.load(open('jci-audit-$VER.crate.sigstore.json')); \
  print(base64.b64decode(b['messageSignature']['messageDigest']['digest']).hex())"

# (b) The Fulcio signing certificate binds the signature to this project's CI build identity
python3 -c "import json,base64; b=json.load(open('jci-audit-$VER.crate.sigstore.json')); \
  open('leaf.der','wb').write(base64.b64decode( \
  b['verificationMaterial']['x509CertificateChain']['certificates'][0]['rawBytes']))"
openssl x509 -inform DER -in leaf.der -noout -text | grep -A2 "Subject Alternative Name"
```

The two SHA-256 values in (a) must match. In (b) the certificate's SAN embeds the CircleCI
pipeline identity and the OIDC issuer `https://oidc.circleci.com/org/<org-id>`, proving the crate
was signed by this project's own release pipeline. The signing event is also recorded in the
public **Rekor** transparency log referenced in the bundle.

### 3. The binary tarball signature

`cargo binstall` verifies the tarball automatically using the minisign public key published in
the crate's `Cargo.toml`:

```bash
cargo binstall jci-audit          # verifies the .sig before installing
```

To verify by hand, obtain that version's public key from its `Cargo.toml` on crates.io and:

```bash
rsign verify -P "<pubkey>" -x jci-audit-<target>.tar.gz.sig jci-audit-<target>.tar.gz
```

## Trust model summary

- **GPG** — a long-lived CI signing key, published on the bot account; verify against its
  published public key.
- **Sigstore (crate)** — *keyless*: there is no long-lived key to trust; trust derives from the
  Fulcio CA, the Rekor transparency log, and the CircleCI OIDC identity embedded in the
  short-lived certificate.
- **minisign (binary)** — an ephemeral key generated per release; its public key is published in
  the released crate's `Cargo.toml` and used by `cargo binstall`.
