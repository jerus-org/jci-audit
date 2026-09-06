FROM rust:1-slim-trixie@sha256:17d1ba895198f9934c6314ec5346a0d5115372f3243390c3d731e242f35c2f27 AS builder
ARG CRATE_VERSION
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && { err=/tmp/cargo-install.err; n=0; \
       until cargo install jci-audit --locked \
             --version "${CRATE_VERSION}" 2>"$err"; do \
         cat "$err" >&2; \
         grep -q "failed to compile" "$err" \
           && echo "build failed, not an index delay" >&2 && exit 1; \
         n=$((n+1)); \
         [ "$n" -ge 40 ] \
           && echo "crates.io index never served ${CRATE_VERSION}" >&2 \
           && exit 1; \
         echo "waiting for crates.io index: ${CRATE_VERSION} (try $n)"; \
         rm -rf "${CARGO_HOME:-/usr/local/cargo}"/registry/index/*/.cache; \
         sleep 15; \
       done; }
# Pinned below the jci-audit install above, not above it: an ENV layer
# invalidates every RUN after it, and these four versions have nothing to do
# with that install, so bumping one must not force it to rebuild too.
# renovate: datasource=crate depName=cargo-about packageName=cargo-about versioning=semver-coerced
ENV CARGO_ABOUT_VERSION=0.9.2
# renovate: datasource=crate depName=cargo-audit packageName=cargo-audit versioning=semver-coerced
ENV CARGO_AUDIT_VERSION=0.22.2
# renovate: datasource=crate depName=cargo-deny packageName=cargo-deny versioning=semver-coerced
ENV CARGO_DENY_VERSION=0.20.2
# renovate: datasource=crate depName=rsign2 packageName=rsign2 versioning=semver-coerced
ENV RSIGN2_VERSION=0.6.6
RUN cargo install cargo-binstall --locked \
    && cargo binstall --locked cargo-about --version "${CARGO_ABOUT_VERSION}" --no-confirm \
    && cargo binstall --locked cargo-audit --version "${CARGO_AUDIT_VERSION}" --no-confirm \
    && cargo binstall --locked cargo-deny --version "${CARGO_DENY_VERSION}" --no-confirm \
    && cargo binstall --locked rsign2 --version "${RSIGN2_VERSION}" --no-confirm

FROM rust:1-slim-trixie@sha256:17d1ba895198f9934c6314ec5346a0d5115372f3243390c3d731e242f35c2f27
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    gnupg \
    openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -ms /bin/bash circleci
COPY --from=builder /usr/local/cargo/bin/jci-audit /usr/local/bin/jci-audit
COPY --from=builder /usr/local/cargo/bin/cargo-about /usr/local/bin/cargo-about
COPY --from=builder /usr/local/cargo/bin/cargo-audit /usr/local/bin/cargo-audit
COPY --from=builder /usr/local/cargo/bin/cargo-deny /usr/local/bin/cargo-deny
COPY --from=builder /usr/local/cargo/bin/rsign /usr/local/bin/rsign
USER circleci
WORKDIR /home/circleci/project
