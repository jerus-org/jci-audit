FROM rust:1-slim-trixie@sha256:cc0448b41c3b7b7fea44f5dc50eacba729a56db365b65b7bd5e8a82d5b3db078 AS builder
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
RUN cargo install cargo-binstall --locked \
    && cargo binstall --no-confirm \
    cargo-about \
    cargo-audit \
    cargo-deny \
    rsign2

FROM rust:1-slim-trixie@sha256:cc0448b41c3b7b7fea44f5dc50eacba729a56db365b65b7bd5e8a82d5b3db078
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
