FROM rust:1-slim-trixie@sha256:5c6f46a6e4472ab1ca7ba7d494e6677f2f219ebc02f32025d3986f057635ec9c AS builder
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
    && { n=0; until cargo install jci-audit --version "${CRATE_VERSION}" --locked; do \
         n=$((n+1)); \
         [ "$n" -ge 20 ] && echo "crates.io index never served ${CRATE_VERSION}" >&2 && exit 1; \
         echo "waiting for crates.io index to propagate ${CRATE_VERSION} (attempt $n)"; \
         sleep 15; \
       done; }
RUN cargo install cargo-binstall --locked \
    && cargo binstall --no-confirm cargo-audit cargo-deny

FROM rust:1-slim-trixie@sha256:5c6f46a6e4472ab1ca7ba7d494e6677f2f219ebc02f32025d3986f057635ec9c
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    gnupg \
    openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -ms /bin/bash circleci
COPY --from=builder /usr/local/cargo/bin/jci-audit /usr/local/bin/jci-audit
COPY --from=builder /usr/local/cargo/bin/cargo-audit /usr/local/bin/cargo-audit
COPY --from=builder /usr/local/cargo/bin/cargo-deny /usr/local/bin/cargo-deny
USER circleci
WORKDIR /home/circleci/project
