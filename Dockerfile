# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.79.0

# NOTE: Keep builder on bullseye (glibc 2.31). Do not switch to bookworm/latest.
FROM rust:${RUST_VERSION}-bullseye AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    pkg-config \
    libssl-dev \
    binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependency-resolution layer (cache-friendly with BuildKit mounts).
COPY Cargo.toml Cargo.lock ./
COPY crates/common/Cargo.toml crates/common/
COPY crates/ingest/Cargo.toml crates/ingest/
COPY crates/adapter-radius/Cargo.toml crates/adapter-radius/
COPY crates/adapter-ad-logs/Cargo.toml crates/adapter-ad-logs/
COPY crates/adapter-dhcp-logs/Cargo.toml crates/adapter-dhcp-logs/
COPY crates/utils/Cargo.toml crates/utils/
COPY crates/agent/Cargo.toml crates/agent/
COPY apps/engine/Cargo.toml apps/engine/
COPY apps/cli/Cargo.toml apps/cli/
COPY apps/web/Cargo.toml apps/web/
COPY tests/Cargo.toml tests/

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo fetch --locked

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --bin trueid-engine --bin trueid-web --bin trueid

# Hard gate: fail build if required GLIBC exceeds 2.31.
RUN set -eux; \
    max_glibc="$(strings /src/target/release/trueid-engine | grep -o 'GLIBC_[0-9.]\+' | sort -Vu | tail -n 1)"; \
    echo "Detected max required glibc: ${max_glibc}"; \
    test -n "${max_glibc}"; \
    max_ver="${max_glibc#GLIBC_}"; \
    dpkg --compare-versions "${max_ver}" le "2.31"

FROM debian:bullseye-slim AS runtime

# Minimal runtime set. If ldd shows extra libs, add only missing ones.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl1.1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r trueid \
    && useradd -r -g trueid -d /app trueid

WORKDIR /app

COPY --from=builder /src/target/release/trueid-engine /usr/local/bin/trueid-engine
COPY --from=builder /src/target/release/trueid        /usr/local/bin/trueid
COPY --from=builder /src/target/release/trueid-web    /usr/local/bin/trueid-web
COPY --from=builder /src/apps/web/assets              /app/assets

RUN mkdir -p /app/data /app/tls && chown -R trueid:trueid /app

USER trueid

ENV DATABASE_URL=sqlite:///app/data/net-identity.db?mode=rwc

EXPOSE 1813/udp 5514/udp 5516/udp 5518/udp 3000 8080
