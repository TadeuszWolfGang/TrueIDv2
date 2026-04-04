# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.88.0

FROM rust:${RUST_VERSION}-bookworm AS builder

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

# Workspace path dependencies need minimal targets before `cargo fetch`.
RUN set -eux; \
    mkdir -p \
      crates/common/src crates/ingest/src crates/adapter-radius/src \
      crates/adapter-ad-logs/src crates/adapter-dhcp-logs/src crates/utils/src \
      crates/agent/src apps/engine/src apps/cli/src apps/web/src tests/src; \
    for d in crates/common crates/ingest crates/adapter-radius crates/adapter-ad-logs \
             crates/adapter-dhcp-logs crates/utils crates/agent tests; do \
      printf '%s\n' "pub fn _dummy() {}" > "$d/src/lib.rs"; \
    done; \
    printf '%s\n' "fn main() {}" > apps/engine/src/main.rs; \
    printf '%s\n' "fn main() {}" > apps/cli/src/main.rs; \
    printf '%s\n' "fn main() {}" > apps/web/src/main.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo fetch --locked

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    set -eux; \
    cargo build --release --locked --bin trueid-engine --bin trueid-web --bin trueid --bin trueid-probe; \
    max_glibc="$(strings /src/target/release/trueid-engine | grep -o 'GLIBC_[0-9.]\+' | sort -Vu | tail -n 1)"; \
    echo "Detected max required glibc: ${max_glibc}"; \
    test -n "${max_glibc}"; \
    max_ver="${max_glibc#GLIBC_}"; \
    dpkg --compare-versions "${max_ver}" le "2.36"; \
    mkdir -p /out; \
    cp /src/target/release/trueid-engine /out/trueid-engine; \
    cp /src/target/release/trueid /out/trueid; \
    cp /src/target/release/trueid-probe /out/trueid-probe; \
    cp /src/target/release/trueid-web /out/trueid-web; \
    if [ -f /src/data/oui.csv ]; then cp /src/data/oui.csv /out/oui.csv; else : > /out/oui.csv; fi

RUN mkdir -p /runtime-root/usr/local/bin /runtime-root/app/data /runtime-root/app/tls \
    && cp /out/trueid-engine /runtime-root/usr/local/bin/trueid-engine \
    && cp /out/trueid /runtime-root/usr/local/bin/trueid \
    && cp /src/target/release/trueid-probe /runtime-root/usr/local/bin/trueid-probe \
    && cp /out/trueid-web /runtime-root/usr/local/bin/trueid-web \
    && cp -R /src/crates/common/migrations /runtime-root/app/migrations \
    && cp -R /src/apps/web/assets /runtime-root/app/assets \
    && cp /out/oui.csv /runtime-root/app/oui.csv

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /runtime-root/ /

ENV DATABASE_URL=sqlite:///app/data/net-identity.db?mode=rwc
ENV OUI_CSV_PATH=/app/oui.csv
ENV TRUEID_MIGRATIONS_DIR=/app/migrations
ENV ASSETS_DIR=/app/assets

EXPOSE 1813/udp 5514/udp 5516/udp 5518/udp 3000

CMD ["/usr/local/bin/trueid-engine"]
