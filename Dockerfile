# Stage 1: Build
FROM rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates/common/Cargo.toml crates/common/
COPY crates/ingest/Cargo.toml crates/ingest/
COPY crates/adapter-radius/Cargo.toml crates/adapter-radius/
COPY crates/adapter-ad-logs/Cargo.toml crates/adapter-ad-logs/
COPY crates/adapter-dhcp-logs/Cargo.toml crates/adapter-dhcp-logs/
COPY crates/utils/Cargo.toml crates/utils/
COPY crates/agent/Cargo.toml crates/agent/
COPY apps/engine/Cargo.toml apps/engine/
COPY apps/web/Cargo.toml apps/web/
COPY tests/Cargo.toml tests/
# Create dummy src files for dependency caching
RUN mkdir -p crates/common/src crates/ingest/src crates/adapter-radius/src \
    crates/adapter-ad-logs/src crates/adapter-dhcp-logs/src crates/utils/src \
    crates/agent/src apps/engine/src apps/web/src tests/src && \
    for d in crates/common crates/ingest crates/adapter-radius crates/adapter-ad-logs \
    crates/adapter-dhcp-logs crates/utils crates/agent apps/engine apps/web tests; do \
        echo "" > "$d/src/lib.rs"; \
    done && \
    echo "fn main(){}" > apps/engine/src/main.rs && \
    echo "fn main(){}" > apps/web/src/main.rs
RUN cargo build --release --locked 2>/dev/null || true
# Now copy real source and build
COPY . .
RUN touch crates/*/src/*.rs apps/*/src/*.rs && \
    cargo build --release --locked --bin trueid-engine --bin trueid-web

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 sqlite3 curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r trueid && useradd -r -g trueid -d /app trueid

COPY --from=builder /src/target/release/trueid-engine /usr/local/bin/trueid-engine
COPY --from=builder /src/target/release/trueid-web   /usr/local/bin/trueid-web
COPY --from=builder /src/apps/web/assets              /app/assets

RUN mkdir -p /app/data /app/tls && chown -R trueid:trueid /app

WORKDIR /app
USER trueid

ENV DATABASE_URL=sqlite:///app/data/net-identity.db?mode=rwc

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:3000/health || exit 1

EXPOSE 1813/udp 5514/udp 5516/udp 5518/udp 3000 8080
