# Stage 1: Build
FROM rust:1.84-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 sqlite3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/trueid-engine /usr/local/bin/trueid-engine
COPY --from=builder /src/target/release/trueid-web   /usr/local/bin/trueid-web
COPY --from=builder /src/apps/web/assets              /app/assets

WORKDIR /app

ENV DATABASE_URL=sqlite:///app/data/trueid.db?mode=rwc

EXPOSE 1813/udp 5514/udp 5516/udp 3000
