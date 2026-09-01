# TrueID dev container. Toolchain versions are NOT pinned here on purpose:
# - Rust is pinned by rust-toolchain.toml (repo root) — single source of truth,
#   shared with CI and the production Dockerfile.
# - Python is pinned by integrations/sycope/.python-version (managed by uv).
FROM mcr.microsoft.com/devcontainers/base:1-bookworm

# Keep aligned with the builder stage of the root Dockerfile.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        pkg-config \
        libssl-dev \
        sqlite3 \
        jq \
        gettext-base \
    && rm -rf /var/lib/apt/lists/*

# rustup WITHOUT a default toolchain; rust-toolchain.toml drives the version.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:${PATH}
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none --profile minimal --no-modify-path \
    && chmod -R a+rwX /usr/local/rustup /usr/local/cargo

# uv (pinned) — manages its own Pythons, so no system Python is needed.
ARG UV_VERSION=0.12.8
RUN curl -LsSf https://astral.sh/uv/${UV_VERSION}/install.sh \
    | sh -s -- --no-modify-path \
    && mv /root/.local/bin/uv /usr/local/bin/uv \
    && mv /root/.local/bin/uvx /usr/local/bin/uvx \
    && uv --version
ENV UV_PYTHON_INSTALL_DIR=/usr/local/pythons

# Pre-install the pinned CPython as root: the connector requires >=3.11,<3.12
# and the base image ships a newer system Python, so uv would otherwise try to
# download 3.11 at post-create time — as user `vscode`, without write access
# to /usr/local/pythons. Keeping the dir world-writable allows patch updates.
RUN uv python install 3.11 \
    && chmod -R a+rwX /usr/local/pythons
