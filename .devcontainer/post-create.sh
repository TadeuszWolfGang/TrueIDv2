#!/usr/bin/env bash
# Runs inside the dev container after creation.
set -euxo pipefail

# Named volumes are root-owned on first use.
sudo chown -R vscode:vscode /usr/local/cargo /usr/local/rustup || true

# Install the pinned toolchain (from rust-toolchain.toml) and warm the cache.
rustup show
cargo fetch --locked

# Python connector deps (lockfile is created in Phase 5; keep this tolerant
# so the dev container also works on branches without the uv migration).
if [ -f integrations/sycope/pyproject.toml ]; then
  (cd integrations/sycope && uv sync --frozen)
fi
