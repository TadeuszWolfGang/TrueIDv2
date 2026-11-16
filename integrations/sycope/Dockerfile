# syntax=docker/dockerfile:1.7
# Pinned by digest; Dependabot (docker ecosystem, this directory) bumps it.
FROM python:3.11-alpine@sha256:769f2b47fc4722cc68ce31b9629672b2253919ce8286197c9d4fec7bf44c9ae5

COPY --from=ghcr.io/astral-sh/uv:0.12.8 /uv /uvx /bin/

# Pull security fixes published after the pinned base was built (krb5-libs CVEs).
# Guarded on apk so the derived Debian CI fixture skips it.
RUN if command -v apk >/dev/null 2>&1; then apk add --no-cache --upgrade 'krb5-libs>=1.22.3-r0'; fi

# Update inherited packaging tooling separately from the locked application environment.
RUN set -eux; \
    packaging_requirements="$(mktemp)"; \
    printf '%s\n' 'setuptools==84.2.0 --hash=sha256:8cc107ac7a403105dc8d6477664171f36135fab26adf8b5e0edaebc313f39b21' > "$packaging_requirements"; \
    python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r "$packaging_requirements"; \
    rm -f "$packaging_requirements"

ENV UV_PYTHON_INSTALL_DIR=/opt/uv-pythons \
    UV_PROJECT_ENVIRONMENT=/app/integrations/sycope/.venv \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Shared Sycope SDK from repo root (build context is the repo root).
COPY sycope/ /app/sycope/

# Connector: lockfile first for layer caching.
COPY integrations/sycope/pyproject.toml integrations/sycope/uv.lock integrations/sycope/.python-version /app/integrations/sycope/

RUN cd integrations/sycope && uv sync --frozen --no-dev --compile-bytecode

# Source (sync also install runtime code paths; no packaging yet).
COPY integrations/sycope/ /app/integrations/sycope/

ENV PYTHONPATH="/app"

WORKDIR /app/integrations/sycope
CMD [".venv/bin/python", "trueid_sync.py"]
