# syntax=docker/dockerfile:1.7
# Pinned by digest; Dependabot (docker ecosystem, this directory) bumps it.
FROM python:3.11-slim@sha256:d1e9ca7c4e78d1e8ecadb5d44bfc8e956e7a65b659a9950f569f243d72b326d0

COPY --from=ghcr.io/astral-sh/uv:0.12.8 /uv /uvx /bin/

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
