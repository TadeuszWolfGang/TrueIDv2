# syntax=docker/dockerfile:1.7
# Pinned by digest; Dependabot (docker ecosystem, this directory) bumps it.
FROM python:3.11-slim@sha256:673719e071ecf27434fd2635bbd8d00f49f4fdd81f243143438a42ced8bedf60

COPY --from=ghcr.io/astral-sh/uv:0.12.8 /uv /uvx /bin/

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
