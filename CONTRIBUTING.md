# Contributing to TrueID

Thanks for your interest in contributing! This document covers the basics.

## Getting Started

```bash
git clone <repo-url> && cd TrueID
make setup
make test
make lint
```

### Requirements

- Rust 1.95.0 (pinned by `rust-toolchain.toml`; rustup installs it automatically)
- SQLite 3
- Docker + Docker Compose (for integration tests)
- Python 3.11 only for the Sycope connector (`integrations/sycope/`)

## Dev Container (recommended)

The whole dev environment (Rust toolchain, uv/Python, Docker CLI) runs in a
container — nothing but Docker is required on your machine:

- **VS Code**: install the "Dev Containers" extension, then
  `Dev Containers: Reopen in Container`.
- **CLI**: `npx @devcontainers/cli up --workspace-folder .`

Everything is pinned for determinism: Rust 1.95.0 via `rust-toolchain.toml`
(shared with CI and the production builder), Python 3.11 via
`.python-version` with dependencies locked in `uv.lock`, and container
features locked in `devcontainer-lock.json`. CI builds and verifies the same
container in `devcontainer.yml`, keeping local and CI environments consistent.

The container reuses the host Docker daemon, so `docker compose up` and
`make docker-*` work inside it. Ports 3000 (web) and 8080 (engine admin API)
are forwarded automatically. UDP listeners (RADIUS/syslog) are NOT forwarded
by dev containers — test them via `docker compose up` with published ports.

## Development Workflow

1. **Fork & branch** — create a feature branch from `main`.
2. **Code** — make your changes.
3. **Test** — run `make test` (unit + integration).
4. **Lint** — run `make lint` (`cargo fmt --check` + `cargo clippy -D warnings`). CI enforces this.
5. **Commit** — use clear, descriptive commit messages.
6. **PR** — open a pull request against `main`.

## Code Style

- Follow standard Rust conventions (`rustfmt` defaults).
- All warnings are errors in CI (`clippy -D warnings`).
- Keep modules focused — one responsibility per file.
- Add doc comments (`///`) to public items.

## Project Structure

| Path | Description |
|------|-------------|
| `crates/common` | Shared models, DB layer, migrations, config |
| `crates/ingest` | Ingestion pipeline and event normalization |
| `crates/adapter-*` | Protocol-specific parsers (RADIUS, AD, DHCP) |
| `crates/agent` | Windows agent for AD/DHCP event collection |
| `apps/engine` | Main engine binary (listeners, correlation, push) |
| `apps/web` | REST API, dashboard, auth/RBAC |
| `apps/cli` | CLI client (`trueid`) |
| `integrations/` | Third-party integration connectors |

## Database Migrations

Migrations live in `crates/common/migrations/` and run automatically on startup.

To add a new migration:
1. Create `NNNN_description.sql` (next sequential number).
2. Write idempotent SQL (`CREATE TABLE IF NOT EXISTS`, etc.).
3. Test with a fresh database (`make clean && make engine`).

## Tests

- **Unit tests**: `cargo test --workspace`
- **Integration tests**: `make test-integration` (requires a running instance)
- **Smoke tests**: `make smoke-test` (curl-based, requires a running instance)

## Reporting Issues

- Use GitHub Issues for bugs and feature requests.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
