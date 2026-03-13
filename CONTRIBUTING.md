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

- Rust stable (>= 1.82) — install via [rustup](https://rustup.rs)
- SQLite 3
- Docker + Docker Compose (for integration tests)

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
