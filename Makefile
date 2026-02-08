.PHONY: setup run engine web check clean help

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  make %-12s %s\n", $$1, $$2}'

setup: ## First-time setup: copy .env, build, init DB
	@echo "=== TrueID Setup ==="
	@test -f .env || (cp .env.example .env && echo "Created .env from .env.example") || \
		echo ".env.example not found — create .env manually (see README.md)"
	@echo "Building project..."
	cargo build
	@echo ""
	@echo "Setup complete! Run: make run"

engine: ## Run trueid-engine (ingestion + admin API)
	cargo run -p trueid-engine

web: ## Run trueid-web (dashboard on port 3000)
	cargo run -p trueid-web

run: ## Run engine + web together (engine in background)
	@echo "Starting engine in background..."
	@cargo run -p trueid-engine &
	@sleep 2
	@echo "Starting web dashboard..."
	cargo run -p trueid-web

check: ## Health check: .env, DB, server status
	@echo "=== TrueID Health Check ==="
	@test -f .env && echo ".env exists" || echo ".env missing — run: make setup"
	@test -f net-identity.db && echo "Database file exists" || echo "Database missing — run: make engine"
	@nc -z 127.0.0.1 3000 2>/dev/null && echo "Web server running on port 3000" || echo "Web server not running — run: make web"
	@nc -z 127.0.0.1 8080 2>/dev/null && echo "Engine admin API running on port 8080" || echo "Engine not running — run: make engine"

test-integration: ## Run integration tests (requires running instance)
	@echo "Running integration tests against $${TRUEID_TEST_URL:-http://127.0.0.1:3000}..."
	cargo test -p trueid-integration-tests -- --test-threads=1

smoke-test: ## Run smoke test with curl (requires running instance)
	@./scripts/smoke-test.sh $${TRUEID_TEST_URL:-http://127.0.0.1:3000}

clean: ## Remove database and temp files
	rm -f net-identity.db net-identity.db-shm net-identity.db-wal
	@echo "Database removed. Run 'make setup' to recreate."
