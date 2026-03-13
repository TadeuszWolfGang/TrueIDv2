.PHONY: setup run engine web check clean help secrets docker-build docker-up docker-down docker-logs docker-status docker-shell-engine docker-shell-web docker-backup test test-web test-engine lint test-integration smoke-test security-pipeline

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

security-pipeline: ## Run 3-layer security pipeline locally (SAST + container + DAST)
	@./scripts/security-pipeline.sh

secrets: ## Generate all required secrets for .env
	@echo "JWT_SECRET=$$(openssl rand -hex 32)"
	@echo "ENGINE_SERVICE_TOKEN=$$(openssl rand -hex 32)"
	@echo "CONFIG_ENCRYPTION_KEY=$$(openssl rand -hex 32)"
	@echo "ARGON2_PEPPER=$$(openssl rand -hex 16)"
	@echo ""
	@echo "Copy these values to your .env file."

docker-build: ## Build Docker image
	docker compose build

docker-up: ## Start all services (detached)
	docker compose up -d

docker-down: ## Stop all services
	docker compose down

docker-logs: ## Follow logs from all services
	docker compose logs -f

docker-status: ## Show service status and health
	docker compose ps

docker-shell-engine: ## Open shell in engine container
	docker compose exec engine sh

docker-shell-web: ## Open shell in web container
	docker compose exec web sh

docker-backup: ## Backup SQLite database
	@mkdir -p backups
	@STAMP=$$(date +%Y%m%d-%H%M%S); \
	docker compose exec engine sqlite3 /app/data/net-identity.db ".backup '/app/data/backup.db'"; \
	docker compose cp engine:/app/data/backup.db ./backups/trueid-$$STAMP.db; \
	docker compose exec engine rm -f /app/data/backup.db; \
	echo "Backup saved to ./backups/trueid-$$STAMP.db"

test: ## Run all tests
	cargo test --workspace

test-web: ## Run web E2E tests only
	cargo test -p trueid-web

test-engine: ## Run engine unit tests only
	cargo test -p trueid-engine

lint: ## Run clippy + fmt check
	cargo fmt -- --check
	cargo clippy --workspace -- -D warnings

clean: ## Remove database and temp files
	rm -f net-identity.db net-identity.db-shm net-identity.db-wal
	@echo "Database removed. Run 'make setup' to recreate."
