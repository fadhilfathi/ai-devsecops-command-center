# =============================================================================
# AI-DevSecOps-Command-Center - Makefile
# =============================================================================
# Common developer and CI entry points. Run `make help` to list targets.
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Load .env if present (do not commit a real .env)
ifneq (,$(wildcard ./.env))
include .env
export
endif

COMPOSE        ?= docker compose
PNPM           ?= pnpm
NODE           ?= node
SERVICES       := auth agent security incident compliance integration
SERVICES_DIR   := backend/services

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
	/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ----------------------------------------------------------------------------
# Local stack
# ----------------------------------------------------------------------------
.PHONY: up down logs ps restart build

up: ## Bring the local stack up (docker compose)
	$(COMPOSE) up -d
	@echo "Stack is up. Frontend: http://localhost:5173  Grafana: http://localhost:3001 (admin/admin)"

down: ## Tear the local stack down
	$(COMPOSE) down

logs: ## Tail logs for the local stack
	$(COMPOSE) logs -f --tail=100

ps: ## List running containers
	$(COMPOSE) ps

restart: ## Restart the local stack
	$(COMPOSE) restart

build: ## Build all images
	$(COMPOSE) build

# ----------------------------------------------------------------------------
# Install / dependencies
# ----------------------------------------------------------------------------
.PHONY: install deps

install: deps ## Install workspace dependencies (pnpm)

deps: ## Install pnpm deps for the whole monorepo
	$(PNPM) install --frozen-lockfile

# ----------------------------------------------------------------------------
# Code quality
# ----------------------------------------------------------------------------
.PHONY: lint format typecheck test test-unit test-e2e

lint: ## Lint everything
	$(PNPM) -r lint

format: ## Format with Prettier
	$(PNPM) format

typecheck: ## Run TypeScript type checks
	$(PNPM) -r typecheck

test: test-unit ## Run unit tests

test-unit: ## Run unit tests across all packages
	$(PNPM) -r --if-present test

test-e2e: ## Run end-to-end tests
	$(PNPM) test:e2e

# ----------------------------------------------------------------------------
# Per-service shortcuts
# ----------------------------------------------------------------------------
.PHONY: svc-%
svc-%: ## Run a command inside a service (e.g. make svc-auth-shell)
	@echo "Target svc-$* is a prefix; use one of the explicit targets."

dev-auth: ## Run auth service in dev mode
	$(PNPM) --filter @aicc/auth-service dev

dev-agent: ## Run agent service in dev mode
	$(PNPM) --filter @aicc/agent-service dev

dev-security: ## Run security service in dev mode
	$(PNPM) --filter @aicc/security-service dev

dev-incident: ## Run incident service in dev mode
	$(PNPM) --filter @aicc/incident-service dev

dev-compliance: ## Run compliance service in dev mode
	$(PNPM) --filter @aicc/compliance-service dev

dev-integration: ## Run integration service in dev mode
	$(PNPM) --filter @aicc/integration-service dev

dev-frontend: ## Run frontend in dev mode
	$(PNPM) --filter @aicc/frontend dev

# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
.PHONY: db-migrate db-rollback db-seed db-reset db-shell

db-migrate: ## Run database migrations
	$(PNPM) --filter @aicc/db-migrations run migrate

db-rollback: ## Roll back the last migration
	$(PNPM) --filter @aicc/db-migrations run rollback

db-seed: ## Seed the database with demo data
	$(PNPM) --filter @aicc/db-migrations run seed

db-reset: ## Drop, recreate, migrate, and seed the database (DESTRUCTIVE)
	@echo "This will DESTROY all data in your local database." && \
	read -p "Are you sure? [y/N] " ans && [[ $$ans == y ]] && $(COMPOSE) down -v && $(COMPOSE) up -d postgres && \
	sleep 5 && $(MAKE) db-migrate && $(MAKE) db-seed || echo "Aborted."

db-shell: ## Open a psql shell against the dev database
	$(COMPOSE) exec postgres psql -U aionrs -d command_center

# ----------------------------------------------------------------------------
# Release
# ----------------------------------------------------------------------------
.PHONY: release release-dry

release-dry: ## Dry-run a release (no commit/tag)
	$(PNPM) exec standard-version --dry-run

release: ## Cut a release (commits, tags, updates CHANGELOG)
	$(PNPM) exec standard-version

# ----------------------------------------------------------------------------
# Housekeeping
# ----------------------------------------------------------------------------
.PHONY: clean clean-all

clean: ## Remove build artifacts and caches
	$(PNPM) -r exec rimraf dist node_modules .turbo .cache coverage
	rm -rf .turbo

clean-all: clean ## Remove build artifacts, caches, and Docker volumes
	$(COMPOSE) down -v
	docker system prune -f
