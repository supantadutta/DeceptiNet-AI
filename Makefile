# DeceptiNet-AI — operator entrypoints.
# `make help` lists targets. Docker Compose is the primary deployment (spec §3).

COMPOSE ?= docker compose
PY ?= python3
VENV ?= .venv
KILL_FILE ?= /tmp/deceptinet.stop

.DEFAULT_GOAL := help
.PHONY: help venv test lint up down build logs ps kill resume experiment \
        run-local clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create the local virtualenv and install dev dependencies
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install -q --upgrade pip
	$(VENV)/bin/pip install -q -r requirements-dev.txt

test: ## Run the test suite (creates venv if needed)
	@[ -x $(VENV)/bin/pytest ] || $(MAKE) venv
	$(VENV)/bin/python -m pytest -q

build: ## Build the Docker images
	$(COMPOSE) build

up: ## Start the honeypot stack (Docker, default-deny egress)
	$(COMPOSE) up -d --build
	@echo "DeceptiNet-AI up. Health: http://127.0.0.1:8000/health"

down: ## Stop the stack
	$(COMPOSE) down

logs: ## Tail the honeypot logs
	$(COMPOSE) logs -f deceptinet

ps: ## Show running services
	$(COMPOSE) ps

kill: ## KILL SWITCH: stop all exposed listeners immediately
	@$(COMPOSE) exec deceptinet touch $(KILL_FILE) \
		&& echo "Kill switch ENGAGED ($(KILL_FILE)). Listeners stop within ~1s." \
		|| echo "Could not engage kill switch (is the stack running?)."

resume: ## Release the kill switch and resume listeners
	@$(COMPOSE) exec deceptinet rm -f $(KILL_FILE) \
		&& echo "Kill switch RELEASED. Listeners resume within ~1s." \
		|| echo "Could not release kill switch (is the stack running?)."

run-local: ## Run the honeypot directly (no Docker; SQLite datastore)
	@[ -x $(VENV)/bin/python ] || $(MAKE) venv
	$(VENV)/bin/python -m deceptinet

experiment: ## Run the A/B comparison harness over captured data (-> paper/)
	@[ -x $(VENV)/bin/python ] || $(MAKE) venv
	$(VENV)/bin/python scripts/experiment.py

clean: ## Remove local runtime artifacts (data/, caches). Keeps source.
	rm -rf data/ .pytest_cache __pycache__ */__pycache__ */*/__pycache__
	@echo "Cleaned runtime artifacts."
