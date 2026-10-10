.DEFAULT_GOAL := help

.PHONY: help setup start stop restart logs status doctor config-check migrate backup verify-backup restore encrypt-evidence agent-gateway-demo promptfoo-run test lint build release-gate clean

help:
	@echo "AEGISAI local security lab"
	@echo "  make setup    Create .env from the safe local template"
	@echo "  make start    Build and launch the lab at http://127.0.0.1:5173"
	@echo "  make stop     Stop the lab without deleting evaluation data"
	@echo "  make logs     Follow service logs"
	@echo "  make status   Show service status"
	@echo "  make doctor   Validate the Docker configuration"
	@echo "  make config-check  Validate effective AEGISAI settings without printing secrets"
	@echo "  make migrate  Apply PostgreSQL schema migrations"
	@echo "  make backup   Save a checksummed PostgreSQL backup under backups/"
	@echo "  make verify-backup BACKUP=backups/file.dump  Verify a backup before storing or restoring it"
	@echo "  make restore BACKUP=backups/file.dump CONFIRM_RESTORE=YES  Replace the database from a verified backup"
	@echo "  make encrypt-evidence  Encrypt legacy evidence after configuring its key"
	@echo "  make agent-gateway-demo SYSTEM_ID=id  Test the agent runtime integration client"
	@echo "  make promptfoo-run RUN_ID=id  Run an approved Promptfoo job in the isolated runner"
	@echo "  make test     Run backend tests in Docker"
	@echo "  make lint     Run backend lint and frontend lint in Docker"
	@echo "  make release-gate  Validate the locked evaluation release policy"
	@echo "  make clean    Stop the lab and remove local evaluation data"

setup:
	@test -f .env || cp .env.example .env
	@echo "Created .env if it did not already exist. Review OLLAMA_BASE_URL before starting."

start: setup
	docker compose up --build --detach
	@echo "AEGISAI is starting at http://127.0.0.1:5173"
	@echo "API health: http://127.0.0.1:8000/health"

stop:
	docker compose down

restart: stop start

logs:
	docker compose logs --follow

status:
	docker compose ps

doctor:
	docker compose config --quiet
	@echo "Docker configuration is valid."

config-check:
	docker compose run --rm --no-deps api python scripts/verify_runtime_config.py

migrate:
	docker compose exec api alembic upgrade head

backup:
	scripts/backup.sh

verify-backup:
	@test -n "$(BACKUP)" || (echo "Set BACKUP=backups/file.dump" >&2; exit 2)
	scripts/verify_backup.sh "$(BACKUP)"

restore:
	@test -n "$(BACKUP)" || (echo "Set BACKUP=backups/file.dump" >&2; exit 2)
	CONFIRM_RESTORE="$(CONFIRM_RESTORE)" scripts/restore.sh "$(BACKUP)"

encrypt-evidence:
	docker compose exec api python scripts/encrypt_existing_evidence.py

agent-gateway-demo:
	@test -n "$(SYSTEM_ID)" || (echo "Set SYSTEM_ID to an agent-capable AI system ID" >&2; exit 2)
	docker compose exec --workdir /app api python scripts/agent_gateway_demo.py --system-id "$(SYSTEM_ID)"

promptfoo-run:
	@test -n "$(RUN_ID)" || (echo "Set RUN_ID to a pending Promptfoo evaluation run ID" >&2; exit 2)
	docker compose --profile tools build promptfoo-runner
	docker compose --profile tools run --rm -e RUN_ID="$(RUN_ID)" promptfoo-runner

test:
	docker compose run --rm --no-deps api pytest /app/tests

lint:
	docker compose run --rm --no-deps api ruff check /app
	docker compose run --rm --no-deps web-check

build:
	docker compose build

release-gate:
	docker compose run --rm --no-deps api python scripts/release_gate.py

clean:
	docker compose down --volumes --remove-orphans
