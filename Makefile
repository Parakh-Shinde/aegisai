.DEFAULT_GOAL := help

.PHONY: help setup start stop restart logs status doctor migrate backup test lint build clean

help:
	@echo "AEGISAI local security lab"
	@echo "  make setup    Create .env from the safe local template"
	@echo "  make start    Build and launch the lab at http://127.0.0.1:5173"
	@echo "  make stop     Stop the lab without deleting evaluation data"
	@echo "  make logs     Follow service logs"
	@echo "  make status   Show service status"
	@echo "  make doctor   Validate the Docker configuration"
	@echo "  make migrate  Apply PostgreSQL schema migrations"
	@echo "  make backup   Save a timestamped PostgreSQL backup under backups/"
	@echo "  make test     Run backend tests in Docker"
	@echo "  make lint     Run backend lint and frontend lint in Docker"
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

migrate:
	docker compose exec api alembic upgrade head

backup:
	@mkdir -p backups
	docker compose exec -T postgres pg_dump -U "$${POSTGRES_USER:-aegisai}" "$${POSTGRES_DB:-aegisai}" > backups/aegisai-$$(date +%Y%m%d-%H%M%S).sql
	@echo "Database backup saved under backups/."

test:
	docker compose run --rm --no-deps api pytest /app/tests

lint:
	docker compose run --rm --no-deps api ruff check /app
	docker compose run --rm --no-deps web-check

build:
	docker compose build

clean:
	docker compose down --volumes --remove-orphans
