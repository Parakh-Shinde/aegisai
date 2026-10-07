#!/usr/bin/env sh
set -eu

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Review OLLAMA_BASE_URL before starting."
fi

docker compose up --build --detach
echo "AEGISAI is starting at http://127.0.0.1:5173"
