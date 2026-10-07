# Run AEGISAI with Docker

AEGISAI uses Docker Compose to run the dashboard, API, and PostgreSQL as local-only services.
The database is stored in the local Docker volume `aegisai-postgres`, so test evidence
survives a restart.

## Prerequisites

- Docker Desktop with Docker Compose v2.
- Ollama running on the same computer.
- At least one installed Ollama model, such as `qwen2.5:3b`.

On Windows, start Ollama in PowerShell:

```powershell
$env:OLLAMA_HOST="0.0.0.0:11434"
ollama serve
```

## Start the lab

```bash
git clone https://github.com/Parakh-Shinde/aegisai.git
cd aegisai
make start
```

Open the dashboard at <http://127.0.0.1:5173>.

The API is available only from the same computer at
<http://127.0.0.1:8000>. Confirm it is healthy with:

```bash
curl http://127.0.0.1:8000/health
```

## Configure Ollama

`make start` copies `.env.example` to `.env` if needed. The default works with
Docker Desktop on Windows and macOS:

```env
OLLAMA_BASE_URL=http://host.docker.internal:11434
```

If you use Docker from WSL and Ollama runs on Windows, replace the hostname with
the Windows host IP:

```bash
ip route | awk '/default/ {print $3}'
```

Then set `OLLAMA_BASE_URL` in `.env` to `http://<that-ip>:11434` and run:

```bash
make restart
```

## Useful commands

```bash
make status  # service status
make logs    # live logs
make test    # backend test suite
make lint    # backend and frontend lint checks
make stop    # stop services; keep data
```

`make clean` deletes the local Docker volume and permanently removes local
evaluation results. Use it only when you intentionally want a blank lab.

## Authentication modes

The default `.env` is intentionally **local development mode**: it creates a local
Administrator inside one local organization so the dashboard remains easy to use.
It is not suitable for a shared or internet-exposed deployment.

For staging or production, set these values before the first start and rebuild the
web application:

```env
AEGISAI_ENVIRONMENT=production
AEGISAI_AUTH_REQUIRED=true
VITE_AUTH_REQUIRED=true
AEGISAI_JWT_SECRET=<at-least-32-random-characters>
AEGISAI_BOOTSTRAP_TOKEN=<one-time-random-token>
POSTGRES_PASSWORD=<strong-database-password>
```

Apply the stack, then create the first organization administrator once:

```bash
curl -X POST http://127.0.0.1:8000/auth/bootstrap \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: <one-time-random-token>" \
  -d '{"organization_name":"Example Security","organization_slug":"example-security","email":"admin@example.com","password":"use-a-long-unique-password"}'
```

Remove `AEGISAI_BOOTSTRAP_TOKEN` after the initial administrator is created, then
run `make restart`. The login page uses `/auth/login` and stores only the short-lived
JWT in the browser's local storage.

## Database operations

Database migrations run automatically when the API container starts. You can also
run `make migrate` explicitly. Use `make backup` before upgrades and keep backups
in storage with access controls and a documented restore test. `make clean` removes
the PostgreSQL volume and cannot be undone.
