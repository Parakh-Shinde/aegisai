# AEGISAI

AEGISAI is an AI security testing dashboard for evaluating local LLMs against
prompt injection, sensitive data exposure, jailbreak attempts, privacy leakage,
and tool-injection scenarios.

The project connects a FastAPI backend, SQL database, Ollama local models, and a
React security console. It can run individual tests, execute corpus-based
campaigns, store evidence, calculate safety scorecards, support analyst review,
apply release gates, and export JSON reports.

## Features

- Local model testing through Ollama
- Prompt injection, jailbreak, privacy, sensitive-data, and tool-injection checks
- Corpus-based campaign execution
- Risk classification: `blocked`, `uncertain`, `leaked`
- Severity scoring: `none`, `medium`, `high`
- Safety score and model comparison views
- Analyst review queue with review notes
- Campaign release gate decisions
- JSON export for individual findings and campaigns
- SQL-backed result persistence

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | FastAPI, Python |
| Database | SQLAlchemy, PostgreSQL or SQLite |
| Local LLM Runtime | Ollama |
| Code Quality | Ruff, ESLint |
| Tests | Pytest |
| CI | GitHub Actions |

## Security Model

AEGISAI is a prototype evaluator. It uses deterministic marker-based checks to
identify obvious refusals, uncertain outputs, and unsafe leakage patterns. This
is useful for repeatable local regression testing, but it is not a complete
replacement for professional model red teaming.

Recommended production improvements:

- Add a stronger LLM-as-judge or rule-engine evaluation layer.
- Expand the corpus with encoded, multi-turn, multilingual, and tool-use attacks.
- Add authentication and authorization before exposing the dashboard.
- Add database migrations before using this with long-lived data.
- Review every `uncertain` result manually before trusting a release decision.

## Project Structure

```text
aegisai/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── corpus/
│   │   ├── db/
│   │   ├── models/
│   │   ├── services/
│   │   └── main.py
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── tests/
├── frontend/
│   ├── src/
│   └── package.json
├── .github/workflows/
├── .env.example
├── LICENSE
└── README.md
```

## Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cd ..
cp .env.example .env
uvicorn app.main:app --app-dir backend --reload
```

The API will run at `http://127.0.0.1:8000`.

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The dashboard will run at `http://127.0.0.1:5173`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./aegisai.db` | SQLAlchemy database connection |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama API endpoint |

For WSL-to-Windows Ollama access, set `OLLAMA_BASE_URL` to the Windows host IP,
for example `http://172.x.x.x:11434`.

## Quality Checks

```bash
ruff check backend
pytest
cd frontend
npm run build
```

## License

This project is licensed under the MIT License.
