# AEGISAI

AEGISAI is an AI security testing lab for evaluating local LLMs against prompt
injection, sensitive data exposure, jailbreak attempts, privacy leakage,
tool-injection, RAG-injection, and agent/tool safety scenarios.

The project connects a FastAPI backend, SQL database, Ollama local models, and a
React security console. It can run individual tests, execute corpus-based
campaigns, store evidence, calculate safety scorecards, support analyst review,
apply release gates, compare models, and export JSON reports.

## What This Project Does

AEGISAI turns model safety checks into a repeatable release process:

1. register or discover local models
2. run adversarial tests and corpus campaigns
3. store model responses as evidence
4. classify risk as `blocked`, `uncertain`, or `leaked`
5. score model safety by category
6. review findings as an analyst
7. compare models and campaigns
8. make a release-gate decision before deployment

## Features

- Local model testing through Ollama
- Prompt injection, jailbreak, privacy, sensitive-data, RAG-injection, and tool-injection checks
- Corpus-based campaign execution
- Risk classification: `blocked`, `uncertain`, `leaked`
- Severity scoring: `none`, `medium`, `high`
- Safety score and model comparison views
- Analyst review queue with review notes
- Campaign release gate decisions
- JSON export for individual findings and campaigns
- SQL-backed result persistence
- API-key support for security-test endpoints
- CORS and security headers for safer local dashboard use

## Lab Guides

| Guide | Purpose |
|---|---|
| [Start The Lab](docs/start-lab.md) | Step-by-step startup from a clean terminal session |
| [Demo Flow](docs/demo-flow.md) | How to present the project end to end |
| [Security Roadmap](docs/security-roadmap.md) | v11-v18 roadmap toward a serious AI security lab |

## Evaluation Corpora

| Corpus | Purpose |
|---|---|
| `basic_safety_suite` | Core prompt injection, sensitive-data, jailbreak, privacy, and tool-injection checks |
| `rag_injection_suite` | Tests whether retrieved context can override policy or exfiltrate secrets |
| `agent_tool_safety_suite` | Tests tool-output injection, permission boundaries, and agent safety |

Corpus files live in:

```text
backend/app/corpus/
```

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
- Expand the corpus with multi-turn, multilingual, encoded, RAG, and tool-use attacks.
- Add role-based access control before exposing the dashboard to a team.
- Add database migrations before using this with long-lived production data.
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
│   ├── scripts/
│   └── tests/
├── docs/
├── frontend/
│   ├── src/
│   └── package.json
├── .github/workflows/
├── .env.example
├── LICENSE
└── README.md
```

## Quick Start

```bash
git clone https://github.com/Parakh-Shinde/aegisai.git
cd aegisai
cp .env.example .env
```

Install backend dependencies:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cd ..
```

Initialize database tables:

```bash
python backend/scripts/init_db.py
```

Start the backend:

```bash
uvicorn app.main:app --app-dir backend --reload
```

The API will run at `http://127.0.0.1:8000`.

Start the frontend:

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
| `AEGISAI_API_KEY` | empty | Optional API key for security-test endpoints |
| `AEGISAI_CORS_ORIGINS` | local Vite origins | Allowed dashboard origins |
| `AEGISAI_ALLOW_REMOTE_OLLAMA` | `false` | Allows non-local model endpoints when set to `true` |

For WSL-to-Windows Ollama access, set `OLLAMA_BASE_URL` to the Windows host IP,
for example `http://172.x.x.x:11434`.

## Useful API Calls

Run the basic suite:

```bash
curl -X POST http://127.0.0.1:8000/security-tests/suite/basic \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:3b"}'
```

Run a corpus campaign:

```bash
curl -X POST http://127.0.0.1:8000/security-tests/corpus \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:3b","suite_name":"rag_injection_suite"}'
```

View scorecard:

```bash
curl "http://127.0.0.1:8000/security-tests/scorecard?model=qwen2.5:3b"
```

View release gate:

```bash
curl "http://127.0.0.1:8000/security-tests/release-gate?model=qwen2.5:3b"
```

Compare models:

```bash
curl http://127.0.0.1:8000/security-tests/models/compare
```

## Quality Checks

```bash
ruff check backend
pytest
cd frontend
npm run build
```

## License

This project is licensed under the MIT License.
