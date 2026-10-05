# AEGISAI

AEGISAI is an AI security testing dashboard for evaluating local LLMs against prompt injection, sensitive data exposure, and jailbreak attempts.

It connects a FastAPI backend, PostgreSQL database, Ollama local models, and a React security console to run tests, store evidence, calculate risk, and export reports.

## Features

- Test local LLMs through Ollama
- Prompt injection testing
- Sensitive data exposure testing
- Jailbreak resistance testing
- Basic security test suite
- Risk classification: blocked, uncertain, leaked
- Severity scoring: none, medium, high
- Safety score calculation
- Latency tracking
- PostgreSQL result persistence
- Dashboard summary metrics
- Filter results by category, risk, and severity
- View full test evidence
- Export JSON security reports
- Delete test results

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | FastAPI, Python |
| Database | PostgreSQL |
| Local LLM Runtime | Ollama |
| Code Quality | Ruff |
| API Testing | curl, FastAPI docs |

## Screenshots

Screenshots will be added soon:

- Dashboard overview
- Security test runner
- Latest results table
- Evidence modal
- JSON export report

## Project Structure

```text
aegisai/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── db/
│   │   ├── models/
│   │   ├── services/
│   │   └── main.py
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   └── App.css
│   └── package.json
├── docs/
├── reports/
└── README.md