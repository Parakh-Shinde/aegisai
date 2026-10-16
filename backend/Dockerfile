FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system aegisai && adduser --system --ingroup aegisai aegisai

# Production image installs runtime dependencies only; test and lint tooling stays in CI.
COPY requirements.txt ./
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./

RUN mkdir /data && chown -R aegisai:aegisai /app /data

USER aegisai

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
