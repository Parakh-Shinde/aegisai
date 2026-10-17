FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

RUN apt-get update \
    && apt-get install --no-install-recommends -y tesseract-ocr tesseract-ocr-eng \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ocr \
    && useradd --system --gid ocr --home-dir /tmp ocr

WORKDIR /app
COPY server.py ./server.py

USER ocr
EXPOSE 8090
ENTRYPOINT ["python", "/app/server.py"]
