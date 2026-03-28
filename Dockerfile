# OmniAudit — Dockerfile (Fly.io optimised, v2.2.0)
# Supports DB_BACKEND=sqlite (default, Fly free tier) or postgres

FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc libssl-dev libffi-dev libyara-dev curl wget \
    && rm -rf /var/lib/apt/lists/*

# Install Litestream for SQLite WAL replication to Tigris/S3
# Litestream streams the SQLite WAL to object storage — gives you point-in-time
# restore and durability without a separate Postgres machine.
RUN wget -qO /tmp/litestream.tar.gz \
    https://github.com/benbjohnson/litestream/releases/download/v0.3.13/litestream-v0.3.13-linux-amd64.tar.gz \
    && tar -C /usr/local/bin -xzf /tmp/litestream.tar.gz \
    && rm /tmp/litestream.tar.gz

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir semgrep

COPY src/ src/
# Litestream config — reads replica URL from env at runtime
COPY litestream.yml /etc/litestream.yml

RUN useradd -m -u 1000 omniaudit \
    && mkdir -p /app/data \
    && chown -R omniaudit:omniaudit /app
USER omniaudit

ENV PYTHONPATH=/app/src
ENV PORT=8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Litestream wraps uvicorn: it restores the DB on cold start, then runs the
# app as a subprocess. On shutdown it flushes the final WAL segment.
# If LITESTREAM_REPLICA_URL is unset (local dev), fall back to plain uvicorn.
CMD ["sh", "-c", \
    "if [ -n \"${LITESTREAM_REPLICA_URL}\" ]; then \
        litestream replicate -config /etc/litestream.yml -exec \
        'uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1'; \
     else \
        uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1; \
     fi"]
