FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# sqlite3 CLI for interactive DB inspection via `railway ssh -- sqlite3 /data/...`.
# less + vim-tiny for general triage during ssh sessions. Tiny — adds < 5 MB.
RUN apt-get update \
 && apt-get install -y --no-install-recommends sqlite3 less vim-tiny ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY src/ /app/src/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

ENV FEEDBACK_DB_PATH=/data/email-engine-v2.db \
    PORT=8000 \
    PYTHONPATH=/app/src

EXPOSE 8000
CMD ["/app/entrypoint.sh"]
