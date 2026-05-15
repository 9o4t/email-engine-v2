#!/bin/sh
set -e

# Ensure the data directory exists. Railway mounts the Volume here; locally
# Docker creates the dir if not present.
mkdir -p /data

# Background: the poller. Foreground: gunicorn serving the web UI.
# Signal handling: forward TERM to the poller so SIGTERM from Railway
# unwinds both processes cleanly.
python -m src.poller &
POLLER_PID=$!

trap "kill -TERM $POLLER_PID 2>/dev/null || true" TERM INT

exec gunicorn \
    --chdir /app/src \
    --bind "0.0.0.0:${PORT:-8000}" \
    --workers 1 \
    --threads 4 \
    --timeout 120 \
    --access-logfile - \
    web:app
