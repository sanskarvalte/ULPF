#!/bin/sh
set -e

# Default to starting the uvicorn server
if [ "$1" = "" ]; then
    echo "🚀 Starting ULPF Server in Offline Container Mode..."
    exec uvicorn app.main:app --app-dir /app/backend --host 0.0.0.0 --port 8000
else
    exec "$@"
fi
