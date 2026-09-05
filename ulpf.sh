#!/usr/bin/env bash
# ULPF macOS/Linux Local Launcher
# Runs 100% locally on a port without any online dependencies.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$SCRIPT_DIR/backend"

if [ -f "$SCRIPT_DIR/.venv/bin/python3" ]; then
    exec "$SCRIPT_DIR/.venv/bin/python3" "$SCRIPT_DIR/backend/app/main.py" "$@"
elif [ -f "$SCRIPT_DIR/.venv/bin/python" ]; then
    exec "$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/backend/app/main.py" "$@"
else
    exec python3 "$SCRIPT_DIR/backend/app/main.py" "$@"
fi
