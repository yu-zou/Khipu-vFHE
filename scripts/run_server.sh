#!/usr/bin/env bash
# run_server.sh — Start the tee-vfhe-bgvrns TDX+FHE server in the foreground.
#
# Usage:
#   ./scripts/run_server.sh [--port PORT] [extra args...]
#   PORT=9090 ./scripts/run_server.sh
#
# The port defaults to 8080. Extra args after the recognized flags are passed
# through to tee_server.
set -euo pipefail

# Resolve repo root (parent of scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$REPO_ROOT/tee-vfhe-bgvrns/build/tee_server"

# --- 1. Binary check ---------------------------------------------------------
if [ ! -x "$BIN" ]; then
    echo "[run_server] ERROR: server binary not found: $BIN" >&2
    echo "[run_server]        Run ./scripts/build_project.sh first." >&2
    exit 1
fi

# --- 2. Parse args + PORT env ------------------------------------------------
# Default port from env, then 8080.
PORT="${PORT:-8080}"

# We separate recognized flags (--port) from passthrough args.
PASSTHROUGH=()
while [ $# -gt 0 ]; do
    case "$1" in
        --port)
            if [ $# -lt 2 ]; then
                echo "[run_server] ERROR: --port requires a value." >&2
                exit 1
            fi
            PORT="$2"
            shift 2
            ;;
        --port=*)
            PORT="${1#--port=}"
            shift
            ;;
        *)
            PASSTHROUGH+=("$1")
            shift
            ;;
    esac
done

echo "[run_server] Starting tee_server on port ${PORT} (foreground)."
echo "[run_server] Binary: $BIN"
echo "[run_server] Press Ctrl+C to stop."
if [ ${#PASSTHROUGH[@]} -gt 0 ]; then
    echo "[run_server] Extra args: ${PASSTHROUGH[*]}"
fi

# --- 3. Run in foreground ----------------------------------------------------
exec "$BIN" --port "$PORT" "${PASSTHROUGH[@]}"
