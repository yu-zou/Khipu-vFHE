#!/usr/bin/env bash
# run_client.sh — Run the tee-vfhe client against a running server.
#
# Usage:
#   ./scripts/run_client.sh [--host HOST] [--port PORT]
#                           [--workload ID] [--expected-mr-td HEX]
#                           [extra args...]
#
# Defaults:
#   host:     127.0.0.1
#   port:     8080 (or $PORT env var)
#   workload: toy
#   expected-mr-td: read from scripts/expected_mrtd.txt if present and not
#                   provided on the command line. If neither is available the
#                   flag is omitted (the client will skip MR_TD verification).
set -euo pipefail

# Resolve repo root (parent of scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$REPO_ROOT/tee-vfhe/build/tee_client"
EXPECTED_MRTD_FILE="$SCRIPT_DIR/expected_mrtd.txt"

# --- 1. Binary check ---------------------------------------------------------
if [ ! -x "$BIN" ]; then
    echo "[run_client] ERROR: client binary not found: $BIN" >&2
    echo "[run_client]        Run ./scripts/build_project.sh first." >&2
    exit 1
fi

# --- 2. Defaults -------------------------------------------------------------
HOST="127.0.0.1"
PORT="${PORT:-8080}"
WORKLOAD="toy"
EXPECTED_MRTD=""
MRTD_PROVIDED=0

# --- 3. Parse args -----------------------------------------------------------
PASSTHROUGH=()
while [ $# -gt 0 ]; do
    case "$1" in
        --host)
            [ $# -lt 2 ] && { echo "[run_client] ERROR: --host requires a value." >&2; exit 1; }
            HOST="$2"; shift 2 ;;
        --host=*)
            HOST="${1#--host=}"; shift ;;
        --port)
            [ $# -lt 2 ] && { echo "[run_client] ERROR: --port requires a value." >&2; exit 1; }
            PORT="$2"; shift 2 ;;
        --port=*)
            PORT="${1#--port=}"; shift ;;
        --workload)
            [ $# -lt 2 ] && { echo "[run_client] ERROR: --workload requires a value." >&2; exit 1; }
            WORKLOAD="$2"; shift 2 ;;
        --workload=*)
            WORKLOAD="${1#--workload=}"; shift ;;
        --expected-mr-td)
            [ $# -lt 2 ] && { echo "[run_client] ERROR: --expected-mr-td requires a value." >&2; exit 1; }
            EXPECTED_MRTD="$2"; MRTD_PROVIDED=1; shift 2 ;;
        --expected-mr-td=*)
            EXPECTED_MRTD="${1#--expected-mr-td=}"; MRTD_PROVIDED=1; shift ;;
        *)
            PASSTHROUGH+=("$1"); shift ;;
    esac
done

# --- 4. Default expected-mr-td from file ------------------------------------
if [ "$MRTD_PROVIDED" -ne 1 ]; then
    if [ -f "$EXPECTED_MRTD_FILE" ]; then
        # Read first non-empty, non-comment line and strip whitespace.
        EXPECTED_MRTD="$(grep -vE '^\s*(#|$)' "$EXPECTED_MRTD_FILE" | head -1 | tr -d '[:space:]')"
        if [ -n "$EXPECTED_MRTD" ]; then
            echo "[run_client] Using expected MR_TD from $EXPECTED_MRTD_FILE"
        fi
    else
        echo "[run_client] WARNING: $EXPECTED_MRTD_FILE not found; no --expected-mr-td." >&2
    fi
fi

# --- 5. Assemble args --------------------------------------------------------
ARGS=(--host "$HOST" --port "$PORT" --workload "$WORKLOAD")
if [ -n "$EXPECTED_MRTD" ]; then
    ARGS+=(--expected-mr-td "$EXPECTED_MRTD")
fi
ARGS+=("${PASSTHROUGH[@]}")

echo "[run_client] Connecting to $HOST:$PORT, workload=$WORKLOAD"
echo "[run_client] Binary: $BIN"
exec "$BIN" "${ARGS[@]}"
