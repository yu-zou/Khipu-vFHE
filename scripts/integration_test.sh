#!/usr/bin/env bash
# integration_test.sh — Full end-to-end integration test for tee-vfhe-bgvrns.
#
# Runs the complete flow on a TDX-capable VM:
#   - Build project
#   - Start server, run client, stop server
#   - Run benchmark runner
#   - Run ctest
#   - Verify all expected outcomes
#
# Both transcript verification and TDX quote verification MUST succeed.
#
# Usage:
#   ./scripts/integration_test.sh
#
# Exit code: 0 on success (all expected checks pass).
set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_DIR="$REPO_ROOT/tee-vfhe-bgvrns"
BUILD_DIR="$PROJECT_DIR/build"
BENCHMARK_CSV="$BUILD_DIR/benchmark_results.csv"
SERVER_LOG="$BUILD_DIR/server_integration_test.log"
CLIENT_LOG="$BUILD_DIR/client_integration_test.log"
PORT=8083

# ---------------------------------------------------------------------------
# Cleanup handler — kill server on exit
# ---------------------------------------------------------------------------
SERVER_PID=""
cleanup() {
    local rc=$?
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "[integration] Stopping server (PID $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    # Remove old CSV so we don't confuse line-count checks
    rm -f "$BENCHMARK_CSV"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Step 1: Build
# ---------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "  STEP 1/6: Build project"
echo "========================================================================"
"$SCRIPT_DIR/build_project.sh"
echo "[integration] Build SUCCESS"

# ---------------------------------------------------------------------------
# Step 2: Start server in background
# ---------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "  STEP 2/6: Start server on port $PORT"
echo "========================================================================"
"$SCRIPT_DIR/run_server.sh" --port "$PORT" &>"$SERVER_LOG" &
SERVER_PID=$!
echo "[integration] Server PID: $SERVER_PID"

# Wait for the server to bind to the port (up to 30 seconds)
echo "[integration] Waiting for server to bind port $PORT..."
for i in $(seq 1 30); do
    if ss -tlnp "sport = :$PORT" 2>/dev/null | grep -q ":$PORT"; then
        echo "[integration] Server bound to port $PORT after ${i}s"
        break
    fi
    # Also check if the server process died
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "[integration] ERROR: server died during startup. Log:"
        cat "$SERVER_LOG"
        exit 1
    fi
    sleep 1
done

if ! ss -tlnp "sport = :$PORT" 2>/dev/null | grep -q ":$PORT"; then
    echo "[integration] ERROR: server did not bind port $PORT within 30s. Log:"
    cat "$SERVER_LOG"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Run client
# ---------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "  STEP 3/6: Run client (workload=toy)"
echo "========================================================================"
CLIENT_RC=0
"$SCRIPT_DIR/run_client.sh" --port "$PORT" --workload toy 2>&1 | tee "$CLIENT_LOG" || CLIENT_RC=$?
echo "[integration] Client exit code: $CLIENT_RC"

# ---------------------------------------------------------------------------
# Step 4: Stop server
# ---------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "  STEP 4/6: Stop server"
echo "========================================================================"
if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    echo "[integration] Server stopped"
fi
SERVER_PID=""

# ---------------------------------------------------------------------------
# Step 5: Run benchmark runner
# ---------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "  STEP 5/6: Run benchmark runner"
echo "========================================================================"
# Restart server for benchmark runner
"$SCRIPT_DIR/run_server.sh" --port "$PORT" &>"$SERVER_LOG" &
SERVER_PID=$!
echo "[integration] Benchmark server PID: $SERVER_PID"

# Wait for port again
for i in $(seq 1 30); do
    if ss -tlnp "sport = :$PORT" 2>/dev/null | grep -q ":$PORT"; then
        echo "[integration] Server bound after ${i}s"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "[integration] ERROR: server died during benchmark startup. Log:"
        cat "$SERVER_LOG"
        exit 1
    fi
    sleep 1
done

# Read expected MR_TD
EXPECTED_MRTD=""
if [ -f "$SCRIPT_DIR/expected_mrtd.txt" ]; then
    EXPECTED_MRTD="$(grep -vE '^\s*(#|$)' "$SCRIPT_DIR/expected_mrtd.txt" | head -1 | tr -d '[:space:]')"
fi

BENCH_RC=0
"$BUILD_DIR/benchmark_runner" \
    --host 127.0.0.1 \
    --port "$PORT" \
    --expected-mr-td "$EXPECTED_MRTD" \
    > "$BENCHMARK_CSV" 2>"$BUILD_DIR/benchmark_runner.log" || BENCH_RC=$?
echo "[integration] Benchmark runner exit code: $BENCH_RC"

# Stop benchmark server
if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    echo "[integration] Benchmark server stopped"
fi
SERVER_PID=""

# ---------------------------------------------------------------------------
# Step 6: Run ctest
# ---------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "  STEP 6/6: Run ctest"
echo "========================================================================"
CTEST_RC=0
(cd "$BUILD_DIR" && ctest --output-on-failure) || CTEST_RC=$?
echo "[integration] ctest exit code: $CTEST_RC"

# ---------------------------------------------------------------------------
# Verify results
# ---------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "  VERIFICATION"
echo "========================================================================"

# 1. Client must exit zero (attestation succeeds on TDX-capable VM)
if [ "$CLIENT_RC" -ne 0 ]; then
    echo "[integration] FAIL: client exited $CLIENT_RC but expected 0 (attestation should succeed)"
    exit 1
fi
echo "[integration] PASS: client exited 0 (attestation succeeded)"

# 2. Client output must show transcript verification succeeded
if grep -q "transcript verification FAILED" "$CLIENT_LOG"; then
    echo "[integration] FAIL: transcript verification FAILED (should have succeeded)"
    exit 1
fi
echo "[integration] PASS: transcript verification succeeded"

# 3. Client output must show attestation verification succeeded
if grep -q "attestation verification FAILED" "$CLIENT_LOG"; then
    echo "[integration] FAIL: attestation verification FAILED (should have succeeded)"
    exit 1
fi
echo "[integration] PASS: attestation verification succeeded"

# 4. Benchmark runner must exit 0
if [ "$BENCH_RC" -ne 0 ]; then
    echo "[integration] FAIL: benchmark runner exited $BENCH_RC (expected 0)"
    exit 1
fi
echo "[integration] PASS: benchmark runner exited 0"

# 5. ctest must exit 0
if [ "$CTEST_RC" -ne 0 ]; then
    echo "[integration] FAIL: ctest exited $CTEST_RC (expected 0)"
    exit 1
fi
echo "[integration] PASS: ctest exited 0"

# 6. CSV must have 11 lines (header + 10 workloads)
if [ ! -f "$BENCHMARK_CSV" ]; then
    echo "[integration] FAIL: benchmark CSV not found at $BENCHMARK_CSV"
    exit 1
fi
CSV_LINES=$(wc -l < "$BENCHMARK_CSV" | tr -d '[:space:]')
if [ "$CSV_LINES" -ne 11 ]; then
    echo "[integration] FAIL: benchmark CSV has $CSV_LINES lines (expected 11)"
    exit 1
fi
echo "[integration] PASS: benchmark CSV has $CSV_LINES lines (expected 11)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "  INTEGRATION TEST SUMMARY"
echo "========================================================================"
echo "  client RC  = $CLIENT_RC (expected 0)"
echo "  bench RC   = $BENCH_RC  (expected 0)"
echo "  ctest RC   = $CTEST_RC  (expected 0)"
echo "  CSV lines  = $CSV_LINES (expected 11)"
echo ""
echo "  Transcript verification:  PASS"
echo "  Attestation verification: PASS"
echo "  Benchmark runner:         PASS"
echo "  Unit tests:               PASS"
echo "  CSV output:               PASS"
echo ""
echo "[integration] ALL CHECKS PASSED"
exit 0
