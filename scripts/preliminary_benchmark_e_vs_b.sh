#!/bin/bash
# Preliminary benchmark script comparing Prototype E (BGV TDX) vs Prototype B (BGV ZK)
# NOTE: benchmark_runner runs ALL workloads per invocation. We call it once per server.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_ROOT/test_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS_DIR"

echo "=== Preliminary E vs B Benchmark ==="
echo "Timestamp: $TIMESTAMP"
echo ""

# Build both prototypes
echo "Building Prototype E (tee-vfhe-bgvrns)..."
cd "$PROJECT_ROOT/tee-vfhe-bgvrns"
cmake --build build --parallel $(nproc) 2>&1 | tail -5
echo "✓ Prototype E built"

echo ""
echo "Building Prototype B (zk-vfhe)..."
cd "$PROJECT_ROOT/zk-vfhe"
cmake --build build --parallel $(nproc) 2>&1 | tail -5
echo "✓ Prototype B built"

# CSV headers
E_CSV="$RESULTS_DIR/preliminary_e_vs_b_E_${TIMESTAMP}.csv"
B_CSV="$RESULTS_DIR/preliminary_e_vs_b_B_${TIMESTAMP}.csv"

echo "workload,server_e2e_us,client_us,attestation_us,fhe_eval_us" > "$E_CSV"
echo "workload,server_e2e_us,client_us,attestation_us,fhe_eval_us" > "$B_CSV"

# ─── Prototype E ────────────────────────────────────────────────────────────────
echo ""
echo "━━━ Prototype E (tee-vfhe-bgvrns) ━━━"

echo "Starting Prototype E server on port 8080..."
cd "$PROJECT_ROOT/tee-vfhe-bgvrns"
> /tmp/server_e.log
./build/tee_server --port 8080 > /tmp/server_e.log 2>&1 &
SERVER_E_PID=$!
sleep 3

if ! kill -0 $SERVER_E_PID 2>/dev/null; then
    echo "ERROR: Prototype E server failed to start"
    cat /tmp/server_e.log
    exit 1
fi
echo "  Server PID: $SERVER_E_PID"

echo "Running benchmark_runner (all workloads)..."
cd "$PROJECT_ROOT/tee-vfhe-bgvrns"
E_OUTPUT=$(./build/benchmark_runner --host 127.0.0.1 --port 8080 2>&1) || {
    echo "ERROR: benchmark_runner for E failed"
    echo "$E_OUTPUT"
    kill $SERVER_E_PID 2>/dev/null
    exit 1
}

# E CSV: workload(1),server_e2e(2),client(3),input_loading(4),fhe_eval(5),transcript(6),quote(7),packaging(8),verify(9),peak_mem(10),transcript_bytes(11),quote_bytes(12)
#   Extract: workload, server_e2e, client, transcript/attestation, fhe_eval
echo "$E_OUTPUT" | awk -F',' 'NR>1 && $1 ~ /^(noop|toy|small|medium|BGV.Add.4K|BGV.Mul.4K)$/ {print $1","$2","$3","$6","$5}' >> "$E_CSV"

kill $SERVER_E_PID 2>/dev/null || true
wait $SERVER_E_PID 2>/dev/null || true
sleep 1
echo "✓ Prototype E benchmark complete"

# ─── Prototype B ────────────────────────────────────────────────────────────────
echo ""
echo "━━━ Prototype B (zk-vfhe) ━━━"

echo "Starting Prototype B server on port 8081..."
cd "$PROJECT_ROOT/zk-vfhe"
> /tmp/server_b.log
./build/zk_server --port 8081 > /tmp/server_b.log 2>&1 &
SERVER_B_PID=$!
sleep 3

if ! kill -0 $SERVER_B_PID 2>/dev/null; then
    echo "ERROR: Prototype B server failed to start"
    cat /tmp/server_b.log
    exit 1
fi
echo "  Server PID: $SERVER_B_PID"

echo "Running benchmark_runner (all workloads)..."
cd "$PROJECT_ROOT/zk-vfhe"
B_OUTPUT=$(./build/benchmark_runner --host 127.0.0.1 --port 8081 2>&1) || {
    echo "ERROR: benchmark_runner for B failed"
    echo "$B_OUTPUT"
    kill $SERVER_B_PID 2>/dev/null
    exit 1
}

# B CSV: workload(1),server_e2e(2),client(3),input_loading(4),fhe_eval(5),witness(6),proof(7),packaging(8),verify(9),peak_mem(10),proof_size(11)
#   Extract: workload, server_e2e, client, witness/attestation, fhe_eval
echo "$B_OUTPUT" | awk -F',' 'NR>1 && $1 ~ /^(noop|toy|small|medium|BGV.Add.4K|BGV.Mul.4K)$/ {print $1","$2","$3","$6","$5}' >> "$B_CSV"

kill $SERVER_B_PID 2>/dev/null || true
wait $SERVER_B_PID 2>/dev/null || true
sleep 1
echo "✓ Prototype B benchmark complete"

# ─── Generate Summary ───────────────────────────────────────────────────────────
SUMMARY="$RESULTS_DIR/preliminary_e_vs_b_summary_${TIMESTAMP}.md"

{
echo "# Preliminary E vs B Benchmark Results"
echo ""
echo "**Timestamp:** $TIMESTAMP"
echo ""
echo "## Overview"
echo ""
echo "This benchmark compares Prototype E (BGV with TDX attestation) against Prototype B (BGV with ZK proofs) across representative workloads."
echo ""
echo "## Results"
echo ""
echo "### Server E2E Latency (μs)"
echo ""
echo "| Workload | Prototype E | Prototype B | Ratio (B/E) |"
echo "|----------|-------------|-------------|-------------|"
} > "$SUMMARY"

WORKLOADS="noop toy small medium BGV-Add-4K BGV-Mul-4K"
for workload in $WORKLOADS; do
    E_VAL=$(grep "^$workload," "$E_CSV" | cut -d',' -f2)
    B_VAL=$(grep "^$workload," "$B_CSV" | cut -d',' -f2)
    if [ -n "$E_VAL" ] && [ -n "$B_VAL" ] && [ "$E_VAL" != "0" ]; then
        RATIO=$(echo "scale=2; $B_VAL / $E_VAL" | bc)
        echo "| $workload | $E_VAL | $B_VAL | $RATIO |" >> "$SUMMARY"
    else
        echo "| $workload | $E_VAL | $B_VAL | N/A |" >> "$SUMMARY"
    fi
done

{
echo ""
echo "### Client-side Execution (μs)"
echo ""
echo "| Workload | Prototype E | Prototype B | Ratio (B/E) |"
echo "|----------|-------------|-------------|-------------|"
} >> "$SUMMARY"

for workload in $WORKLOADS; do
    E_VAL=$(grep "^$workload," "$E_CSV" | cut -d',' -f3)
    B_VAL=$(grep "^$workload," "$B_CSV" | cut -d',' -f3)
    if [ -n "$E_VAL" ] && [ -n "$B_VAL" ] && [ "$E_VAL" != "0" ]; then
        RATIO=$(echo "scale=2; $B_VAL / $E_VAL" | bc)
        echo "| $workload | $E_VAL | $B_VAL | $RATIO |" >> "$SUMMARY"
    else
        echo "| $workload | $E_VAL | $B_VAL | N/A |" >> "$SUMMARY"
    fi
done

{
echo ""
echo "### Attestation Overhead (μs)"
echo ""
echo "| Workload | Prototype E (transcript) | Prototype B (witness) | Ratio (B/E) |"
echo "|----------|--------------------------|----------------------|-------------|"
} >> "$SUMMARY"

for workload in $WORKLOADS; do
    E_VAL=$(grep "^$workload," "$E_CSV" | cut -d',' -f4)
    B_VAL=$(grep "^$workload," "$B_CSV" | cut -d',' -f4)
    if [ -n "$E_VAL" ] && [ -n "$B_VAL" ] && [ "$E_VAL" != "0" ]; then
        RATIO=$(echo "scale=2; $B_VAL / $E_VAL" | bc)
        echo "| $workload | $E_VAL | $B_VAL | $RATIO |" >> "$SUMMARY"
    else
        echo "| $workload | $E_VAL | $B_VAL | N/A |" >> "$SUMMARY"
    fi
done

{
echo ""
echo "### FHE Execution Time (μs)"
echo ""
echo "| Workload | Prototype E | Prototype B | Ratio (B/E) |"
echo "|----------|-------------|-------------|-------------|"
} >> "$SUMMARY"

for workload in $WORKLOADS; do
    E_VAL=$(grep "^$workload," "$E_CSV" | cut -d',' -f5)
    B_VAL=$(grep "^$workload," "$B_CSV" | cut -d',' -f5)
    if [ -n "$E_VAL" ] && [ -n "$B_VAL" ] && [ "$E_VAL" != "0" ]; then
        RATIO=$(echo "scale=2; $B_VAL / $E_VAL" | bc)
        echo "| $workload | $E_VAL | $B_VAL | $RATIO |" >> "$SUMMARY"
    else
        echo "| $workload | $E_VAL | $B_VAL | N/A |" >> "$SUMMARY"
    fi
done

{
echo ""
echo "## Analysis"
echo ""
echo "### Expected Results"
echo ""
echo "Prototype E (hardware TDX-based) is expected to be significantly more performant than Prototype B (ZK-based), especially for attestation overhead:"
echo "- **TDX attestation**: Hardware-based, typically 2-5ms"
echo "- **ZK proof generation**: Software-based, typically 100-500ms for complex circuits"
echo ""
echo "### Observations"
echo ""
echo "[To be filled after benchmark execution]"
echo ""
echo "## Raw Data"
echo ""
echo "- Prototype E results: \`$(basename "$E_CSV")\`"
echo "- Prototype B results: \`$(basename "$B_CSV")\`"
echo ""
echo "## Notes"
echo ""
echo "- This is a preliminary observation only, not an official statistical comparison"
echo "- Both prototypes use identical BGV parameters (ring=8192, depth=4, batch=4096, plaintext=65537)"
echo "- Server E2E = sum of server-reported phases (input_loading + fhe_eval + transcript/quote + packaging)"
echo "- Client-side = request_prep + network_transfer + verify"
echo "- E attestation = transcript_us; B attestation = witness_us"
echo "- Column mapping verified against benchmark_runner source code"
} >> "$SUMMARY"

echo ""
echo "=== Benchmark Complete ==="
echo "Results saved to:"
echo "  - $E_CSV"
echo "  - $B_CSV"
echo "  - $SUMMARY"
echo ""
echo "Summary preview:"
echo "----------------"
head -30 "$SUMMARY"