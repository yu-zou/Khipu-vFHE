#!/bin/bash
# benchmark_a_vs_c.sh - Benchmark Prototype A vs C toy workload
# 1 warmup + 10 measured requests, each with fresh nonce
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
A_DIR="$REPO_ROOT/tee-vfhe/build"
C_DIR="$REPO_ROOT/gpucc-vfhe/build"
MR_TD=$(cat "$REPO_ROOT/scripts/expected_mrtd.txt")
PORT_A=8095
PORT_C=8096
ITERS=11  # 1 warmup + 10 measured
WORKLOAD=toy

echo "=== Benchmark A vs C: $WORKLOAD workload ==="
echo "MRTD: $MR_TD"
echo "Iterations: $ITERS (1 warmup + 10 measured)"
echo ""

# Start both servers
"$A_DIR/tee_server" --port $PORT_A > /tmp/bench_server_a.log 2>&1 &
PID_A=$!
sleep 2

"$C_DIR/tee_server" --port $PORT_C > /tmp/bench_server_c.log 2>&1 &
PID_C=$!
sleep 2

# Check servers
kill -0 $PID_A 2>/dev/null && echo "Server A (PID $PID_A) started on port $PORT_A"
kill -0 $PID_C 2>/dev/null && echo "Server C (PID $PID_C) started on port $PORT_C"
echo ""

# Benchmark function
run_benchmark() {
    local name=$1
    local port=$2
    local output=$3

    echo "--- $name ---"
    local i=0
    while [ $i -lt $ITERS ]; do
        local start=$(date +%s%N)
        local out=$("$A_DIR/tee_client" --port $port --workload $WORKLOAD --expected-mr-td "$MR_TD" 2>&1)
        local end=$(date +%s%N)
        local elapsed=$(( (end - start) / 1000000 ))  # ms

        if [ $i -eq 0 ]; then
            echo "  warmup: ${elapsed}ms"
        else
            echo "  run $i: ${elapsed}ms"
            echo "$elapsed" >> "$output"
        fi
        i=$((i + 1))
    done
    echo ""
}

# Run benchmarks
run_benchmark "Prototype A (tee-vfhe)" $PORT_A /tmp/bench_a_times.txt
run_benchmark "Prototype C (gpucc-vfhe)" $PORT_C /tmp/bench_c_times.txt

# Compute median
compute_stats() {
    local file=$1
    sort -n "$file" | awk '
    { a[NR] = $1 }
    END {
        if (NR % 2 == 1) median = a[(NR+1)/2]
        else median = (a[NR/2] + a[NR/2+1]) / 2
        sum = 0; for (i=1; i<=NR; i++) sum += a[i]
        mean = sum / NR
        printf "  min=%dms  median=%dms  mean=%dms  max=%dms  n=%d\n", a[1], median, mean, a[NR], NR
    }'
}

echo "=== Results ==="
echo "Prototype A:"
compute_stats /tmp/bench_a_times.txt
echo "Prototype C:"
compute_stats /tmp/bench_c_times.txt

echo ""
echo "=== Server logs ==="
echo "--- Server A ---"
grep "workload=" /tmp/bench_server_a.log
echo "--- Server C ---"
grep -E "workload=|h100|GPU evidence" /tmp/bench_server_c.log

# Cleanup
kill $PID_A $PID_C 2>/dev/null || true
wait $PID_A $PID_C 2>/dev/null || true
rm -f /tmp/bench_a_times.txt /tmp/bench_c_times.txt
echo ""
echo "Done"
