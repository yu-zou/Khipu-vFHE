#!/bin/bash
# benchmark_b_vs_e.sh - Fair B-vs-E benchmark for all BGV workloads.
# 10 independent runs per workload, fresh server per run, no warmup.
#   Prototype E = tee-vfhe-bgvrns (TDX-attested BGV, CPU)
#   Prototype B = zk-vfhe         (ZK-proved BGV, CPU)
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E_DIR="$REPO_ROOT/tee-vfhe-bgvrns/build"
B_DIR="$REPO_ROOT/zk-vfhe/build"
MR_TD=$(cat "$REPO_ROOT/scripts/expected_mrtd.txt")
PORT_E=8210
PORT_B=8211
RUNS=10
OUT="/tmp/bench_b_vs_e"
rm -rf "$OUT"; mkdir -p "$OUT"
WORKLOADS="noop toy small medium BGV-Add-4K BGV-Mul-4K"

echo "=== B vs E Benchmark (BGV, no warmup, $RUNS runs) ==="
echo "MR_TD: $MR_TD"

if [ -f /sys/module/tdx_guest/parameters/tsm_api ]; then
    TSM=$(cat /sys/module/tdx_guest/parameters/tsm_api)
    [ "$TSM" != "N" ] && echo "WARNING: tsm_api=$TSM (expected N). Run: sudo rmmod tdx_guest && sudo modprobe tdx_guest tsm_api=0"
fi

echo ""
echo "--- Prototype E (tee-vfhe-bgvrns, TDX) ---"
for workload in $WORKLOADS; do
    echo "  workload: $workload"
    mkdir -p "$OUT/E_${workload}"
    for i in $(seq 1 $RUNS); do
        pkill -f "tee_server.*--port $PORT_E" 2>/dev/null; sleep 0.5
        "$E_DIR/tee_server" --port $PORT_E > "$OUT/E_${workload}/server_${i}.log" 2>&1 &
        SRV_PID=$!
        sleep 2
        CLIENT_OUT=$("$E_DIR/tee_client" --port $PORT_E --workload "$workload" \
            --expected-mr-td "$MR_TD" 2>/dev/null)
        EXIT_CODE=$?
        kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null
        if [ $EXIT_CODE -ne 0 ]; then echo "    run $i: FAILED (exit=$EXIT_CODE)"; continue; fi
        TIMING_LINE=$(echo "$CLIENT_OUT" | grep "^TIMING:")
        echo "$TIMING_LINE" >> "$OUT/E_${workload}/timings.txt"
        echo "    run $i: $TIMING_LINE"
    done
done

echo ""
echo "--- Prototype B (zk-vfhe, ZK proof) ---"
for workload in $WORKLOADS; do
    echo "  workload: $workload"
    mkdir -p "$OUT/B_${workload}"
    for i in $(seq 1 $RUNS); do
        pkill -f "zk_server.*--port $PORT_B" 2>/dev/null; sleep 0.5
        "$B_DIR/zk_server" --port $PORT_B > "$OUT/B_${workload}/server_${i}.log" 2>&1 &
        SRV_PID=$!
        sleep 2
        CLIENT_OUT=$("$B_DIR/zk_client" --host 127.0.0.1 --port $PORT_B \
            --workload "$workload" 2>/dev/null)
        EXIT_CODE=$?
        kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null
        if [ $EXIT_CODE -ne 0 ]; then echo "    run $i: FAILED (exit=$EXIT_CODE)"; continue; fi
        TIMING_LINE=$(echo "$CLIENT_OUT" | grep "^TIMING:")
        echo "$TIMING_LINE" >> "$OUT/B_${workload}/timings.txt"
        echo "    run $i: $TIMING_LINE"
    done
done

echo ""
echo "=== Raw data saved to $OUT ==="

extract_median() {
    local file=$1; local field=$2
    grep -oP "${field}=\K[0-9]+" "$file" 2>/dev/null | sort -n | awk '
    { a[NR]=$1 }
    END {
        if (NR==0) { print "0"; exit }
        if (NR%2==1) print a[(NR+1)/2]; else print int((a[NR/2]+a[NR/2+1])/2)
    }'
}

echo ""
echo "=== Summary E (median of $RUNS runs, us) ==="
printf "%-12s | %8s %8s %8s %10s %8s %13s\n" Workload ctx eval outser transcript quote client_verify
for w in $WORKLOADS; do
    F="$OUT/E_${w}/timings.txt"; [ -f "$F" ] || continue
    printf "%-12s | %8s %8s %8s %10s %8s %13s\n" "$w" \
        "$(extract_median "$F" ctx)" "$(extract_median "$F" eval)" \
        "$(extract_median "$F" outser)" "$(extract_median "$F" transcript)" \
        "$(extract_median "$F" quote)" "$(extract_median "$F" client_verify)"
done
echo ""
echo "=== Summary B (median of $RUNS runs, us) ==="
printf "%-12s | %10s %8s %10s %10s %13s\n" Workload input_load eval witness proof client_verify
for w in $WORKLOADS; do
    F="$OUT/B_${w}/timings.txt"; [ -f "$F" ] || continue
    printf "%-12s | %10s %8s %10s %10s %13s\n" "$w" \
        "$(extract_median "$F" input_loading)" "$(extract_median "$F" eval)" \
        "$(extract_median "$F" witness)" "$(extract_median "$F" proof)" \
        "$(extract_median "$F" client_verify)"
done
echo ""
echo "Done. Raw timing files in $OUT/*/timings.txt"
