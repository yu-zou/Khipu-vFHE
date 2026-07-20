#!/bin/bash
# benchmark_logreg_a_vs_c.sh
# Fair A-vs-C benchmark for the encrypted logistic-regression workload
# (no-bootstrap, 2 iterations, identical algorithm on both prototypes).
#
# Prototype A = tee-vfhe   (CPU, stock OpenFHE)
# Prototype C = gpucc-vfhe (GPU H20, FIDESlib)
#
# Metrics captured from each server's own logs:
#   Prototype A: eval=  (pure CPU FHE compute)
#   Prototype C: compute=  (pure GPU FHE compute, excludes one-time LoadContext),
#                plus context+LoadContext= and input_upload= for context.
#
# Correctness: both clients print "trained weights: max|w|=..." which must match.
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
A_DIR="$REPO_ROOT/tee-vfhe/build"
C_DIR="$REPO_ROOT/gpucc-vfhe/build"
MR_TD=$(cat "$REPO_ROOT/scripts/expected_mrtd.txt")
PORT_A=8101
PORT_C=8102
WARMUP=1
RUNS=3
OUT=/root/Khipu-vFHE/tmp_test/bench_logreg
mkdir -p "$OUT"

echo "=== A-vs-C logistic-regression benchmark (no-bootstrap, 2 iters) ==="
echo "warmup=$WARMUP runs=$RUNS"
echo ""

# NOTE: the servers currently handle a single request cleanly (GPU/global-key
# teardown between requests is not yet robust), so we start a FRESH server for
# every run to get independent measurements.

# ---------------- Prototype A (CPU) ----------------
echo "--- Prototype A (tee-vfhe, CPU) ---"
: > "$OUT/A_eval.txt"
for i in $(seq 0 $RUNS); do
    pkill -9 tee_server 2>/dev/null; sleep 1
    "$A_DIR/tee_server" --port $PORT_A > "$OUT/serverA_$i.log" 2>&1 &
    SRV_A=$!
    sleep 3
    "$A_DIR/tee_client" --port $PORT_A --workload logistic-regression \
        --expected-mr-td "$MR_TD" > "$OUT/A_client_$i.log" 2>&1
    ev=$(grep -oE "eval=[0-9]+ms" "$OUT/serverA_$i.log" | tail -1 | grep -oE "[0-9]+")
    w=$(grep "trained weights" "$OUT/A_client_$i.log" | head -1)
    kill $SRV_A 2>/dev/null; wait $SRV_A 2>/dev/null
    if [ "$i" -eq 0 ]; then
        echo "  warmup: eval=${ev}ms   $w"
    else
        echo "  run $i: eval=${ev}ms"
        echo "$ev" >> "$OUT/A_eval.txt"
    fi
done
echo ""

# ---------------- Prototype C (GPU) ----------------
echo "--- Prototype C (gpucc-vfhe, GPU H20) ---"
nvidia-smi conf-compute -grs 2>&1 | grep -i ready
: > "$OUT/C_compute.txt"; : > "$OUT/C_setup.txt"
for i in $(seq 0 $RUNS); do
    pkill -9 tee_server 2>/dev/null; sleep 1
    "$C_DIR/tee_server" --port $PORT_C > "$OUT/serverC_$i.log" 2>&1 &
    SRV_C=$!
    sleep 3
    "$C_DIR/tee_client" --port $PORT_C --workload logistic-regression \
        --expected-mr-td "$MR_TD" > "$OUT/C_client_$i.log" 2>&1
    cmp=$(grep -oE "compute\([0-9]+ iters\)=[0-9]+ms" "$OUT/serverC_$i.log" | tail -1 | grep -oE "=[0-9]+ms" | grep -oE "[0-9]+")
    setup=$(grep -oE "context\+LoadContext=[0-9]+ms" "$OUT/serverC_$i.log" | tail -1 | grep -oE "[0-9]+")
    w=$(grep "trained weights" "$OUT/C_client_$i.log" | head -1)
    kill $SRV_C 2>/dev/null; wait $SRV_C 2>/dev/null
    if [ "$i" -eq 0 ]; then
        echo "  warmup: compute=${cmp}ms setup=${setup}ms   $w"
    else
        echo "  run $i: compute=${cmp}ms setup=${setup}ms"
        echo "$cmp" >> "$OUT/C_compute.txt"
        echo "$setup" >> "$OUT/C_setup.txt"
    fi
done
echo ""

stats() {
    sort -n "$1" | awk '
    { a[NR]=$1 }
    END {
        if (NR==0){ print "  (no data)"; exit }
        if (NR%2==1) m=a[(NR+1)/2]; else m=(a[NR/2]+a[NR/2+1])/2
        s=0; for(i=1;i<=NR;i++) s+=a[i]
        printf "  min=%dms  median=%dms  mean=%dms  max=%dms  n=%d\n", a[1], m, s/NR, a[NR], NR
    }'
}

echo "=== Results (pure FHE compute) ==="
echo "Prototype A (CPU) eval:";       stats "$OUT/A_eval.txt"
echo "Prototype C (GPU) compute:";    stats "$OUT/C_compute.txt"
echo "Prototype C (GPU) one-time setup (LoadContext):"; stats "$OUT/C_setup.txt"
echo ""
echo "Correctness (weights must match across A and C):"
grep -h "trained weights" "$OUT/A_client_1.log" "$OUT/C_client_1.log" 2>/dev/null | sed 's/^/  /'
echo ""
echo "Done"
