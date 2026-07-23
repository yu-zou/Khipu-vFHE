#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PARAMS=data/params/system_params.json
RESULTS=results
mkdir -p "$RESULTS"

echo "== Stage 1: measure system params =="
measure/run_measurements.sh

echo "== Stage 2: trace FIDESlib microbenchmarks =="
trace/run_nsys.sh

echo "== Stage 3: simulate 16 runs =="
for trace_file in data/traces/*.json; do
  base=$(basename "$trace_file" .json)
  for sec in aes-gcm gmac; do
    python -m simulator.run_sim --params "$PARAMS" --trace "$trace_file" \
      --secmode "$sec" --out "$RESULTS/${base}_${sec}.json"
  done
done

echo "== Stage 3b: transfer-size sweep =="
python -m analyze.make_size_sweep --params "$PARAMS" --out "$RESULTS/size_sweep.csv"

echo "== Stage 4: aggregate + plot =="
python -m analyze.aggregate --results-dir "$RESULTS" --out "$RESULTS/summary.csv"
python -m analyze.plots --summary "$RESULTS/summary.csv" --sweep "$RESULTS/size_sweep.csv" \
  --outdir "$RESULTS/figures"
echo "Done. See $RESULTS/summary.csv, $RESULTS/speedup.csv, $RESULTS/figures/"
