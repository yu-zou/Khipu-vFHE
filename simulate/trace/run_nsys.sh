#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
BUILD=build
OUT=../data/traces
mkdir -p "$OUT"
export CUDA_VISIBLE_DEVICES=0

declare -A BIN=( [ckks_add]=bench_add [ckks_mult_relin_rescale]=bench_mult
                 [ckks_rotate]=bench_rotate [ckks_bootstrap]=bench_bootstrap )

for wl in "${!BIN[@]}"; do
  for km in cold warm; do
    rep="/tmp/${wl}_${km}"
    # CUDA 13 removed cudaProfilerApi; capture full process for both modes
    nsys profile --trace=cuda --force-overwrite=true -o "$rep" \
      "$BUILD/${BIN[$wl]}" --keymode $km
    nsys export --type=sqlite --force-overwrite=true -o "${rep}.sqlite" "${rep}.nsys-rep"
    eval "$(/opt/conda/bin/conda shell.bash hook)"
    conda run -n prototype-d python parse_nsys.py --sqlite "${rep}.sqlite" --workload "$wl" \
      --keymode "$km" --out "$OUT/${wl}_${km}.json"
    echo "wrote $OUT/${wl}_${km}.json"
  done
done
