#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
make
mkdir -p ../data/params
./cpu_crypto_bench > /tmp/cpu.json
./swiotlb_copy_bench > /tmp/swiotlb.json
CUDA_VISIBLE_DEVICES=0 ./pcie_bench > /tmp/pcie.json
python assemble_params.py --cpu /tmp/cpu.json --swiotlb /tmp/swiotlb.json \
  --pcie /tmp/pcie.json --out ../data/params/system_params.json
echo "wrote ../data/params/system_params.json"
