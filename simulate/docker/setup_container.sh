#!/usr/bin/env bash
# Run INSIDE the container (nvidia/cuda:13.3.0-runtime-ubuntu24.04) to install
# the CUDA toolkit (nvcc) and Nsight Systems (nsys). Relies on the proxy env
# vars mapped in by run_container.sh.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
# System tools only (build toolchain + CUDA/nsys). Python packages go in conda, NOT here.
apt-get install -y --no-install-recommends \
  cuda-toolkit nsight-systems build-essential cmake libssl-dev wget ca-certificates
# Verify the two tools we depend on are now present.
command -v nvcc >/dev/null || { echo "FATAL: nvcc not found after install"; exit 1; }
command -v nsys >/dev/null || { echo "FATAL: nsys not found after install"; exit 1; }
echo "container setup ok: $(nvcc --version | tail -1); $(nsys --version)"

# Python: use an isolated miniconda env (do NOT install packages into the base image python).
# If miniconda is not already available on the mounted repo/host, install it here, then:
#   conda create -y -n prototype-d python=3.11 && conda activate prototype-d
#   pip install -r requirements.txt
echo "reminder: create/activate the 'prototype-d' conda env before running Python stages"
