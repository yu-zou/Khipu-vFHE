#!/usr/bin/env bash
# Starts the Prototype D GPU container: single GPU, host proxies mapped in,
# repo mounted at /work. Run hardware stages (measure/trace) inside it.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="nvidia/cuda:13.3.0-runtime-ubuntu24.04"

docker run --rm -it \
  --gpus '"device=0"' \
  -e http_proxy -e https_proxy -e all_proxy \
  -e HTTP_PROXY -e HTTPS_PROXY -e ALL_PROXY \
  -e CUDA_VISIBLE_DEVICES=0 \
  -v "$REPO_ROOT":/work -w /work/simulate \
  "$IMAGE" bash
