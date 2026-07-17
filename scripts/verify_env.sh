#!/usr/bin/env bash
# verify_env.sh — Verify all environment dependencies for Prototype A & C.
set -euo pipefail

echo "=== Environment Verification ==="

echo "[1/7] GCC: $(gcc --version | head -1)"

echo "[2/7] CMake: $(cmake --version | head -1)"

echo "[3/7] Stock OpenFHE (for tee-vfhe / Prototype A):"
if [ -f /usr/local/openfhe-stock/include/openfhe/pke/openfhe.h ]; then
    echo "  Headers: OK"
else
    echo "  Headers: MISSING" >&2; exit 1
fi
if ldconfig -p | grep -q "libOPENFHEcore.so.*openfhe-stock"; then
    echo "  Libraries: OK"
else
    echo "  Libraries: MISSING" >&2; exit 1
fi

echo "[4/7] FIDESlib OpenFHE (for gpucc-vfhe / Prototype C):"
if [ -f /usr/local/openfhe-fideslib/include/openfhe/pke/openfhe.h ]; then
    echo "  Patched OpenFHE headers: OK"
else
    echo "  Patched OpenFHE headers: MISSING" >&2; exit 1
fi
if ldconfig -p | grep -q "libOPENFHEcore.so.*openfhe-fideslib"; then
    echo "  Patched OpenFHE libraries: OK"
else
    echo "  Patched OpenFHE libraries: MISSING" >&2; exit 1
fi

echo "[5/7] FIDESlib:"
if [ -f /usr/local/fideslib/lib64/fideslib.a ]; then
    echo "  Static library: OK"
else
    echo "  Static library: MISSING" >&2; exit 1
fi
if [ -f /usr/local/fideslib/include/fideslib/fideslib.hpp ]; then
    echo "  Headers: OK"
else
    echo "  Headers: MISSING" >&2; exit 1
fi

echo "[6/7] NVTrust libnvat:"
if [ -f /usr/local/nvat/include/nvat.h ]; then
    echo "  Headers: OK"
else
    echo "  Headers: MISSING" >&2; exit 1
fi
if ldconfig -p | grep -q libnvat; then
    echo "  Libraries: OK"
else
    echo "  Libraries: MISSING" >&2; exit 1
fi

echo "[7/7] TDX:"
if [ -e /dev/tdx_guest ]; then
    echo "  /dev/tdx_guest: OK"
else
    echo "  /dev/tdx_guest: MISSING" >&2; exit 1
fi
if [ -e /dev/tdx-attest ] || ldconfig -p | grep -q libtdx_attest; then
    echo "  libtdx_attest: OK"
else
    echo "  libtdx_attest: MISSING" >&2; exit 1
fi

echo ""
echo "[GPU] NVIDIA:"
nvidia-smi --query-gpu=name,compute_cap,memory.total --format=csv,noheader 2>/dev/null || echo "  nvidia-smi failed"

echo ""
echo "[Python] Version:"
python3 --version 2>/dev/null || echo "  python3 not found"
python3 -c "import torch, sklearn; print('  PyTorch + sklearn: OK')" 2>/dev/null || echo "  PyTorch or sklearn missing"

echo ""
echo "=== All checks passed ==="
