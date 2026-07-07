#!/usr/bin/env bash
# setup_tdx_env.sh — Verify and configure the TDX + OpenFHE build environment.
#
# Idempotent: safe to run multiple times. Performs:
#   1. Install cmake via yum if missing.
#   2. Verify GCC >= 9.
#   3. Verify cmake >= 3.16.3.
#   4. Configure /etc/sgx_default_qcnl.conf with a reasonable PCCS_URL.
#   5. Verify TDX attestation is available (/dev/tdx-attest or libtdx_attest).
#   6. Update the dynamic linker cache for /usr/local/lib.
set -euo pipefail

# --- root/sudo detection -----------------------------------------------------
SUDO=""
if [ "$(id -u)" != "0" ]; then
    SUDO="sudo"
fi

echo "[setup] Verifying TDX + OpenFHE build environment..."

# --- 1. cmake install --------------------------------------------------------
if ! command -v cmake >/dev/null 2>&1; then
    echo "[setup] cmake not found; installing via yum..."
    $SUDO yum install -y cmake
else
    echo "[setup] cmake already installed: $(cmake --version | head -1)"
fi

# --- 2. GCC version >= 9 -----------------------------------------------------
if ! command -v gcc >/dev/null 2>&1; then
    echo "[setup] ERROR: gcc not found. Install gcc >= 9 (e.g. yum install gcc gcc-c++)." >&2
    exit 1
fi
GCC_MAJOR=$(gcc -dumpversion | cut -d. -f1)
if [ "$GCC_MAJOR" -lt 9 ]; then
    echo "[setup] ERROR: gcc version $(gcc -dumpversion) < 9 (required >= 9)." >&2
    exit 1
fi
echo "[setup] gcc $(gcc -dumpversion) OK (>= 9)"

# --- 3. cmake version >= 3.16.3 ----------------------------------------------
CMAKE_VERSION_OUTPUT="$(cmake --version | head -1)"
# Extract the version number (e.g. "cmake version 3.26.5" -> "3.26.5")
CMAKE_VER="$(echo "$CMAKE_VERSION_OUTPUT" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
CMAKE_MAJOR="$(echo "$CMAKE_VER" | cut -d. -f1)"
CMAKE_MINOR="$(echo "$CMAKE_VER" | cut -d. -f2)"
CMAKE_PATCH="$(echo "$CMAKE_VER" | cut -d. -f3)"
# Compare against 3.16.3
VERSION_OK=0
if [ "$CMAKE_MAJOR" -gt 3 ] \
    || { [ "$CMAKE_MAJOR" -eq 3 ] && [ "$CMAKE_MINOR" -gt 16 ]; } \
    || { [ "$CMAKE_MAJOR" -eq 3 ] && [ "$CMAKE_MINOR" -eq 16 ] && [ "$CMAKE_PATCH" -ge 3 ]; }; then
    VERSION_OK=1
fi
if [ "$VERSION_OK" -ne 1 ]; then
    echo "[setup] ERROR: cmake $CMAKE_VER < 3.16.3 (required)." >&2
    exit 1
fi
echo "[setup] cmake $CMAKE_VER OK (>= 3.16.3)"

# --- 4. /etc/sgx_default_qcnl.conf -------------------------------------------
PCCS_CONF="/etc/sgx_default_qcnl.conf"
# Reasonable default PCCS URL (local provisioning certificate caching service).
DEFAULT_PCCS_URL="https://localhost:8081/sgx/certification/v3/"

if [ -f "$PCCS_CONF" ]; then
    if grep -qE '^\s*PCCS_URL' "$PCCS_CONF"; then
        echo "[setup] $PCCS_CONF already has PCCS_URL; leaving unchanged."
    else
        echo "[setup] $PCCS_CONF exists but has no PCCS_URL; appending default."
        $SUDO bash -c "cat >> '$PCCS_CONF' << EOF

# Added by setup_tdx_env.sh
PCCS_URL = ${DEFAULT_PCCS_URL}
USE_SECURE_CERT = ON
EOF"
    fi
else
    if $SUDO test -w "$(dirname "$PCCS_CONF")" 2>/dev/null || [ "$(id -u)" = "0" ]; then
        echo "[setup] Creating $PCCS_CONF with default PCCS_URL."
        $SUDO bash -c "cat > '$PCCS_CONF' << EOF
# SGX/TDX DCAP QCNL config — created by setup_tdx_env.sh
PCCS_URL = ${DEFAULT_PCCS_URL}
USE_SECURE_CERT = ON
EOF"
    else
        echo "[setup] WARNING: $PCCS_CONF does not exist and cannot be created (need root). Continuing." >&2
    fi
fi

# --- 5. TDX attestation availability -----------------------------------------
TDX_OK=0
if [ -e /dev/tdx-attest ]; then
    echo "[setup] /dev/tdx-attest present."
    TDX_OK=1
else
    echo "[setup] /dev/tdx-attest not present; checking libtdx_attest linkage..."
    # Try to compile and link a minimal program referencing tdx_att_get_quote.
    TDX_TEST_SRC="$(mktemp /tmp/tdx_test_XXXXXX.c)"
    TDX_TEST_BIN="$(mktemp /tmp/tdx_test_XXXXXX)"
    cat > "$TDX_TEST_SRC" << 'EOF'
extern int tdx_att_get_quote(void);
int main(void) { return (long)(void *)&tdx_att_get_quote == 0; }
EOF
    if gcc "$TDX_TEST_SRC" -ltdx_attest -o "$TDX_TEST_BIN" >/dev/null 2>&1; then
        echo "[setup] libtdx_attest links successfully (tdx_att_get_quote resolved)."
        TDX_OK=1
    else
        echo "[setup] WARNING: cannot link -ltdx_attest; TDX attestation may be unavailable." >&2
    fi
    rm -f "$TDX_TEST_SRC" "$TDX_TEST_BIN"
fi

if [ "$TDX_OK" -ne 1 ]; then
    echo "[setup] WARNING: TDX attestation is not available. The server will still build" >&2
    echo "[setup]          but attestation will fail at runtime. Continuing." >&2
fi

# --- 6. dynamic linker cache for /usr/local/lib ------------------------------
LOCAL_CONF="/etc/ld.so.conf.d/local.conf"
if ! grep -q '/usr/local/lib' "$LOCAL_CONF" 2>/dev/null; then
    echo "[setup] Adding /usr/local/lib to $LOCAL_CONF..."
    $SUDO bash -c "echo '/usr/local/lib' > '$LOCAL_CONF'"
else
    echo "[setup] /usr/local/lib already in $LOCAL_CONF."
fi
$SUDO ldconfig

echo "[setup] Environment verification complete."
echo "[setup]   GCC:      $(gcc -dumpversion)"
echo "[setup]   cmake:    $CMAKE_VER"
echo "[setup]   TDX:      $([ "$TDX_OK" = "1" ] && echo "available" || echo "UNAVAILABLE (warned)")"
echo "[setup]   ldconfig: refreshed"
echo "[setup] SUCCESS: TDX environment ready."
