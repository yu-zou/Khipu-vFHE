#!/usr/bin/env bash
# build_openfhe.sh — Download, build, and install OpenFHE v1.5.1.
#
# Idempotent: skips downloads/extraction if already present. OpenFHE is built
# as shared libraries with native optimizations and installed to a local prefix
# (default: /usr/local/openfhe-stock) to avoid conflicts with FIDESlib-patched
# OpenFHE. Override with OPENFHE_INSTALL_PREFIX env var.
# The cereal header-only submodule is fetched separately because the release
# tarball does not include git submodules.
set -euo pipefail

# --- root/sudo detection -----------------------------------------------------
SUDO=""
if [ "$(id -u)" != "0" ]; then
    SUDO="sudo"
fi

# Resolve repo root (parent of scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
THIRDPARTY="$REPO_ROOT/thirdparty"

OPENFHE_VERSION="1.5.1"
OPENFHE_TARBALL="$THIRDPARTY/openfhe-v${OPENFHE_VERSION}.tar.gz"
OPENFHE_SRC_DIR="$THIRDPARTY/openfhe-development"
OPENFHE_BUILD_DIR="$OPENFHE_SRC_DIR/build"
CEREAL_DIR="$OPENFHE_SRC_DIR/third-party/cereal"

OPENFHE_URL="https://github.com/openfheorg/openfhe-development/archive/refs/tags/v${OPENFHE_VERSION}.tar.gz"
CEREAL_URL="https://github.com/openfheorg/cereal/archive/refs/heads/master.tar.gz"

# Install prefix: can be overridden via OPENFHE_INSTALL_PREFIX env var.
# Default: /usr/local/openfhe-stock (avoids conflicts with FIDESlib-patched OpenFHE).
OPENFHE_INSTALL_PREFIX="${OPENFHE_INSTALL_PREFIX:-/usr/local/openfhe-stock}"

echo "[openfhe] Building OpenFHE v${OPENFHE_VERSION}..."
echo "[openfhe] Install prefix: ${OPENFHE_INSTALL_PREFIX}"

# --- thirdparty/ dir ---------------------------------------------------------
mkdir -p "$THIRDPARTY"

# --- 1. Download OpenFHE tarball --------------------------------------------
if [ ! -f "$OPENFHE_TARBALL" ]; then
    echo "[openfhe] Downloading OpenFHE v${OPENFHE_VERSION} tarball..."
    curl -L -f --retry 3 -o "$OPENFHE_TARBALL" "$OPENFHE_URL"
else
    echo "[openfhe] Tarball already present: $OPENFHE_TARBALL"
fi

# --- 2. Extract OpenFHE ------------------------------------------------------
if [ ! -d "$OPENFHE_SRC_DIR" ]; then
    echo "[openfhe] Extracting tarball..."
    tar -xzf "$OPENFHE_TARBALL" -C "$THIRDPARTY"
    # The tarball extracts to openfhe-development-<version>; rename if needed.
    EXTRACTED_DIR="$THIRDPARTY/openfhe-development-${OPENFHE_VERSION}"
    if [ -d "$EXTRACTED_DIR" ] && [ ! -d "$OPENFHE_SRC_DIR" ]; then
        mv "$EXTRACTED_DIR" "$OPENFHE_SRC_DIR"
    fi
else
    echo "[openfhe] Source dir already present: $OPENFHE_SRC_DIR"
fi

# --- 3. cereal submodule -----------------------------------------------------
if [ ! -d "$CEREAL_DIR" ] || [ -z "$(ls -A "$CEREAL_DIR" 2>/dev/null)" ]; then
    echo "[openfhe] Fetching cereal header-only submodule..."
    mkdir -p "$OPENFHE_SRC_DIR/third-party"
    CEREAL_TARBALL="$THIRDPARTY/cereal-master.tar.gz"
    curl -L -f --retry 3 -o "$CEREAL_TARBALL" "$CEREAL_URL"
    # Extract to a temp dir then move the inner folder into place.
    TMP_EXTRACT="$THIRDPARTY/.cereal_extract"
    rm -rf "$TMP_EXTRACT"
    mkdir -p "$TMP_EXTRACT"
    tar -xzf "$CEREAL_TARBALL" -C "$TMP_EXTRACT"
    # The archive extracts to cereal-main/ or cereal-master/; move whichever exists.
    rm -rf "$CEREAL_DIR"
    if [ -d "$TMP_EXTRACT/cereal-main" ]; then
        mv "$TMP_EXTRACT/cereal-main" "$CEREAL_DIR"
    elif [ -d "$TMP_EXTRACT/cereal-master" ]; then
        mv "$TMP_EXTRACT/cereal-master" "$CEREAL_DIR"
    else
        echo "[openfhe] ERROR: unexpected cereal archive contents." >&2
        rm -rf "$TMP_EXTRACT"
        exit 1
    fi
    rm -rf "$TMP_EXTRACT" "$CEREAL_TARBALL"
else
    echo "[openfhe] cereal submodule already present: $CEREAL_DIR"
fi

# --- 4. Configure with cmake -------------------------------------------------
mkdir -p "$OPENFHE_BUILD_DIR"
echo "[openfhe] Configuring (cmake)..."
cmake -S "$OPENFHE_SRC_DIR" -B "$OPENFHE_BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$OPENFHE_INSTALL_PREFIX" \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_UNITTESTS=OFF \
    -DBUILD_BENCHMARKS=OFF \
    -DBUILD_EXTRAS=OFF \
    -DWITH_NATIVEOPT=ON \
    -DBUILD_STATIC=OFF

# --- 5. Build with OOM fallback ---------------------------------------------
echo "[openfhe] Building (make -j\$(nproc))..."
if ! make -C "$OPENFHE_BUILD_DIR" -j"$(nproc)"; then
    echo "[openfhe] make -j$(nproc) failed (possible OOM); retrying with -j4..."
    make -C "$OPENFHE_BUILD_DIR" -j4
fi

# --- 6. Install --------------------------------------------------------------
echo "[openfhe] Installing to ${OPENFHE_INSTALL_PREFIX}..."
$SUDO make -C "$OPENFHE_BUILD_DIR" install

# --- 7. ldconfig -------------------------------------------------------------
# Ensure the install prefix lib dir is in the linker path.
PREFIX_LIB="${OPENFHE_INSTALL_PREFIX}/lib"
if [ -d "$PREFIX_LIB" ]; then
    PREFIX_CONF="/etc/ld.so.conf.d/openfhe-stock.conf"
    if ! grep -q "$PREFIX_LIB" "$PREFIX_CONF" 2>/dev/null; then
        $SUDO bash -c "echo '$PREFIX_LIB' > '$PREFIX_CONF'"
    fi
fi
$SUDO ldconfig

# --- Verify ------------------------------------------------------------------
if [ -f "${OPENFHE_INSTALL_PREFIX}/lib/OpenFHE/OpenFHEConfig.cmake" ] || \
   [ -f "${OPENFHE_INSTALL_PREFIX}/lib/cmake/OpenFHE/OpenFHEConfig.cmake" ]; then
    echo "[openfhe] OpenFHEConfig.cmake found at ${OPENFHE_INSTALL_PREFIX}"
else
    echo "[openfhe] ERROR: OpenFHEConfig.cmake not found after install." >&2
    exit 1
fi

echo "[openfhe] SUCCESS: OpenFHE v${OPENFHE_VERSION} installed to ${OPENFHE_INSTALL_PREFIX}."
