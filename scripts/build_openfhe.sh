#!/usr/bin/env bash
# build_openfhe.sh — Download, build, and install OpenFHE v1.5.1.
#
# Idempotent: skips downloads/extraction if already present. OpenFHE is built
# as shared libraries with native optimizations and installed to /usr/local.
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

echo "[openfhe] Building OpenFHE v${OPENFHE_VERSION}..."

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
    # The archive extracts to cereal-master/; move it to the target.
    rm -rf "$CEREAL_DIR"
    mv "$TMP_EXTRACT/cereal-master" "$CEREAL_DIR"
    rm -rf "$TMP_EXTRACT" "$CEREAL_TARBALL"
else
    echo "[openfhe] cereal submodule already present: $CEREAL_DIR"
fi

# --- 4. Configure with cmake -------------------------------------------------
mkdir -p "$OPENFHE_BUILD_DIR"
echo "[openfhe] Configuring (cmake)..."
cmake -S "$OPENFHE_SRC_DIR" -B "$OPENFHE_BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
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
echo "[openfhe] Installing to /usr/local..."
$SUDO make -C "$OPENFHE_BUILD_DIR" install

# --- 7. ldconfig -------------------------------------------------------------
# Ensure /usr/local/lib is in the linker path.
LOCAL_CONF="/etc/ld.so.conf.d/local.conf"
if ! grep -q '/usr/local/lib' "$LOCAL_CONF" 2>/dev/null; then
    $SUDO bash -c "echo '/usr/local/lib' > '$LOCAL_CONF'"
fi
$SUDO ldconfig

# --- Verify ------------------------------------------------------------------
if [ -f /usr/local/lib/OpenFHE/OpenFHEConfig.cmake ]; then
    echo "[openfhe] OpenFHEConfig.cmake found at /usr/local/lib/OpenFHE/"
else
    echo "[openfhe] ERROR: OpenFHEConfig.cmake not found after install." >&2
    exit 1
fi

echo "[openfhe] SUCCESS: OpenFHE v${OPENFHE_VERSION} installed to /usr/local."
