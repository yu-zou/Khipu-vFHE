#!/usr/bin/env bash
# build_project.sh — Configure and build tee-vfhe (server, client, benchmark).
#
# Idempotent: preserves existing build/ contents; only runs cmake configure
# if CMakeCache.txt is missing or CMakeLists.txt changed since last configure.
# Verifies all three expected binaries exist after the build.
set -euo pipefail

# Resolve repo root (parent of scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_DIR="$REPO_ROOT/tee-vfhe"
BUILD_DIR="$PROJECT_DIR/build"

echo "[build] Building tee-vfhe in $BUILD_DIR..."

# --- 1. Create build dir -----------------------------------------------------
mkdir -p "$BUILD_DIR"

# --- 2. Configure (cmake) ----------------------------------------------------
# Reconfigure if no cache or if CMakeLists.txt is newer than the cache.
NEED_CONFIGURE=0
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
    NEED_CONFIGURE=1
elif [ "$PROJECT_DIR/CMakeLists.txt" -nt "$BUILD_DIR/CMakeCache.txt" ]; then
    NEED_CONFIGURE=1
fi

if [ "$NEED_CONFIGURE" -eq 1 ]; then
    echo "[build] Configuring (cmake ..)..."
    cmake -S "$PROJECT_DIR" -B "$BUILD_DIR"
else
    echo "[build] CMake cache up-to-date; skipping configure."
fi

# --- 3. Build ----------------------------------------------------------------
echo "[build] Compiling (make -j\$(nproc))..."
if ! make -C "$BUILD_DIR" -j"$(nproc)"; then
    echo "[build] make -j$(nproc) failed (possible OOM); retrying with -j4..."
    make -C "$BUILD_DIR" -j4
fi

# --- 4. Verify binaries ------------------------------------------------------
BIN_SERVER="$BUILD_DIR/tee_server"
BIN_CLIENT="$BUILD_DIR/tee_client"
BIN_BENCHMARK="$BUILD_DIR/benchmark/benchmark_runner"

MISSING=0
for bin in "$BIN_SERVER" "$BIN_CLIENT" "$BIN_BENCHMARK"; do
    if [ ! -x "$bin" ]; then
        echo "[build] ERROR: expected binary not found or not executable: $bin" >&2
        MISSING=1
    fi
done

if [ "$MISSING" -ne 0 ]; then
    echo "[build] FAILED: one or more binaries missing." >&2
    exit 1
fi

echo "[build] SUCCESS: all binaries built."
echo "[build]   $BIN_SERVER"
echo "[build]   $BIN_CLIENT"
echo "[build]   $BIN_BENCHMARK"
