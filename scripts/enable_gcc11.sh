#!/usr/bin/env bash
# enable_gcc11.sh — Enable GCC >= 11 for FIDESlib builds.
#
# Usage: source scripts/enable_gcc11.sh
#
# Tries gcc-toolset-12 first (preferred), then gcc-toolset-11, then devtoolset-11.
# FIDESlib requires GCC >= 11.

if [ -f /opt/rh/gcc-toolset-12/enable ]; then
    source /opt/rh/gcc-toolset-12/enable
elif [ -f /opt/rh/gcc-toolset-11/enable ]; then
    source /opt/rh/gcc-toolset-11/enable
elif [ -f /opt/rh/devtoolset-11/enable ]; then
    source /opt/rh/devtoolset-11/enable
else
    echo "ERROR: No GCC >= 11 toolset found." >&2
    echo "Install one of: gcc-toolset-12-gcc gcc-toolset-11-gcc devtoolset-11-gcc" >&2
    return 1 2>/dev/null || exit 1
fi
echo "GCC version: $(gcc --version | head -1)"
