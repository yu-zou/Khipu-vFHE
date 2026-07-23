#!/usr/bin/env bash
# run.sh — execute the AES-GCM / GMAC benchmark and produce a markdown report.
#
# Usage: ./run.sh [--warmup]
#
# Generates: report.md  (formatted markdown table)
#            results.csv (raw CSV data)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_BIN="$SCRIPT_DIR/bench"
REPORT_MD="$SCRIPT_DIR/report.md"
RESULTS_CSV="$SCRIPT_DIR/results.csv"
WARMUP_FLAG=""

if [[ "${1:-}" == "--warmup" ]]; then
    WARMUP_FLAG="--warmup"
fi

# ── Build ────────────────────────────────────────────────────────────────────
echo "==> Building benchmark..."
make -C "$SCRIPT_DIR" clean
make -C "$SCRIPT_DIR"

if [[ ! -x "$BENCH_BIN" ]]; then
    echo "ERROR: failed to build benchmark binary at $BENCH_BIN"
    exit 1
fi

# ── CPU / Platform info ──────────────────────────────────────────────────────
CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs || echo "unknown")
CPU_CORES=$(grep -c '^processor' /proc/cpuinfo || echo "unknown")
OPENSSL_VER=$(openssl version 2>/dev/null || echo "unknown")
AESNI_SUPPORT=$(grep -o '\baes\b' /proc/cpuinfo | wc -l)
AESNI_NOTE="yes (count=${AESNI_SUPPORT})"
if [[ "$AESNI_SUPPORT" -eq 0 ]]; then
    AESNI_NOTE="no"
fi

echo "==> CPU:        $CPU_MODEL"
echo "==> Cores:      $CPU_CORES"
echo "==> OpenSSL:    $OPENSSL_VER"
echo "==> AES-NI:     $AESNI_NOTE"

# ── Run benchmark ────────────────────────────────────────────────────────────
echo ""
echo "==> Running benchmark (this may take a minute)..."
echo ""

# Capture the table output
"$BENCH_BIN" $WARMUP_FLAG | tee "$SCRIPT_DIR/bench_output.txt"

# Also produce CSV
"$BENCH_BIN" --csv $WARMUP_FLAG > "$RESULTS_CSV"

# ── Generate Markdown report ─────────────────────────────────────────────────
echo "==> Generating markdown report..."

TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
HOSTNAME=$(hostname -f 2>/dev/null || hostname)

# Build the report header
cat > "$REPORT_MD" << 'REPORTHEADER'
# AES-256-GCM vs GMAC-256 Throughput Benchmark (AES-NI)

## Test Environment

REPORTHEADER

{
    echo ""
    echo "- **Date:**       ${TIMESTAMP}"
    echo "- **Host:**       ${HOSTNAME}"
    echo "- **CPU:**        ${CPU_MODEL}"
    echo "- **Cores:**      ${CPU_CORES}"
    echo "- **OpenSSL:**    ${OPENSSL_VER}"
    echo "- **AES-NI:**     ${AESNI_NOTE}"
    echo "- **Compiler:**   $(g++ --version | head -1)"
    echo ""
} >> "$REPORT_MD"

cat >> "$REPORT_MD" << 'REPORTMETHODOLOGY'
## Methodology

- **AES-GCM-256:** Encrypt `<input_size>` bytes of plaintext with a 16-byte
  fixed AAD (simulating metadata/headers) and a 12-byte IV, producing
  ciphertext + 16-byte authentication tag.
- **GMAC-256:** Authenticate `<input_size>` bytes of AAD with zero plaintext
  and a 12-byte IV, producing only a 16-byte authentication tag. GMAC is
  GCM with no plaintext — no CTR-mode encryption is performed.
- **Timing:** Median per-operation time, measured over enough iterations to
  accumulate ~2 seconds of total wall-clock time for each data point.
  Warm-up iterations are executed before each measurement batch.
- **AES-NI:** Enabled automatically by OpenSSL when hardware support is
  detected (no special flags needed at the application level).

## Results

REPORTMETHODOLOGY

# Append the formatted table output from the benchmark
echo "" >> "$REPORT_MD"

# Extract the table from bench_output.txt and convert to proper markdown format.
# The bench program outputs a box-drawing table; we extract content rows
# (lines starting with "|" that have actual data, not the dashed sub-header)
# and rebuild as a proper markdown table.
awk '
# Collect all "| ... |" content lines (not the box-drawing +/- lines)
/^\|.*\|/ {
    line = $0
    sub(/^\|/, "", line)
    sub(/\|$/, "", line)
    n = split(line, cols, "|")
    out = "|"
    for (i = 1; i <= n; i++) {
        gsub(/^[ \t]+|[ \t]+$/, "", cols[i])
        out = out " " cols[i] " |"
    }
    rows[++row_count] = out
}
END {
    if (row_count >= 2) {
        # Row 1 is the column header
        print rows[1]
        # Separator row
        nf = split(rows[1], hdr, "|")
        sep = "|"
        for (i = 2; i < nf; i++) {
            sep = sep " --- |"
        }
        print sep
        # Rows 2+ are the data rows
        for (r = 2; r <= row_count; r++) {
            print rows[r]
        }
    }
}
' "$SCRIPT_DIR/bench_output.txt" >> "$REPORT_MD"

# Append notes
cat >> "$REPORT_MD" << 'REPORTNOTES'

## Notes

- **AES-GCM throughput** = `input_size / aes_gcm_time` (plaintext bytes per second).
- **GMAC throughput** = `input_size / gmac_time` (AAD bytes per second).
- **Speedup** = `aes_gcm_time / gmac_time` — how many times faster GMAC
  (auth-only) is compared to full AES-GCM (encrypt + auth).
- GMAC is faster because it skips the CTR-mode encryption of the plaintext;
  only the GHASH polynomial evaluation (over the AAD and lengths) and the
  final AES block encryption are performed.
REPORTNOTES

echo ""
echo "==> Done."
echo "    Markdown report: $REPORT_MD"
echo "    Raw CSV data:    $RESULTS_CSV"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat "$REPORT_MD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
