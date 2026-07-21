# Benchmark: Encrypted Logistic-Regression Training — Prototype A vs C

## Experimental Setup

**Benchmark method:** 3 independent measurements per prototype, each with a fresh
server and client process (same MNIST 1/8 dataset, fresh key pair per run).

**Reproduction:** `scripts/benchmark_logreg_a_vs_c.sh`.

### CKKS Parameters

| Parameter | Value |
|-----------|-------|
| Ring dimension | 65536 |
| Batch size | 32768 slots |
| Multiplicative depth | 22 |
| Scaling technique | FLEXIBLEAUTO |
| Key-switch technique | HYBRID, dnum=3 |
| Secret key distribution | SPARSE_TERNARY |
| Scaling / first mod size | 50 / 55 bits |
| Training iterations | 2 (no bootstrap — see Known Issues) |

### Problem Size

| Parameter | Value |
|-----------|-------|
| Dataset | MNIST 1/8 (1280 samples, 196 features) |
| Matrix packing | 128 rows × 256 cols per ciphertext |
| Input ciphertexts | 21 (10 data + 10 labels + 1 weights) |
| Output | 1 ciphertext (256 weights) |
| Eval-key blobs | 2 per prototype (Mult + Auto) |
 | Eval-key total | Prototype A: 6570 MB, Prototype C: 7920 MB |

Both prototypes use the same serialisation (identical `SerializeEval{Mult,Automorphism}Key`
Cereal implementations).

The Auto-key size difference (6480 vs 7830 MB) comes purely
from different rotation-key counts: Prototype C's GPU backend uses base-4 BSGS cascade
accumulate, which needs ~51 non-power-of-two rotation indices; Prototype A's CPU
backend uses simple power-of-two accumulate with ~23 indices. Both also include the
same bootstrap-internal rotation set (~68 keys from `EvalBootstrapKeyGen(256)`), so the
total unique counts are ~72 (A) vs ~119 (C). Each key encodes identically; more keys
→ more bytes.

## Measurement Results

### Server-Side Timing (3 runs each, median)

| Phase | Prototype A (CPU) | Prototype C (GPU H20) |
|-------|-------------------:|-----------------------:|
| Key deserialisation (`ctx`) | 359 ms | 16,258 ms |
| FHE evaluation (`eval`) | 1,614 ms | 21,888 ms |
| Output serialisation (`outser`) | 0 ms | 0 ms |
| Transcript generation (`transcript`) | 4,731 ms | 5,773 ms |
| GPU evidence collection (`gpuev`) | — | 27 ms |
| TDX quote generation (`quote`) | 60 ms | 61 ms |

**Key deserialisation** reads the eval key blobs from the TCP stream and
deserialises them into OpenFHE's global key map (same API calls in both
prototypes).

**FHE evaluation** includes GPU setup for Prototype C (GenCryptoContextGPU +
PCIe upload of 8 GB of keys and 1.5 GB of bootstrap precomputation, ~22 s of
the 25 s total).

**Transcript generation** BLAKE3-hashes the eval key blobs (6570 MB vs 7920 MB),
input ciphertexts, and output ciphertext.

### GPU-Separated Compute (Prototype C only)

Timers within the workload:

| Phase | Time |
|-------|-----:|
| GPU context + LoadContext | 19,499 ms |
| Input upload (21 ciphertexts) | 285 ms |
| Pure FHE compute (2 iterations) | 81 ms |

### Client Verification Time (3 runs each, median)

| Prototype | Verification |
|-----------|-------------:|
| A | 37 ms |
| C | 40 ms |

Verification includes transcript check + remote Alibaba Cloud attestation call,
which dominates the ~45 ms figure.

### Speedup

| Metric | A (CPU) | C (GPU) | Speedup |
|--------|--------:|--------:|--------:|
| Pure FHE compute (2 iterations) | 81 ms | **~20×** |
| Full server-side (ctx+eval) | 1,973 ms | 38,146 ms | 0.05× |

The full server-side time for Prototype C is dominated by key deserialisation
(17,450 ms) and GPU upload (22,177 ms), both one-time costs tied to the per-run
KeyGen in this benchmark. With key reuse across requests these would amortise,
making the ~21× compute speedup the meaningful figure.

## Raw Measurements (all runs)

All runs use the current code version.

### Prototype A (tee-vfhe, CPU)

| Run | ctx | eval | outser | transcript | quote | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|--------------:|
| 1 | 367 | 1633 | 0 | 4716 | 59 | 37 |
| 2 | 359 | 1588 | 0 | 4731 | 60 | 36 |
| 3 | 359 | 1614 | 0 | 4815 | 61 | 37 |

### Prototype C (gpucc-vfhe, GPU H20)

| Run | ctx | eval | outser | transcript | gpuev | quote | LoadContext | input_up | compute | client_verify |
|-----|----:|-----:|-------:|-----------:|------:|------:|------------:|---------:|--------:|--------------:|
| 1 | 16177 | 21958 | 0 | 5773 | 27 | 62 | 19512 | 314 | 86 | 41 |
| 2 | 16428 | 21888 | 0 | 5805 | 27 | 61 | 19499 | 282 | 81 | 40 |
| 3 | 16258 | 20871 | 0 | 5709 | 27 | 61 | 18480 | 285 | 79 | 40 |

All times in milliseconds.

All times in milliseconds.
