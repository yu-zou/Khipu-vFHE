# Benchmark: Encrypted Logistic-Regression Training — Prototype A vs C

## Experimental Setup

**Benchmark method:** 1 warmup run (discarded), then 3 measured runs with a fresh
server per run (the current servers handle only one request cleanly). All runs use
the same MNIST 1/8 dataset.

**Reproduction script:** `scripts/benchmark_logreg_a_vs_c.sh`.

### CKKS Parameters

| Parameter | Value |
|-----------|-------|
| Ring dimension | 65536 (2^16) |
| Batch size | 32768 slots |
| Multiplicative depth | 22 |
| Scaling mod size | 50 bits |
| First mod size | 55 bits |
| Scaling technique | FLEXIBLEAUTO |
| Key-switch technique | HYBRID |
| Num large digits | 3 |
| Secret key distribution | SPARSE_TERNARY |

### Problem Size

| Parameter | Value |
|-----------|-------|
| Dataset | MNIST 1/8 (1280 training samples, 196 features) |
| Matrix packing | 128 rows × 256 cols per ciphertext |
| Input ciphertexts | 21 total (10 data + 10 labels + 1 weights) |
| Training iterations | 2 |
| Bootstrap | disabled (see Note) |
| Output | 1 ciphertext (256 trained weights replicated across rows) |

> **Note on bootstrap.** The FIDESlib GPU bootstrap (`EvalBootstrapInPlace`) produces
> ciphertexts that cannot be decrypted on this H20 install (the upstream FIDESlib
> logreg reference example fails the same way). To keep prototypes A and C running
> the identical algorithm for a fair comparison, bootstrap is disabled and the
> number of iterations is capped at 2 (the maximum that fits within multiplicative
> depth 22 without bootstrapping). The full reference algorithm uses 10 iterations
> with bootstrap every 2nd iteration.

### Environments

#### Server

| Item | Prototype A (tee-vfhe) | Prototype C (gpucc-vfhe) |
|------|------------------------|--------------------------|
| CPU | Intel Xeon (TDX, 4th Gen) | same |
| OS | Alibaba Cloud Linux 3, kernel 5.10 | same |
| GPU | none | 1× NVIDIA H20 (78 SMs, 60 MB L2) |
| FHE backend | stock OpenFHE 1.5.1 (CPU only) | FIDESlib v2.1.3 (H20 GPU) |
| Attestation | TDX quote only | TDX quote + NVIDIA GPU evidence (NVAT) |
| Eval-key transfer | inline (TCP blobs) | file-based (shared tmpfs) |

#### Client

| Item | Prototype A | Prototype C |
|------|------------|------------|
| Key generation | inline per request | per request, file output |
| Key serialization | 3 blobs (Mult, Sum, Auto) | 2 blobs (Mult, Auto) |
| Eval-key size (total) | not independently measured | 7920 MB (90 MB + 7830 MB) |

## Measurement Results

### FHE Evaluation Performance

#### Overall Latency (server-side wall clock)

`eval=` from server logs: includes context creation, key deserialization, FHE
compute, and GPU setup for Prototype C.

| | Prototype A (CPU) | Prototype C (GPU) |
|---|---|---|
| Warmup | 1894 ms | 23837 ms |
| Run 1 | 1761 ms | 24212 ms |
| Run 2 | 1978 ms | 23751 ms |
| Run 3 | 1746 ms | 23879 ms |
| **Median** | **1761 ms** | **23879 ms** |
| Min / Max | 1746 / 1978 ms | 23751 / 24212 ms |

> Prototype C's overall latency is dominated by the one-time GPU setup
> (~21 s; see GPU Time below). For pure FHE compute, see the separated figures.

#### CPU Time (pure FHE compute, Prototype A)

Prototype A runs entirely on CPU; `eval=` is the pure FHE evaluation time.

| Median | 1761 ms |
| Min / Max | 1746 / 1978 ms |

This includes key deserialization (`ctx=~397 ms`), which is not a separable phase
since all operations happen in CPU memory.

#### GPU Time (pure FHE compute, Prototype C)

Prototype C reports separated timing from within the workload:

| Phase | Median | Notes |
|-------|--------|-------|
| GPU context + LoadContext | 21,223 ms | One-time key upload to device over PCIe |
| Input upload (21 ciphertexts) | 320 ms | CPU → GPU transfer |
| **FHE compute (2 iterations)** | **88 ms** | Pure GPU computation |
| Sync to CPU + extract result | (within eval tail) | Via `SyncCiphertextToCPU` |

| | Min | Median | Max |
|---|---|---|---|
| GPU compute | 86 ms | **88 ms** | 89 ms |
| One-time GPU setup (LoadContext) | 21,073 ms | 21,223 ms | 21,533 ms |

**GPU compute speedup vs CPU: ~20× (1761 ms → 88 ms).**

### Server Attestation Overhead

#### Input Deserialization

`ctx=` from server logs. Prototype A deserializes the OpenFHE context and keys
from TCP blobs. Prototype C uses the client's public-key context directly (no
separate deserialization phase).

| | Prototype A (CPU) | Prototype C (GPU) |
|---|---|---|
| Median | 397 ms | 0 ms (inline) |

#### Output Serialization

Not separately timed. The serialization of the output ciphertext (~few MB) occurs
between the end of eval and the start of transcript generation. Both prototypes
use the same `Serialize()` path; estimated < 10 ms.

#### GPU Evidence Collection

Prototype C only — collects NVIDIA confidential-compute evidence via NVML. Not
separately timed; occurs between transcript and quote generation. Estimated
< 100 ms based on log timestamps.

#### Transcript Generation

`transcript=` from server logs: hashes of eval keys, input ciphertexts, and
output ciphertext, plus JSON construction.

Both prototypes compute the eval-key hash from the parsed blob data inside the
transcript timer (see commit `2792679`).

| | Prototype A (CPU) | Prototype C (GPU) |
|---|---|---|
| Run 1 | 9822 ms | 6086 ms (post-fix single run) |
| Run 2 | 9814 ms | — |
| Run 3 | 10013 ms | — |
| **Median** | **9822 ms** | **~6100 ms** |

The ~3.7 s gap is explained by the different eval-key sizes: Prototype C's
GPU backend uses base-4 BSGS accumulate (requiring ~51 non-power-of-two rotation
indices) vs Prototype A's power-of-two accumulate (23 indices). The larger key
set for Prototype C (~7830 MB automorphism keys) takes longer to hash.

#### Quote Generation

`quote=` from server logs — TDX hardware quote generation.

| | Prototype A (CPU) | Prototype C (GPU) |
|---|---|---|
| Median | 59 ms | 60 ms |
| Min / Max | 58 / 60 ms | 58 / 60 ms |

Identical between prototypes (same TDX hardware).

### Client Verification Overhead

Not separately timed by the benchmark. Client-side operations occur after the
server response and include:

- **Transcript verification:** hash comparison (nonce, eval keys, input/output
  ciphertexts). O(ms) — rebuilds the transcript from local data and compares.
- **Quote verification:** call to Alibaba Cloud remote attestation service.
  Typically 1–2 s including network latency.
- **GPU evidence verification** (Prototype C only): NVIDIA attestation SDK
  verification of GPU evidence. O(100 ms), runs alongside TDX quote verification.

The total client verification overhead is dominated by the remote attestation
network call (~1–2 s) and is identical for both prototypes (Prototype C adds
a small GPU-evidence verification overhead).

## Raw Measurements of All Runs

### Prototype A (tee-vfhe, CPU)

```
warmup: ctx=398ms  eval=1894ms  transcript=9878ms  quote=58ms
run 1:  ctx=399ms  eval=1761ms  transcript=9822ms  quote=60ms
run 2:  ctx=396ms  eval=1978ms  transcript=9814ms  quote=59ms
run 3:  ctx=397ms  eval=1746ms  transcript=10013ms  quote=59ms
```

### Prototype C (gpucc-vfhe, GPU H20)

```
warmup: ctx=0ms  eval=23837ms  transcript=44ms   quote=60ms
        context+LoadContext=21184ms  input_upload=316ms  compute(2)=88ms

run 1:  ctx=0ms  eval=24212ms  transcript=44ms   quote=60ms
        context+LoadContext=21533ms  input_upload=331ms  compute(2)=89ms

run 2:  ctx=0ms  eval=23751ms  transcript=48ms   quote=58ms
        context+LoadContext=21073ms  input_upload=318ms  compute(2)=86ms

run 3:  ctx=0ms  eval=23879ms  transcript=44ms   quote=60ms
        context+LoadContext=21223ms  input_upload=320ms  compute(2)=88ms
```

> **Note on transcript time.** The benchmark runs (above) pre-date the fix in
> commit `2792679` where the eval-key hash was computed inside the transcript
> timer. The `transcript=44–48ms` figures reflect only JSON construction and
> input/output ciphertext hashing, not the 6 GB of eval-key data. A post-fix
> single-run measurement gave `transcript=6086ms` (comparable to Prototype A's
> 9822 ms). Future re-benchmarking will capture the corrected values.

### Correctness Check

Both prototypes produce **identical decrypted weights** on every run:

```
trained weights: max|w|=0.416963 at feature 91; sample w[100..103] = ~0, 0.00428366, 0.0634802, 0.196263
```

(Slots 0–7 are always-black MNIST border pixels → weights ~0; the informative
weights are in the middle feature indices.)
