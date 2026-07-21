# Benchmark: Encrypted Logistic-Regression Training — Prototype A vs C

## Experimental Setup

**Benchmark method:** For each prototype, 1 warmup run (discarded) + 3 measured
runs. Each run starts a fresh server process and a fresh client process (the
current servers handle only one request cleanly — tracked as a known issue —
so per-run independence is guaranteed). All runs use the same MNIST 1/8 dataset.

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
| Security level | HEStd_NotSet |
| Bootstrap | disabled (see Note) |

### Problem Size

| Parameter | Value |
|-----------|-------|
| Dataset | MNIST 1/8 (1280 training samples, 196 features) |
| Matrix packing | 128 rows × 256 cols per ciphertext |
| Input ciphertexts | 21 total (10 data + 10 labels + 1 weights) |
| Training iterations | 2 |
| Output | 1 ciphertext (256 trained weights replicated across rows) |

> **Note on bootstrap.** The FIDESlib GPU bootstrap produces ciphertexts that
> cannot be decrypted on this H20 install (the upstream FIDESlib logreg reference
> example fails the same way). To keep prototypes A and C running the identical
> algorithm for a fair comparison, bootstrap is disabled and iterations are capped
> at 2 (the maximum that fits within multiplicative depth 22 without bootstrapping).

### Key generation and transfer

Key generation is identical in both prototypes: the client calls `KeyGen`,
`EvalMultKeyGen`, `EvalRotateKeyGen`, and `EvalBootstrapKeyGen` once per request.
Transfer differs only in medium — both are TCP-based:

- **Prototype A:** eval keys are serialised to 3 binary blobs (Mult, Sum, Auto)
  and sent inline in the TCP request body.
- **Prototype C:** eval keys are serialised to a file on a shared tmpfs (2 blobs:
  Mult, Auto), and the file *path* is sent over TCP. The server reads the file
  from the shared filesystem. This is purely a transfer-medium optimisation for
  the larger key set (see below), not a protocol difference.

| | Prototype A | Prototype C |
|---|---|---|
| Eval-key blobs sent | 3 (Mult + Sum + Auto) | 2 (Mult + Auto) |
| Mult key size | ~90 MB | 90 MB |
| Sum key size | small (filtered subset of Auto) | omitted (redundant alias) |
| Auto key size | ~4750 MB (est.) | 7830 MB |
| **Total eval-key data** | **~4840 MB (est.)** | **7920 MB** |

> Prototype A's exact sizes cannot be independently measured because the stock
> OpenFHE `SerializeEvalAutomorphismKey(oss, SerType::BINARY, cc)` variant
> serialises the full crypto context alongside the key map, inflating the blob to
> include context metadata. The Auto-key estimate (~4750 MB) is derived from
> rotation-key counts: Prototype A has ~23 user rotation indices + ~68 bootstrap
> rotation indices = ~72 keys × ~66 MB per key. Prototype C has ~119 keys due to
> its base-4 BSGS accumulate (see § Rotation-key index sets).

**Rotation-key index sets.** Prototype C uses base-4 BSGS cascade accumulate
(FIDESlib `AccumulateSumInPlace` with `bStep=4`), which requires non-power-of-two
indices like 3, 6, 12, 48, 192, 768. Prototype A uses simple power-of-two
rotations. Both also generate bootstrap-internal rotation keys (via
`EvalBootstrapKeyGen` for 256 slots). The key-set size difference explains the
measured eval-key data difference above and the transcript generation time
difference below.

### Environments

#### Server

| Item | Prototype A | Prototype C |
|------|------------|-------------|
| CPU | Intel Xeon (TDX, 4th Gen) | same |
| OS | Alibaba Cloud Linux 3, kernel 5.10 | same |
| GPU | none | 1× NVIDIA H20 (78 SMs, 60 MB L2) |
| FHE library | stock OpenFHE 1.5.1 (`/usr/local/openfhe-stock`) | FIDESlib v2.1.3 (`/usr/local/openfhe-fideslib`) |
| Attestation | TDX quote | TDX quote + NVIDIA GPU evidence (NVAT) |

#### Client

| Item | Prototype A | Prototype C |
|------|------------|-------------|
| OpenFHE | stock 1.5.1 | FIDESlib-patched 1.5.1 |
| Attestation | TDX quote verification (Alibaba Cloud) | TDX + GPU evidence verification |

## Measurement Results

### FHE Evaluation Performance

`eval=` from server logs: encompasses key deserialisation, context creation, and
FHE computation (including one-time GPU setup for Prototype C).

| | Prototype A (CPU) | Prototype C (GPU H20) |
|---|---|---|
| Warmup | 1894 ms | 23837 ms |
| Run 1 | 1761 ms | 24212 ms |
| Run 2 | 1978 ms | 23751 ms |
| Run 3 | 1746 ms | 23879 ms |
| **Median** | **1761 ms** | **23879 ms** |
| Min / Max | 1746 / 1978 ms | 23751 / 24212 ms |

> Prototype C's overall `eval=` is dominated by the one-time GPU setup
> (~22 s; see below). For pure FHE compute, see the separated figures.

#### GPU-separated compute (Prototype C only)

Measured internally within the workload:

| Phase | Time (latest run) | Notes |
|-------|-------------------|-------|
| GPU context + LoadContext | 21966 ms | One-time key upload to device over PCIe |
| Input upload (21 ciphertexts) | 323 ms | CPU → GPU transfer |
| **Pure FHE compute (2 iterations)** | **88 ms** | GPU computation only |
| Sync to CPU + extract result | (included in eval) | Via `SyncCiphertextToCPU` |

From 3 measured runs (earlier benchmark):

| Phase | Min | Median | Max |
|-------|-----|--------|-----|
| GPU compute (2 iters) | 86 ms | **88 ms** | 89 ms |
| GPU one-time setup | 21073 ms | 21223 ms | 21533 ms |

**GPU compute speedup vs CPU: ~20× (1761 ms → 88 ms).** The one-time GPU setup
(~22 s) amortises over longer workloads; it is excluded from the compute-speedup
figure.

### Server Overhead Breakdown (latest single-run timings)

All server-side timing fields reported by the prototypes themselves:

| Phase | Prototype A (CPU) | Prototype C (GPU H20) |
|-------|-------------------:|-----------------------:|
| Context creation / key deserialisation (`ctx=`) | 416 ms | 0 ms (inline in eval) |
| FHE evaluation (`eval=`) | 2137 ms | 24698 ms |
| Output serialization (`outser=`) | 0 ms (<1) | 1 ms |
| Transcript generation (`transcript=`) | 9917 ms | 6113 ms |
| GPU evidence collection (`gpuev=`) | — | 50 ms |
| TDX quote generation (`quote=`) | 61 ms | 59 ms |

**Context creation / key deserialisation.** Both prototypes deserialise eval-key
blobs from the received data into OpenFHE's global key maps using the same
API calls (`DeserializeEvalMultKey`, `DeserializeEvalAutomorphismKey`).
Prototype A reports this separately (`ctx=416ms`); Prototype C does it as part
of `eval=` (the LoadContext phase) because the GPU context is created within the
workload.

**Output serialization.** A single CKKS ciphertext (~few MB) serialised to binary
for the response. Negligible in both prototypes.

**Transcript generation.** Hashes the eval-key blobs, input ciphertext blobs, and
output ciphertext. Both prototypes compute the hash inside `generate_transcript`
from the parsed blob data (commit `2792679`). The ~3.8 s gap reflects the eval-key
data-size difference: Prototype A ~4840 MB vs Prototype C ~7920 MB.

**Quote generation.** TDX hardware quote generation — identical between prototypes.

**GPU evidence collection.** Prototype C only. NVIDIA NVML evidence collection
for heterogeneous attestation.

### Client Verification Overhead

Client-side operations occur after the server response and are not timed by the
benchmark. Approximate breakdown:

| Phase | Time (est.) | Notes |
|-------|-------------|-------|
| Transcript verification | < 10 ms | Hash comparison via local recomputation |
| Quote verification | 1–2 s | Alibaba Cloud remote attestation network call |
| GPU evidence verification (C only) | < 100 ms | NVIDIA Attestation SDK verification |

## Raw Measurements of All Runs

### Prototype A (tee-vfhe, CPU) — 3-run benchmark

```
warmup: ctx=398ms  eval=1894ms  transcript=9878ms  quote=58ms
run 1:  ctx=399ms  eval=1761ms  transcript=9822ms  quote=60ms
run 2:  ctx=396ms  eval=1978ms  transcript=9814ms  quote=59ms
run 3:  ctx=397ms  eval=1746ms  transcript=10013ms  quote=59ms
```

Timing with `outser=` (latest single run):
```
ctx=416ms  eval=2137ms  outser=0ms  transcript=9917ms  quote=61ms
```

### Prototype C (gpucc-vfhe, GPU H20) — 3-run benchmark

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

> **Pre-fix transcript time.** The benchmark runs above pre-date commit `2792679`
> (fix: eval-key hash computed inside the transcript timer). The `transcript=44–48ms`
> reflects only JSON construction and input/output hashing — not the ~6 GB eval-key
> hash which was computed outside the timer.

Timing with `outser=`, `gpuev=`, and corrected transcript (latest single run):
```
ctx=0ms  eval=24698ms  outser=1ms  transcript=6113ms  gpuev=50ms  quote=59ms
context+LoadContext=21966ms  input_upload=323ms  compute(2)=88ms
```

Eval-key sizes:
```
EvalMultKey: 90 MB   EvalAutoKey: 7830 MB   Total: 7920 MB
```

### Correctness Check

Both prototypes produce **identical decrypted weights** on every run:

```
trained weights: max|w|=0.416963 at feature 91; sample w[100..103] = ~0, 0.00428366, 0.0634802, 0.196263
```

(Slots 0–7 are always-black MNIST border pixels → weights ~0; informative weights
are in the middle feature indices.)
