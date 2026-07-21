# Benchmark: Encrypted Logistic-Regression Training — Prototype A vs C

## Experimental Setup

**Benchmark method:** 3 independent measurements per prototype. Each measurement
starts a fresh server process and a fresh client process — no persistent state is
shared between runs, so every run is independent and equivalent. All runs use the
same MNIST 1/8 dataset.

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

### Eval-Key Transfer and Sizes

Both prototypes transfer eval keys inline over TCP:

- **Client** generates keys (`KeyGen`, `EvalMultKeyGen`, `EvalRotateKeyGen`,
  `EvalBootstrapKeyGen`) and serialises them to binary blobs.
- **Server** reads the blobs from the TCP stream and deserialises each into the
  global OpenFHE key map, trying `DeserializeEvalMultKey` → `DeserializeEvalSumKey`
  → `DeserializeEvalAutomorphismKey` for each blob.

| | Prototype A | Prototype C |
|---|---|---|
| Blobs sent | 2 (Mult, Sum, Auto) | 2 (Mult, Auto) |
| EvalSumKey | serialised separately (redundant alias of Auto) | omitted |
| Mult key | 90 MB | 90 MB |
| Sum key | 6480 MB | — |
| Auto key | 6480 MB | 7830 MB |
| **Total** | **13050 MB** | **7920 MB** |

Prototype A's Sum-key blob is a redundant copy of the automorphism key map (stock
OpenFHE's `SerializeEvalSumKey` delegates to `SerializeEvalAutomorphismKey`).
Prototype C omits this alias, sending only the automorphism blob directly.

The Auto-key size difference (6480 MB in stock OpenFHE vs 7830 MB in the
FIDESlib-patched OpenFHE) reflects different Cereal binary encodings for the same
key map content plus Prototype C's larger rotation-key set (base-4 BSGS accumulate
requires ~51 non-power-of-two indices vs Prototype A's ~23 power-of-two indices).

### Environments

| Item | Prototype A | Prototype C |
|------|------------|-------------|
| CPU | Intel Xeon (TDX, 4th Gen) | same |
| OS | Alibaba Cloud Linux 3, kernel 5.10 | same |
| GPU | none | 1× NVIDIA H20 (78 SMs, 60 MB L2) |
| FHE library | stock OpenFHE 1.5.1 | FIDESlib v2.1.3 (patched OpenFHE) |
| Attestation | TDX quote | TDX quote + GPU evidence (NVAT) |

## Measurement Results

### FHE Evaluation Performance

#### Overall Latency (server-side `eval=`)

| | Prototype A (CPU) | Prototype C (GPU H20) |
|---|---|---|
| Run 1 | 1761 ms | 24212 ms |
| Run 2 | 1978 ms | 23751 ms |
| Run 3 | 1746 ms | 23879 ms |
| **Median** | **1761 ms** | **23879 ms** |
| Min / Max | 1746 / 1978 ms | 23751 / 24212 ms |

> Prototype C's overall `eval=` is dominated by the one-time GPU setup
> (~22 s; see next section). For pure FHE compute, see the separated figures.

#### GPU-Separated Compute (Prototype C only)

Measured internally within the workload:

| Phase | Median | Notes |
|-------|--------|-------|
| GPU context + LoadContext | 21,223 ms | One-time key upload to device over PCIe |
| Input upload (21 ciphertexts) | 320 ms | CPU → GPU transfer |
| **Pure FHE compute (2 iterations)** | **88 ms** | GPU computation only |

| | Min | Median | Max |
|---|---|---|---|
| GPU compute (2 iters) | 86 ms | **88 ms** | 89 ms |
| GPU one-time setup | 21,073 ms | 21,223 ms | 21,533 ms |

**GPU compute speedup vs CPU: ~20× (1761 ms → 88 ms).**

### Server Overhead Breakdown (latest single-run timings)

| Phase | Prototype A (CPU) | Prototype C (GPU H20) |
|-------|-------------------:|-----------------------:|
| Context creation / key deserialisation (`ctx=`) | 409 ms | 0 ms (inline in eval) |
| FHE evaluation (`eval=`) | 1937 ms | 24680 ms |
| Output serialization (`outser=`) | 0 ms | 0 ms |
| Transcript generation (`transcript=`) | 10033 ms | 6044 ms |
| GPU evidence collection (`gpuev=`) | — | 29 ms |
| TDX quote generation (`quote=`) | 62 ms | 58 ms |

**Context creation / key deserialisation.** Both prototypes deserialise eval-key
blobs into OpenFHE's global key maps using the same API calls. Prototype A reports
this separately; Prototype C does it as part of `eval=` because the GPU context
(LoadContext) is created within the workload.

**Output serialization.** A single CKKS ciphertext serialised to binary —
negligible in both prototypes.

**Transcript generation.** Hashes the eval-key blobs (13050 MB for A, 7920 MB for
C), input ciphertexts, and output ciphertext. Both compute the hash from the parsed
blob data inside `generate_transcript`. The ~4 s gap reflects the data-size
difference (Prototype A hashes ~5300 MB more data).

**GPU evidence collection** (Prototype C only). NVIDIA NVML evidence collection
for heterogeneous attestation.

**Quote generation.** TDX hardware quote generation — identical between prototypes.

### Client Verification Overhead

Client-side operations run after the server response and are not timed by the
benchmark. Approximate breakdown:

| Phase | Time (est.) | Notes |
|-------|-------------|-------|
| Transcript verification | < 10 ms | Hash comparison via local recomputation |
| Quote verification | 1–2 s | Alibaba Cloud remote attestation network call |
| GPU evidence verification (C only) | < 100 ms | NVIDIA Attestation SDK |

## Raw Measurements

### Prototype A (tee-vfhe, CPU)

```
run 1:  ctx=399ms  eval=1761ms  transcript=9822ms  quote=60ms
run 2:  ctx=396ms  eval=1978ms  transcript=9814ms  quote=59ms
run 3:  ctx=397ms  eval=1746ms  transcript=10013ms  quote=59ms

latest single-run with outser=:
  ctx=409ms  eval=1937ms  outser=0ms  transcript=10033ms  quote=62ms
```

Eval-key sizes:
```
EvalMultKey: 90 MB   EvalSumKey: 6480 MB   EvalAutoKey: 6480 MB   Total: 13050 MB
```

### Prototype C (gpucc-vfhe, GPU H20)

```
run 1:  ctx=0ms  eval=24212ms  quote=60ms
        context+LoadContext=21533ms  input_upload=331ms  compute(2)=89ms
run 2:  ctx=0ms  eval=23751ms  quote=58ms
        context+LoadContext=21073ms  input_upload=318ms  compute(2)=86ms
run 3:  ctx=0ms  eval=23879ms  quote=60ms
        context+LoadContext=21223ms  input_upload=320ms  compute(2)=88ms

latest single-run with outser=, gpuev=:
  ctx=0ms  eval=24680ms  outser=0ms  transcript=6044ms  gpuev=29ms  quote=58ms
  context+LoadContext=21947ms  input_upload=331ms  compute(2)=87ms
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
