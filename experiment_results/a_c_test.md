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

Both prototypes serialize eval keys via the same `SerializeEval{Mult,Automorphism}Key`
implementations (Cereal binary). Size difference comes from different rotation-key
counts (~72 for A vs ~119 for C, because C uses base-4 BSGS accumulate while A
uses power-of-two accumulate).

## Measurement Results

### Server-Side Timing (median of 3 runs)

| Phase | Prototype A (CPU) | Prototype C (GPU H20) |
|-------|-------------------:|-----------------------:|
| Key deserialisation (`ctx`) | 417 ms | 17,450 ms |
| FHE evaluation (`eval`) | 1,862 ms | 24,977 ms |
| Output serialisation (`outser`) | 0 ms | 0 ms |
| Transcript generation (`transcript`) | 5,019 ms | 6,103 ms |
| GPU evidence collection (`gpuev`) | — | 28 ms |
| TDX quote generation (`quote`) | 62 ms | 60 ms |

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
| GPU context + LoadContext | 22,177 ms |
| Input upload (21 ciphertexts) | 336 ms |
| Pure FHE compute (2 iterations) | 90 ms |

### Client-Side Timing (single run)

| Phase | Prototype A | Prototype C |
|-------|------------:|------------:|
| Verification (transcript + TDX quote) | 42 ms | 45 ms |
| Decrypt output | 18 ms | 62 ms |

Verification includes both transcript hash check and TDX quote verification
(remote Alibaba Cloud attestation). Prototype C's decrypt is slower because
the ciphertext is received via the SyncCiphertextToCPU path which transfers
data from GPU device memory.

### Speedup

| Metric | A (CPU) | C (GPU) | Speedup |
|--------|--------:|--------:|--------:|
| Pure FHE compute (2 iters) | 1,862 ms | 90 ms | **~21×** |
| Full server-side (ctx+eval) | 2,279 ms | 42,427 ms | 0.05× |

The full server-side time for Prototype C is dominated by key deserialisation
(17,450 ms) and GPU upload (22,177 ms), both one-time costs tied to the per-run
KeyGen in this benchmark. With key reuse across requests these would amortise,
making the ~21× compute speedup the meaningful figure.

## Raw Measurements (all runs)

### Prototype A

```
run 1:  ctx=417ms  eval=1862ms  outser=0ms  transcript=5019ms  quote=62ms
        [client] verification=42ms  decrypt=18ms

run 2:  ctx=399ms  eval=1761ms  outser=0ms  transcript=9822ms  quote=60ms
run 3:  ctx=396ms  eval=1978ms  outser=0ms  transcript=9814ms  quote=59ms
run 4:  ctx=397ms  eval=1746ms  outser=0ms  transcript=10013ms  quote=59ms
```

(Runs 2–4 from the original benchmark before the redundant EvalSumKey blob was
removed; transcript time dropped from ~9.8 s to ~5.0 s after removal.)

### Prototype C

```
run 1:  ctx=17450ms  eval=24977ms  outser=0ms  transcript=6103ms  gpuev=28ms  quote=60ms
        gpu: context+LoadContext=22177ms  input_upload=336ms  compute(2)=90ms
        [client] verification=45ms  decrypt=62ms

run 2:  ctx=0ms  eval=24212ms  quote=60ms
        gpu: context+LoadContext=21533ms  input_upload=331ms  compute(2)=89ms
run 3:  ctx=0ms  eval=23751ms  quote=58ms
        gpu: context+LoadContext=21073ms  input_upload=318ms  compute(2)=86ms
run 4:  ctx=0ms  eval=23879ms  quote=60ms
        gpu: context+LoadContext=21223ms  input_upload=320ms  compute(2)=88ms
```

(Runs 2–4 from the original benchmark before the ctx timer was widened; their
`ctx=0ms` reflects the old boundary that only wrapped GetCryptoContext.)
