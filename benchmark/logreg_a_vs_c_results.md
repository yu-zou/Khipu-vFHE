# Prototype A vs C — Encrypted Logistic-Regression Benchmark

Encrypted logistic-regression training (MNIST 1/8, CKKS) comparing:

- **Prototype A** — `tee-vfhe`, CPU, stock OpenFHE.
- **Prototype C** — `gpucc-vfhe`, TDX + NVIDIA H20 GPU, FIDESlib backend.

Both prototypes run the **identical algorithm** (same CKKS parameters, same packing,
same masked activation, row/column accumulation, and gradient update). The only
difference is the compute backend (CPU OpenFHE vs. GPU FIDESlib).

## Configuration

| Parameter | Value |
|-----------|-------|
| Ring dimension | 65536 |
| Batch size (slots) | 32768 |
| Multiplicative depth | 22 |
| Scaling / first mod size | 50 / 55 |
| Scaling technique | FLEXIBLEAUTO, HYBRID key-switch |
| Secret key dist | SPARSE_TERNARY |
| Matrix packing | 128 rows × 256 cols |
| Features | 196 (MNIST 1/8) |
| Training iterations | 2 |
| Bootstrap | disabled (see note) |

**Note on iterations / bootstrap.** Each training iteration consumes ~4
multiplicative levels, so 2 iterations fit within depth 22 without bootstrapping.
Bootstrapping is disabled for this comparison: the FIDESlib GPU bootstrap does not
produce decryptable ciphertexts on this H20 install (the upstream FIDESlib logreg
reference example also fails to bootstrap here). Disabling it keeps A and C running
the identical workload for a fair, apples-to-apples compute comparison.

## Correctness

Both prototypes decrypt to **identical trained weights**:

```
trained weights: max|w|=0.416963 at feature 91; w[100..103] = ~0, 0.00428366, 0.0634802, 0.196263
```

(Slots 0–7 are always-black MNIST border pixels, so their weights stay ~0; the
informative weights are in the middle feature indices.)

## Timing (pure FHE compute)

3 independent runs each (fresh server per run), 1 warmup discarded.

| Metric | Prototype A (CPU) | Prototype C (GPU H20) |
|--------|-------------------|-----------------------|
| Compute — min | 1746 ms | 86 ms |
| Compute — **median** | **1761 ms** | **88 ms** |
| Compute — mean | 1828 ms | 87 ms |
| Compute — max | 1978 ms | 89 ms |
| Transcript (incl. eval-key hashing) — median | ~9800 ms | ~6100 ms |
| TDX quote generation — median | ~59 ms | ~60 ms |

**GPU compute speedup: ~20× (1761 ms → 88 ms) for the identical 2-iteration workload.**

### Transcript timing

Both prototypes now compute the eval-key hash from the parsed blob data inside the
`generate_transcript` timer, so `transcript=` is directly comparable. The ~3.7 s
difference reflects different key-set sizes (the two prototypes use different
rotation-key index sets due to their different backends).

### One-time GPU setup (Prototype C only)

The GPU path has a one-time cost to build the FIDESlib GPU context and upload the
evaluation keys to the device (`LoadContext`), plus input upload. This is setup, not
compute, and is excluded from the compute figures above:

| Phase | Median |
|-------|--------|
| context + LoadContext (key upload to GPU) | ~21 200 ms |
| input upload (21 ciphertexts) | ~0.3 s |

For a long-running training job the one-time setup amortizes; the GPU compute
advantage dominates as the number of iterations grows.

## How to reproduce

```
bash scripts/benchmark_logreg_a_vs_c.sh
```

The script starts each server fresh per run, drives the matching client, and reports
the server-side compute timings plus the decrypted weights for correctness.

## Known issues

- FIDESlib GPU bootstrap is broken on this H20 install (not our integration code;
  the upstream reference example fails the same way). Tracked separately.
- The servers currently handle one request cleanly; GPU / global-key teardown
  between requests is not yet robust, so the benchmark starts a fresh server per run.
