# GPU-accelerated Verifiable FHE (gpucc-vfhe)

Prototype C (FIDESlib GPU) and Prototype D (heterogeneous vFHE) — CKKS
FHE accelerated on NVIDIA H20 GPUs via FIDESlib, with Intel TDX + NVIDIA
confidential-compute attestation.

## Prerequisites

Same system requirements as Prototype A (`tee-vfhe/`), plus:

- **NVIDIA H20 GPU** (or other compute-capable NVIDIA GPU with CC support)
- **CUDA 12+** and the NVIDIA confidential-compute SDK (`libnvat`)
- **FIDESlib v2.1.3** (patched OpenFHE variant; pre-installed at `/usr/local`)

## Build

```bash
mkdir -p gpucc-vfhe/build && cd gpucc-vfhe/build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc) tee_server tee_client
```

## Run

**Server** (starts on the GPU; must be inside a TDX VM for attestation):

```bash
./build/tee_server --port 8123
```

**Client**:

```bash
./build/tee_client \
  --port 8123 \
  --workload logistic-regression \
  --expected-mr-td $(cat ../scripts/expected_mrtd.txt)
```

The logistic-regression client generates 21 ciphertexts (10 data batches,
10 label batches, 1 weights) and sends them alongside the serialized
evaluation keys and public key to the server.

## Benchmark: Prototype C vs Prototype A (logistic-regression)

The identical encrypted logistic-regression workload (MNIST 1/8, CKKS,
2 iterations, no bootstrap) was run on both prototypes:

| Metric | Prototype A (CPU, `tee-vfhe`) | Prototype C (GPU, `gpucc-vfhe`) |
|--------|-------------------------------|----------------------------------|
| FHE compute — median | **1761 ms** | **88 ms** |
| FHE compute — min / max | 1746 / 1978 ms | 86 / 89 ms |
| **Speedup** | — | **~20×** |

- **Identical decrypted weights** on A and C (`max|w|=0.416963` at
  feature 91), confirming algorithmic equivalence.
- One-time GPU setup (LoadContext, key upload) is ~21 s — excluded from
  the compute figures, amortises over longer workloads.

Full results: [`benchmark/logreg_a_vs_c_results.md`](../benchmark/logreg_a_vs_c_results.md).

## Known issues

1. **GPU bootstrap is broken on this H20 install.** The FIDESlib
   `EvalBootstrapInPlace` produces ciphertexts that cannot be decrypted
   ("approximation error too high").  The upstream FIDESlib logreg
   reference example (`thirdparty/FIDESlib/examples/logreg`) fails the
   same way on this machine, so this is a library-level issue, not an
   integration bug.  The no-bootstrap benchmark above works around it
   by capping iterations to 2 (the budget without bootstrapping).

2. **Servers handle only one request cleanly.** GPU-resource / global-key
   teardown between requests is not yet robust, so the benchmark script
   starts a fresh server per run.

## Architecture

```
   Client                              Server (TDX VM + H20)
┌──────────────────┐                  ┌─────────────────────────┐
│  KeyGen          │  TCP / file I/O  │  Deserialize keys       │
│  Encrypt inputs  │ ◄──────────────► │  Create FIDESlib GPU    │
│  Verify / Decrypt│                  │    context (LoadContext) │
└──────────────────┘                  │  Upload ciphertexts     │
                                      │  Run FHE on GPU         │
                                      │  Retrieve result (CPU)  │
                                      │  Transcript + TDX quote │
                                      │  + GPU evidence (NVAT)  │
                                      └─────────────────────────┘
```

The server holds **no secret key** — all keys are generated client-side
and transferred as serialised blobs.  FIDESlib's `LoadContext` resolves
them from the global OpenFHE key maps by the client public key's `KeyTag`.
