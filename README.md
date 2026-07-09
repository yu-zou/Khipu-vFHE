# Khipu-vFHE

Khipu-vFHE is a research project that compares two approaches to verifiable fully homomorphic encryption (FHE): hardware-based verifiable FHE inside Intel TDX trusted execution environments, and zero-knowledge-based verifiable FHE using zkOpenFHE. The repository contains multiple prototypes, shared build and test scripts, and cross-prototype benchmarks.

## Repository Layout

| Directory | Description |
|-----------|-------------|
| `tee-vfhe/` | Prototype A: CKKS + TDX vFHE baseline (see its `README.md`) |
| `tee-vfhe-bgvrns/` | Prototype E: BGVrns + TDX vFHE for comparison with zkOpenFHE (see its `README.md`) |
| `zk-vfhe/` | Prototype B: zkOpenFHE ZK-based vFHE (separate prototype) |
| `gpucc-vfhe/` | Prototype C/D: GPU and heterogeneous vFHE variants (separate prototypes) |
| `scripts/` | Shared setup, build, run, and integration-test shell scripts |
| `thirdparty/` | Vendored dependencies: BLAKE3 and nlohmann/json |
| `benchmark/` | Cross-prototype benchmark assets and harnesses |
| `design_guideline/` | Design documents (gitignored, may be populated separately) |

## Prerequisites

### System Requirements

- **Operating System**: Alibaba Cloud Linux 3 (or compatible RHEL/CentOS 8+)
- **Kernel**: 5.10.134-19.6.al8.x86_64 or later with TDX support
- **CPU**: Intel Xeon with TDX support (e.g., 4th Gen Xeon Scalable)
- **Memory**: Minimum 8 GB RAM (16 GB recommended for large workloads)
- **Disk**: 10 GB free space for OpenFHE build and dependencies

### Software Dependencies

1. **CMake** (≥ 3.16)
   ```bash
   sudo yum install cmake
   ```

2. **GCC** (≥ 9.0 with C++17 support)
   ```bash
   sudo yum install gcc gcc-c++
   ```

3. **OpenFHE v1.5.1** (must be built from source)
   ```bash
   # See scripts/build_openfhe.sh for automated build
   ```

4. **Intel TDX Attestation Libraries**
   ```bash
   sudo yum install libtdx-attest libtdx-attest-devel
   ```

5. **Google Test** (fetched automatically via CMake FetchContent if not found)

6. **libcurl** (for remote attestation)
   ```bash
   sudo yum install libcurl-devel
   ```

7. **OpenSSL** (for JWT signature verification)
   ```bash
   sudo yum install openssl-devel
   ```

8. **Intel SGX DCAP Libraries** (for quote verification)
   ```bash
   sudo yum install libsgx-dcap-quote-verify-devel
   ```

### One-Time Environment Setup

Run the shared setup scripts once to configure the TDX guest and build OpenFHE:

```bash
cd /path/to/Khipu-vFHE
./scripts/setup_tdx_env.sh
./scripts/build_openfhe.sh
```

`setup_tdx_env.sh` enables the TSM API, configures configfs-based quote generation, and sets the Alibaba Cloud PCCS URL for your region. `build_openfhe.sh` downloads, builds, and installs OpenFHE v1.5.1 to `/usr/local`.

## Quick Start

### Build a Prototype

The current default build script builds `tee-vfhe-bgvrns`:

```bash
cd /path/to/Khipu-vFHE
./scripts/build_project.sh
```

To build a specific prototype manually, run CMake from its source directory:

```bash
cmake -S tee-vfhe-bgvrns -B tee-vfhe-bgvrns/build
cmake --build tee-vfhe-bgvrns/build -j$(nproc)
```

### Run an Experiment

Start the server inside a TDX-enabled VM:

```bash
./scripts/run_server.sh --port 8080
```

In another terminal, run the client:

```bash
./scripts/run_client.sh --port 8080 --workload toy
```

The client uses the expected MR_TD stored in `scripts/expected_mrtd.txt` by default.

### Run the Full Integration Test

```bash
./scripts/integration_test.sh
```

This builds the active prototype, starts the server, runs the client and benchmark runner, executes all unit tests, and reports a pass/fail summary.

## Prototypes

### Prototype A: CKKS TDX vFHE (`tee-vfhe/`)

The original baseline prototype. It uses OpenFHE CKKS with FIXEDMANUAL scaling and lazy transcript plus TDX quote attestation. See `tee-vfhe/README.md` for details.

### Prototype E: BGVrns TDX vFHE (`tee-vfhe-bgvrns/`)

A BGVrns variant of the TDX vFHE prototype. It keeps the same transcript and attestation design as Prototype A but uses native integer arithmetic modulo 65537 instead of CKKS approximation. This enables a direct apples-to-apples comparison with zkOpenFHE (Prototype B). See `tee-vfhe-bgvrns/README.md` for details.

### Prototype B: zkOpenFHE (`zk-vfhe/`)

A zero-knowledge-based verifiable FHE prototype built on zkOpenFHE. This prototype is separate from the TDX-based prototypes and proves FHE evaluation correctness with ZK proofs rather than hardware attestation.

### Prototypes C and D: GPU and Heterogeneous vFHE (`gpucc-vfhe/`)

GPU and heterogeneous vFHE prototypes. These explore acceleration and partitioning strategies on GPU hardware and are kept separate from the CPU-only TDX prototypes.

## References

- [OpenFHE Documentation](https://openfhe-development.readthedocs.io/)
- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html)
- [Alibaba Cloud TDX Guide](https://help.aliyun.com/zh/ecs/user-guide/build-a-tdx-confidential-computing-environment)
