# TDX + GPU Attestation Configuration

## Prerequisites (run after each reboot)

### 1. TDX Attestation: Set `tsm_api=0`

TDX quote generation on `ecs.gn8v.4xlarge` (GPU) instances requires `tsm_api=0`
(the configfs/TSM path doesn't generate quotes on this instance type; the ioctl
path works correctly).

```bash
sudo rmmod tdx_guest
sudo modprobe tdx_guest tsm_api=0
```

Persistent config (`/etc/modprobe.d/tdx.conf`):
```
options tdx_guest tsm_api=0
```

Verify: `cat /sys/module/tdx_guest/parameters/tsm_api` → `N`

### 2. CUDA/GPU: Set GPU Ready State

The H20 GPU has CC (Confidential Computing) mode ON by default. CUDA operations
fail with "system not yet initialized" until GPU Ready State is set.

```bash
sudo nvidia-smi conf-compute -srs 1
```

Verify: `nvidia-smi conf-compute -f` → `CC GPUs Ready State: Ready`

Without this, FIDESlib's `LoadContext()` segfaults because CUDA runtime cannot
initialize.

### Combined Setup Script

```bash
sudo rmmod tdx_guest && sudo modprobe tdx_guest tsm_api=0
sudo nvidia-smi conf-compute -srs 1
```

## Cross-Machine Comparison

| Config | Local (gn8v GPU) | Remote (g8i non-GPU) |
|---|---|---|
| Instance type | `ecs.gn8v.4xlarge` | `ecs.g8i.2xlarge` |
| GPU | NVIDIA H20 (CC mode ON) | None |
| Kernel | `5.10.134-19.7.al8.x86_64` | `5.10.134-19.6.al8.x86_64` |
| TDX `tsm_api` | **0** (ioctl path) | 1 (configfs path) |
| GPU Ready State | Must set via `nvidia-smi` | N/A |
| `/dev/tdx_guest` minor | 124 | 125 |
| TDX quote generation | Works (ioctl) | Works (configfs) |
| MRTD | 48 bytes, from quote verification | From configfs |
| AESM service | Not needed | Not needed |
| FIDESlib GPU | Requires GPU Ready State | N/A |

## Key Differences Between Instance Types

### gn8v (GPU) Instance
- GPU in CC mode → must set Ready State before CUDA works
- `tsm_api=0` required for TDX quote generation (configfs path produces empty outblob)
- TDX device minor 124
- FIDESlib GPU context initialization works after Ready State is set
- GPU evidence collection via NVTrust libnvat: 12069 bytes per collection

### g8i (non-GPU) Instance  
- No GPU → no Ready State needed
- `tsm_api=1` works (configfs path generates quotes)
- TDX device minor 125
- Standard TDX attestation flow

## Software Stack

| Component | Version | Location |
|---|---|---|
| Stock OpenFHE | 1.5.1 | `/usr/local/openfhe-stock/` |
| FIDESlib-patched OpenFHE | 1.5.1 (fideslib-ref-v1.5.1.1) | `/usr/local/openfhe-fideslib/` |
| FIDESlib | v2.1.3 (commit b368ba6) | `/usr/local/fideslib/lib64/fideslib.a` |
| NVTrust libnvat | 1.2.2 | `/usr/local/nvat/` |
| CUDA toolkit | 13.0 | `/usr/local/cuda/` |
| NVIDIA driver | 580.126.09 | `/lib64/libcuda.so.580.126.09` |
| GCC (system) | 10.2.1 | `/usr/bin/gcc` |
| GCC (FIDESlib builds) | 12.3.0 | `/opt/rh/gcc-toolset-12/` |
| Python | 3.11.13 | For MNIST data generation |

## TDX Quote Format

- Quote size: 5006 bytes
- MRTD: 48 bytes (384 bits), extracted from quote verification JWT
- Report data: 64 bytes (32 bytes transcript digest + 32 bytes zeros for Prototype A;
  32 bytes heterogeneous binding digest + 32 bytes zeros for Prototype C)
