# TDX Attestation Configuration

## Solution (2026-07-17)

TDX quote generation works on this machine (`ecs.gn8v.4xlarge`) by setting
`tsm_api=0` on the `tdx_guest` kernel module.

### Key Configuration

```bash
# /etc/modprobe.d/tdx.conf
options tdx_guest tsm_api=0
```

Reload the module to apply:

```bash
sudo rmmod tdx_guest
sudo modprobe tdx_guest tsm_api=0
```

### Required Packages (from Alibaba Cloud enclave repo)

```bash
# Add the Alibaba Cloud enclave yum repo
token=$(curl -s -X PUT -H "X-aliyun-ecs-metadata-token-ttl-seconds: 5" "http://100.100.100.200/latest/api/token")
region_id=$(curl -s -H "X-aliyun-ecs-metadata-token: $token" http://100.100.100.200/latest/meta-data/region-id)
sudo yum-config-manager --add-repo https://enclave-${region_id}.oss-${region_id}-internal.aliyuncs.com/repo/alinux/enclave-expr.repo

# Install TDX attestation packages
sudo yum install -y libtdx-attest libtdx-attest-devel \
  libsgx-dcap-ql-devel libsgx-dcap-quote-verify-devel libsgx-dcap-default-qpl-devel \
  tdx-quote-generation-sample tdx-quote-verification-sample tee-appraisal-tool

# Configure PCCS URL (Alibaba Cloud remote attestation service)
sudo sed -i "s|PCCS_URL=.*|PCCS_URL=https://sgx-dcap-server.${region_id}.aliyuncs.com/sgx/certification/v4/|" /etc/sgx_default_qcnl.conf
```

### Why `tsm_api=0`?

The `tdx_guest` module has a `tsm_api` boolean parameter:

- **`tsm_api=1` (configfs/TSM mode)**: The module exposes attestation via
  `/sys/kernel/config/tsm/report/com.intel.dcap/`. The user writes report data
  to `inblob` and reads the quote from `outblob`. This mode works on
  `ecs.g8i.*` instances where the hypervisor supports GetQuote via the TSM
  configfs interface.

- **`tsm_api=0` (ioctl mode)**: The module exposes attestation via ioctl on
  `/dev/tdx_guest`. The `libtdx_attest` library calls `tdx_att_get_quote()`
  which uses the ioctl path to make a GetQuote hypercall. This mode works on
  `ecs.gn8v.*` (GPU) instances.

On this `ecs.gn8v.4xlarge` instance, the configfs `outblob` returns 0 bytes
(empty) with `tsm_api=1`, meaning the hypervisor does not support GetQuote
through the TSM configfs path. Switching to `tsm_api=0` enables the ioctl
path, which successfully generates 5006-byte TD Quotes.

### Cross-Machine Comparison

| Config | Local (gn8v) | Remote (g8i, 39.96.66.195) |
|---|---|---|
| Instance type | `ecs.gn8v.4xlarge` (GPU) | `ecs.g8i.2xlarge` (non-GPU) |
| Kernel | `5.10.134-19.7.al8.x86_64` | `5.10.134-19.6.al8.x86_64` |
| `/dev/tdx_guest` minor | 124 | 125 |
| `tsm_api=1` quote works? | No (outblob empty) | Yes (5006 bytes) |
| `tsm_api=0` quote works? | **Yes** (5006 bytes) | Not tested |
| sgx-aesm-service | Installed (not needed) | Not installed |
| PCCS_URL | `sgx-dcap-server.cn-beijing.aliyuncs.com/sgx/certification/v4/` | Same |
| USE_SECURE_CERT | `=TRUE` | `#USE_SECURE_CERT=FALSE` (commented) |

### Verification

```bash
# Verify quote generation
cat > /tmp/test_quote.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <tdx_attest.h>
int main() {
    tdx_report_data_t rd; memset(&rd, 0, sizeof(rd));
    tdx_uuid_t kid; uint8_t *qb = NULL; uint32_t qs = 0;
    tdx_attest_error_t rc = tdx_att_get_quote(&rd, NULL, 0, &kid, &qb, &qs, 0);
    if (rc == TDX_ATTEST_SUCCESS) {
        printf("SUCCESS: %u bytes\n", qs);
        tdx_att_free_quote(qb);
    } else {
        printf("FAILED: 0x%x\n", rc);
    }
    return rc;
}
EOF
gcc /tmp/test_quote.c -ltdx_attest -o /tmp/test_quote && /tmp/test_quote
# Expected: SUCCESS: 5006 bytes
```

### Fetching MRTD

```bash
cat > /tmp/get_mrtd.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <tdx_attest.h>
int main() {
    tdx_report_data_t rd; memset(&rd, 0, sizeof(rd));
    tdx_report_t rep; memset(&rep, 0, sizeof(rep));
    if (tdx_att_get_report(&rd, &rep) == TDX_ATTEST_SUCCESS) {
        for (int i = 96; i < 128; i++) printf("%02x", rep.d[i]);
        printf("\n");
    }
    return 0;
}
EOF
gcc /tmp/get_mrtd.c -ltdx_attest -o /tmp/get_mrtd && /tmp/get_mrtd
# Output: 43b0aa0aa2a1372ad62f25e5b8ce0c7c9a67a3c28c79c2bc7927ba5a71072c66
```

### Notes

- The `sgx-aesm-service` package is NOT required for TDX quote generation.
  It's only needed for SGX-based attestation. On TDX instances, the quote
  generation is handled by the TDX module via hypercalls, not by the AESM/QE.
- The `USE_SECURE_CERT` setting in `/etc/sgx_default_qcnl.conf` controls TLS
  certificate verification for the PCCS connection. It does not affect the
  configfs/ ioctl quote generation path.
- The MRTD value changes when the kernel or guest image changes. Always fetch
  a fresh MRTD after rebooting or updating the system.
