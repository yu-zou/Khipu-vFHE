# BGV TDX-based Verifiable FHE Prototype (tee-vfhe-bgvrns)

Prototype E of the Khipu-vFHE project. This prototype implements verifiable fully homomorphic encryption (FHE) using Intel TDX (Trusted Domain Extensions) for hardware-based attestation, just like Prototype A (`tee-vfhe`). The difference is that Prototype E uses OpenFHE's BGVrns scheme with native integer arithmetic modulo 65537 instead of CKKS approximation. All decrypted results are exact integers, which enables a direct comparison with zkOpenFHE (Prototype B) and avoids CKKS precision errors.

## Design Philosophy

### Core Principles

1. **Hardware-Backed Verifiability**: Leverages Intel TDX to provide cryptographic proof that computations occurred within a trusted execution environment. The TDX quote binds the computation transcript to hardware attestation.

2. **Transcript-Based Attestation**: Instead of attesting every operation, we use a lazy attestation model where the server generates a transcript of the FHE evaluation and binds it to a TDX quote. The client verifies both the transcript integrity and the TDX attestation before trusting results.

3. **Verification-Before-Decryption**: The client enforces a strict security policy: results are only decrypted after successful verification of both the transcript (nonce, eval key hash, input/output ciphertext hashes) and the TDX quote (via Alibaba Cloud remote attestation service).

4. **BGVrns with Exact Integer Arithmetic**: Uses OpenFHE's BGVrns scheme with plaintext modulus 65537. Computations are exact mod 65537, so there is no CKKS approximation error to manage.

### Architecture

```
┌─────────────┐         TCP          ┌─────────────┐
│   Client    │◄────────────────────►│   Server    │
│             │                      │  (in TDX)   │
│ • Key Gen   │   REQUEST:           │             │
│ • Encrypt   │   - nonce            │ • Workload  │
│ • Verify    │   - eval keys        │   Registry  │
│ • Decrypt   │   - input CTs        │ • FHE Eval  │
│             │   - workload_id      │ • Transcript│
│             │                      │ • TDX Quote │
│             │   RESPONSE:          │             │
│             │   - output CT        │             │
│             │   - transcript.json  │             │
│             │   - tdx_quote.bin    │             │
└─────────────┘                      └─────────────┘
       │                                    │
       │                                    │
       ▼                                    ▼
┌─────────────┐                    ┌─────────────┐
│  Verifier   │                    │  Attestation│
│  Library    │                    │  Library    │
│             │                    │             │
│ • Transcript│                    │ • Transcript│
│   Verify    │                    │   Hash      │
│ • TDX Quote │                    │ • TDX Quote │
│   Verify    │                    │   Generate  │
│   (Alibaba  │                    │   (libtdx-  │
│    Cloud)   │                    │    attest)  │
└─────────────┘                    └─────────────┘
```

### Security Model

- **Transcript Integrity**: Blake3 hashes of nonce, evaluation keys, input ciphertexts, and output ciphertext ensure the server cannot tamper with the computation.
- **TDX Quote Binding**: The transcript hash is embedded in the TDX `report_data` field (first 32 bytes), cryptographically binding the computation to the hardware attestation.
- **Remote Attestation**: The client verifies the TDX quote via Alibaba Cloud's attestation service, ensuring the server is running in a genuine TDX environment.
- **MR_TD Verification**: Optional verification of the TDX measurement (MR_TD) ensures the server is running the expected software configuration.

### BGV Parameters

The default BGVrns parameter set is:

| Parameter | Value |
|-----------|-------|
| `plaintextModulus` | 65537 |
| `batchSize` | 64 |
| `multiplicativeDepth` | 2 |
| `securityStandard` | HEStd_128_classic |
| `scalingTechnique` | FIXEDMANUAL |
| `keySwitchingTechnique` | BV |
| `digitSize` | 4 |
| `firstModSize` | 60 |

The `app_inference` workload uses `multiplicativeDepth=5` to support its two-layer neural network. All other workloads use the default depth of 2 or less.

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

### TDX Environment Setup

The TDX setup is identical to Prototype A. Run the shared setup script:

```bash
cd /path/to/Khipu-vFHE
./scripts/setup_tdx_env.sh
```

Or verify TDX manually:

```bash
# Check for TDX guest support
lscpu | grep -i tdx

# Expected output: tdx_guest

# Check for TDX device
ls -l /dev/tdx_guest

# Expected: crw------- 1 root root 10, 125 ... /dev/tdx_guest
```

Configure TDX attestation:

```bash
# Enable TSM API (required for configfs-based quote generation)
sudo modprobe -r tdx_guest
sudo modprobe tdx_guest tsm_api=1

# Make permanent
echo "options tdx_guest tsm_api=1" | sudo tee /etc/modprobe.d/tdx.conf

# Configure attestation library to use configfs mode
sudo sh -c 'echo "" > /etc/tdx-attest.conf'

# Configure PCCS URL for your region
REGION=$(curl -s -H "X-aliyun-ecs-metadata-token: $(curl -s -X PUT -H 'X-aliyun-ecs-metadata-token-ttl-seconds: 5' http://100.100.100.200/latest/api/token)" http://100.100.100.200/latest/meta-data/region-id)
sudo sed -i "s|PCCS_URL=.*|PCCS_URL=https://sgx-dcap-server.${REGION}.aliyuncs.com/sgx/certification/v4/|" /etc/sgx_default_qcnl.conf
```

## Installation

### 1. Build OpenFHE from Source

```bash
cd /path/to/Khipu-vFHE
./scripts/build_openfhe.sh
```

This script:
- Downloads OpenFHE v1.5.1 source
- Builds with Release optimizations and native CPU features
- Installs to `/usr/local`
- Takes approximately 30-60 minutes

### 2. Build the Project

```bash
cd tee-vfhe-bgvrns
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

Or use the automated script:

```bash
./scripts/build_project.sh
```

### 3. Verify Build

```bash
# Binaries are created in the top-level build directory
ls -lh tee_server tee_client benchmark_runner

# Run unit tests
ctest --output-on-failure
```

## Compilation Details

### Build Targets

The CMake build system creates the following targets:

**Libraries:**
- `blake3` - Blake3 hashing (vendored C implementation)
- `tee_common` - Common types (transcript, hashing, serialization)
- `tcp_transport` - TCP client-server transport layer
- `tee_attestation` - TDX attestation library (server-side)
- `tee_verifier` - Quote verification library (client-side)
- `tee_workloads` - Workload registry and implementations

**Executables:**
- `tee_server` - TDX-protected FHE server
- `tee_client` - Client with verification-before-decryption
- `benchmark_runner` - Performance benchmarking tool

**Test Executables:**
- `test_attestation` - TDX attestation tests
- `test_hashing` - Blake3 hashing tests
- `test_transcript` - Transcript JSON tests
- `test_verifier` - Quote verification tests
- `test_workloads` - Workload correctness tests
- `test_negative` - Security negative tests

### Compiler Flags

The build uses OpenFHE's recommended flags:
- `-march=native` - Optimize for current CPU
- `-fopenmp` - Enable OpenMP parallelization
- `-DMATHBACKEND=4` - Use GMP backend for large integers
- `-DOPENFHE_VERSION=1.5.1` - Version macro
- `-Wall -Wextra -Werror` - Strict warnings

## Execution

### Starting the Server

The server must run inside a TDX-enabled VM:

```bash
# Using the script
./scripts/run_server.sh --port 8080

# Or directly
./build/tee_server --port 8080
```

**Server Options:**
- `--port PORT` - TCP port to listen on (default: 8080)
- `--bind ADDR` - Bind address (default: 0.0.0.0)

The server will:
1. Initialize the workload registry
2. Start listening for TCP connections
3. For each connection:
   - Receive REQUEST (nonce, eval keys, input ciphertexts, workload_id)
   - Execute the requested workload
   - Generate transcript and TDX quote
   - Send RESPONSE (output ciphertext, transcript.json, tdx_quote.bin)

### Running the Client

```bash
# Using the script
./scripts/run_client.sh --port 8080 --workload toy

# Or directly
./build/tee_client \
  --host 127.0.0.1 \
  --port 8080 \
  --workload toy \
  --expected-mr-td $(cat scripts/expected_mrtd.txt)
```

**Client Options:**
- `--host HOST` - Server hostname (default: 127.0.0.1)
- `--port PORT` - Server port (default: 8080)
- `--workload ID` - Workload to execute (see Available Workloads)
- `--expected-mr-td HEX` - Expected TDX measurement (48-byte hex string)

**Client Workflow:**
1. Generate BGV keys (public/secret/evaluation)
2. Encrypt input data
3. Send REQUEST to server
4. Receive RESPONSE
5. **Verify transcript** (nonce, eval key hash, input/output hashes)
6. **Verify TDX quote** (via Alibaba Cloud remote attestation)
7. **Only if verification passes**: decrypt and output results
8. **If verification fails**: abort with error (never decrypt unverified results)

### Available Workloads

| Workload ID | Description | Multiplicative Depth | Input Size |
|-------------|-------------|---------------------|------------|
| `noop` | Identity pass-through | 0 | 1 × 64 slots |
| `toy` | EvalMult of two vectors (c1 * c2 mod 65537) | 1 | 2 × 64 slots |
| `small` | 32-element dot product via EvalMult + EvalSum | 2 | 1 × 64 slots |
| `medium` | 64×64 matrix-vector multiply (masked diagonal method) | 2 | 1 × 64 slots |
| `micro_add` | EvalAdd | 0 | 2 × 64 slots |
| `micro_mul` | EvalMult | 1 | 2 × 64 slots |
| `micro_modswitch` | ModReduce (preserves plaintext) | 0 | 1 × 64 slots |
| `micro_rotate` | EvalRotate(ct, 1) | 0 | 1 × 64 slots |
| `app_matvec` | 64×64 integer matvec (power-of-two rotation keys) | 2 | 1 × 64 slots |
| `app_inference` | 2-layer NN (32→16→10, z² activation) | 5 | 1 × 64 slots |

### Running Benchmarks

```bash
# Start server first
./scripts/run_server.sh --port 8080 &

# Run benchmark
./build/benchmark_runner \
  --host 127.0.0.1 \
  --port 8080 \
  --expected-mr-td $(cat scripts/expected_mrtd.txt) \
  > benchmark_results.csv

# View results
cat benchmark_results.csv
```

**Benchmark Output Format:**
```csv
workload,fhe_eval_us,transcript_us,quote_us,verify_us,e2e_us,peak_mem_kb,transcript_bytes,quote_bytes
toy,12345,678,2345,1234,16789,45678,1024,4096
...
```

The benchmark runner writes the CSV to stdout and diagnostic messages to stderr. The output contains a header line plus one line for each of the 10 workloads, for a total of 11 lines.

**Metrics:**
- `fhe_eval_us` - FHE computation time (microseconds)
- `transcript_us` - Transcript generation time
- `quote_us` - TDX quote generation time
- `verify_us` - Quote verification time (includes network)
- `e2e_us` - End-to-end latency
- `peak_mem_kb` - Peak memory usage (KB)
- `transcript_bytes` - Transcript JSON size
- `quote_bytes` - TDX quote size

### Exact Integer Verification

Because BGVrns uses a plaintext modulus `p = 65537`, decrypted values are returned centered in `[-p/2, p/2)`. Normalize them before comparing with the expected integer result:

```cpp
int64_t normalize(int64_t v) {
    return v < 0 ? v + 65537 : v;
}
```

All tests expect an exact mod-65537 match after normalization. There is no floating-point tolerance because BGVrns operates on exact integer plaintexts.

## Testing

### Running All Tests

```bash
cd tee-vfhe-bgvrns/build
ctest --output-on-failure
```

Expected output:
```
Test project /path/to/tee-vfhe-bgvrns/build
      Start  1: test_hashing
 1/23 Test  #1: test_hashing .....................   Passed    0.00 sec
      Start  2: test_transcript
 2/23 Test  #2: test_transcript ..................   Passed    0.00 sec
      Start  3: test_attestation
 3/23 Test  #3: test_attestation .................   Passed    0.01 sec
      Start  4: test_verifier
 4/23 Test  #4: test_verifier ....................   Passed    0.05 sec
      Start  5: test_workloads
 5/23 Test  #5: test_workloads ...................   Passed   13.66 sec
      Start  6: test_negative
 6/23 Test  #6: test_negative ....................   Passed    0.01 sec

100% tests passed, 0 tests failed out of 23
```

### Test Categories

#### 1. Unit Tests

**test_hashing** - Hashing operations:
- Blake3 empty string hash
- Blake3 "test" string hash
- Hash concatenation

**test_transcript** - Transcript handling:
- JSON round-trip with timing fields
- JSON round-trip without timing fields

#### 2. Integration Tests

**test_attestation** - TDX attestation:
- Transcript generation
- Transcript hash computation
- TDX quote generation (requires TDX environment)

**test_verifier** - Quote verification:
- Transcript verification (nonce, hashes)
- TDX quote verification (requires TDX environment)
- Full verification flow

**test_workloads** - Workload correctness:
- All 10 workloads produce correct results
- Exact mod-65537 match after normalization

#### 3. Security Tests (Negative Tests)

**test_negative** - Security property verification:

1. **Tampered Output Ciphertext**: Modifying the output ciphertext causes verification to fail
2. **Tampered Input Ciphertext Hash**: Modifying input hash in transcript causes verification to fail
3. **Replay Attack**: Reusing old transcript with new input causes verification to fail
4. **Mismatched TDX Quote**: Using quote from different computation causes verification to fail
5. **Decrypt Before Verify**: Attempting to decrypt before verification throws exception

### Running Integration Test

The integration test performs a full end-to-end flow:

```bash
./scripts/integration_test.sh
```

This script:
1. Builds the project
2. Starts the server
3. Runs the client with the `toy` workload
4. Verifies the client successfully decrypts the result
5. Runs the benchmark suite
6. Runs all unit tests
7. Reports pass/fail status

## Project Structure

```
tee-vfhe-bgvrns/
├── CMakeLists.txt              # Top-level build configuration
├── README.md                   # This file
├── include/
│   ├── client/
│   │   └── verifier.h          # Quote verification interface
│   ├── common/
│   │   ├── attestation.h       # TDX attestation interface
│   │   ├── hashing.h           # Blake3 hashing interface
│   │   ├── serialization.h     # OpenFHE serialization wrappers
│   │   ├── tcp_transport.h     # TCP client-server interface
│   │   └── transcript.h        # Transcript data structure
│   └── server/
│       └── workload_registry.h # Workload registration interface
├── src/
│   ├── client/
│   │   ├── client_main.cpp     # Client executable
│   │   └── verifier.cpp        # Quote verification implementation
│   ├── common/
│   │   ├── attestation.cpp     # TDX attestation implementation
│   │   ├── hashing.cpp         # Blake3 hashing implementation
│   │   ├── serialization.cpp   # OpenFHE serialization
│   │   ├── tcp_transport.cpp   # TCP transport implementation
│   │   └── transcript.cpp      # Transcript JSON serialization
│   └── server/
│       └── server_main.cpp     # Server executable
├── workloads/
│   ├── noop.cpp                # Identity pass-through
│   ├── toy.cpp                 # EvalMult of two vectors
│   ├── small_dot.cpp           # 32-element dot product
│   ├── medium_matvec.cpp       # 64×64 matrix-vector multiply
│   ├── micro_add.cpp           # Microbenchmark: addition
│   ├── micro_mul.cpp           # Microbenchmark: multiplication
│   ├── micro_modswitch.cpp     # Microbenchmark: mod switch
│   ├── micro_rotate.cpp        # Microbenchmark: rotation
│   ├── app_matvec.cpp          # Application: 64×64 integer matvec
│   └── app_inference.cpp       # Application: 2-layer NN
├── tests/
│   ├── CMakeLists.txt          # Test build configuration
│   ├── test_attestation.cpp    # Attestation tests
│   ├── test_hashing.cpp        # Hashing tests
│   ├── test_negative.cpp       # Security negative tests
│   ├── test_transcript.cpp     # Transcript tests
│   ├── test_verifier.cpp       # Verifier tests
│   └── test_workloads.cpp      # Workload correctness tests
└── benchmark/
    └── benchmark_runner.cpp    # Benchmark runner executable
```

## Troubleshooting

### TDX Quote Generation Fails

**Symptom**: `tdx_att_get_quote failed (code 8)`

**Solution**:
1. Verify TDX is enabled: `lscpu | grep tdx_guest`
2. Check TSM API is enabled: `cat /sys/module/tdx_guest/parameters/tsm_api` (should be `Y`)
3. Verify `/etc/tdx-attest.conf` is empty (forces configfs mode)
4. Check PCCS URL is correct for your region

### Remote Attestation Fails

**Symptom**: Client reports "attestation verification FAILED"

**Solution**:
1. Verify network connectivity to Alibaba Cloud attestation service
2. Check PCCS URL in `/etc/sgx_default_qcnl.conf`
3. Verify the TDX quote is valid: `hexdump -C tdx_quote.bin | head`
4. Check server logs for quote generation errors

### Build Fails with OpenFHE Errors

**Symptom**: CMake cannot find OpenFHE

**Solution**:
1. Verify OpenFHE is installed: `ls /usr/local/include/openfhe/openfhe.h`
2. Check CMake can find OpenFHE: `cmake --find-package -DNAME=OpenFHE -DCOMPILER_ID=GNU -DLANGUAGE=CXX -DMODE=EXIST`
3. Rebuild OpenFHE: `./scripts/build_openfhe.sh`

### Tests Fail in Non-TDX Environment

**Symptom**: `test_attestation` or `test_verifier` fail

**Solution**:
- These tests require a TDX-enabled environment
- Run tests inside a TDX VM
- Or skip TDX-specific tests: `ctest -E "attestation|verifier"`

### High Memory Usage

**Symptom**: Benchmark runs out of memory

**Solution**:
1. Use power-of-two rotation keys (already enabled for `app_matvec` and `app_inference`)
2. The BGV prototype generates evaluation-key blobs of approximately 184 MB
3. Use smaller workloads (`noop`, `toy`, `small`) for memory-constrained environments
4. Increase system memory or swap space

## Security Considerations

### What This Prototype Provides

✅ **Hardware-backed attestation**: TDX quote proves computation occurred in a TEE  
✅ **Transcript integrity**: Blake3 hashes prevent tampering  
✅ **Replay protection**: Nonce prevents replay attacks  
✅ **Verification-before-decryption**: Client enforces security policy  
✅ **Remote attestation**: Alibaba Cloud service verifies TDX quote authenticity  
✅ **Exact integer arithmetic**: BGVrns avoids CKKS approximation errors  

### What This Prototype Does NOT Provide

❌ **Production-grade security**: This is a research prototype  
❌ **Bootstrapping**: No BGV bootstrapping (limited multiplicative depth)  
❌ **Network encryption**: TCP is unencrypted (relies on TDX for confidentiality)  
❌ **Key management**: Keys are generated per-session, not persisted  
❌ **Access control**: No authentication or authorization  
❌ **Audit logging**: No persistent logs of computations  

### Known Limitations

1. **Multiplicative Depth**: Limited to depth 5 without bootstrapping
2. **Plaintext Modulus**: Fixed at 65537 for exact integer arithmetic
3. **Performance**: TDX attestation adds 3-5 seconds per computation
4. **Scalability**: Single-threaded server, no connection pooling
5. **Error Handling**: Minimal error recovery in prototype

## Contributing

This is a research prototype developed as part of the Khipu-vFHE project. For questions or contributions, please refer to the main project repository.

## License

See the main project repository for license information.

## References

- [OpenFHE Documentation](https://openfhe-development.readthedocs.io/)
- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html)
- [Alibaba Cloud TDX Guide](https://help.aliyun.com/zh/ecs/user-guide/build-a-tdx-confidential-computing-environment)
- [BGV Scheme](https://eprint.iacr.org/2011/277)



