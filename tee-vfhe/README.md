# TDX-based Verifiable FHE Prototype (tee-vfhe)

A prototype implementation of verifiable fully homomorphic encryption (FHE) using Intel TDX (Trusted Domain Extensions) for hardware-based attestation. This system enables clients to verify that FHE computations were performed correctly by a trusted execution environment (TEE) before decrypting results.

## Design Philosophy

### Core Principles

1. **Hardware-Backed Verifiability**: Leverages Intel TDX to provide cryptographic proof that computations occurred within a trusted execution environment. The TDX quote binds the computation transcript to hardware attestation.

2. **Transcript-Based Attestation**: Instead of attesting every operation (expensive), we use a lazy attestation model where the server generates a transcript of the FHE evaluation and binds it to a TDX quote. The client verifies both the transcript integrity and the TDX attestation before trusting results.

3. **Verification-Before-Decryption**: The client enforces a strict security policy: results are only decrypted after successful verification of both the transcript (nonce, eval key hash, input/output ciphertext hashes) and the TDX quote (via Alibaba Cloud remote attestation service).

4. **CKKS with FIXEDMANUAL Scaling**: Uses OpenFHE's CKKS scheme with FIXEDMANUAL scaling technique for explicit control over multiplicative depth and rescaling operations, matching the Argos protocol's approach.

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

The system must run inside an Intel TDX-enabled virtual machine. Verify TDX is enabled:

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
cd tee-vfhe
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
# Check that binaries were created
ls -lh tee_server tee_client benchmark/benchmark_runner

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
- `test_common` - Transcript, hashing, serialization tests
- `test_transport` - TCP transport tests
- `test_attestation` - TDX attestation tests
- `test_verifier` - Quote verification tests
- `test_server` - Server functionality tests
- `test_client` - Client functionality tests
- `test_workloads` - Workload correctness tests
- `test_negative` - Security negative tests
- `test_hashing` - Blake3 hashing tests
- `test_transcript` - Transcript JSON tests

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
./scripts/run_client.sh --host 127.0.0.1 --port 8080 --workload toy

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
1. Generate CKKS keys (public/secret/evaluation)
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
| `toy` | Single multiplication + rescale | 1 | 2 × 32 slots |
| `small` | 32-slot dot product | 2 | 1 × 32 slots |
| `medium` | 64×64 matrix-vector multiply | 3 | 1 × 64 slots |
| `micro_add` | CKKS addition | 0 | 2 × 32 slots |
| `micro_mul` | CKKS multiplication | 1 | 2 × 32 slots |
| `micro_mul_rescale` | Multiplication + rescale | 1 | 2 × 32 slots |
| `micro_rotate` | Slot rotation | 0 | 1 × 32 slots |
| `app_matvec` | 256×256 matrix-vector multiply | 4 | 1 × 256 slots |
| `app_inference` | 1-layer MLP (128→64→10) | 5 | 1 × 128 slots |
| `logistic_regression` | Encrypted logistic-regression training (MNIST 1/8) | 22 | 21 × 32768 slots |

### Running Benchmarks

```bash
# Start server first
./scripts/run_server.sh --port 8080 &

# Run benchmark
./build/benchmark/benchmark_runner \
  --server 127.0.0.1:8080 \
  --expected-mr-td $(cat scripts/expected_mrtd.txt) \
  --output benchmark_results.csv

# View results
cat benchmark_results.csv
```

**Benchmark Output Format:**
```csv
workload,fhe_eval_us,transcript_us,quote_us,verify_us,e2e_us,peak_mem_kb,transcript_bytes,quote_bytes
toy,12345,678,2345,1234,16789,45678,1024,4096
...
```

**Metrics:**
- `fhe_eval_us` - FHE computation time (microseconds)
- `transcript_us` - Transcript generation time
- `quote_us` - TDX quote generation time
- `verify_us` - Quote verification time (includes network)
- `e2e_us` - End-to-end latency
- `peak_mem_kb` - Peak memory usage (KB)
- `transcript_bytes` - Transcript JSON size
- `quote_bytes` - TDX quote size

## Testing

### Running All Tests

```bash
cd tee-vfhe/build
ctest --output-on-failure
```

Expected output:
```
Test project /path/to/tee-vfhe/build
      Start  1: test_common
 1/10 Test  #1: test_common ......................   Passed    0.14 sec
      Start  2: test_transport
 2/10 Test  #2: test_transport ...................   Passed    0.00 sec
      Start  3: test_attestation
 3/10 Test  #3: test_attestation .................   Passed    0.01 sec
      Start  4: test_verifier
 4/10 Test  #4: test_verifier ....................   Passed    0.05 sec
      Start  5: test_server
 5/10 Test  #5: test_server ......................   Passed    0.07 sec
      Start  6: test_workloads
 6/10 Test  #6: test_workloads ...................   Passed   13.66 sec
      Start  7: test_client
 7/10 Test  #7: test_client ......................   Passed    0.19 sec
      Start  8: test_transcript
 8/10 Test  #8: test_transcript ..................   Passed    0.00 sec
      Start  9: test_hashing
 9/10 Test  #9: test_hashing ....................   Passed    0.00 sec
      Start 10: test_negative
10/10 Test #10: test_negative ....................   Passed    0.01 sec

100% tests passed, 0 tests failed out of 10
```

### Test Categories

#### 1. Unit Tests

**test_common** - Core functionality:
- Blake3 hash correctness (known test vectors)
- CKKS ciphertext serialization round-trip
- Transcript JSON serialization/deserialization

**test_hashing** - Hashing operations:
- Blake3 empty string hash
- Blake3 "test" string hash
- Hash concatenation

**test_transcript** - Transcript handling:
- JSON round-trip with timing fields
- JSON round-trip without timing fields

**test_transport** - TCP transport:
- Client-server connection
- Message send/receive
- Large payload handling

#### 2. Integration Tests

**test_attestation** - TDX attestation:
- Transcript generation
- Transcript hash computation
- TDX quote generation (requires TDX environment)

**test_verifier** - Quote verification:
- Transcript verification (nonce, hashes)
- TDX quote verification (requires TDX environment)
- Full verification flow

**test_server** - Server functionality:
- Request parsing
- Workload dispatch
- Response generation

**test_client** - Client functionality:
- Key generation
- Encryption/decryption
- Verification-before-decryption enforcement

**test_workloads** - Workload correctness:
- All 9 workloads produce correct results
- CKKS precision within tolerance:
  - Depth 0-1: relative error < 1e-4
  - Depth 2: relative error < 1e-3
  - Depth 3-4: relative error < 1e-2
  - Depth 5: relative error < 1e-1

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

Expected output:
```
[integration] PASS: client exited 0 (attestation succeeded)
[integration] PASS: transcript verification succeeded
[integration] PASS: attestation verification succeeded
[integration] PASS: benchmark runner exited 0
[integration] PASS: ctest exited 0
[integration] PASS: benchmark CSV has 10 lines (expected 10)

========================================================================
  INTEGRATION TEST SUMMARY
========================================================================
  client RC  = 0 (expected 0)
  bench RC   = 0  (expected 0)
  ctest RC   = 0  (expected 0)
  CSV lines  = 10 (expected 10)

  Transcript verification:  PASS
  Attestation verification: PASS
  Benchmark runner:         PASS
  Unit tests:               PASS
  CSV output:               PASS

[integration] ALL CHECKS PASSED
```

## Project Structure

```
tee-vfhe/
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
│       ├── server_main.cpp     # Server executable
│       └── workload_registry.cpp # Workload registry implementation
├── workloads/
│   ├── noop.cpp                # No-op workload (for testing)
│   ├── toy.cpp                 # Toy workload (1 mult + rescale)
│   ├── small_dot.cpp           # Small dot product
│   ├── medium_matvec.cpp       # Medium matrix-vector multiply
│   ├── micro_add.cpp           # Microbenchmark: addition
│   ├── micro_mul.cpp           # Microbenchmark: multiplication
│   ├── micro_mul_rescale.cpp   # Microbenchmark: mul + rescale
│   ├── micro_rotate.cpp        # Microbenchmark: rotation
│   ├── app_matvec.cpp          # Application: 256×256 matvec
│   └── app_inference.cpp       # Application: 1-layer MLP
├── tests/
│   ├── CMakeLists.txt          # Test build configuration
│   ├── test_common.cpp         # Common functionality tests
│   ├── test_hashing.cpp        # Hashing tests
│   ├── test_transcript.cpp     # Transcript tests
│   ├── test_transport.cpp      # Transport tests
│   ├── test_attestation.cpp    # Attestation tests
│   ├── test_verifier.cpp       # Verifier tests
│   ├── test_server.cpp         # Server tests
│   ├── test_client.cpp         # Client tests
│   ├── test_workloads.cpp      # Workload correctness tests
│   └── test_negative.cpp       # Security negative tests
└── benchmark/
    ├── CMakeLists.txt          # Benchmark build configuration
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
1. Reduce batch size in workload parameters
2. Use smaller workloads (toy, small, medium)
3. Increase system memory or swap space
4. Check for memory leaks: `valgrind --leak-check=full ./tee_server`

## Performance Characteristics

### Typical Latencies (TDX Environment)

| Workload | FHE Eval | Transcript | Quote Gen | Verify | Total |
|----------|----------|------------|-----------|--------|-------|
| toy | ~100 ms | ~1 ms | ~2-3 s | ~1-2 s | ~4-5 s |
| small | ~150 ms | ~1 ms | ~2-3 s | ~1-2 s | ~4-5 s |
| medium | ~500 ms | ~1 ms | ~2-3 s | ~1-2 s | ~5-6 s |
| app_matvec | ~8-9 s | ~1 ms | ~2-3 s | ~1-2 s | ~12-15 s |
| app_inference | ~8-9 s | ~1 ms | ~2-3 s | ~1-2 s | ~12-15 s |

**Note**: TDX quote generation and verification dominate the latency. The FHE computation time is relatively small compared to attestation overhead.

### Memory Usage

- **Server**: ~500 MB - 2 GB (depending on workload)
- **Client**: ~200 MB - 500 MB
- **Peak**: app_matvec and app_inference use ~1.5-2 GB

## Security Considerations

### What This Prototype Provides

✅ **Hardware-backed attestation**: TDX quote proves computation occurred in a TEE  
✅ **Transcript integrity**: Blake3 hashes prevent tampering  
✅ **Replay protection**: Nonce prevents replay attacks  
✅ **Verification-before-decryption**: Client enforces security policy  
✅ **Remote attestation**: Alibaba Cloud service verifies TDX quote authenticity  

### What This Prototype Does NOT Provide

❌ **Production-grade security**: This is a research prototype  
❌ **Bootstrapping**: No CKKS bootstrapping (limited multiplicative depth)  
❌ **Network encryption**: TCP is unencrypted (relies on TDX for confidentiality)  
❌ **Key management**: Keys are generated per-session, not persisted  
❌ **Access control**: No authentication or authorization  
❌ **Audit logging**: No persistent logs of computations  

### Known Limitations

1. **Multiplicative Depth**: Limited to depth 5 without bootstrapping
2. **Precision**: CKKS approximation errors accumulate with depth
3. **Performance**: TDX attestation adds 3-5 seconds per computation
4. **Scalability**: Single-threaded server, no connection pooling
5. **Error Handling**: Minimal error recovery in prototype
6. **Single-request servers**: Global-key-map / connection state does not cleanly
   teardown between requests; servers need a restart per client.

### Benchmark vs Prototype C (GPU)

The identical encrypted logistic-regression workload (MNIST 1/8, CKKS,
2 iterations, no bootstrap) was run on both Prototype A and Prototype C
(FIDESlib GPU). See `benchmark/logreg_a_vs_c_results.md` for the full report.

| Metric | A (CPU, tee-vfhe) | C (GPU, gpucc-vfhe) |
|--------|-------------------:|---------------------:|
| FHE compute — median | **1761 ms** | **88 ms** |
| One-time GPU setup | — | ~21 s |

Both produce **identical decrypted weights**, confirming algorithmic equivalence.

## Contributing

This is a research prototype developed as part of the Khipu-vFHE project. For questions or contributions, please refer to the main project repository.

## License

See the main project repository for license information.

## References

- [OpenFHE Documentation](https://openfhe-development.readthedocs.io/)
- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html)
- [Alibaba Cloud TDX Guide](https://help.aliyun.com/zh/ecs/user-guide/build-a-tdx-confidential-computing-environment)
- [CKKS Scheme](https://eprint.iacr.org/2020/1181)
- [Argos Protocol](https://arxiv.org/abs/2304.10436)

## Acknowledgments

This prototype implements the verifiable FHE architecture described in the project design document, inspired by the Argos protocol and adapted for Intel TDX.
