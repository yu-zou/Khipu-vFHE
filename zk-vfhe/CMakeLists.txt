cmake_minimum_required(VERSION 3.16)
project(zk-vfhe VERSION 0.1.0 LANGUAGES CXX C ASM)

# ── C++ Standard ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
enable_testing()

# ── Dependencies ──────────────────────────────────────────────────────────────

# OpenFHE (must be installed separately; includes zkOpenFHE proofsystem headers
# at /usr/local/include/openfhe/pke/proofsystem/)
find_package(OpenFHE CONFIG REQUIRED)

# Apply OpenFHE build flags (includes -march=native -fopenmp -DMATHBACKEND=4)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS}")

# zkOpenFHE + libsnark require CURVE_BN128 so libff::default_ec_pp resolves
# to alt_bn128 (matching both the GG and PGHR13 ppzksnark defaults).
add_compile_definitions(CURVE_BN128)

# libff/libsnark serialization uses #ifdef BINARY_OUTPUT to select binary vs
# decimal mode for bigint/field-element stream operators. libsnark is built
# with BINARY_OUTPUT=ON; without matching it here, our compilation unit
# instantiates the decimal code path while libsnark's compiled code uses
# binary, causing mismatched proof/VK/public-input serialization and
# assertion failures in bigint::operator>>. Define it globally.
add_compile_definitions(BINARY_OUTPUT)

# OpenFHE imported targets do not carry include dirs; add them globally.
# Consumer needs ${OpenFHE_INCLUDE} + {core,pke,binfhe} subdirs.
# zkOpenFHE proofsystem headers are at pke/proofsystem/ (added explicitly).
include_directories(
  ${OpenFHE_INCLUDE}
  ${OpenFHE_INCLUDE}/core
  ${OpenFHE_INCLUDE}/pke
  ${OpenFHE_INCLUDE}/binfhe
  ${OpenFHE_INCLUDE}/pke/proofsystem
)

link_directories(/usr/lib64)

# libsnark (static library installed at /usr/local/lib/libsnark.a)
# libff (libsnark depends on libff for curve operations, pairings, field arithmetic)
# libzm (polynomial multiplication library used by libff)
# GMP is required by libsnark for big-integer arithmetic.
find_library(SNARK_LIBRARY snark PATHS /usr/local/lib REQUIRED)
find_library(FF_LIBRARY ff PATHS /usr/local/lib REQUIRED)
find_library(ZM_LIBRARY zm PATHS /tmp/zkOpenFHE/build/lib /usr/local/lib)
find_library(GMP_LIBRARY gmp REQUIRED)
find_library(GMPXX_LIBRARY gmpxx REQUIRED)

# libfqfft headers ship inside libsnark's depends/ tree (libsnark's r1cs_ppzksnark
# .tcc pulls in <libfqfft/.../evaluation_domain.hpp>).
set(LIBFQFFT_INCLUDE_DIR /tmp/zkOpenFHE/third-party/libsnark/depends/libfqfft CACHE PATH "libfqfft headers")
include_directories(${LIBFQFFT_INCLUDE_DIR})

# Google Test - prefer system package, fall back to FetchContent tarball.
find_package(GTest QUIET)
if(NOT GTest_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
  )
  set(FETCHCONTENT_QUIET OFF)
  FetchContent_MakeAvailable(googletest)
endif()

# ── Blake3 (vendored C implementation) ────────────────────────────────────────
add_library(blake3 STATIC
  ${CMAKE_SOURCE_DIR}/../thirdparty/blake3/blake3.c
  ${CMAKE_SOURCE_DIR}/../thirdparty/blake3/blake3_dispatch.c
  ${CMAKE_SOURCE_DIR}/../thirdparty/blake3/blake3_portable.c
  ${CMAKE_SOURCE_DIR}/../thirdparty/blake3/blake3_sse2_x86-64_unix.S
  ${CMAKE_SOURCE_DIR}/../thirdparty/blake3/blake3_sse41_x86-64_unix.S
  ${CMAKE_SOURCE_DIR}/../thirdparty/blake3/blake3_avx2_x86-64_unix.S
  ${CMAKE_SOURCE_DIR}/../thirdparty/blake3/blake3_avx512_x86-64_unix.S
)
target_include_directories(blake3 PUBLIC
  ${CMAKE_SOURCE_DIR}/../thirdparty/blake3
)
target_compile_options(blake3 PRIVATE -O3 -march=native)

# ── nlohmann/json (vendored single header) ────────────────────────────────────
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE
  ${CMAKE_SOURCE_DIR}/../thirdparty
)

# ── Library: Common types (hashing, transcript, serialization) ────────────────
# Uses BGV serialization (scheme/bgvrns/bgvrns-ser.h), not CKKS.
add_library(zk_common STATIC
  src/common/baseline_params.cpp
  src/common/hashing.cpp
  src/common/transcript.cpp
  src/common/serialization.cpp
)
target_include_directories(zk_common PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(zk_common PUBLIC
  blake3
  nlohmann_json
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
)

# ── Library: TCP transport layer ──────────────────────────────────────────────
add_library(tcp_transport STATIC
  src/common/tcp_transport.cpp
)
target_include_directories(tcp_transport PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(tcp_transport PUBLIC
  zk_common
)

# ── Library: zkOpenFHE proof system (server-side) ─────────────────────────────
# Replaces TDX attestation with zkOpenFHE ZK proofs.
# Uses libsnark for R1CS constraint system and proving.
add_library(zk_proof STATIC
  src/common/proof_generation.cpp
)
target_include_directories(zk_proof PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
  /tmp/zkOpenFHE/third-party/libsnark/depends/libfqfft
)
target_compile_definitions(zk_proof PUBLIC
  CURVE_BN128
)
target_link_libraries(zk_proof PUBLIC
  zk_common
  ${SNARK_LIBRARY}
  ${FF_LIBRARY}
  ${ZM_LIBRARY}
  ${GMP_LIBRARY}
)

# ── Library: ZK proof verifier (client-side) ──────────────────────────────────
add_library(zk_verifier STATIC
  src/client/verifier.cpp
)
target_include_directories(zk_verifier PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(zk_verifier PUBLIC
  tcp_transport
  zk_proof
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  ${SNARK_LIBRARY}
  ${FF_LIBRARY}
  ${ZM_LIBRARY}
  ${GMP_LIBRARY}
)

# ── Library: Server-side workload registry ────────────────────────────────────
# Registration is inline in server_main.cpp per the plan; this library contains
# only the workload implementation files.
add_library(zk_workloads STATIC
  workloads/noop.cpp
  workloads/toy.cpp
  workloads/small_circuit.cpp
  workloads/medium_circuit.cpp
  workloads/bgv_add_4k.cpp
  workloads/bgv_mul_4k.cpp
)
target_include_directories(zk_workloads PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(zk_workloads PUBLIC
  zk_common
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
)

# ── Executable: ZK + FHE server ───────────────────────────────────────────────
add_executable(zk_server
  src/server/server_main.cpp
)
target_include_directories(zk_server PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(zk_server PRIVATE
  -Wl,--whole-archive zk_workloads -Wl,--no-whole-archive
  zk_proof
  tcp_transport
  zk_common
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  ${SNARK_LIBRARY}
  ${FF_LIBRARY}
  ${ZM_LIBRARY}
  ${GMPXX_LIBRARY}
  ${GMP_LIBRARY}
  pthread
)

# ── Executable: Client ────────────────────────────────────────────────────────
add_executable(zk_client
  src/client/client_main.cpp
)
target_include_directories(zk_client PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(zk_client PRIVATE
  zk_verifier
  -Wl,--whole-archive zk_workloads -Wl,--no-whole-archive
  zk_proof
  tcp_transport
  zk_common
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  ${SNARK_LIBRARY}
  ${FF_LIBRARY}
  ${ZM_LIBRARY}
  ${GMPXX_LIBRARY}
  ${GMP_LIBRARY}
  pthread
)

# ── Executable: Benchmark runner ──────────────────────────────────────────────
add_executable(benchmark_runner
  benchmark/benchmark_runner.cpp
)
target_include_directories(benchmark_runner PRIVATE
  ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(benchmark_runner PRIVATE
  zk_verifier
  -Wl,--whole-archive zk_workloads -Wl,--no-whole-archive
  zk_proof
  tcp_transport
  zk_common
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  ${SNARK_LIBRARY}
  ${FF_LIBRARY}
  ${ZM_LIBRARY}
  ${GMPXX_LIBRARY}
  ${GMP_LIBRARY}
  pthread
)

# ── Tests ─────────────────────────────────────────────────────────────────────
add_subdirectory(tests)
