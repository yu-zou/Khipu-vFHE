cmake_minimum_required(VERSION 3.16)
project(tee-vfhe VERSION 0.1.0 LANGUAGES CXX C ASM)

# ── C++ Standard ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
enable_testing()

# ── Dependencies ──────────────────────────────────────────────────────────────

# OpenFHE (installed to local prefix to avoid conflicts with FIDESlib-patched version)
# Hint: set -DOpenFHE_DIR=/usr/local/openfhe-stock/lib/OpenFHE when configuring.
set(OpenFHE_DIR "/usr/local/openfhe-stock" CACHE PATH "OpenFHE install prefix")
find_package(OpenFHE CONFIG REQUIRED PATHS
  "${OpenFHE_DIR}/lib/OpenFHE"
  "${OpenFHE_DIR}/lib/cmake/OpenFHE"
  NO_DEFAULT_PATH
)

# Apply OpenFHE build flags (includes -march=native -fopenmp -DMATHBACKEND=4)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS} -std=c++17")

# OpenFHE imported targets do not carry include dirs; add them globally.
# Consumer needs ${OpenFHE_INCLUDE} + {core,pke,binfhe} subdirs.
# Also add the parent dir so that #include "openfhe/pke/..." resolves correctly.
include_directories(
  /usr/local/openfhe-stock/include
  ${OpenFHE_INCLUDE}
  ${OpenFHE_INCLUDE}/core
  ${OpenFHE_INCLUDE}/pke
  ${OpenFHE_INCLUDE}/binfhe
)

link_directories(/usr/lib64)

# Google Test — prefer system package, fall back to FetchContent tarball.
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
add_library(tee_common STATIC
  src/common/hashing.cpp
  src/common/transcript.cpp
  src/common/serialization.cpp
)
target_include_directories(tee_common PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(tee_common PUBLIC
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
  tee_common
)

# ── Library: TDX attestation (server-side) ────────────────────────────────────
add_library(tee_attestation STATIC
  src/common/attestation.cpp
)
target_include_directories(tee_attestation PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(tee_attestation PUBLIC
  tee_common
  tdx_attest
)

# ── Library: Quote verifier (client-side) ─────────────────────────────────────
add_library(tee_verifier STATIC
  src/client/verifier.cpp
)
target_include_directories(tee_verifier PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(tee_verifier PUBLIC
  tcp_transport
  tee_attestation
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  curl
  crypto
  sgx_dcap_quoteverify
)

# ── Library: Server-side workload registry ────────────────────────────────────
add_library(tee_workloads STATIC
  src/server/workload_registry.cpp
  workloads/noop.cpp
  workloads/toy.cpp
  workloads/small_dot.cpp
  workloads/medium_matvec.cpp
  workloads/micro_add.cpp
  workloads/micro_mul.cpp
  workloads/micro_mul_rescale.cpp
  workloads/micro_rotate.cpp
  workloads/app_matvec.cpp
  workloads/app_inference.cpp
)
target_include_directories(tee_workloads PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(tee_workloads PUBLIC
  tee_common
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
)

# ── Executable: TDX + FHE server ──────────────────────────────────────────────
add_executable(tee_server
  src/server/server_main.cpp
)
target_include_directories(tee_server PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(tee_server PRIVATE
  tee_workloads
  tee_attestation
  tcp_transport
  tee_common
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  tdx_attest
  pthread
)

# ── Executable: Client ────────────────────────────────────────────────────────
add_executable(tee_client
  src/client/client_main.cpp
)
target_include_directories(tee_client PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(tee_client PRIVATE
  tee_verifier
  tee_workloads
  tee_attestation
  tcp_transport
  tee_common
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  tdx_attest
  curl
  crypto
  pthread
)

# ── Tests ─────────────────────────────────────────────────────────────────────
add_subdirectory(tests)

# ── Benchmark (optional, prepared) ────────────────────────────────────────────
add_subdirectory(benchmark)
