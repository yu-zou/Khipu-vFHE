# Tests for tee-vfhe

# ── Common types test (Blake3 KAT, ciphertext round-trip, transcript JSON) ────
add_executable(test_common
  test_common.cpp
)
target_link_libraries(test_common PRIVATE
  tee_common
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
)
add_test(NAME test_common COMMAND test_common)

# ── TCP transport tests ─────────────────────────────────────────────────────
add_executable(test_transport
  test_transport.cpp
)
target_link_libraries(test_transport PRIVATE
  tcp_transport
  GTest::gtest_main
)
add_test(NAME test_transport COMMAND test_transport)

# ── TDX attestation tests ──────────────────────────────────────────────────
add_executable(test_attestation
  test_attestation.cpp
)
target_link_libraries(test_attestation PRIVATE
  tee_attestation
  tee_common
  GTest::gtest_main
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  tdx_attest
)
add_test(NAME test_attestation COMMAND test_attestation)

# ── Client verifier tests ──────────────────────────────────────────────────
add_executable(test_verifier
  test_verifier.cpp
)
target_link_libraries(test_verifier PRIVATE
  tee_verifier
  tee_attestation
  tee_common
  GTest::gtest_main
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  curl
  crypto
  tdx_attest
)
add_test(NAME test_verifier COMMAND test_verifier)

# ── Server end-to-end tests ───────────────────────────────────────────────
add_executable(test_server
  test_server.cpp
)
target_link_libraries(test_server PRIVATE
  tee_workloads
  tee_attestation
  tcp_transport
  tee_common
  GTest::gtest_main
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  tdx_attest
  pthread
)
add_test(NAME test_server COMMAND test_server)

# ── Workload correctness tests ────────────────────────────────────────────
add_executable(test_workloads
  test_workloads.cpp
)
target_link_libraries(test_workloads PRIVATE
  tee_workloads
  tee_common
  GTest::gtest_main
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  pthread
)
add_test(NAME test_workloads COMMAND test_workloads)

# ── Client end-to-end tests ──────────────────────────────────────────────
add_executable(test_client
  test_client.cpp
)
target_link_libraries(test_client PRIVATE
  tee_verifier
  tee_workloads
  tee_attestation
  tcp_transport
  tee_common
  GTest::gtest_main
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  tdx_attest
  curl
  crypto
  pthread
)
add_test(NAME test_client COMMAND test_client)
set_tests_properties(test_client PROPERTIES DEPENDS tee_client)

# ── Transcript JSON round-trip unit tests ─────────────────────────────────
add_executable(test_transcript
  test_transcript.cpp
)
target_link_libraries(test_transcript PRIVATE
  tee_common
  GTest::gtest_main
)
add_test(NAME test_transcript COMMAND test_transcript)

# ── Blake3 hashing KAT and determinism unit tests ────────────────────────
add_executable(test_hashing
  test_hashing.cpp
)
target_link_libraries(test_hashing PRIVATE
  tee_common
  GTest::gtest_main
)
add_test(NAME test_hashing COMMAND test_hashing)

# ── Negative security tests (PRD Section 10.1) ───────────────────────────
add_executable(test_negative
  test_negative.cpp
)
target_link_libraries(test_negative PRIVATE
  tee_verifier
  tee_attestation
  tee_common
  tcp_transport
  GTest::gtest_main
  OPENFHEpke
  OPENFHEcore
  OPENFHEbinfhe
  curl
  crypto
  tdx_attest
  pthread
)
add_test(NAME test_negative COMMAND test_negative)

# ── Unit tests (will be added in task 6+) ─────────────────────────────────────
# add_executable(unit_tests
#   test_attestation.cpp
#   test_verifier.cpp
#   test_transport.cpp
#   test_crypto.cpp
# )
# target_link_libraries(unit_tests PRIVATE
#   tee_attestation
#   tee_verifier
#   tcp_transport
#   GTest::gtest_main
#   GTest::gmock
#   OPENFHEpke
#   OPENFHEcore
# )
# gtest_discover_tests(unit_tests)
