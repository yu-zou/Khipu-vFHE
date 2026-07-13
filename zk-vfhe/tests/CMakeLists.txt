enable_testing()

include(GoogleTest)

# ── test_hashing: Blake3 hashing correctness ────────────────────────────────
# Compile hashing.cpp directly to avoid zk_common's transitive OpenFHE dep
add_executable(test_hashing test_hashing.cpp ../src/common/hashing.cpp)
target_include_directories(test_hashing PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/blake3
)
target_link_libraries(test_hashing PRIVATE
    blake3
    GTest::gtest_main
    pthread)
gtest_discover_tests(test_hashing)

# ── test_transcript: Transcript JSON round-trip + BGV serialization ─────────
add_executable(test_transcript test_transcript.cpp
    ../src/common/hashing.cpp
    ../src/common/transcript.cpp
    ../src/common/serialization.cpp
)
target_include_directories(test_transcript PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/blake3
    ${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty
)
target_link_libraries(test_transcript PRIVATE
    blake3
    nlohmann_json
    OPENFHEpke
    OPENFHEcore
    OPENFHEbinfhe
    ${FF_LIBRARY}
    ${GMP_LIBRARY}
    ${GMPXX_LIBRARY}
    GTest::gtest_main
    pthread)
gtest_discover_tests(test_transcript)

# ── test_workloads: All 10 BGV workloads produce correct results ────────────
add_executable(test_workloads test_workloads.cpp)
target_link_libraries(test_workloads PRIVATE
    -Wl,--whole-archive zk_workloads -Wl,--no-whole-archive
    zk_proof
    zk_common
    OPENFHEpke
    OPENFHEcore
    OPENFHEbinfhe
    ${SNARK_LIBRARY}
    ${FF_LIBRARY}
    ${GMP_LIBRARY}
    ${GMPXX_LIBRARY}
    GTest::gtest_main
    pthread)
gtest_discover_tests(test_workloads)

# ── test_negative: 4 negative tests from PRD Section 10.2 ───────────────────
# 1. Tamper with ZK proof -> verification fails
# 2. Tamper with output ciphertext -> verification fails
# 3. Mismatched public input -> verification fails
# 4. Replay proof across sessions -> verification fails
add_executable(test_negative test_negative.cpp)
target_include_directories(test_negative PRIVATE
    /tmp/zkOpenFHE/third-party/libsnark/depends/libfqfft
)
target_compile_definitions(test_negative PRIVATE CURVE_BN128)
target_link_libraries(test_negative PRIVATE
    zk_verifier
    zk_proof
    zk_common
    OPENFHEpke
    OPENFHEcore
    OPENFHEbinfhe
    ${SNARK_LIBRARY}
    ${FF_LIBRARY}
    ${ZM_LIBRARY}
    ${GMPXX_LIBRARY}
    ${GMP_LIBRARY}
    GTest::gtest_main
    pthread)
gtest_discover_tests(test_negative)
