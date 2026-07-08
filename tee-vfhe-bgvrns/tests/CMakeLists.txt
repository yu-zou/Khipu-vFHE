enable_testing()

include(GoogleTest)

set(BGV_TEST_LIBS
    tee_common
    tee_attestation
    OPENFHEpke
    OPENFHEcore
    OPENFHEbinfhe
    GTest::gtest_main
    pthread
)

add_executable(test_transcript test_transcript.cpp)
target_link_libraries(test_transcript PRIVATE ${BGV_TEST_LIBS})
gtest_discover_tests(test_transcript)

add_executable(test_hashing test_hashing.cpp)
target_link_libraries(test_hashing PRIVATE tee_common GTest::gtest_main pthread)
gtest_discover_tests(test_hashing)

add_executable(test_attestation test_attestation.cpp)
target_link_libraries(test_attestation PRIVATE
    tee_attestation
    tee_common
    OPENFHEpke
    OPENFHEcore
    OPENFHEbinfhe
    tdx_attest
    GTest::gtest_main
    pthread)
gtest_discover_tests(test_attestation)

add_executable(test_verifier test_verifier.cpp)
target_link_libraries(test_verifier PRIVATE
    tee_verifier
    tee_attestation
    tee_common
    OPENFHEpke
    OPENFHEcore
    OPENFHEbinfhe
    tdx_attest
    curl
    crypto
    GTest::gtest_main
    pthread)
gtest_discover_tests(test_verifier)

# test_workloads: tests all 10 registered BGV workloads
add_executable(test_workloads test_workloads.cpp)
target_link_libraries(test_workloads PRIVATE
    -Wl,--whole-archive tee_workloads -Wl,--no-whole-archive
    tee_common
    tee_attestation
    OPENFHEpke
    OPENFHEcore
    OPENFHEbinfhe
    GTest::gtest_main
    pthread)
gtest_discover_tests(test_workloads)

# test_negative: negative scenario tests for verifier + transcript
add_executable(test_negative test_negative.cpp)
target_link_libraries(test_negative PRIVATE
    tee_verifier
    tee_attestation
    tee_common
    OPENFHEpke
    OPENFHEcore
    OPENFHEbinfhe
    tdx_attest
    curl
    crypto
    GTest::gtest_main
    pthread)
gtest_discover_tests(test_negative)
