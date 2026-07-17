# Tests for gpucc-vfhe

add_executable(test_attestation test_attestation.cpp)
target_link_libraries(test_attestation PRIVATE tee_attestation tee_common GTest::gtest_main OPENFHEpke OPENFHEcore OPENFHEbinfhe tdx_attest nvat)
add_test(NAME test_attestation COMMAND test_attestation)

add_executable(test_verifier test_verifier.cpp)
target_link_libraries(test_verifier PRIVATE tee_verifier tee_attestation tee_common GTest::gtest_main OPENFHEpke OPENFHEcore OPENFHEbinfhe curl crypto tdx_attest nvat)
add_test(NAME test_verifier COMMAND test_verifier)

add_executable(test_workloads test_workloads.cpp)
target_link_libraries(test_workloads PRIVATE -Wl,--whole-archive tee_workloads -Wl,--no-whole-archive tee_common GTest::gtest_main OPENFHEpke OPENFHEcore OPENFHEbinfhe pthread)
add_test(NAME test_workloads COMMAND test_workloads)

add_executable(test_transcript test_transcript.cpp)
target_link_libraries(test_transcript PRIVATE tee_common GTest::gtest_main)
add_test(NAME test_transcript COMMAND test_transcript)

add_executable(test_hashing test_hashing.cpp)
target_link_libraries(test_hashing PRIVATE tee_common GTest::gtest_main)
add_test(NAME test_hashing COMMAND test_hashing)

add_executable(test_negative test_negative.cpp)
target_link_libraries(test_negative PRIVATE tee_verifier tee_attestation tee_common tcp_transport GTest::gtest_main OPENFHEpke OPENFHEcore OPENFHEbinfhe curl crypto tdx_attest nvat pthread)
add_test(NAME test_negative COMMAND test_negative)
