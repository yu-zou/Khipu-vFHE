add_executable(benchmark_runner benchmark_runner.cpp)
target_include_directories(benchmark_runner PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(benchmark_runner PRIVATE
  tee_verifier -Wl,--whole-archive tee_workloads -Wl,--no-whole-archive tee_attestation tcp_transport tee_common
  OPENFHEpke OPENFHEcore OPENFHEbinfhe tdx_attest curl crypto pthread)