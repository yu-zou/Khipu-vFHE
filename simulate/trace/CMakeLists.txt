cmake_minimum_required(VERSION 3.25.2)
set(CMAKE_CXX_STANDARD 20)
project(fideslib_microbench LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(fideslib REQUIRED CONFIG)
if (NOT fideslib_FOUND)
    message(FATAL_ERROR "PACKAGE FIDESlib NOT FOUND")
endif ()
find_package(CUDAToolkit REQUIRED)

set(CMAKE_CXX_COMPILER ${FIDESLIB_CXX_COMPILER})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FIDESLIB_CXX_FLAGS}")

foreach(bench add mult rotate bootstrap)
    add_executable(bench_${bench} bench_${bench}.cpp)
    target_link_libraries(bench_${bench} PRIVATE fideslib::fideslib CUDA::cudart)
endforeach()
