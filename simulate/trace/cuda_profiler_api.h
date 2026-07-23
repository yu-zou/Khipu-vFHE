#pragma once
// Compatibility stub for CUDA >= 12 where cudaProfilerStart/Stop were removed.
// nsys --capture-range=cudaProfilerApi will not work with this stub;
// use --capture-range=nvtx or capture the full process instead.
#ifdef __cplusplus
extern "C" {
#endif
static inline void cudaProfilerStart(void) {}
static inline void cudaProfilerStop(void) {}
#ifdef __cplusplus
}
#endif
