#include <cstdio>
#include <cuda_runtime.h>
#include <chrono>

static const size_t SIZES[] = {4096, 65536, 262144, 1048576, 4194304, 16777216};
static const int NSIZES = 6;

static double now_s() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

static double bench(void *dst, void *src, size_t n, cudaMemcpyKind kind, double *fixed_us) {
    double start = now_s(); long iters = 0;
    while (now_s() - start < 0.1) { cudaMemcpy(dst, src, n, kind); cudaDeviceSynchronize(); iters++; }
    double secs = now_s() - start;
    if (fixed_us) *fixed_us = secs / iters * 1e6;
    return (double)n * iters / secs / 1e9;
}

static void curve(const char *name, int h2d, void *host, void *dev) {
    double fixed_small = 0.0;
    printf("\"%s\": {\"bandwidth_curve\": [", name);
    for (int i = 0; i < NSIZES; i++) {
        double fixed;
        double gbps = h2d ? bench(dev, host, SIZES[i], cudaMemcpyHostToDevice, &fixed)
                          : bench(host, dev, SIZES[i], cudaMemcpyDeviceToHost, &fixed);
        if (i == 0) fixed_small = fixed;
        printf("%s[%zu, %.4f]", i ? ", " : "", SIZES[i], gbps);
    }
    printf("], \"fixed_latency_us\": %.4f}", fixed_small);
}

int main() {
    cudaSetDevice(0);
    size_t maxn = SIZES[NSIZES - 1];
    void *host, *dev;
    cudaMallocHost(&host, maxn);
    cudaMalloc(&dev, maxn);
    printf("{");
    curve("h2d", 1, host, dev);
    printf(", ");
    curve("d2h", 0, host, dev);
    printf("}\n");
    cudaFreeHost(host); cudaFree(dev);
    return 0;
}
