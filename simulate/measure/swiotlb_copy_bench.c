#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_s(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static double copy_gbps(unsigned char *dst, unsigned char *src, size_t n) {
    double start = now_s(); long iters = 0;
    while (now_s() - start < 0.2) { memcpy(dst, src, n); iters++; }
    double secs = now_s() - start;
    return (double)n * iters / secs / 1e9;
}

int main(void) {
    size_t n = 16UL << 20;               /* 16 MiB */
    unsigned char *priv = malloc(n), *shared = malloc(n);
    memset(priv, 0xcd, n); memset(shared, 0, n);

    double p2s = copy_gbps(shared, priv, n);
    double s2p = copy_gbps(priv, shared, n);

    /* fixed per-op overhead proxy: tiny copy */
    double start = now_s(); long iters = 0;
    while (now_s() - start < 0.2) { memcpy(shared, priv, 64); iters++; }
    double per_op_us = (now_s() - start) / iters * 1e6;

    printf("{\"map_unmap_fixed_us\": %.4f, \"private_to_shared_gbps\": %.4f, "
           "\"shared_to_private_gbps\": %.4f}\n", per_op_us, p2s, s2p);
    free(priv); free(shared);
    return 0;
}
