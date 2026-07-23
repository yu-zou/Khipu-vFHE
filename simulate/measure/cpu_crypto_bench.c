#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

/* CPUID feature detection — AES-NI = CPUID.01H:ECX[25], PCLMULQDQ = CPUID.01H:ECX[1] */
static int has_aesni(void) {
    unsigned int eax = 1, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    return (ecx >> 25) & 1;
}
static int has_pclmulqdq(void) {
    unsigned int eax = 1, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    return ecx & 1;
}

static double now_s(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static const size_t SIZES[] = {1024, 4096, 16384, 65536, 262144, 1048576, 4194304};
static const int NSIZES = 7;

/* returns GB/s; sets *per_op_us for per-operation latency */
static double bench(int gmac_only, size_t n, double *per_op_us) {
    unsigned char key[32], iv[12], tag[16];
    RAND_bytes(key, sizeof key); RAND_bytes(iv, sizeof iv);
    unsigned char *in = malloc(n), *out = malloc(n);
    memset(in, 0xab, n);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    double start = now_s();
    long iters = 0; int len;
    while (now_s() - start < 0.2) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        if (gmac_only) {
            EVP_EncryptUpdate(ctx, NULL, &len, in, (int)n);   /* AAD only */
        } else {
            EVP_EncryptUpdate(ctx, out, &len, in, (int)n);    /* ciphertext */
        }
        EVP_EncryptFinal_ex(ctx, out, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        iters++;
    }
    double secs = now_s() - start;
    EVP_CIPHER_CTX_free(ctx); free(in); free(out);
    if (per_op_us) *per_op_us = secs / iters * 1e6;
    return (double)n * iters / secs / 1e9;
}

static void print_curve(const char *name, int gmac_only) {
    double per_op_small = 0.0;
    printf("\"%s\": {\"throughput_curve\": [", name);
    for (int i = 0; i < NSIZES; i++) {
        double per_op;
        double gbps = bench(gmac_only, SIZES[i], &per_op);
        if (i == 0) per_op_small = per_op;
        printf("%s[%zu, %.4f]", i ? ", " : "", SIZES[i], gbps);
    }
    printf("], \"fixed_latency_us\": %.4f}", per_op_small);
}

int main(void) {
    if (!has_aesni() || !has_pclmulqdq()) {
        fprintf(stderr, "FATAL: AES-NI (%d) or PCLMULQDQ (%d) not available; refusing to emit params\n",
                has_aesni(), has_pclmulqdq());
        return 2;
    }
    printf("{\"aesni\": true, \"pclmulqdq\": true, \"security_bits\": 256, ");
    print_curve("aes_gcm", 0);
    printf(", ");
    print_curve("gmac", 1);
    printf("}\n");
    return 0;
}
