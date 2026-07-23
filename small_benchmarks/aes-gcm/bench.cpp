// bench.cpp — throughput benchmark for AES-256-GCM and GMAC-256 (AES-NI)
//
// Compares AES-256-GCM (encryption + authentication) against GMAC-256
// (authentication only) across varying input sizes.
// Uses OpenSSL's EVP interface which automatically leverages AES-NI.
//
// Build: make
// Run:   ./bench [--csv] [--warmup]

#include <openssl/evp.h>
#include <openssl/err.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Helper: format a byte count into human-readable form
// ─────────────────────────────────────────────────────────────────────────────
static std::string fmt_bytes(double n) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int idx = 0;
    while (n >= 1024.0 && idx < 3) {
        n /= 1024.0;
        ++idx;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f %s", n, units[idx]);
    return buf;
}

static std::string fmt_throughput(double bytes_per_sec) {
    // Always report in GB/s for large sizes, MB/s for smaller
    double gb = bytes_per_sec / 1e9;
    if (gb >= 1.0) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f GB/s", gb);
        return buf;
    }
    double mb = bytes_per_sec / 1e6;
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f MB/s", mb);
    return buf;
}

// Format a time value for table display
static std::string fmt_time(double seconds) {
    char buf[32];
    if (seconds >= 1.0) {
        snprintf(buf, sizeof(buf), "%.3f s", seconds);
    } else if (seconds >= 1e-3) {
        snprintf(buf, sizeof(buf), "%.3f ms", seconds * 1e3);
    } else if (seconds >= 1e-6) {
        snprintf(buf, sizeof(buf), "%.2f us", seconds * 1e6);
    } else {
        snprintf(buf, sizeof(buf), "%.2f ns", seconds * 1e9);
    }
    return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark a single AES-256-GCM encryption operation
// ─────────────────────────────────────────────────────────────────────────────
// Returns the median time per operation in seconds.
static double bench_aes_gcm(const uint8_t* key,
                            const uint8_t* iv,
                            const uint8_t* aad,
                            size_t aad_len,
                            const uint8_t* plaintext,
                            size_t pt_len,
                            int iterations) {
    std::vector<uint8_t> ciphertext(pt_len);
    std::vector<uint8_t> tag(16);

    // Warm-up (3 iterations, not measured)
    for (int w = 0; w < 3; ++w) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
        int len;
        if (aad_len > 0) {
            EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len);
        }
        if (pt_len > 0) {
            EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, pt_len);
        }
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        EVP_CIPHER_CTX_free(ctx);
    }

    // Measured iterations
    std::vector<double> times;
    times.reserve(iterations);
    for (int i = 0; i < iterations; ++i) {
        auto t0 = std::chrono::high_resolution_clock::now();

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
        int len;
        if (aad_len > 0) {
            EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len);
        }
        if (pt_len > 0) {
            EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, pt_len);
        }
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        EVP_CIPHER_CTX_free(ctx);

        auto t1 = std::chrono::high_resolution_clock::now();
        times.push_back(std::chrono::duration<double>(t1 - t0).count());
    }

    // Return median
    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark a single GMAC operation (GCM with zero plaintext)
// ─────────────────────────────────────────────────────────────────────────────
static double bench_gmac(const uint8_t* key,
                         const uint8_t* iv,
                         const uint8_t* aad,
                         size_t aad_len,
                         int iterations) {
    std::vector<uint8_t> tag(16);

    // Warm-up
    for (int w = 0; w < 3; ++w) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
        int len;
        if (aad_len > 0) {
            EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len);
        }
        EVP_EncryptFinal_ex(ctx, nullptr, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        EVP_CIPHER_CTX_free(ctx);
    }

    // Measured iterations
    std::vector<double> times;
    times.reserve(iterations);
    for (int i = 0; i < iterations; ++i) {
        auto t0 = std::chrono::high_resolution_clock::now();

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
        int len;
        if (aad_len > 0) {
            EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len);
        }
        EVP_EncryptFinal_ex(ctx, nullptr, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        EVP_CIPHER_CTX_free(ctx);

        auto t1 = std::chrono::high_resolution_clock::now();
        times.push_back(std::chrono::duration<double>(t1 - t0).count());
    }

    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}

// ─────────────────────────────────────────────────────────────────────────────
// Calibrate iterations: find number of iterations so total time ≈ target_sec
//
// bench_aes_gcm / bench_gmac both return the *median per-operation time*
// (not the total batch time), so we compute: est = target_sec / t.
// ─────────────────────────────────────────────────────────────────────────────
static int calibrate_iterations(const uint8_t* key,
                                const uint8_t* iv,
                                const uint8_t* aad,
                                size_t aad_len,
                                const uint8_t* plaintext,
                                size_t pt_len,
                                double target_sec) {
    // Quick estimate with 10 iterations
    int n = 10;
    double t = bench_aes_gcm(key, iv, aad, aad_len, plaintext, pt_len, n);
    // t is median per-operation time; clamp to avoid overflow or underflow
    if (t <= 1e-12) t = 1e-12;
    double est = target_sec / t;
    if (est > 100000.0) est = 100000.0;
    if (est < 5.0) est = 5.0;
    return (int)est;
}

static int calibrate_gmac_iterations(const uint8_t* key,
                                     const uint8_t* iv,
                                     const uint8_t* aad,
                                     size_t aad_len,
                                     double target_sec) {
    int n = 10;
    double t = bench_gmac(key, iv, aad, aad_len, n);
    if (t <= 1e-12) t = 1e-12;
    double est = target_sec / t;
    if (est > 100000.0) est = 100000.0;
    if (est < 5.0) est = 5.0;
    return (int)est;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    bool csv_mode = false;
    bool do_warmup = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--csv") == 0) {
            csv_mode = true;
        } else if (strcmp(argv[i], "--warmup") == 0) {
            do_warmup = true;
        }
    }

    // Initialise OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Fixed key (256-bit) and IV (96-bit / 12-byte)
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
    };

    // Small fixed AAD for GCM (metadata / header simulation)
    static const uint8_t fixed_aad[16] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78,
    };

    // Sizes to benchmark (bytes)
    const size_t sizes[] = {
        256,                    // 256 B
        1024,                   // 1 KB
        4096,                   // 4 KB
        16384,                  // 16 KB
        65536,                  // 64 KB
        262144,                 // 256 KB
        1048576,                // 1 MB
        4194304,                // 4 MB
        16777216,               // 16 MB
        67108864,               // 64 MB
        268435456,              // 256 MB
    };
    const size_t num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    // Target ~2 seconds of total measured time per benchmark point
    const double target_sec = 2.0;

    // Pre-compute the largest data buffer we'll need
    size_t max_size = sizes[num_sizes - 1];
    std::vector<uint8_t> data_buffer(max_size);
    // Fill with repeating pattern
    for (size_t i = 0; i < max_size; ++i) {
        data_buffer[i] = (uint8_t)(i & 0xFF);
    }

    // System warm-up: execute a few large GCM ops to get CPU into steady state
    if (do_warmup) {
        bench_aes_gcm(key, iv, fixed_aad, sizeof(fixed_aad),
                      data_buffer.data(), 65536, 50);
        bench_gmac(key, iv, data_buffer.data(), 65536, 50);
    }

    // ── Header ──
    if (csv_mode) {
        std::cout << "size_bytes,size_human,"
                  << "gcm_time_s,gcm_throughput_bps,gcm_throughput_human,"
                  << "gmac_time_s,gmac_throughput_bps,gmac_throughput_human,"
                  << "speedup\n";
    } else {
        std::cout << "+------------+----------------+--------------------+----------------+--------------------+-----------------------------+\n";
        std::cout << "| input size | aes-gcm time   | aes-gcm throughput | gmac time      | gmac throughput    | speedup of gmac over aes-gcm |\n";
        std::cout << "+------------+----------------+--------------------+----------------+--------------------+-----------------------------+\n";
    }

    // ── Benchmark each size ──
    for (size_t si = 0; si < num_sizes; ++si) {
        size_t sz = sizes[si];

        // ── AES-256-GCM ──
        int gcm_iters = calibrate_iterations(key, iv, fixed_aad, sizeof(fixed_aad),
                                             data_buffer.data(), sz, target_sec);
        double gcm_time = bench_aes_gcm(key, iv, fixed_aad, sizeof(fixed_aad),
                                        data_buffer.data(), sz, gcm_iters);
        double gcm_time_per_op = gcm_time;  // median is already per-op
        double gcm_bps = (double)sz / gcm_time_per_op;

        // ── GMAC ──
        int gmac_iters = calibrate_gmac_iterations(key, iv, data_buffer.data(), sz,
                                                   target_sec);
        double gmac_time = bench_gmac(key, iv, data_buffer.data(), sz, gmac_iters);
        double gmac_time_per_op = gmac_time;
        double gmac_bps = (double)sz / gmac_time_per_op;

        // ── Speedup ──
        double speedup = gcm_time_per_op / gmac_time_per_op;

        if (csv_mode) {
            std::cout << sz << "," << fmt_bytes((double)sz) << ","
                      << std::scientific << std::setprecision(6) << gcm_time_per_op << ","
                      << std::defaultfloat << std::setprecision(6) << gcm_bps << "," << fmt_throughput(gcm_bps) << ","
                      << std::scientific << std::setprecision(6) << gmac_time_per_op << ","
                      << std::defaultfloat << std::setprecision(6) << gmac_bps << "," << fmt_throughput(gmac_bps) << ","
                      << std::fixed << std::setprecision(2) << speedup << "\n";
        } else {
            std::cout << "| "
                      << std::left << std::setw(10) << fmt_bytes((double)sz) << " | "
                      << std::right << std::setw(14) << fmt_time(gcm_time_per_op) << " | "
                      << std::left << std::setw(18) << fmt_throughput(gcm_bps) << " | "
                      << std::right << std::setw(14) << fmt_time(gmac_time_per_op) << " | "
                      << std::left << std::setw(18) << fmt_throughput(gmac_bps) << " | "
                      << std::right << std::setw(27) << std::fixed << std::setprecision(2) << speedup << "x |\n";
        }
    }

    if (!csv_mode) {
        std::cout << "+------------+----------------+--------------------+----------------+--------------------+-----------------------------+\n";
        std::cout << "\nNotes:\n";
        std::cout << "  - AES-GCM-256: encrypt <input_size> bytes of plaintext "
                  << "with 16-byte AAD and 12-byte IV.\n";
        std::cout << "  - GMAC-256: authenticate <input_size> bytes of AAD "
                  << "with zero plaintext and 12-byte IV.\n";
        std::cout << "  - Timings are median per operation over calibrated iterations "
                  << "(targeting ~" << target_sec << " s total).\n";
        std::cout << "  - AES-NI is used automatically by OpenSSL.\n";
    }

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
