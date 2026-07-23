#pragma once
#include <fideslib.hpp>
#include <vector>
#include <string>
#include <cstdint>
#include <cuda_runtime.h>

using namespace fideslib;

inline std::vector<int> kDevices() { return {0}; }  // single GPU

// Light leveled context: Add / Mult / Rotate.
inline CryptoContext<DCRTPoly> BuildLightContext() {
    CCParams<CryptoContextCKKSRNS> p;
    p.SetSecretKeyDist(UNIFORM_TERNARY);
    p.SetSecurityLevel(HEStd_NotSet);
    p.SetRingDim(1 << 14);          // 16384
    p.SetMultiplicativeDepth(4);
    p.SetScalingTechnique(FLEXIBLEAUTO);
    p.SetScalingModSize(50);
    p.SetFirstModSize(60);
    p.SetKeySwitchTechnique(HYBRID);
    p.SetNumLargeDigits(3);
    p.SetBatchSize(1 << 13);        // 8192 slots
    p.SetDevices(kDevices());
    auto cc = GenCryptoContext(p);
    cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE);
    return cc;
}

// Bootstrap-capable context: Bootstrap only.
inline CryptoContext<DCRTPoly> BuildBootstrapContext() {
    CCParams<CryptoContextCKKSRNS> p;
    p.SetSecretKeyDist(SPARSE_TERNARY);
    p.SetSecurityLevel(HEStd_NotSet);
    p.SetRingDim(1 << 16);          // 65536
    p.SetMultiplicativeDepth(25);
    p.SetScalingTechnique(FLEXIBLEAUTO);
    p.SetScalingModSize(59);
    p.SetFirstModSize(60);
    p.SetKeySwitchTechnique(HYBRID);
    p.SetNumLargeDigits(3);
    p.SetDevices(kDevices());
    auto cc = GenCryptoContext(p);
    cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE); cc->Enable(FHE);
    return cc;
}

inline std::vector<double> SeededVector(size_t n, unsigned seed) {
    std::vector<double> v(n);
    uint64_t s = seed ? seed : 1;
    for (size_t i = 0; i < n; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;  // deterministic LCG
        v[i] = ((s >> 11) / (double)(1ULL << 53));  // [0,1)
    }
    return v;
}
