#include "common.hpp"
#include "cuda_profiler_api.h"
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    std::string keymode = "cold";
    for (int i = 1; i < argc; i++)
        if (std::string(argv[i]) == "--keymode" && i + 1 < argc) keymode = argv[++i];

    auto cc = BuildLightContext();
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->LoadContext(keys.publicKey);

    auto pt1 = cc->MakeCKKSPackedPlaintext(SeededVector(1 << 13, 1));
    auto pt2 = cc->MakeCKKSPackedPlaintext(SeededVector(1 << 13, 2));
    auto c1 = cc->Encrypt(keys.publicKey, pt1);
    auto c2 = cc->Encrypt(keys.publicKey, pt2);

    bool warm = (keymode == "warm");
    if (warm) { cudaDeviceSynchronize(); cudaProfilerStart(); }

    auto cMul = cc->EvalMult(c1, c2);
    auto cRs = cc->Rescale(cMul);
    cudaDeviceSynchronize();
    if (warm) cudaProfilerStop();

    Plaintext r; cc->Decrypt(keys.secretKey, cRs, &r);
    std::cout << "MULT_OK keymode=" << keymode << std::endl;
    return 0;
}
