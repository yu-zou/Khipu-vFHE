#include "common.hpp"
#include <cuda_profiler_api.h>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    std::string keymode = "cold";
    for (int i = 1; i < argc; i++)
        if (std::string(argv[i]) == "--keymode" && i + 1 < argc) keymode = argv[++i];

    auto cc = BuildLightContext();
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    auto x1 = SeededVector(1 << 13, 1);
    auto x2 = SeededVector(1 << 13, 2);
    auto p1 = cc->MakeCKKSPackedPlaintext(x1);
    auto p2 = cc->MakeCKKSPackedPlaintext(x2);
    auto c1 = cc->Encrypt(keys.publicKey, p1);
    auto c2 = cc->Encrypt(keys.publicKey, p2);

    bool warm = (keymode == "warm");
    if (warm) { cc->LoadContext(keys.publicKey); cudaDeviceSynchronize(); cudaProfilerStart(); }
    else { cc->LoadContext(keys.publicKey); }

    auto cAdd = cc->EvalAdd(c1, c2);
    cudaDeviceSynchronize();
    if (warm) cudaProfilerStop();

    Plaintext r; cc->Decrypt(keys.secretKey, cAdd, &r);
    std::cout << "ADD_OK keymode=" << keymode << std::endl;
    return 0;
}
