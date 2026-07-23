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
    cc->EvalRotateKeyGen(keys.secretKey, {1});
    cc->LoadContext(keys.publicKey);

    auto pt1 = cc->MakeCKKSPackedPlaintext(SeededVector(1 << 13, 1));
    auto c1 = cc->Encrypt(keys.publicKey, pt1);

    bool warm = (keymode == "warm");
    if (warm) { cudaDeviceSynchronize(); cudaProfilerStart(); }

    auto cRot = cc->EvalRotate(c1, 1);
    cudaDeviceSynchronize();
    if (warm) cudaProfilerStop();

    Plaintext r; cc->Decrypt(keys.secretKey, cRot, &r);
    std::cout << "ROTATE_OK keymode=" << keymode << std::endl;
    return 0;
}
