#include "common.hpp"
#include <cuda_profiler_api.h>
#include <iostream>
#include <string>
#include <cmath>
#include <cstdlib>

int main(int argc, char** argv) {
    std::string keymode = "cold";
    for (int i = 1; i < argc; i++)
        if (std::string(argv[i]) == "--keymode" && i + 1 < argc) keymode = argv[++i];

    auto cc = BuildBootstrapContext();
    uint32_t numSlots = 1 << 15;  // 32768
    std::vector<uint32_t> levelBudget = {3, 3};
    std::vector<uint32_t> bsgsDim = {0, 0};

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots, 0);
    cc->EvalBootstrapKeyGen(keys, numSlots);

    auto x = SeededVector(numSlots, 1);
    uint32_t depth = 25;
    auto ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, numSlots);
    ptxt->SetLength(numSlots);
    auto ciph = cc->Encrypt(keys.publicKey, ptxt);

    bool warm = (keymode == "warm");
    cc->LoadContext(keys.publicKey);
    if (warm) { cudaDeviceSynchronize(); cudaProfilerStart(); }

    auto after = cc->EvalBootstrap(ciph);
    cudaDeviceSynchronize();
    if (warm) cudaProfilerStop();

    Plaintext result;
    cc->Decrypt(keys.secretKey, after, &result);
    result->SetLength(numSlots);
    auto out = result->GetRealPackedValue();
    double maxerr = 0.0;
    for (uint32_t i = 0; i < numSlots; i++)
        maxerr = std::max(maxerr, std::fabs(out[i] - x[i]));
    if (maxerr >= 1e-1) {
        std::cerr << "BOOTSTRAP_FAIL maxerr=" << maxerr << std::endl;
        return 3;
    }
    std::cout << "BOOTSTRAP_OK keymode=" << keymode << " maxerr=" << maxerr << std::endl;
    return 0;
}
