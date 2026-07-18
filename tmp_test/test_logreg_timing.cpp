#include <iostream>
#include <chrono>
#include <openfhe.h>
using namespace lbcrypto;
int main() {
    auto t0 = std::chrono::high_resolution_clock::now();
    std::cerr << "Creating context..." << std::endl;
    CCParams<CryptoContextCKKSRNS> params;
    params.SetRingDim(65536);
    params.SetBatchSize(32768);
    params.SetMultiplicativeDepth(22);
    params.SetScalingModSize(50);
    params.SetFirstModSize(55);
    params.SetScalingTechnique(FLEXIBLEAUTO);
    params.SetKeySwitchTechnique(HYBRID);
    params.SetNumLargeDigits(3);
    params.SetSecretKeyDist(SPARSE_TERNARY);
    params.SetSecurityLevel(HEStd_NotSet);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE); cc->Enable(FHE);
    auto t1 = std::chrono::high_resolution_clock::now();
    std::cerr << "Context: " << std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count() << "ms" << std::endl;
    std::cerr << "KeyGen..." << std::endl;
    auto kp = cc->KeyGen();
    auto t2 = std::chrono::high_resolution_clock::now();
    std::cerr << "KeyGen: " << std::chrono::duration_cast<std::chrono::milliseconds>(t2-t1).count() << "ms" << std::endl;
    std::cerr << "EvalMultKeyGen..." << std::endl;
    cc->EvalMultKeyGen(kp.secretKey);
    auto t3 = std::chrono::high_resolution_clock::now();
    std::cerr << "EvalMultKeyGen: " << std::chrono::duration_cast<std::chrono::milliseconds>(t3-t2).count() << "ms" << std::endl;
    std::cerr << "BootstrapSetup..." << std::endl;
    std::vector<uint32_t> lb = {2, 2}, d1 = {16, 16};
    cc->EvalBootstrapSetup(lb, d1, 32768);
    auto t4 = std::chrono::high_resolution_clock::now();
    std::cerr << "BootstrapSetup: " << std::chrono::duration_cast<std::chrono::milliseconds>(t4-t3).count() << "ms" << std::endl;
    std::cerr << "BootstrapKeyGen..." << std::endl;
    cc->EvalBootstrapKeyGen(kp.secretKey, 32768);
    auto t5 = std::chrono::high_resolution_clock::now();
    std::cerr << "BootstrapKeyGen: " << std::chrono::duration_cast<std::chrono::milliseconds>(t5-t4).count() << "ms" << std::endl;
    std::cerr << "TOTAL: " << std::chrono::duration_cast<std::chrono::milliseconds>(t5-t0).count() << "ms" << std::endl;
    return 0;
}
