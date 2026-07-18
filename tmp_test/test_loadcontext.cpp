#include <iostream>
#include <fideslib.hpp>

int main() {
    fideslib::CCParams<fideslib::CryptoContextCKKSRNS> params;
    params.SetRingDim(65536);
    params.SetBatchSize(32768);
    params.SetMultiplicativeDepth(22);
    params.SetScalingModSize(50);
    params.SetFirstModSize(55);
    params.SetScalingTechnique(fideslib::FLEXIBLEAUTO);
    params.SetKeySwitchTechnique(fideslib::HYBRID);
    params.SetNumLargeDigits(3);
    params.SetSecretKeyDist(fideslib::SPARSE_TERNARY);
    params.SetSecurityLevel(fideslib::HEStd_NotSet);
    params.SetDevices(std::vector<int>{0});

    auto cc = fideslib::GenCryptoContext(params);
    cc->Enable(fideslib::PKE);
    cc->Enable(fideslib::KEYSWITCH);
    cc->Enable(fideslib::LEVELEDSHE);
    cc->Enable(fideslib::ADVANCEDSHE);
    cc->Enable(fideslib::FHE);

    auto kp = cc->KeyGen();
    std::cerr << "KeyGen done" << std::endl;
    
    cc->EvalMultKeyGen(kp.secretKey);
    std::cerr << "EvalMultKeyGen done" << std::endl;

    std::vector<int32_t> rots;
    for (uint32_t j = 1; j < 256; j <<= 1) { rots.push_back(j); rots.push_back(-j); }
    for (uint32_t j = 256; j < 128*256; j <<= 1) rots.push_back(j);
    rots.push_back(32765); rots.push_back(32756); rots.push_back(32720); rots.push_back(32576);
    cc->EvalRotateKeyGen(kp.secretKey, rots);
    std::cerr << "EvalRotateKeyGen done" << std::endl;

    std::vector<uint32_t> lb = {4, 4}, d1 = {16, 16};
    cc->EvalBootstrapSetup(lb, d1, 32768, 0);
    std::cerr << "EvalBootstrapSetup done" << std::endl;
    
    cc->EvalBootstrapKeyGen(kp.secretKey, 32768);
    std::cerr << "EvalBootstrapKeyGen done" << std::endl;

    std::cerr << "Calling LoadContext..." << std::endl;
    cc->LoadContext(kp.publicKey);
    std::cerr << "LoadContext done!" << std::endl;
    
    return 0;
}
