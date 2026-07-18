#include <iostream>
#include <chrono>
#include <sstream>
#include <openfhe.h>
#include <openfhe/pke/cryptocontext-ser.h>
#include <openfhe/pke/key/key-ser.h>
#include <openfhe/pke/scheme/ckksrns/ckksrns-ser.h>
#include <openfhe/core/utils/serial.h>
using namespace lbcrypto;

int main() {
    auto t0 = std::chrono::high_resolution_clock::now();
    
    CCParams<CryptoContextCKKSRNS> params;
    params.SetRingDim(65536); params.SetBatchSize(32768);
    params.SetMultiplicativeDepth(22); params.SetScalingModSize(50);
    params.SetFirstModSize(55); params.SetScalingTechnique(FLEXIBLEAUTO);
    params.SetKeySwitchTechnique(HYBRID); params.SetNumLargeDigits(3);
    params.SetSecretKeyDist(SPARSE_TERNARY); params.SetSecurityLevel(HEStd_NotSet);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE); cc->Enable(FHE);
    auto t1 = std::chrono::high_resolution_clock::now();
    std::cerr << "Context: " << std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count() << "ms" << std::endl;
    
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    std::vector<int32_t> rots;
    for (uint32_t j = 1; j < 256; j <<= 1) rots.push_back(j);
    for (uint32_t j = 1; j < 128; j <<= 1) rots.push_back(j * 256);
    cc->EvalRotateKeyGen(kp.secretKey, rots);
    
    // Level budget [4, 4]
    std::vector<uint32_t> lb = {4, 4}, d1 = {16, 16};
    cc->EvalBootstrapSetup(lb, d1, 32768);
    cc->EvalBootstrapKeyGen(kp.secretKey, 32768);
    auto t2 = std::chrono::high_resolution_clock::now();
    std::cerr << "KeyGen+Bootstrap: " << std::chrono::duration_cast<std::chrono::milliseconds>(t2-t1).count() << "ms" << std::endl;
    
    // Serialize eval keys and measure size
    size_t total_size = 0;
    {
        std::ostringstream oss(std::ios::binary);
        CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(oss, SerType::BINARY, cc);
        total_size += oss.str().size();
        std::cerr << "EvalMultKey: " << oss.str().size() / (1024*1024) << " MB" << std::endl;
    }
    {
        std::ostringstream oss(std::ios::binary);
        CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(oss, SerType::BINARY, cc);
        total_size += oss.str().size();
        std::cerr << "EvalSumKey: " << oss.str().size() / (1024*1024) << " MB" << std::endl;
    }
    {
        std::ostringstream oss(std::ios::binary);
        CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(oss, SerType::BINARY, cc);
        total_size += oss.str().size();
        std::cerr << "EvalAutoKey: " << oss.str().size() / (1024*1024) << " MB" << std::endl;
    }
    auto t3 = std::chrono::high_resolution_clock::now();
    std::cerr << "Serialize: " << std::chrono::duration_cast<std::chrono::milliseconds>(t3-t2).count() << "ms" << std::endl;
    std::cerr << "TOTAL serialized: " << total_size / (1024*1024) << " MB (" << total_size / (1024*1024*1024.0) << " GB)" << std::endl;
    return 0;
}
