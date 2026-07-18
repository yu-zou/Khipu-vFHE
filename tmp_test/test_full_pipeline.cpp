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
    auto t2 = std::chrono::high_resolution_clock::now();
    std::cerr << "KeyGen: " << std::chrono::duration_cast<std::chrono::milliseconds>(t2-t1).count() << "ms" << std::endl;
    
    cc->EvalMultKeyGen(kp.secretKey);
    std::vector<int32_t> rots;
    for (uint32_t j = 1; j < 256; j <<= 1) rots.push_back(j);
    for (uint32_t j = 1; j < 128; j <<= 1) rots.push_back(j * 256);
    cc->EvalRotateKeyGen(kp.secretKey, rots);
    auto t3 = std::chrono::high_resolution_clock::now();
    std::cerr << "EvalKeys: " << std::chrono::duration_cast<std::chrono::milliseconds>(t3-t2).count() << "ms" << std::endl;
    
    std::vector<uint32_t> lb = {2, 2}, d1 = {16, 16};
    cc->EvalBootstrapSetup(lb, d1, 32768);
    cc->EvalBootstrapKeyGen(kp.secretKey, 32768);
    auto t4 = std::chrono::high_resolution_clock::now();
    std::cerr << "Bootstrap: " << std::chrono::duration_cast<std::chrono::milliseconds>(t4-t3).count() << "ms" << std::endl;
    
    // Serialize eval keys
    std::cerr << "Serializing eval keys..." << std::endl;
    size_t total_size = 0;
    {
        std::ostringstream oss(std::ios::binary);
        CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(oss, SerType::BINARY, cc);
        total_size += oss.str().size();
    }
    {
        std::ostringstream oss(std::ios::binary);
        CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(oss, SerType::BINARY, cc);
        total_size += oss.str().size();
    }
    {
        std::ostringstream oss(std::ios::binary);
        CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(oss, SerType::BINARY, cc);
        total_size += oss.str().size();
    }
    auto t5 = std::chrono::high_resolution_clock::now();
    std::cerr << "Serialize eval keys: " << std::chrono::duration_cast<std::chrono::milliseconds>(t5-t4).count() 
              << "ms (" << total_size / (1024*1024) << " MB)" << std::endl;
    
    // Serialize public key
    std::string pk_ser;
    {
        std::ostringstream oss(std::ios::binary);
        Serial::Serialize(kp.publicKey, oss, SerType::BINARY);
        pk_ser = oss.str();
    }
    auto t5b = std::chrono::high_resolution_clock::now();
    std::cerr << "Serialize PK: " << std::chrono::duration_cast<std::chrono::milliseconds>(t5b-t5).count() 
              << "ms (" << pk_ser.size() / 1024 << " KB)" << std::endl;
    
    // Encrypt 21 ciphertexts
    std::cerr << "Encrypting 21 ciphertexts (32768 slots each)..." << std::endl;
    std::vector<double> vals(32768, 0.0);
    for (int i = 0; i < 21; i++) {
        auto pt = cc->MakeCKKSPackedPlaintext(vals, 2, 13);
        auto ct = cc->Encrypt(kp.publicKey, pt);
        std::cerr << "  CT " << i << " encrypted" << std::endl;
    }
    auto t6 = std::chrono::high_resolution_clock::now();
    std::cerr << "Encrypt 21 CTs: " << std::chrono::duration_cast<std::chrono::milliseconds>(t6-t5b).count() << "ms" << std::endl;
    
    std::cerr << "TOTAL: " << std::chrono::duration_cast<std::chrono::milliseconds>(t6-t0).count() << "ms" << std::endl;
    return 0;
}
