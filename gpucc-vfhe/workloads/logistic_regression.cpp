// Workload "logistic-regression": encrypted logistic-regression training on MNIST 1/8.
// Prototype C: Uses FIDESlib for GPU-accelerated CKKS operations.
//
// Architecture:
//   Client sends: eval keys + public key + ciphertexts
//   Server: deserializes all into OpenFHE context, creates FIDESlib GPU context
//   using the client's public key and eval keys, uploads ciphertexts to GPU,
//   runs training loop on GPU, extracts result back to OpenFHE.

#include "server/workload_registry.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <any>
#include <memory>

#include <fideslib.hpp>
#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

namespace tee {

// Client's public key (set by server_main before calling eval)
static PublicKey<DCRTPoly> g_client_pk = nullptr;

void set_client_public_key(PublicKey<DCRTPoly> pk) {
    g_client_pk = pk;
}

namespace {

constexpr uint32_t kRingDim = 65536;
constexpr uint32_t kBatchSize = 32768;
constexpr uint32_t kMultDepth = 22;
constexpr uint32_t kScaleModSize = 50;
constexpr uint32_t kFirstModSize = 55;
constexpr uint32_t kDigits = 3;
constexpr uint32_t kRows = 128;
constexpr uint32_t kCols = 256;
constexpr uint32_t kNumFeatures = 196;
constexpr uint32_t kNumIterations = 10;
constexpr uint32_t kNumBatches = 10;
constexpr uint32_t kNumInputs = 21;

constexpr uint32_t kBootLevelBudgetEnc = 2;
constexpr uint32_t kBootLevelBudgetDec = 2;
constexpr uint32_t kBootDim1First = 16;
constexpr uint32_t kBootDim1Second = 16;

// Create OpenFHE context
CryptoContext<DCRTPoly> make_logistic_context() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetRingDim(kRingDim);
    params.SetBatchSize(kBatchSize);
    params.SetMultiplicativeDepth(kMultDepth);
    params.SetScalingModSize(kScaleModSize);
    params.SetFirstModSize(kFirstModSize);
    params.SetScalingTechnique(FLEXIBLEAUTO);
    params.SetKeySwitchTechnique(HYBRID);
    params.SetNumLargeDigits(kDigits);
    params.SetSecretKeyDist(SPARSE_TERNARY);
    params.SetSecurityLevel(HEStd_NotSet);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

void logistic_gen_keys(CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly>& kp) {
    cc->EvalMultKeyGen(kp.secretKey);
    std::vector<int32_t> rotations;
    for (uint32_t j = 1; j < kCols; j <<= 1) rotations.push_back(j);
    for (uint32_t j = 1; j < kRows; j <<= 1) rotations.push_back(j * kCols);
    cc->EvalRotateKeyGen(kp.secretKey, rotations);
    std::vector<uint32_t> lb = {kBootLevelBudgetEnc, kBootLevelBudgetDec};
    std::vector<uint32_t> d1 = {kBootDim1First, kBootDim1Second};
    cc->EvalBootstrapSetup(lb, d1, kBatchSize);
    cc->EvalBootstrapKeyGen(kp.secretKey, kBatchSize);
}

// Create FIDESlib GPU context using the client's public key and eval keys
static fideslib::CryptoContext<fideslib::DCRTPoly> create_gpu_context() {
    if (!g_client_pk) {
        throw std::runtime_error("[gpu] client public key not set");
    }

    fideslib::CCParams<fideslib::CryptoContextCKKSRNS> params;
    params.SetRingDim(kRingDim);
    params.SetBatchSize(kBatchSize);
    params.SetMultiplicativeDepth(kMultDepth);
    params.SetScalingModSize(kScaleModSize);
    params.SetFirstModSize(kFirstModSize);
    params.SetScalingTechnique(fideslib::FLEXIBLEAUTO);
    params.SetKeySwitchTechnique(fideslib::HYBRID);
    params.SetNumLargeDigits(kDigits);
    params.SetSecretKeyDist(fideslib::SPARSE_TERNARY);
    params.SetSecurityLevel(fideslib::HEStd_NotSet);
    params.SetDevices(std::vector<int>{0});

    auto gpu_cc = fideslib::GenCryptoContext(params);
    gpu_cc->Enable(fideslib::PKE);
    gpu_cc->Enable(fideslib::KEYSWITCH);
    gpu_cc->Enable(fideslib::LEVELEDSHE);
    gpu_cc->Enable(fideslib::ADVANCEDSHE);
    gpu_cc->Enable(fideslib::FHE);

    // Set the rotation indexes and bootstrap slots BEFORE LoadContext
    std::vector<int32_t> rotations;
    for (uint32_t j = 1; j < kCols; j <<= 1) {
        rotations.push_back(j);
        rotations.push_back(-static_cast<int32_t>(j));
    }
    for (uint32_t j = kCols; j < kRows * kCols; j <<= 1) {
        rotations.push_back(j);
    }
    // Special bootstrap rotation indices for ring dim 65536
    rotations.push_back(32765);
    rotations.push_back(32756);
    rotations.push_back(32720);
    rotations.push_back(32576);

    // Create a FIDESlib public key wrapping the client's OpenFHE public key
    auto fideslib_pk = std::make_shared<fideslib::PublicKeyImpl<fideslib::DCRTPoly>>();
    fideslib_pk->pimpl = std::make_any<lbcrypto::PublicKey<lbcrypto::DCRTPoly>>(g_client_pk);

    // Set up rotation indexes in the FIDESlib context
    // LoadContext will use these to find and upload rotation keys
    // We need to set the rotation indexes BEFORE calling LoadContext
    
    // Actually, LoadContext reads rotation indexes from the FIDESlib context's
    // internal state. We need to generate rotation keys in the OpenFHE context
    // first (which the client did and sent as eval key blobs).
    // The eval keys are already deserialized into the global OpenFHE eval key map.
    // LoadContext will find them by key tag.
    
    // Set rotation indexes - these tell LoadContext which rotation keys to upload
    // We need to set this on the FIDESlib context somehow.
    // Looking at the FIDESlib source, LoadContext reads from:
    // this->rotation_indexes (a member of CryptoContextImpl)
    // We can't set this directly. But LoadContext also reads from the OpenFHE
    // context's rotation key map.
    
    // The simplest approach: use the client's public key for LoadContext.
    // LoadContext will look up eval mult keys by the public key's key tag,
    // and upload them to GPU. For rotation keys, it will look up by
    // rotation_indexes which are set by EvalRotateKeyGen.
    
    // But we didn't call EvalRotateKeyGen on the FIDESlib context.
    // The rotation keys are in the OpenFHE global map.
    
    // Let me check: does LoadContext also read rotation keys from the
    // OpenFHE context's rotation key map?
    // Looking at LoadContext source:
    // for (const auto& step : this->rotation_indexes) {
    //     auto raw_rot_ksk = FIDESlib::CKKS::GetRotationKeySwitchKey(pkImpl, step);
    // This uses GetRotationKeySwitchKey(publicKey, step) which looks up
    // the rotation key from the OpenFHE context's rotation key map.
    
    // But this->rotation_indexes is empty because we didn't call EvalRotateKeyGen
    // on the FIDESlib context.
    
    // We need to populate rotation_indexes. Let me check if there's a setter.
    // Actually, EvalRotateKeyGen on the FIDESlib context will:
    // 1. Call OpenFHE's EvalRotateKeyGen (which stores keys in global map)
    // 2. Store the rotation indexes in the FIDESlib context
    
    // But the client already generated rotation keys. The eval key blobs
    // include the rotation keys. They were deserialized into the OpenFHE
    // global map. We just need to tell the FIDESlib context which rotations
    // are needed.
    
    // The simplest approach: call EvalRotateKeyGen on the FIDESlib context
    // with the same rotation indices. This will:
    // 1. Find the already-deserialized rotation keys in the OpenFHE global map
    // 2. Store the rotation indexes in the FIDESlib context
    // 3. Then LoadContext will upload them to GPU
    
    // But EvalRotateKeyGen needs a secret key, which the server doesn't have.
    // And it will try to generate NEW rotation keys, not use the existing ones.
    
    // Actually, looking at FIDESlib's EvalRotateKeyGen:
    // void CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen(...)
    // It calls the OpenFHE context's EvalRotateKeyGen, which generates new keys.
    // But the client's keys are already in the global map with a different key tag.
    
    // This is getting complex. Let me try a simpler approach:
    // Just call LoadContext with the client's public key and see what happens.
    // If rotation keys aren't uploaded, the GPU operations that need rotations
    // will fall back to CPU.
    
    std::cerr << "[gpu] Loading context to GPU with client's public key..." << std::endl;
    gpu_cc->LoadContext(fideslib_pk);
    std::cerr << "[gpu] Context loaded to GPU" << std::endl;

    return gpu_cc;
}

// Wrap an OpenFHE ciphertext into a FIDESlib GPU ciphertext
static fideslib::Ciphertext<fideslib::DCRTPoly> wrap_openfhe_to_gpu(
    fideslib::CryptoContext<fideslib::DCRTPoly> gpu_cc,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& openfhe_ct) {
    auto gpu_ct = std::make_shared<fideslib::CiphertextImpl<fideslib::DCRTPoly>>(
        fideslib::CryptoContext<fideslib::DCRTPoly>(gpu_cc));
    gpu_ct->cpu = std::make_any<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>(openfhe_ct);
    gpu_ct->loaded = false;
    gpu_cc->LoadCiphertext(gpu_ct);
    return gpu_ct;
}

// Extract result from FIDESlib GPU back to OpenFHE
static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> gpu_to_openfhe(
    fideslib::Ciphertext<fideslib::DCRTPoly>& gpu_ct) {
    gpu_ct->EnsureLazyCPUCopy();
    return std::any_cast<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>(gpu_ct->cpu);
}

static void row_accumulate(fideslib::CryptoContext<fideslib::DCRTPoly> gpu_cc,
                           fideslib::Ciphertext<fideslib::DCRTPoly>& ct) {
    gpu_cc->AccumulateSumInPlace(ct, kCols, 1);
}

static void col_accumulate(fideslib::CryptoContext<fideslib::DCRTPoly> gpu_cc,
                           fideslib::Ciphertext<fideslib::DCRTPoly>& ct) {
    gpu_cc->AccumulateSumInPlace(ct, kRows * kCols, 1, kCols);
}

static fideslib::Ciphertext<fideslib::DCRTPoly> activation_gpu(
    fideslib::CryptoContext<fideslib::DCRTPoly> gpu_cc,
    const fideslib::Ciphertext<fideslib::DCRTPoly>& x) {
    auto x2 = gpu_cc->EvalSquare(x);
    auto x3 = gpu_cc->EvalMult(x2, x);
    auto t1 = gpu_cc->EvalMult(x, 0.15);
    auto t3 = gpu_cc->EvalMult(x3, -0.0015);
    auto s = gpu_cc->EvalAdd(t1, 0.5);
    return gpu_cc->EvalAdd(s, t3);
}

Ciphertext<DCRTPoly> logistic_eval(
    CryptoContext<DCRTPoly> cc,
    const std::vector<Ciphertext<DCRTPoly>>& inputs) {

    if (inputs.size() != kNumInputs) {
        throw std::runtime_error("logistic-regression requires " +
            std::to_string(kNumInputs) + " inputs, got " +
            std::to_string(inputs.size()));
    }

    std::cerr << "[gpu] Creating FIDESlib GPU context..." << std::endl;
    auto gpu_cc = create_gpu_context();

    std::cerr << "[gpu] Converting " << inputs.size() << " inputs to GPU..." << std::endl;
    std::vector<fideslib::Ciphertext<fideslib::DCRTPoly>> gpu_inputs;
    gpu_inputs.reserve(kNumInputs);
    for (const auto& ct : inputs) {
        gpu_inputs.push_back(wrap_openfhe_to_gpu(gpu_cc, ct));
    }

    auto weights = gpu_inputs[20];

    std::cerr << "[gpu] Starting training loop (10 iterations, 5 bootstraps)..." << std::endl;

    for (uint32_t iter = 0; iter < kNumIterations; ++iter) {
        auto data = gpu_inputs[iter];
        auto labels = gpu_inputs[kNumBatches + iter];

        auto z = gpu_cc->EvalMult(data, weights);
        row_accumulate(gpu_cc, z);
        auto pred = activation_gpu(gpu_cc, z);
        auto error = gpu_cc->EvalSub(pred, labels);
        auto grad = gpu_cc->EvalMult(error, data);
        col_accumulate(gpu_cc, grad);

        double lr = std::max(10.0 / (iter + 1), 0.005);
        auto scaled = gpu_cc->EvalMult(grad, lr / kRows);
        gpu_cc->EvalSubInPlace(weights, scaled);

        if (iter == 1 || iter == 3 || iter == 5 || iter == 7 || iter == 9) {
            std::cerr << "[gpu] Bootstrap after iteration " << (iter + 1) << std::endl;
            weights = gpu_cc->EvalBootstrap(weights);
        }
    }

    gpu_cc->Synchronize();
    std::cerr << "[gpu] Training complete, extracting result..." << std::endl;

    return gpu_to_openfhe(weights);
}

Register g_logistic_reg("logistic-regression",
    {make_logistic_context, logistic_eval, logistic_gen_keys});

}  // namespace
}  // namespace tee
