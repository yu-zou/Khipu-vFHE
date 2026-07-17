// Workload "logistic-regression": encrypted logistic-regression training on MNIST 1/8.
// Reference: FIDESlib examples/logreg
// Inputs: 10 data ciphertexts (each 128 rows × 256 cols),
//         10 label ciphertexts (each 128 rows × 256 cols),
//         1 weights ciphertext (256 values replicated across 128 rows).
// Output: 1 ciphertext with trained weights in slots 0..195.

#include "server/workload_registry.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

namespace tee {
namespace {

// ── CKKS Parameters (from FIDESlib examples/logref, spec §2.8.2) ─────────────

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
constexpr uint32_t kNumInputs = 21;  // 10 data + 10 labels + 1 weights

// Bootstrap parameters
constexpr uint32_t kBootLevelBudgetEnc = 2;
constexpr uint32_t kBootLevelBudgetDec = 2;
constexpr uint32_t kBootDim1First = 16;
constexpr uint32_t kBootDim1Second = 16;

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

void logistic_gen_keys(CC cc, const KeyPair<DCRTPoly>& kp) {
    cc->EvalMultKeyGen(kp.secretKey);
    
    // Rotation keys for row accumulation (powers of 2 up to cols)
    std::vector<int32_t> rotations;
    for (uint32_t j = 1; j < kCols; j <<= 1) {
        rotations.push_back(static_cast<int32_t>(j));
    }
    // Also need rotations for accumulating across rows
    for (uint32_t j = 1; j < kRows; j <<= 1) {
        rotations.push_back(static_cast<int32_t>(j * kCols));
    }
    cc->EvalRotateKeyGen(kp.secretKey, rotations);
    
    // Bootstrap keys
    std::vector<uint32_t> levelBudget = {kBootLevelBudgetEnc, kBootLevelBudgetDec};
    std::vector<uint32_t> dim1 = {kBootDim1First, kBootDim1Second};
    cc->EvalBootstrapSetup(levelBudget, dim1, kBatchSize);
    cc->EvalBootstrapKeyGen(kp.secretKey, kBatchSize);
}

// Row-accumulate: sum across kCols columns within each row.
// After this, slot r*kCols contains the sum of row r.
void row_accumulate(CC cc, Ciphertext<DCRTPoly>& ct) {
    for (uint32_t j = 1; j < kCols; j <<= 1) {
        auto rotated = cc->EvalRotate(ct, static_cast<int32_t>(j));
        cc->EvalAddInPlace(ct, rotated);
    }
}

// Column-accumulate: sum across kRows rows.
// After this, all slots in each column contain the sum of that column across all rows.
void col_accumulate(CC cc, Ciphertext<DCRTPoly>& ct) {
    for (uint32_t j = 1; j < kRows; j <<= 1) {
        auto rotated = cc->EvalRotate(ct, static_cast<int32_t>(j * kCols));
        cc->EvalAddInPlace(ct, rotated);
    }
}

// Apply activation: 0.5 + 0.15*x - 0.0015*x^3
Ciphertext<DCRTPoly> activation(CC cc, const Ciphertext<DCRTPoly>& x) {
    auto x2 = cc->EvalSquare(x);
    auto x3 = cc->EvalMult(x2, x);
    cc->RelinearizeInPlace(x3);
    
    auto term1 = cc->EvalMult(x, 0.15);
    auto term3 = cc->EvalMult(x3, -0.0015);
    auto sum = cc->EvalAdd(term1, 0.5);
    return cc->EvalAdd(sum, term3);
}

Ciphertext<DCRTPoly> logistic_eval(
    CC cc,
    const std::vector<Ciphertext<DCRTPoly>>& inputs) {
    
    if (inputs.size() != kNumInputs) {
        throw std::runtime_error("logistic-regression workload requires exactly " +
            std::to_string(kNumInputs) + " inputs");
    }
    
    // inputs[0..9]: 10 data ciphertexts (128 rows × 256 cols each)
    // inputs[10..19]: 10 label ciphertexts
    // inputs[20]: initial weights (256 features replicated across 128 rows)
    
    auto weights = inputs[20];
    
    for (uint32_t iter = 0; iter < kNumIterations; ++iter) {
        auto data = inputs[iter];
        auto labels = inputs[kNumBatches + iter];
        
        // Forward pass: z = accumulate(data * weights) per row
        auto z = cc->EvalMult(data, weights);
        cc->RelinearizeInPlace(z);
        row_accumulate(cc, z);
        
        // Apply activation
        auto pred = activation(cc, z);
        
        // Error: pred - labels
        auto error = cc->EvalSub(pred, labels);
        
        // Gradient: error * data, then accumulate across rows
        auto grad = cc->EvalMult(error, data);
        cc->RelinearizeInPlace(grad);
        col_accumulate(cc, grad);
        
        // Learning rate: max(10/(i+1), 0.005), gradient multiplier = lr/128
        double lr = std::max(10.0 / (iter + 1), 0.005);
        double grad_mult = lr / static_cast<double>(kRows);
        
        // Update weights: weights -= grad_mult * grad
        auto scaled_grad = cc->EvalMult(grad, grad_mult);
        cc->RelinearizeInPlace(scaled_grad);
        cc->EvalSubInPlace(weights, scaled_grad);
        
        // Bootstrap after iterations 1, 3, 5, 7, 9 (0-indexed)
        if (iter == 1 || iter == 3 || iter == 5 || iter == 7 || iter == 9) {
            weights = cc->EvalBootstrap(weights);
        }
    }
    
    return weights;
}

// Self-register
Register g_logistic_reg("logistic-regression",
    {make_logistic_context, logistic_eval, logistic_gen_keys});

}  // namespace
}  // namespace tee
