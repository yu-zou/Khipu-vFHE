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
// Iterations that fit within the multiplicative budget WITHOUT bootstrap.
// (Bootstrap is disabled in this build: the FIDESlib GPU bootstrap is broken on
// this H20 install, so for a fair A-vs-C comparison both prototypes run the same
// no-bootstrap workload. Each iteration consumes ~4 levels; 2 fit in depth 22.)
constexpr uint32_t kNumIterations = 2;
constexpr uint32_t kNumBatches = 10;
constexpr uint32_t kNumInputs = 21;  // 10 data + 10 labels + 1 weights

// Bootstrap parameters (bootstrap disabled for the no-bootstrap benchmark; kept
// for key-generation parity with Prototype C).
constexpr uint32_t kBootLevelBudgetEnc = 2;
constexpr uint32_t kBootLevelBudgetDec = 2;
constexpr uint32_t kBootDim1First = 16;
constexpr uint32_t kBootDim1Second = 16;
constexpr uint32_t kBootSlots = kCols;  // 256, matches Prototype C

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

    // Rotation keys (power-of-two BSGS on CPU, matching this workload's
    // row_accumulate / row_propagate / col_accumulate):
    //   row_accumulate: +1,+2,...,+kCols/2
    //   row_propagate:  -1,-2,...,-kCols/2
    //   col_accumulate: +kCols,+2kCols,... up to +kRows*kCols/2
    std::vector<int32_t> rotations;
    for (uint32_t j = 1; j < kCols; j <<= 1) {
        rotations.push_back(static_cast<int32_t>(j));
        rotations.push_back(-static_cast<int32_t>(j));
    }
    for (uint32_t j = 1; j < kRows; j <<= 1) {
        rotations.push_back(static_cast<int32_t>(j * kCols));
    }
    cc->EvalRotateKeyGen(kp.secretKey, rotations);

    // Bootstrap keys (kCols slots), for parity with Prototype C's key set even
    // though bootstrap is not exercised in the no-bootstrap benchmark.
    std::vector<uint32_t> levelBudget = {kBootLevelBudgetEnc, kBootLevelBudgetDec};
    std::vector<uint32_t> dim1 = {kBootDim1First, kBootDim1Second};
    cc->EvalBootstrapSetup(levelBudget, dim1, kBootSlots);
    cc->EvalBootstrapKeyGen(kp.secretKey, kBootSlots);
}

// Row-accumulate: sum the kCols values within each row into slot r*kCols.
void row_accumulate(CC cc, Ciphertext<DCRTPoly>& ct) {
    for (uint32_t j = 1; j < kCols; j <<= 1) {
        auto rotated = cc->EvalRotate(ct, static_cast<int32_t>(j));
        cc->EvalAddInPlace(ct, rotated);
    }
}

// Row-propagate: broadcast slot r*kCols back across the row (negative rotations).
void row_propagate(CC cc, Ciphertext<DCRTPoly>& ct) {
    for (uint32_t j = 1; j < kCols; j <<= 1) {
        auto rotated = cc->EvalRotate(ct, -static_cast<int32_t>(j));
        cc->EvalAddInPlace(ct, rotated);
    }
}

// Column-accumulate: sum across kRows rows (stride kCols). After this each slot
// holds the sum of its column across all rows (replicated across rows).
void col_accumulate(CC cc, Ciphertext<DCRTPoly>& ct) {
    for (uint32_t j = 1; j < kRows; j <<= 1) {
        auto rotated = cc->EvalRotate(ct, static_cast<int32_t>(j * kCols));
        cc->EvalAddInPlace(ct, rotated);
    }
}

// Activation p(x) = 0.5 + 0.15*x - 0.0015*x^3 applied with masks so only slot 0
// of each row carries the result (identical to Prototype C's activation_gpu).
Ciphertext<DCRTPoly> activation(CC cc, Ciphertext<DCRTPoly> ct,
                                Plaintext mask_0, Plaintext mask_1,
                                Plaintext mask_3) {
    auto ct3 = cc->EvalSquare(ct);        // x^2
    auto aux = cc->EvalMult(ct, mask_3);  // -0.0015*x (slot 0)
    ct3 = cc->EvalMult(ct3, aux);         // -0.0015*x^3
    ct = cc->EvalMult(ct, mask_1);        // 0.15*x
    cc->EvalAddInPlace(ct, ct3);          // 0.15*x - 0.0015*x^3
    cc->EvalAddInPlace(ct, mask_0);       // + 0.5
    return ct;
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

    // Activation masks (kCols slots; only slot 0 nonzero, replicated per row).
    std::vector<double> m0(kCols, 0.0), m1(kCols, 0.0), m3(kCols, 0.0);
    m0[0] = 0.5; m1[0] = 0.15; m3[0] = -0.0015;
    auto mask_0 = cc->MakeCKKSPackedPlaintext(m0, 1, 0, nullptr, kCols);
    auto mask_1 = cc->MakeCKKSPackedPlaintext(m1, 1, 0, nullptr, kCols);
    auto mask_3 = cc->MakeCKKSPackedPlaintext(m3, 1, 0, nullptr, kCols);

    auto weights = inputs[20];

    for (uint32_t iter = 0; iter < kNumIterations; ++iter) {
        auto data = inputs[iter];
        auto labels = inputs[kNumBatches + iter];

        // Forward: z = activation(rowsum(data * weights)) - labels
        auto ct = cc->EvalMult(data, weights);
        cc->RelinearizeInPlace(ct);
        row_accumulate(cc, ct);
        ct = activation(cc, ct, mask_0, mask_1, mask_3);
        cc->EvalSubInPlace(ct, labels);
        row_propagate(cc, ct);

        // Gradient: (error) * (scaled data), summed across rows.
        double lr = std::max(10.0 / (iter + 1), 0.005);
        double scale = lr / static_cast<double>(kRows);
        auto data_scaled = cc->EvalMult(data, scale);
        ct = cc->EvalMult(ct, data_scaled);
        cc->RelinearizeInPlace(ct);
        col_accumulate(cc, ct);

        // weights -= gradient
        cc->EvalSubInPlace(weights, ct);

        // NOTE: bootstrap intentionally omitted (see kNumIterations comment).
    }

    return weights;
}

// Self-register
Register g_logistic_reg("logistic-regression",
    {make_logistic_context, logistic_eval, logistic_gen_keys});

}  // namespace
}  // namespace tee
