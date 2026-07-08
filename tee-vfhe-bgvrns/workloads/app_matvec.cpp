// BGV app_matvec workload: y = A * x mod 65537
// A is a 64x64 dense integer matrix, x is a length-64 vector.
// One input ciphertext encoding x. Uses the diagonal method.
// BGV params: multiplicativeDepth=2, plaintextModulus=65537, batchSize=64,
// FIXEDMANUAL, BV key switching.
// Uses power-of-two rotation keys {±1,±2,±4,±8,±16,±32} with composed
// rotations to keep eval-key memory footprint under ~184 MB (vs ~2 GB for
// all ±1..±63). Self-registers into the global WorkloadRegistry at static init
// time.

#include "server/workload_registry.h"

#include <random>
#include <stdexcept>
#include <vector>

#include "openfhe.h"

namespace {

using namespace lbcrypto;

constexpr size_t kN = 64;
constexpr int64_t kModulus = 65537;

// Fixed deterministic 64x64 integer matrix A (seed 42, uniform [0, 65536]).
std::vector<std::vector<int64_t>> make_app_matrix() {
    std::mt19937 gen(42);
    std::uniform_int_distribution<int64_t> dist(0, kModulus - 1);
    std::vector<std::vector<int64_t>> A(kN, std::vector<int64_t>(kN));
    for (size_t i = 0; i < kN; ++i)
        for (size_t j = 0; j < kN; ++j) A[i][j] = dist(gen);
    return A;
}

// Compose a rotation by idx using only power-of-two rotation keys.
// Decomposes |idx| into binary and applies the corresponding signed
// EvalRotate for each set bit.  Example: idx=13 → +1, +4, +8.
tee::CT compose_rotate(tee::CC cc, const tee::CT& ct, int32_t idx) {
    if (idx == 0) return ct;
    tee::CT result = ct;
    uint32_t abs_idx = (idx > 0) ? static_cast<uint32_t>(idx)
                                  : static_cast<uint32_t>(-idx);
    int32_t sign = (idx > 0) ? 1 : -1;
    for (int bit = 0; bit < 6; ++bit) {
        if (abs_idx & (1u << bit)) {
            result = cc->EvalRotate(result, sign * (1 << bit));
        }
    }
    return result;
}

tee::CC make_app_matvec_context() {
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(2);
    params.SetPlaintextModulus(kModulus);
    params.SetBatchSize(kN);
    params.SetSecurityLevel(HEStd_128_classic);
    params.SetKeySwitchTechnique(BV);
    params.SetDigitSize(4);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetFirstModSize(60);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);  // Required for EvalRotate (automorphism keys)
    return cc;
}

tee::CT app_matvec_eval(tee::CC cc, const std::vector<tee::CT>& inputs) {
    if (inputs.size() != 1) {
        throw std::runtime_error(
            "app_matvec workload requires exactly 1 input ciphertext");
    }
    auto A = make_app_matrix();
    const auto& x = inputs[0];

    // Diagonal method: result = sum_{d=0}^{N-1} diag_d \odot rot(x, d)
    // where diag_d[i] = A[i][(i+d) % N].
    //
    // EvalRotate wraps at the full ring dimension (8192 slots), not batchSize (64).
    // For each d in 1..63, we split the rotation into two parts with masks:
    //   low part  (slots 0..63-d): EvalRotate(x, d) is correct
    //   high part (slots 64-d..63): EvalRotate(x, d-64) gives the wrapped values
    // Rotations are composed from power-of-two keys via compose_rotate().
    tee::CT acc;
    for (size_t d = 0; d < kN; ++d) {
        std::vector<int64_t> diag(kN);
        for (size_t i = 0; i < kN; ++i) diag[i] = A[i][(i + d) % kN];
        auto ptxt_diag = cc->MakePackedPlaintext(diag);

        tee::CT ct_rot;
        if (d == 0) {
            ct_rot = x;
        } else {
            int32_t dd = static_cast<int32_t>(d);
            // low_mask:  1 for slots 0..kN-d-1, 0 elsewhere
            // high_mask: 1 for slots kN-d..kN-1, 0 elsewhere
            std::vector<int64_t> low_mask_vec(kN, 0);
            std::vector<int64_t> high_mask_vec(kN, 0);
            for (size_t i = 0; i < kN - d; ++i) low_mask_vec[i] = 1;
            for (size_t i = kN - d; i < kN; ++i) high_mask_vec[i] = 1;

            auto low_mask = cc->MakePackedPlaintext(low_mask_vec);
            auto high_mask = cc->MakePackedPlaintext(high_mask_vec);

            auto rot_low = compose_rotate(cc, x, dd);
            auto rot_high = compose_rotate(cc, x, dd - static_cast<int32_t>(kN));

            auto masked_low = cc->EvalMult(rot_low, low_mask);
            auto masked_high = cc->EvalMult(rot_high, high_mask);

            ct_rot = cc->EvalAdd(masked_low, masked_high);
        }

        auto ct_term = cc->EvalMult(ct_rot, ptxt_diag);
        if (d == 0) {
            // d=0 term is at level 1 (one ct-pt mult); d>0 terms are at level 2
            // (mask mult + diag mult). Level-up d=0 with a dummy all-ones mult
            // so all terms are at the same level for EvalAdd.
            std::vector<int64_t> ones_vec(kN, 1);
            auto ones = cc->MakePackedPlaintext(ones_vec);
            ct_term = cc->EvalMult(ct_term, ones);
            acc = ct_term;
        } else {
            acc = cc->EvalAdd(acc, ct_term);
        }
    }
    // BGV does not use Rescale (that is CKKS). All terms are at depth 2
    // (mask EvalMult at depth 1, diagonal EvalMult at depth 2).
    // multiplicativeDepth=2 provides sufficient modulus chain headroom.
    return acc;
}

void app_matvec_gen_keys(tee::CC cc,
                          const lbcrypto::KeyPair<lbcrypto::DCRTPoly>& kp) {
    // Power-of-two rotation keys only: ±1, ±2, ±4, ±8, ±16, ±32.
    // Composed rotations via compose_rotate() handle all 1..63 indices.
    // Total key blob ~184 MB vs ~2 GB for all ±1..±63.
    std::vector<int32_t> indices = {
        1, -1, 2, -2, 4, -4, 8, -8, 16, -16, 32, -32
    };
    cc->EvalRotateKeyGen(kp.secretKey, indices);
}

// Self-register at static initialization time.
[[maybe_unused]] tee::Register g_app_matvec_reg(
    "app_matvec",
    tee::Workload{make_app_matvec_context, app_matvec_eval,
                   app_matvec_gen_keys});

}  // namespace
