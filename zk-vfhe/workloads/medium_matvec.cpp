// BGV medium_matvec workload: y = W * x mod 65537
// 64x64 dense integer matrix-vector multiplication using the diagonal method.
// One input ciphertext encodes x; the matrix W is deterministic and embedded
// in the eval function (model weights live inside the TEE).
// Uses the shared baseline context (batchSize=4096, ringDim=8192, depth=3).
// Uses power-of-two rotation keys {±1,±2,±4,±8,±16,±32} with composed
// rotations to keep eval-key memory footprint under ~184 MB (vs ~2 GB for
// all ±1..±63). Self-registers into the global WorkloadRegistry at static init
// time.

#include "common/baseline_params.h"
#include "server/workload_registry.h"
#include "openfhe.h"

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

using namespace lbcrypto;

constexpr int kDim = 64;
constexpr uint64_t kModulus = 65537;

// Deterministic weight matrix: W[i][j] = (i * kDim + j + 1) % kModulus.
// Values are in [1, 4096], well within the 16-bit plaintext modulus.
// This formula is replicated by the standalone test to compute expected output.
std::vector<std::vector<int64_t>> make_weight_matrix() {
    std::vector<std::vector<int64_t>> W(kDim, std::vector<int64_t>(kDim));
    for (int i = 0; i < kDim; ++i) {
        for (int j = 0; j < kDim; ++j) {
            W[i][j] = static_cast<int64_t>(
                (static_cast<uint64_t>(i) * kDim + static_cast<uint64_t>(j) + 1) %
                kModulus);
        }
    }
    return W;
}

// Extract the d-th diagonal: diag_d[i] = W[i][(i + d) % kDim].
std::vector<int64_t> extract_diagonal(
    const std::vector<std::vector<int64_t>>& W, int d) {
    std::vector<int64_t> diag(kDim);
    for (int i = 0; i < kDim; ++i) {
        diag[i] = W[i][(i + d) % kDim];
    }
    return diag;
}

// Compose a rotation by idx using only power-of-two rotation keys.
// Decomposes |idx| into binary and applies the corresponding signed
// EvalRotate for each set bit.  Example: idx=13 → +1, +4, +8.
zk::CT compose_rotate(zk::CC cc, const zk::CT& ct, int32_t idx) {
    if (idx == 0) return ct;
    zk::CT result = ct;
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

void medium_matvec_gen_keys(zk::CC cc,
                            const KeyPair<DCRTPoly>& kp) {
    // Power-of-two rotation keys only: ±1, ±2, ±4, ±8, ±16, ±32.
    // Composed rotations via compose_rotate() handle all 1..63 indices.
    // Total key blob ~184 MB vs ~2 GB for all ±1..±63.
    std::vector<int32_t> rot_indices = {
        1, -1, 2, -2, 4, -4, 8, -8, 16, -16, 32, -32
    };
    cc->EvalRotateKeyGen(kp.secretKey, rot_indices);
}

// Diagonal matvec: y = sum_{d=0}^{63} diag_d * rot(x, d)
//   where diag_d[i] = W[i][(i+d) % 64]
//   and   rot(x, d)[i] = x[(i+d) % 64]   (left cyclic rotation within batch)
//
// EvalRotate wraps at the full ring dimension (8192 slots), not batchSize (4096).
// For each d in 1..63, we split the rotation into two parts:
//   low part  (slots 0..63-d): EvalRotate(x, d) is correct here
//   high part (slots 64-d..63): EvalRotate(x, d-64) gives the wrapped values
// We combine them with plaintext masks, then multiply by the diagonal plaintext.
// Rotations are composed from power-of-two keys via compose_rotate().
zk::CT medium_matvec_eval(zk::CC cc, const std::vector<zk::CT>& inputs) {
    if (inputs.size() != 1) {
        throw std::runtime_error("medium_matvec requires exactly 1 input ciphertext");
    }
    const zk::CT& x = inputs[0];

    auto W = make_weight_matrix();
    zk::CT result;

    for (int d = 0; d < kDim; ++d) {
        auto diag = extract_diagonal(W, d);
        auto pt = cc->MakePackedPlaintext(diag);

        zk::CT rotated;
        if (d == 0) {
            rotated = x;  // identity rotation
        } else {
            // low_mask:  1 for slots 0..63-d, 0 elsewhere
            // high_mask: 1 for slots 64-d..63, 0 elsewhere
            std::vector<int64_t> low_mask_vec(kDim, 0);
            std::vector<int64_t> high_mask_vec(kDim, 0);
            for (int i = 0; i < kDim - d; ++i) low_mask_vec[i] = 1;
            for (int i = kDim - d; i < kDim; ++i) high_mask_vec[i] = 1;

            auto low_mask = cc->MakePackedPlaintext(low_mask_vec);
            auto high_mask = cc->MakePackedPlaintext(high_mask_vec);

            auto rot_low = compose_rotate(cc, x, d);
            auto rot_high = compose_rotate(cc, x, d - static_cast<int>(kDim));

            auto masked_low = cc->EvalMult(rot_low, low_mask);
            auto masked_high = cc->EvalMult(rot_high, high_mask);

            rotated = cc->EvalAdd(masked_low, masked_high);
        }

        zk::CT term = cc->EvalMult(rotated, pt);
        if (d == 0) {
            // d=0 term is at level 1 (one ct-pt mult); d>0 terms are at level 2
            // (mask mult + diag mult). Level-up d=0 with a dummy all-ones mult
            // so all terms are at the same level for EvalAdd.
            std::vector<int64_t> ones_vec(kDim, 1);
            auto ones = cc->MakePackedPlaintext(ones_vec);
            term = cc->EvalMult(term, ones);
            result = term;
        } else {
            result = cc->EvalAdd(result, term);
        }
    }

    return result;
}

// Self-register at static initialization time.
// Uses the shared baseline context (batchSize=4096, ringDim=8192, depth=3).
[[maybe_unused]] zk::Register g_medium_reg("medium",
    zk::Workload{make_baseline_bgvrns_context, medium_matvec_eval,
                  medium_matvec_gen_keys});

}  // namespace
