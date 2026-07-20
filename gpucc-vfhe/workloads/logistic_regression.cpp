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
#include <chrono>
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

// Client's public key (set by server_main before calling eval). The server
// holds NO secret key; all keys are generated client-side.
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
// Iterations that fit within the multiplicative budget WITHOUT bootstrap.
// Bootstrap is disabled (FIDESlib GPU bootstrap is broken on this H20 install);
// both prototypes run the identical no-bootstrap workload for a fair comparison.
constexpr uint32_t kNumIterations = 2;
constexpr uint32_t kNumBatches = 10;
constexpr uint32_t kNumInputs = 21;

constexpr uint32_t kBootLevelBudgetEnc = 2;
constexpr uint32_t kBootLevelBudgetDec = 2;
constexpr uint32_t kBootDim1First = 16;
constexpr uint32_t kBootDim1Second = 16;
// Active bootstrap slots = kCols (256), matching the FIDESlib logreg reference.
// The trained weights live in the first kCols slots (consolidated via
// row_propagate before bootstrapping), so we only bootstrap kCols slots. This
// keeps the bootstrap-key set and precompute small. The eval loop does the
// SetSlots(kCols) / SetSlots(kBatchSize) dance around EvalBootstrap.
constexpr uint32_t kBootSlots = kCols;
// Bootstrap schedule: bootstrap every 2 iterations (after iters 2,4,6,8,10),
// i.e. on odd 0-based indices 1,3,5,7,9. Matches spec + reference (boot_every2).

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

static std::vector<int32_t> logreg_rotation_indices();  // defined below

// Client-side key generation. Runs with the client's secret key; produces the
// exact rotation-key set and bootstrap keys the GPU server context will later
// resolve by KeyTag. Must stay in sync with logreg_rotation_indices() and
// kBootSlots used in create_gpu_context().
//
// IMPORTANT: EvalRotateKeyGen must come AFTER EvalBootstrapKeyGen. The FIDESlib
// GenBootstrapKeys uses InsertEvalAutomorphismKey which replaces the entire
// automorphism key map for this key tag. If we call EvalRotateKeyGen first, its
// keys get overwritten. Calling it last ensures our rotation keys persist
// (EvalRotateKeyGen merges into the existing map).
void logistic_gen_keys(CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly>& kp) {
    cc->EvalMultKeyGen(kp.secretKey);
    std::vector<uint32_t> lb = {kBootLevelBudgetEnc, kBootLevelBudgetDec};
    std::vector<uint32_t> d1 = {kBootDim1First, kBootDim1Second};
    cc->EvalBootstrapSetup(lb, d1, kBootSlots);
    cc->EvalBootstrapKeyGen(kp.secretKey, kBootSlots);
    // Add logreg rotation keys AFTER bootstrap keygen so they aren't overwritten.
    cc->EvalRotateKeyGen(kp.secretKey, logreg_rotation_indices());
}

// FIDESlib AccumulateSumInPlace uses a base-bStep (=4) BSGS cascade, NOT simple
// power-of-two rotations. The rotation indices it needs are given by these
// generators, which mirror FIDESlib::CKKS::Accumulate / AccumulateCascadeImpl in
// AccumulateBroadcast.cu. The server holds no secret key, so the client must
// pre-generate keys for exactly these indices.
static constexpr int kAccBStep = 4;

// Reduce a raw rotation amount into the signed range (-kBatchSize/2, kBatchSize/2].
// The GPU rotate reduces indices modulo the number of slots; the client must
// generate the rotation key for the SAME reduced index.
static int32_t reduce_rotation(long long idx) {
    long long n = static_cast<long long>(kBatchSize);
    long long r = ((idx % n) + n) % n;          // [0, n)
    if (r > n / 2) r -= n;                        // (-n/2, n/2]
    return static_cast<int32_t>(r);
}

// Mirrors Accumulate(ctxt, bStep, stride, size): s starts at 1.
static void emit_accumulate_indices(std::vector<int32_t>& out, long long stride, int size) {
    int logbStep = 2;  // log2(4)
    for (long long s = 1; s < size; s <<= logbStep) {
        for (long long idx = stride * s; idx < stride * (long long)size && idx < (long long)kAccBStep * stride * s;
             idx += stride * s) {
            out.push_back(reduce_rotation(idx));
        }
    }
}

// Mirrors AccumulateCascadeImpl(ctxt, bStep, stride, size, startFactor).
static void emit_accumulate_cascade_indices(std::vector<int32_t>& out, long long stride,
                                            int size, int startFactor) {
    int logbStep = 2;
    for (long long s = startFactor; s < size; s <<= logbStep) {
        for (long long idx = stride * s; idx < stride * (long long)size && idx < (long long)kAccBStep * stride * s;
             idx += stride * s) {
            out.push_back(reduce_rotation(idx));
        }
    }
}

// The rotation indices required by the logreg algorithm. Must match the FIDESlib
// GPU primitives used in the eval loop AND the bootstrap BSGS indices requested
// by LoadContext -> AddBootstrapKeys (which OpenFHE's EvalBootstrapKeyGen does
// not fully generate for these params). The client generates keys for exactly
// this set; the server resolves them by key tag.
static std::vector<int32_t> logreg_rotation_indices() {
    std::vector<int32_t> rotations;

    // row_accumulate:  AccumulateSumInPlace(ct, kCols, 1)         -> Accumulate(4, 1, kCols)
    emit_accumulate_indices(rotations, 1, static_cast<int>(kCols));
    // row_propagate:   AccumulateSumInPlace(ct, kCols, kBatchSize-1) -> Accumulate(4, kBatchSize-1, kCols)
    emit_accumulate_indices(rotations, static_cast<int>(kBatchSize - 1), static_cast<int>(kCols));
    // col_accumulate:  AccumulateSumInPlace(ct, kRows*kCols, 1, kCols)
    //                  -> AccumulateCascadeImpl(4, 1, kRows*kCols, kCols)
    emit_accumulate_cascade_indices(rotations, 1, static_cast<int>(kRows * kCols),
                                    static_cast<int>(kCols));

    // Bootstrap BSGS baby-step indices requested by FIDESlib GetBootstrapIndexes
    // for kCols=256 slots, levelBudget {2,2}, which OpenFHE's EvalBootstrapKeyGen
    // does not itself generate. Determined empirically against AddBootstrapKeys.
    for (int i : {3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 257}) {
        rotations.push_back(i);
    }

    // De-duplicate.
    std::sort(rotations.begin(), rotations.end());
    rotations.erase(std::unique(rotations.begin(), rotations.end()), rotations.end());
    return rotations;
}

// Create the FIDESlib GPU context bound to the CLIENT's keypair.
//
// The client generates ALL keys (mult, rotation, bootstrap) with its own secret
// key and sends the public key + serialized eval/automorphism keys to the server.
// The server never holds a secret key. FIDESlib's LoadContext reads the client's
// relinearization/rotation/bootstrap keys from the (static, global) OpenFHE key
// maps keyed by the client public key's KeyTag, so incoming client ciphertexts
// (which carry that same KeyTag) resolve correctly during GPU EvalMult/rotations.
static fideslib::CryptoContext<fideslib::DCRTPoly> create_gpu_context(
    CryptoContext<DCRTPoly> /*server_cc*/) {

    if (!g_client_pk) {
        throw std::runtime_error(
            "create_gpu_context: client public key not set (call set_client_public_key first)");
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

    // The client's public key carries its own (deserialized) OpenFHE crypto
    // context. The client's eval-mult / automorphism (rotation + bootstrap +
    // conjugation) keys were already deserialized into the global key maps under
    // this key's tag by server_main. LoadContext resolves them from there.
    auto client_cc = g_client_pk->GetCryptoContext();

    // CRITICAL: bind the FIDESlib context's internal OpenFHE context to the
    // CLIENT's context. The incoming ciphertexts were encrypted under the client
    // context; if we leave gpu_cc->cpu as the fresh GenCryptoContext context, its
    // FLEXIBLEAUTO scaling factors differ subtly and plaintext masks encoded via
    // gpu_cc->MakeCKKSPackedPlaintext won't align with the ciphertexts (activation
    // then produces garbage / near-zero weights). LoadContext also reads params
    // and key maps from gpu_cc->cpu, so this keeps everything on one context.
    gpu_cc->cpu = std::make_any<lbcrypto::CryptoContext<lbcrypto::DCRTPoly>>(client_cc);

    // Build the bootstrap precomputation tables on the CLIENT's context (this is
    // the context LoadContext -> AddBootstrapPrecomputation reads from). This
    // needs NO secret key: EvalBootstrapSetup only computes public plaintext
    // tables. The matching bootstrap KEYS were generated client-side and arrive
    // via the serialized automorphism-key blob.
    std::vector<uint32_t> lb = {kBootLevelBudgetEnc, kBootLevelBudgetDec};
    std::vector<uint32_t> d1 = {kBootDim1First, kBootDim1Second};
    client_cc->EvalBootstrapSetup(lb, d1, kBootSlots);

    // Tell the GPU context which rotation keys and bootstrap slots to upload.
    // These are plain index lists (no secret material); LoadContext then pulls
    // the actual key-switching keys from the client's key maps by KeyTag.
    gpu_cc->rotation_indexes = logreg_rotation_indices();
    gpu_cc->slots_bootstrap = {kBootSlots};

    // Wrap the client's lbcrypto public key into a FIDESlib public key handle.
    fideslib::PublicKey<fideslib::DCRTPoly> client_pk_gpu =
        std::make_shared<fideslib::PublicKeyImpl<fideslib::DCRTPoly>>();
    client_pk_gpu->pimpl = std::make_any<lbcrypto::PublicKey<lbcrypto::DCRTPoly>>(g_client_pk);

    std::cerr << "[gpu] Loading context to GPU (client keypair)..." << std::endl;
    gpu_cc->LoadContext(client_pk_gpu);
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

// Extract result from FIDESlib GPU back to OpenFHE. Must sync the GPU-computed
// data back into the CPU ciphertext (store + GetOpenFHECipherText); a plain
// EnsureLazyCPUCopy would return the STALE input ciphertext, not the result.
//
// The GPU result can be at a higher level (more RNS limbs) than the stale input
// ciphertext used as its CPU shadow — e.g. after a bootstrap. If we synced into
// that stale template, GetOpenFHECipherText would clamp to the template's limb
// count and the scaling-factor / level metadata would no longer match the data,
// so decryption fails ("approximation error too high"). To avoid this we install
// a FRESH top-level CPU template (a public-key encryption of zeros on the client
// context) before syncing; GetOpenFHECipherText then resizes it down to exactly
// the GPU result's limb count with consistent metadata. Needs only the public key.
static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> gpu_to_openfhe(
    fideslib::CryptoContext<fideslib::DCRTPoly> gpu_cc,
    fideslib::Ciphertext<fideslib::DCRTPoly>& gpu_ct) {
    if (g_client_pk) {
        auto client_cc = g_client_pk->GetCryptoContext();
        std::vector<double> zeros(kCols, 0.0);
        auto tmpl_pt = client_cc->MakeCKKSPackedPlaintext(zeros, 1, 0, nullptr, kBatchSize);
        auto tmpl_ct = client_cc->Encrypt(g_client_pk, tmpl_pt);  // top level, full limbs
        gpu_ct->cpu = std::make_any<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>(tmpl_ct);
        gpu_ct->need_lazy_copy = false;
    }
    gpu_cc->SyncCiphertextToCPU(gpu_ct);
    return std::any_cast<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>(gpu_ct->cpu);
}

// Row accumulate: sum the kCols values within each row into slot r*kCols.
static void row_accumulate(fideslib::CryptoContext<fideslib::DCRTPoly> gpu_cc,
                           fideslib::Ciphertext<fideslib::DCRTPoly>& ct) {
    gpu_cc->AccumulateSumInPlace(ct, kCols, 1);
}

// Row propagate: broadcast slot r*kCols back across the row (negative dir).
static void row_propagate(fideslib::CryptoContext<fideslib::DCRTPoly> gpu_cc,
                          fideslib::Ciphertext<fideslib::DCRTPoly>& ct) {
    gpu_cc->AccumulateSumInPlace(ct, static_cast<int>(kCols),
                                 static_cast<int>(kBatchSize - 1));
}

// Column accumulate: sum across the kRows rows (stride kCols).
static void col_accumulate(fideslib::CryptoContext<fideslib::DCRTPoly> gpu_cc,
                           fideslib::Ciphertext<fideslib::DCRTPoly>& ct) {
    gpu_cc->AccumulateSumInPlace(ct, kRows * kCols, 1, kCols);
}

// Activation p(x) = 0.5 + 0.15*x - 0.0015*x^3, applied with masks so that only
// slot 0 of each row carries the result (matching the FIDESlib reference).
// mask_0 has 0.5 in slot 0, mask_1 has 0.15, mask_3 has -0.0015.
static void activation_gpu(fideslib::CryptoContext<fideslib::DCRTPoly> gpu_cc,
                           fideslib::Ciphertext<fideslib::DCRTPoly>& ct,
                           fideslib::Plaintext mask_0,
                           fideslib::Plaintext mask_1,
                           fideslib::Plaintext mask_3) {
    auto ct3 = gpu_cc->EvalSquare(ct);        // x^2
    auto aux = gpu_cc->EvalMult(ct, mask_3);  // -0.0015*x (slot 0)
    ct3 = gpu_cc->EvalMult(ct3, aux);         // -0.0015*x^3
    gpu_cc->EvalMultInPlace(ct, mask_1);      // 0.15*x
    gpu_cc->EvalAddInPlace(ct, ct3);          // 0.15*x - 0.0015*x^3
    gpu_cc->EvalAddInPlace(ct, mask_0);       // + 0.5
}

Ciphertext<DCRTPoly> logistic_eval(
    CryptoContext<DCRTPoly> cc,
    const std::vector<Ciphertext<DCRTPoly>>& inputs) {

    if (inputs.size() != kNumInputs) {
        throw std::runtime_error("logistic-regression requires " +
            std::to_string(kNumInputs) + " inputs, got " +
            std::to_string(inputs.size()));
    }

    using clk = std::chrono::high_resolution_clock;
    auto t_setup0 = clk::now();
    std::cerr << "[gpu] Creating FIDESlib GPU context..." << std::endl;
    auto gpu_cc = create_gpu_context(cc);

    // Build activation masks (kCols slots; only slot 0 nonzero).
    std::vector<double> m0(kCols, 0.0), m1(kCols, 0.0), m3(kCols, 0.0);
    m0[0] = 0.5; m1[0] = 0.15; m3[0] = -0.0015;
    auto mask_0 = gpu_cc->MakeCKKSPackedPlaintext(m0, 1, 0, nullptr, kCols);
    auto mask_1 = gpu_cc->MakeCKKSPackedPlaintext(m1, 1, 0, nullptr, kCols);
    auto mask_3 = gpu_cc->MakeCKKSPackedPlaintext(m3, 1, 0, nullptr, kCols);
    auto t_setup1 = clk::now();

    std::cerr << "[gpu] Converting " << inputs.size() << " inputs to GPU..." << std::endl;
    std::vector<fideslib::Ciphertext<fideslib::DCRTPoly>> gpu_inputs;
    gpu_inputs.reserve(kNumInputs);
    for (const auto& ct : inputs) {
        gpu_inputs.push_back(wrap_openfhe_to_gpu(gpu_cc, ct));
    }
    gpu_cc->Synchronize();
    auto t_upload1 = clk::now();

    auto weights = gpu_inputs[20];

    std::cerr << "[gpu] Starting training loop (" << kNumIterations
              << " iterations, no bootstrap)..." << std::endl;
    auto t_compute0 = clk::now();

    for (uint32_t iter = 0; iter < kNumIterations; ++iter) {
        // Fresh copies of the batch inputs (data is mutated in-place below).
        auto data = gpu_inputs[iter]->Clone();
        const auto& labels = gpu_inputs[kNumBatches + iter];

        // Forward: z = activation(rowsum(data * weights)) - labels
        auto ct = gpu_cc->EvalMult(data, weights);
        row_accumulate(gpu_cc, ct);
        activation_gpu(gpu_cc, ct, mask_0, mask_1, mask_3);
        gpu_cc->EvalSubInPlace(ct, labels);
        row_propagate(gpu_cc, ct);

        // Gradient: (error) * (scaled data), summed across rows.
        double lr = std::max(10.0 / (iter + 1), 0.005);
        double scale = lr / static_cast<double>(kRows);
        gpu_cc->EvalMultInPlace(data, scale);
        ct = gpu_cc->EvalMult(ct, data);
        col_accumulate(gpu_cc, ct);

        // weights -= gradient
        gpu_cc->EvalSubInPlace(weights, ct);

        // NOTE: bootstrap intentionally omitted (see kNumIterations comment).
    }

    gpu_cc->Synchronize();
    auto t_compute1 = clk::now();
    std::cerr << "[gpu] Training complete, extracting result..." << std::endl;

    auto ms = [](auto a, auto b) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
    };
    std::cerr << "[gpu][timing] context+LoadContext=" << ms(t_setup0, t_setup1) << "ms"
              << " input_upload=" << ms(t_setup1, t_upload1) << "ms"
              << " compute(" << kNumIterations << " iters)=" << ms(t_compute0, t_compute1) << "ms"
              << std::endl;

    return gpu_to_openfhe(gpu_cc, weights);
}

Register g_logistic_reg("logistic-regression",
    {make_logistic_context, logistic_eval, logistic_gen_keys});

}  // namespace
}  // namespace tee
