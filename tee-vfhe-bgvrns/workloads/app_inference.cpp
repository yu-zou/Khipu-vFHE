// BGV app_inference workload: 2-layer neural network inference mod 65537.
// layer1: z1 = W1 * x + b1  (32 -> 16), activation: z2 = z1^2
// layer2: y  = W2 * z2 + b2  (16 -> 10)
// One input ciphertext encoding x (32 values, padded to batch 64).
// BGV params: multiplicativeDepth=2, plaintextModulus=65537, batchSize=64,
// FIXEDMANUAL, BV key switching.
// Uses power-of-two rotation keys {±1,±2,±4,±8,±16} with composed rotations.
// Self-registers into the global WorkloadRegistry at static init time.

#include "server/workload_registry.h"

#include <random>
#include <stdexcept>
#include <vector>

#include "openfhe.h"

namespace {

using namespace lbcrypto;

constexpr int64_t kMod = 65537;

std::vector<std::vector<int64_t>> make_W1() {
    std::mt19937 g(100); std::uniform_int_distribution<int64_t> d(0,kMod-1);
    std::vector<std::vector<int64_t>> W(16, std::vector<int64_t>(32));
    for (int i=0;i<16;++i) for (int j=0;j<32;++j) W[i][j]=d(g);
    return W;
}
std::vector<int64_t> make_b1() {
    std::mt19937 g(200); std::uniform_int_distribution<int64_t> d(0,kMod-1);
    std::vector<int64_t> b(16); for (int i=0;i<16;++i) b[i]=d(g); return b;
}
std::vector<std::vector<int64_t>> make_W2() {
    std::mt19937 g(300); std::uniform_int_distribution<int64_t> d(0,kMod-1);
    std::vector<std::vector<int64_t>> W(10, std::vector<int64_t>(16));
    for (int i=0;i<10;++i) for (int j=0;j<16;++j) W[i][j]=d(g);
    return W;
}
std::vector<int64_t> make_b2() {
    std::mt19937 g(400); std::uniform_int_distribution<int64_t> d(0,kMod-1);
    std::vector<int64_t> b(10); for (int i=0;i<10;++i) b[i]=d(g); return b;
}

tee::CT compose_rotate(tee::CC cc, const tee::CT& ct, int32_t idx) {
    if (idx==0) return ct;
    tee::CT r=ct; uint32_t a=idx>0?idx:-idx; int s=idx>0?1:-1;
    for (int b=0;b<5;++b) if (a&(1u<<b)) r=cc->EvalRotate(r,s*(1<<b));
    return r;
}

tee::CT masked_rot(tee::CC cc, const tee::CT& ct, int dim, int d) {
    if (d==0) return ct;
    std::vector<int64_t> lm(dim,0), hm(dim,0);
    for (int i=0;i<dim-d;++i) lm[i]=1;
    for (int i=dim-d;i<dim;++i) hm[i]=1;
    auto low = cc->EvalMult(compose_rotate(cc,ct, d),     cc->MakePackedPlaintext(lm));
    auto high= cc->EvalMult(compose_rotate(cc,ct,d-dim), cc->MakePackedPlaintext(hm));
    return cc->EvalAdd(low, high);
}

tee::CT diag_matvec(tee::CC cc, const tee::CT& x,
                    const std::vector<std::vector<int64_t>>& M,
                    int in_dim, int out_dim) {
    tee::CT acc;
    std::vector<int64_t> ones(in_dim,1);
    auto pt_ones = cc->MakePackedPlaintext(ones);
    for (int d=0; d<in_dim; ++d) {
        std::vector<int64_t> diag(in_dim,0);
        for (int i=0;i<out_dim;++i) diag[i] = M[i][(i+d)%in_dim];
        auto term = cc->EvalMult(masked_rot(cc,x,in_dim,d), cc->MakePackedPlaintext(diag));
        if (d==0) term = cc->EvalMult(term, pt_ones);
        if (d==0) acc = term; else acc = cc->EvalAdd(acc, term);
    }
    return acc;
}

tee::CC make_app_inference_context() {
    CCParams<CryptoContextBGVRNS> p;
    p.SetMultiplicativeDepth(2); p.SetPlaintextModulus(kMod); p.SetBatchSize(64);
    p.SetSecurityLevel(HEStd_128_classic); p.SetKeySwitchTechnique(BV);
    p.SetDigitSize(4); p.SetScalingTechnique(FIXEDMANUAL); p.SetFirstModSize(60);
    auto cc=GenCryptoContext(p);
    cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE); cc->Enable(ADVANCEDSHE);
    return cc;
}

void app_inference_gen_keys(tee::CC cc, const KeyPair<DCRTPoly>& kp) {
    std::vector<int32_t> idx = {1,-1,2,-2,4,-4,8,-8,16,-16};
    cc->EvalRotateKeyGen(kp.secretKey, idx);
}

tee::CT app_inference_eval(tee::CC cc, const std::vector<tee::CT>& inputs) {
    if (inputs.size()!=1) throw std::runtime_error("app_inference needs 1 input");
    auto W1=make_W1(), W2=make_W2();
    auto b1=make_b1(), b2=make_b2();
    // layer1: 32 -> 16
    auto z1 = diag_matvec(cc, inputs[0], W1, 32, 16);
    auto pt_b1 = cc->MakePackedPlaintext(std::vector<int64_t>(b1.begin(), b1.end()));
    z1 = cc->EvalAdd(z1, pt_b1);
    // activation
    auto z2 = cc->EvalMult(z1, z1);
    z2 = cc->ModReduce(z2);
    // layer2: 16 -> 10
    auto y = diag_matvec(cc, z2, W2, 16, 10);
    auto pt_b2 = cc->MakePackedPlaintext(std::vector<int64_t>(b2.begin(), b2.end()));
    y = cc->EvalAdd(y, pt_b2);
    return y;
}

[[maybe_unused]] tee::Register reg("app_inference",
    tee::Workload{make_app_inference_context, app_inference_eval, app_inference_gen_keys});
}
