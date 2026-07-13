#include "common/baseline_params.h"

using namespace lbcrypto;

CryptoContext<DCRTPoly> make_baseline_bgvrns_context() {
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(4);
    params.SetPlaintextModulus(65537);
    params.SetBatchSize(4096);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetRingDim(8192);
    // zkOpenFHE's LibsnarkProofSystem::RelinearizeConstraint / KeySwitchConstraint
    // internally call KeySwitchBV().EvalKeySwitchPrecomputeCore, which requires
    // BV key switching. HYBRID key switching segfaults inside the proofsystem at
    // depth>=2 (the KeySwitchBV call fails on a HYBRID-shaped eval key).
    // BV is also what Prototype E uses, keeping the key-switch technique aligned
    // across B and E.
    params.SetKeySwitchTechnique(BV);
    // Do NOT set FirstModSize explicitly. An unbalanced modulus chain (60-bit
    // first modulus + ~17-bit scaling modulus for plaintextModulus=65537)
    // triggers `assert(oldModulusByHalf > diff)` inside
    // LibsnarkProofSystem::SwitchModulusConstraint during Relinearize/KeySwitch
    // constraint generation. The library default firstModSize avoids this.
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    return cc;
}