#include "common/baseline_params.h"

using namespace lbcrypto;

CryptoContext<DCRTPoly> make_baseline_bgvrns_context() {
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(4);
    params.SetPlaintextModulus(65537);
    params.SetBatchSize(4096);
    params.SetScalingTechnique(FIXEDMANUAL);
    // Use HEStd_NotSet because ringDim=8192 does not comply with the 128-bit
    // classical security recommendation (which requires ringDim≥16384 for
    // this depth). We explicitly set ringDim=8192 for a faster microbenchmark
    // and accept the non-standard security level; the server and client must
    // agree on this parameter or OpenFHE rejects the parameter set.
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetRingDim(8192);
    params.SetKeySwitchTechnique(BV);
    params.SetDigitSize(4);
    params.SetFirstModSize(60);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    return cc;
}