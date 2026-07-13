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