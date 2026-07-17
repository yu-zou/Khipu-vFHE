#pragma once

#include <string>

#include "openfhe/pke/openfhe.h"
#include "openfhe/pke/ciphertext-ser.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/ckksrns/ckksrns-ser.h"

namespace tee {

// OpenFHE element type used throughout the project.
using Element = lbcrypto::DCRTPoly;

// Binary serialization helpers for OpenFHE objects.
// Each returns the serialized bytes as a std::string (binary, not JSON).

// Ciphertext
std::string serialize_ciphertext(
    const lbcrypto::Ciphertext<Element>& ct);
lbcrypto::Ciphertext<Element> deserialize_ciphertext(const std::string& data);

// PublicKey
std::string serialize_public_key(
    const lbcrypto::PublicKey<Element>& pk);
lbcrypto::PublicKey<Element> deserialize_public_key(const std::string& data);

// PrivateKey
std::string serialize_private_key(
    const lbcrypto::PrivateKey<Element>& sk);
lbcrypto::PrivateKey<Element> deserialize_private_key(const std::string& data);

// EvalKey
std::string serialize_eval_key(
    const lbcrypto::EvalKey<Element>& ek);
lbcrypto::EvalKey<Element> deserialize_eval_key(const std::string& data);

}  // namespace tee
