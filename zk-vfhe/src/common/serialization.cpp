#include "common/serialization.h"

#include <sstream>

namespace zk {

std::string serialize_ciphertext(const lbcrypto::Ciphertext<Element>& ct) {
    std::ostringstream oss(std::ios::binary);
    lbcrypto::Serial::Serialize(ct, oss, lbcrypto::SerType::BINARY);
    return oss.str();
}

lbcrypto::Ciphertext<Element> deserialize_ciphertext(const std::string& data) {
    std::istringstream iss(data, std::ios::binary);
    lbcrypto::Ciphertext<Element> ct;
    lbcrypto::Serial::Deserialize(ct, iss, lbcrypto::SerType::BINARY);
    return ct;
}

std::string serialize_public_key(const lbcrypto::PublicKey<Element>& pk) {
    std::ostringstream oss(std::ios::binary);
    lbcrypto::Serial::Serialize(pk, oss, lbcrypto::SerType::BINARY);
    return oss.str();
}

lbcrypto::PublicKey<Element> deserialize_public_key(const std::string& data) {
    std::istringstream iss(data, std::ios::binary);
    lbcrypto::PublicKey<Element> pk;
    lbcrypto::Serial::Deserialize(pk, iss, lbcrypto::SerType::BINARY);
    return pk;
}

std::string serialize_private_key(const lbcrypto::PrivateKey<Element>& sk) {
    std::ostringstream oss(std::ios::binary);
    lbcrypto::Serial::Serialize(sk, oss, lbcrypto::SerType::BINARY);
    return oss.str();
}

lbcrypto::PrivateKey<Element> deserialize_private_key(const std::string& data) {
    std::istringstream iss(data, std::ios::binary);
    lbcrypto::PrivateKey<Element> sk;
    lbcrypto::Serial::Deserialize(sk, iss, lbcrypto::SerType::BINARY);
    return sk;
}

std::string serialize_eval_key(const lbcrypto::EvalKey<Element>& ek) {
    std::ostringstream oss(std::ios::binary);
    lbcrypto::Serial::Serialize(ek, oss, lbcrypto::SerType::BINARY);
    return oss.str();
}

lbcrypto::EvalKey<Element> deserialize_eval_key(const std::string& data) {
    std::istringstream iss(data, std::ios::binary);
    lbcrypto::EvalKey<Element> ek;
    lbcrypto::Serial::Deserialize(ek, iss, lbcrypto::SerType::BINARY);
    return ek;
}

}  // namespace zk
