#include "common/transcript.h"

#include <nlohmann/json.hpp>

namespace tee {

using json = nlohmann::json;

std::string Transcript::to_json() const {
    json j;
    j["nonce"] = to_hex(nonce);
    j["eval_key_hash"] = to_hex(eval_key_hash);

    json input_hashes = json::array();
    for (const auto& h : input_ct_hashes) {
        input_hashes.push_back(to_hex(h));
    }
    j["input_ct_hashes"] = input_hashes;

    j["output_ct_hash"] = to_hex(output_ct_hash);

    j["fhe_eval_us"] = fhe_eval_us;
    j["transcript_us"] = transcript_us;
    j["quote_us"] = quote_us;

    return j.dump();
}

Transcript Transcript::from_json(const std::string& json_str) {
    json j = json::parse(json_str);

    Transcript t;
    t.nonce = from_hex(j.at("nonce").get<std::string>());
    t.eval_key_hash = hash_from_hex(j.at("eval_key_hash").get<std::string>());

    t.input_ct_hashes.clear();
    for (const auto& h : j.at("input_ct_hashes")) {
        t.input_ct_hashes.push_back(hash_from_hex(h.get<std::string>()));
    }

    t.output_ct_hash = hash_from_hex(j.at("output_ct_hash").get<std::string>());

    t.fhe_eval_us = j.value("fhe_eval_us", 0ULL);
    t.transcript_us = j.value("transcript_us", 0ULL);
    t.quote_us = j.value("quote_us", 0ULL);

    return t;
}

}  // namespace tee
