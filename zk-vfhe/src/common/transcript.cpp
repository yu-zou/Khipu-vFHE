#include "common/transcript.h"

#include <nlohmann/json.hpp>

namespace zk {

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
    j["witness_us"] = witness_us;
    j["proof_us"] = proof_us;
    j["transcript_us"] = transcript_us;
    j["quote_us"] = quote_us;
    j["input_loading_us"] = input_loading_us;
    j["packaging_us"] = packaging_us;
    j["peak_mem_kb"] = peak_mem_kb;

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
    t.witness_us = j.value("witness_us", 0ULL);
    t.proof_us = j.value("proof_us", 0ULL);
    t.transcript_us = j.value("transcript_us", 0ULL);
    t.quote_us = j.value("quote_us", 0ULL);
    t.input_loading_us = j.value("input_loading_us", 0ULL);
    t.packaging_us = j.value("packaging_us", 0ULL);
    t.peak_mem_kb = j.value("peak_mem_kb", 0ULL);

    return t;
}

}  // namespace zk
