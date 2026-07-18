#include <arpa/inet.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "client/verifier.h"
#include "common/attestation.h"
#include "common/hashing.h"
#include "common/serialization.h"
#include "common/tcp_transport.h"
#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/ckksrns/ckksrns-ser.h"
#include "server/workload_registry.h"

using namespace tee;
using namespace lbcrypto;

namespace {

class BufReader {
public:
    explicit BufReader(const std::vector<uint8_t>& buf) : buf_(buf), pos_(0) {}
    const uint8_t* read(size_t n) {
        if (pos_ + n > buf_.size()) throw std::runtime_error("response truncated");
        const uint8_t* p = buf_.data() + pos_;
        pos_ += n;
        return p;
    }
    uint32_t read_u32_be() {
        const uint8_t* p = read(4);
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
               (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }
    std::vector<uint8_t> read_blob() {
        uint32_t n = read_u32_be();
        const uint8_t* p = read(n);
        return std::vector<uint8_t>(p, p + n);
    }
    std::string read_string() {
        auto v = read_blob();
        return std::string(v.begin(), v.end());
    }
    size_t remaining() const { return buf_.size() - pos_; }

private:
    const std::vector<uint8_t>& buf_;
    size_t pos_;
};

class BufWriter {
public:
    void write_u32_be(uint32_t v) {
        uint8_t b[4] = {uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v)};
        buf_.insert(buf_.end(), b, b + 4);
    }
    void write_blob(const uint8_t* d, size_t n) {
        write_u32_be(static_cast<uint32_t>(n));
        buf_.insert(buf_.end(), d, d + n);
    }
    void write_blob(const std::vector<uint8_t>& v) { write_blob(v.data(), v.size()); }
    void write_string(const std::string& s) {
        write_blob(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    const std::vector<uint8_t>& data() const { return buf_; }

private:
    std::vector<uint8_t> buf_;
};

std::vector<uint8_t> random_nonce(size_t n) {
    std::vector<uint8_t> out(n);
    std::ifstream ur("/dev/urandom", std::ios::binary);
    if (ur) {
        ur.read(reinterpret_cast<char*>(out.data()),
                static_cast<std::streamsize>(n));
    }
    if (!ur || ur.gcount() != static_cast<std::streamsize>(n)) {
        for (size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>(i * 31u + 7u);
    }
    return out;
}

struct WorkloadSpec {
    std::string id;
    int num_inputs;
    int slots;
    int seed_a;
    int seed_b;
};

const std::vector<WorkloadSpec> kWorkloads = {
    {"toy",               2, 32,  42, 123},
    {"small",             1, 32,  42, 0},
    {"medium",            1, 64,  42, 0},
    {"micro_add",         2, 32,  42, 123},
    {"micro_mul",         2, 32,  42, 123},
    {"micro_mul_rescale", 2, 32,  42, 123},
    {"micro_rotate",      1, 32,  42, 0},
    {"app_matvec",        1, 256, 42, 0},
    {"app_inference",     1, 128, 42, 0},
    {"noop",              1, 32,  42, 0},
    {"logistic-regression", 21, 32768, 42, 0},
};

std::vector<double> gen_input_vec(int slots, int seed) {
    std::mt19937 gen(seed);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> vals(slots);
    for (int i = 0; i < slots; ++i) vals[i] = dist(gen);
    return vals;
}

// Logistic-regression input generation.
// Returns 21 ciphertexts: 10 data + 10 labels + 1 weights.
std::vector<Ciphertext<DCRTPoly>> gen_logreg_inputs(
    CryptoContext<DCRTPoly> cc, const lbcrypto::KeyPair<DCRTPoly>& kp) {
    
    const int kNumFeatures = 196;
    const int kCols = 256;
    const int kRows = 128;
    const int kSlots = 32768;
    const int kNumBatches = 10;
    
    // Read MNIST CSV (first 1280 rows = 10 batches × 128 rows).
    std::ifstream ifs("/root/Khipu-vFHE/thirdparty/FIDESlib/examples/logreg/data/mnist_data_train.csv");
    if (!ifs.is_open()) {
        throw std::runtime_error("Cannot open mnist_data_train.csv");
    }
    
    std::string line;
    std::getline(ifs, line); // skip header
    
    // Read 1280 rows, each with 196 features + 1 label.
    std::vector<std::vector<double>> features;
    std::vector<double> labels;
    features.reserve(1280);
    labels.reserve(1280);
    
    for (int row = 0; row < 1280 && std::getline(ifs, line); ++row) {
        std::istringstream iss(line);
        std::string cell;
        std::vector<double> feat;
        feat.reserve(kCols);
        
        // Read 196 features.
        for (int f = 0; f < kNumFeatures; ++f) {
            std::getline(iss, cell, ',');
            feat.push_back(std::stod(cell));
        }
        
        // Read label (last column).
        std::getline(iss, cell, ',');
        double label = std::stod(cell);
        
        // Pad to 256 columns with zeros.
        feat.resize(kCols, 0.0);
        
        features.push_back(std::move(feat));
        labels.push_back(label);
    }
    ifs.close();
    
    std::vector<Ciphertext<DCRTPoly>> cts;
    
    // Generate 10 data ciphertexts.
    for (int b = 0; b < kNumBatches; ++b) {
        std::vector<double> vals(kSlots, 0.0);
        for (int r = 0; r < kRows; ++r) {
            int sample_idx = b * kRows + r;
            for (int c = 0; c < kCols; ++c) {
                vals[r * kCols + c] = features[sample_idx][c];
            }
        }
        auto pt = cc->MakeCKKSPackedPlaintext(vals, 2, 13);
        auto ct = cc->Encrypt(kp.publicKey, pt);
        cts.push_back(ct);
    }
    
    // Generate 10 label ciphertexts.
    for (int b = 0; b < kNumBatches; ++b) {
        std::vector<double> vals(kSlots, 0.0);
        for (int r = 0; r < kRows; ++r) {
            int sample_idx = b * kRows + r;
            vals[r * kCols] = labels[sample_idx]; // label in first column
        }
        auto pt = cc->MakeCKKSPackedPlaintext(vals, 2, 13);
        auto ct = cc->Encrypt(kp.publicKey, pt);
        cts.push_back(ct);
    }
    
    // Generate 1 weights ciphertext (256 zeros replicated across 128 rows).
    std::vector<double> weights_vals(kSlots, 0.0);
    for (int r = 0; r < kRows; ++r) {
        for (int c = 0; c < kCols; ++c) {
            weights_vals[r * kCols + c] = 0.0; // initial weights are all zeros
        }
    }
    auto weights_pt = cc->MakeCKKSPackedPlaintext(weights_vals, 2, 13);
    auto weights_ct = cc->Encrypt(kp.publicKey, weights_pt);
    cts.push_back(weights_ct);
    
    return cts;
}

std::vector<std::vector<uint8_t>> serialize_all_eval_keys(
    const CryptoContext<DCRTPoly>& cc) {
    std::vector<std::vector<uint8_t>> blobs;
    {
        std::ostringstream oss(std::ios::binary);
        bool ok = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(
            oss, SerType::BINARY, cc);
        if (ok) {
            std::string s = oss.str();
            if (!s.empty())
                blobs.push_back(std::vector<uint8_t>(s.begin(), s.end()));
        }
    }
    {
        std::ostringstream oss(std::ios::binary);
        bool ok = CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(
            oss, SerType::BINARY, cc);
        if (ok) {
            std::string s = oss.str();
            if (!s.empty())
                blobs.push_back(std::vector<uint8_t>(s.begin(), s.end()));
        }
    }
    {
        std::ostringstream oss(std::ios::binary);
        bool ok = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(
            oss, SerType::BINARY, cc);
        if (ok) {
            std::string s = oss.str();
            if (!s.empty())
                blobs.push_back(std::vector<uint8_t>(s.begin(), s.end()));
        }
    }
    return blobs;
}

Hash32 hash_concatenated(const std::vector<std::vector<uint8_t>>& parts) {
    std::vector<uint8_t> buf;
    size_t total = 0;
    for (const auto& p : parts) total += p.size();
    buf.reserve(total);
    for (const auto& p : parts) buf.insert(buf.end(), p.begin(), p.end());
    return blake3_hash(buf);
}

void print_usage(const char* argv0) {
    std::cerr << "Usage: " << argv0
              << " [--host HOST] [--port PORT] [--workload ID]"
                 " [--expected-mr-td HEX] [--help|-h]"
              << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    uint16_t port = 8080;
    std::string workload_id = "noop";
    std::string expected_mr_td;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (a == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (a == "--workload" && i + 1 < argc) {
            workload_id = argv[++i];
        } else if (a == "--expected-mr-td" && i + 1 < argc) {
            expected_mr_td = argv[++i];
        } else if (a == "--help" || a == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << a << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    if (expected_mr_td.empty()) {
        std::cerr << "[client] --expected-mr-td not provided; skipping MR_TD check"
                  << std::endl;
    }

    try {
        auto& registry = get_workload_registry();
        auto it = registry.find(workload_id);
        if (it == registry.end()) {
            std::cerr << "[client] unknown workload: " << workload_id << std::endl;
            return 1;
        }
        const Workload& workload = it->second;

        auto cc = workload.make_context();
        auto kp = cc->KeyGen();

        if (workload.gen_keys) {
            workload.gen_keys(cc, kp);
        }
        cc->EvalMultKeyGen(kp.secretKey);

        std::vector<uint8_t> nonce = random_nonce(16);

        std::vector<std::vector<uint8_t>> eval_keys = serialize_all_eval_keys(cc);

        // Serialize the public key (needed by FIDESlib GPU on server side)
        std::string pk_serialized;
        {
            std::ostringstream oss(std::ios::binary);
            lbcrypto::Serial::Serialize(kp.publicKey, oss, lbcrypto::SerType::BINARY);
            pk_serialized = oss.str();
        }

        std::vector<std::vector<uint8_t>> input_ct_blobs;
        std::vector<Ciphertext<DCRTPoly>> input_cts;

        if (workload_id == "logistic-regression") {
            // Special input generation for logistic regression.
            input_cts = gen_logreg_inputs(cc, kp);
            for (const auto& ct : input_cts) {
                std::string s = serialize_ciphertext(ct);
                input_ct_blobs.emplace_back(s.begin(), s.end());
            }
        } else {
            // Look up the workload spec for deterministic input generation.
            const WorkloadSpec* spec = nullptr;
            for (const auto& s : kWorkloads) {
                if (s.id == workload_id) {
                    spec = &s;
                    break;
                }
            }

            if (spec != nullptr) {
                auto vals_a = gen_input_vec(spec->slots, spec->seed_a);
                auto pt_a = cc->MakeCKKSPackedPlaintext(vals_a);
                auto ct_a = cc->Encrypt(kp.publicKey, pt_a);
                input_cts.push_back(ct_a);
                std::string s_a = serialize_ciphertext(ct_a);
                input_ct_blobs.emplace_back(s_a.begin(), s_a.end());

                if (spec->num_inputs >= 2) {
                    auto vals_b = gen_input_vec(spec->slots, spec->seed_b);
                    auto pt_b = cc->MakeCKKSPackedPlaintext(vals_b);
                    auto ct_b = cc->Encrypt(kp.publicKey, pt_b);
                    input_cts.push_back(ct_b);
                    std::string s_b = serialize_ciphertext(ct_b);
                    input_ct_blobs.emplace_back(s_b.begin(), s_b.end());
                }
            } else {
                std::cerr << "[client] warning: input generation for workload '"
                          << workload_id
                          << "' not implemented; sending empty input set" << std::endl;
            }
        }

        BufWriter w;
        w.write_blob(nonce);
        w.write_u32_be(static_cast<uint32_t>(eval_keys.size()));
        for (const auto& k : eval_keys) w.write_blob(k);
        w.write_blob(std::vector<uint8_t>(pk_serialized.begin(), pk_serialized.end())); // public key
        w.write_u32_be(static_cast<uint32_t>(input_ct_blobs.size()));
        for (const auto& c : input_ct_blobs) w.write_blob(c);
        w.write_string(workload_id);

        TCPClient cli(host, port);
        send_message(cli.fd(), w.data());
        auto resp = recv_message(cli.fd());
        cli.close();

        if (resp.empty()) {
            std::cerr << "[client] empty response from server" << std::endl;
            return 1;
        }

        BufReader rr(resp);
        auto output_ct_bytes = rr.read_blob();
        auto transcript_json = rr.read_string();
        auto gpu_evidence_bytes = rr.read_blob();
        auto quote_bytes = rr.read_blob();

        if (transcript_json.find("\"error\"") != std::string::npos) {
            std::cerr << "[client] server error: " << transcript_json << std::endl;
            return 1;
        }

        Transcript transcript = Transcript::from_json(transcript_json);

        Hash32 expected_eval_key_hash = hash_concatenated(eval_keys);
        std::vector<Hash32> expected_input_ct_hashes;
        expected_input_ct_hashes.reserve(input_ct_blobs.size());
        for (const auto& cb : input_ct_blobs) {
            expected_input_ct_hashes.push_back(blake3_hash(cb));
        }
        Hash32 expected_output_ct_hash = blake3_hash(output_ct_bytes);

        Verifier verifier;

        bool ok;
        if (!gpu_evidence_bytes.empty()) {
            std::cerr << "[client] GPU evidence: " << gpu_evidence_bytes.size() << " bytes" << std::endl;
            ok = verifier.verify_heterogeneous(
                quote_bytes, gpu_evidence_bytes, transcript, nonce, expected_mr_td,
                expected_eval_key_hash, expected_input_ct_hashes,
                expected_output_ct_hash);
        } else {
            bool t_ok = verifier.verify_transcript(
                transcript, nonce, expected_eval_key_hash,
                expected_input_ct_hashes, expected_output_ct_hash);
            if (!t_ok) {
                std::cerr << "[client] transcript verification FAILED" << std::endl;
                return 1;
            }
            ok = verifier.verify_all(
                quote_bytes, transcript, nonce, expected_mr_td,
                expected_eval_key_hash, expected_input_ct_hashes,
                expected_output_ct_hash);
        }

        if (!ok) {
            std::cerr << "[client] attestation verification FAILED; refusing to decrypt"
                      << std::endl;
            return 1;
        }

        auto output_ct = deserialize_ciphertext(
            std::string(output_ct_bytes.begin(), output_ct_bytes.end()));
        Plaintext pt_out;
        cc->Decrypt(kp.secretKey, output_ct, &pt_out);
        pt_out->SetLength(32);
        auto dec = pt_out->GetCKKSPackedValue();

        std::cout << "output[0..7] =";
        for (int i = 0; i < 8 && i < static_cast<int>(dec.size()); ++i) {
            std::cout << " " << dec[i].real();
        }
        std::cout << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[client] error: " << e.what() << std::endl;
        return 1;
    }
}
