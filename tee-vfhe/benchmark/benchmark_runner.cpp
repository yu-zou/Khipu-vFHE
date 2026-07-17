#include <arpa/inet.h>
#include <sys/resource.h>
#include <unistd.h>

#include <chrono>
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
    {"logistic-regression", 21, 32768, 42, 0},
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

Hash32 hash_concatenated(const std::vector<std::vector<uint8_t>>& parts) {
    std::vector<uint8_t> buf;
    size_t total = 0;
    for (const auto& p : parts) total += p.size();
    buf.reserve(total);
    for (const auto& p : parts) buf.insert(buf.end(), p.begin(), p.end());
    return blake3_hash(buf);
}

std::vector<uint8_t> string_to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<std::vector<uint8_t>> serialize_all_eval_keys(const CryptoContext<DCRTPoly>& cc) {
    std::vector<std::vector<uint8_t>> blobs;

    {
        std::ostringstream oss(std::ios::binary);
        bool ok = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(oss, SerType::BINARY, cc);
        if (ok) {
            std::string s = oss.str();
            if (!s.empty()) blobs.push_back(string_to_bytes(s));
        }
    }

    {
        std::ostringstream oss(std::ios::binary);
        bool ok = CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(oss, SerType::BINARY, cc);
        if (ok) {
            std::string s = oss.str();
            if (!s.empty()) blobs.push_back(string_to_bytes(s));
        }
    }

    {
        std::ostringstream oss(std::ios::binary);
        bool ok = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(oss, SerType::BINARY, cc);
        if (ok) {
            std::string s = oss.str();
            if (!s.empty()) blobs.push_back(string_to_bytes(s));
        }
    }

    return blobs;
}

std::vector<double> gen_input_vec(int slots, int seed) {
    std::mt19937 gen(seed);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> vals(slots);
    for (int i = 0; i < slots; ++i) vals[i] = dist(gen);
    return vals;
}

// Logistic-regression input generation (same as client_main.cpp).
std::vector<Ciphertext<DCRTPoly>> gen_logreg_inputs(
    CryptoContext<DCRTPoly> cc, const lbcrypto::KeyPair<DCRTPoly>& kp) {

    const int kNumFeatures = 196;
    const int kCols = 256;
    const int kRows = 128;
    const int kSlots = 32768;
    const int kNumBatches = 10;

    std::ifstream ifs("/root/Khipu-vFHE/thirdparty/FIDESlib/examples/logreg/data/mnist_data_train.csv");
    if (!ifs.is_open()) {
        throw std::runtime_error("Cannot open mnist_data_train.csv");
    }

    std::string line;
    std::getline(ifs, line); // skip header

    std::vector<std::vector<double>> features;
    std::vector<double> labels;
    features.reserve(1280);
    labels.reserve(1280);

    for (int row = 0; row < 1280 && std::getline(ifs, line); ++row) {
        std::istringstream iss(line);
        std::string cell;
        std::vector<double> feat;
        feat.reserve(kCols);

        for (int f = 0; f < kNumFeatures; ++f) {
            std::getline(iss, cell, ',');
            feat.push_back(std::stod(cell));
        }

        std::getline(iss, cell, ',');
        double label = std::stod(cell);
        feat.resize(kCols, 0.0);

        features.push_back(std::move(feat));
        labels.push_back(label);
    }
    ifs.close();

    std::vector<Ciphertext<DCRTPoly>> cts;

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

    for (int b = 0; b < kNumBatches; ++b) {
        std::vector<double> vals(kSlots, 0.0);
        for (int r = 0; r < kRows; ++r) {
            int sample_idx = b * kRows + r;
            vals[r * kCols] = labels[sample_idx];
        }
        auto pt = cc->MakeCKKSPackedPlaintext(vals, 2, 13);
        auto ct = cc->Encrypt(kp.publicKey, pt);
        cts.push_back(ct);
    }

    std::vector<double> weights_vals(kSlots, 0.0);
    auto weights_pt = cc->MakeCKKSPackedPlaintext(weights_vals, 2, 13);
    auto weights_ct = cc->Encrypt(kp.publicKey, weights_pt);
    cts.push_back(weights_ct);

    return cts;
}

long get_peak_mem_kb() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

void print_usage(const char* argv0) {
    std::cerr << "Usage: " << argv0
              << " --server HOST:PORT --expected-mr-td HEX [--output PATH]"
              << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
    std::string server_host = "localhost";
    uint16_t server_port = 8080;
    std::string expected_mr_td;
    std::string output_path = "benchmark_results.csv";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--server" && i + 1 < argc) {
            std::string val = argv[++i];
            auto colon = val.find(':');
            if (colon == std::string::npos) {
                std::cerr << "[benchmark] --server must be HOST:PORT" << std::endl;
                return 1;
            }
            server_host = val.substr(0, colon);
            server_port = static_cast<uint16_t>(std::stoi(val.substr(colon + 1)));
        } else if (a == "--expected-mr-td" && i + 1 < argc) {
            expected_mr_td = argv[++i];
        } else if (a == "--output" && i + 1 < argc) {
            output_path = argv[++i];
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
        std::cerr << "[benchmark] --expected-mr-td is required; aborting" << std::endl;
        return 1;
    }

    auto& registry = get_workload_registry();

    std::ofstream csv(output_path);
    if (!csv) {
        std::cerr << "[benchmark] cannot open output file: " << output_path << std::endl;
        return 1;
    }

    csv << "workload,fhe_eval_us,transcript_us,quote_us,verify_us,e2e_us,"
           "peak_mem_kb,transcript_bytes,quote_bytes\n";

    bool all_ok = true;
    for (const auto& spec : kWorkloads) {
        std::cout << "[benchmark] running workload: " << spec.id << std::endl;

        auto it = registry.find(spec.id);
        if (it == registry.end()) {
            std::cerr << "[benchmark] unknown workload: " << spec.id << " (skipping)" << std::endl;
            all_ok = false;
            continue;
        }
        const Workload& workload = it->second;

        try {
            // Clear all globally-accumulated eval keys from previous workloads.
            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

            auto cc = workload.make_context();
            auto kp = cc->KeyGen();

            if (workload.gen_keys) {
                workload.gen_keys(cc, kp);
            }
            cc->EvalMultKeyGen(kp.secretKey);

            std::vector<std::vector<uint8_t>> eval_keys = serialize_all_eval_keys(cc);

            std::vector<uint8_t> nonce = random_nonce(16);

            std::vector<Ciphertext<DCRTPoly>> input_cts;
            std::vector<std::vector<uint8_t>> input_ct_blobs;

            if (spec.id == "logistic-regression") {
                input_cts = gen_logreg_inputs(cc, kp);
                for (const auto& ct : input_cts) {
                    std::string s = serialize_ciphertext(ct);
                    input_ct_blobs.emplace_back(s.begin(), s.end());
                }
            } else {
                auto vals_a = gen_input_vec(spec.slots, spec.seed_a);
                auto pt_a = cc->MakeCKKSPackedPlaintext(vals_a);
                auto ct_a = cc->Encrypt(kp.publicKey, pt_a);
                input_cts.push_back(ct_a);
                std::string s_a = serialize_ciphertext(ct_a);
                input_ct_blobs.emplace_back(s_a.begin(), s_a.end());

                if (spec.num_inputs >= 2) {
                    auto vals_b = gen_input_vec(spec.slots, spec.seed_b);
                    auto pt_b = cc->MakeCKKSPackedPlaintext(vals_b);
                    auto ct_b = cc->Encrypt(kp.publicKey, pt_b);
                    input_cts.push_back(ct_b);
                    std::string s_b = serialize_ciphertext(ct_b);
                    input_ct_blobs.emplace_back(s_b.begin(), s_b.end());
                }
            }

            BufWriter w;
            w.write_blob(nonce);
            w.write_u32_be(static_cast<uint32_t>(eval_keys.size()));
            for (const auto& k : eval_keys) w.write_blob(k);
            w.write_u32_be(static_cast<uint32_t>(input_ct_blobs.size()));
            for (const auto& c : input_ct_blobs) w.write_blob(c);
            w.write_string(spec.id);

            auto t_e2e_start = std::chrono::steady_clock::now();
            TCPClient cli(server_host, server_port);
            send_message(cli.fd(), w.data());
            auto resp = recv_message(cli.fd());
            cli.close();
            auto t_e2e_end = std::chrono::steady_clock::now();

            if (resp.empty()) {
                std::cerr << "[benchmark] " << spec.id << ": empty response" << std::endl;
                all_ok = false;
                continue;
            }

            BufReader rr(resp);
            auto output_ct_bytes = rr.read_blob();
            auto transcript_json = rr.read_string();
            auto quote_bytes = rr.read_blob();
            if (rr.remaining() != 0) {
                std::cerr << "[benchmark] " << spec.id << ": trailing bytes in response" << std::endl;
                all_ok = false;
                continue;
            }

            if (transcript_json.find("\"error\"") != std::string::npos) {
                std::cerr << "[benchmark] " << spec.id << ": server error: " << transcript_json << std::endl;
                all_ok = false;
                continue;
            }

            Transcript transcript = Transcript::from_json(transcript_json);

            Hash32 expected_eval_key_hash = hash_concatenated(eval_keys);
            std::vector<Hash32> expected_input_ct_hashes;
            expected_input_ct_hashes.reserve(input_ct_blobs.size());
            for (const auto& cb : input_ct_blobs) {
                expected_input_ct_hashes.push_back(blake3_hash(cb));
            }
            Hash32 expected_output_ct_hash = blake3_hash(output_ct_bytes);

            auto t_verify_start = std::chrono::steady_clock::now();
            Verifier verifier;
            bool ok = verifier.verify_all(
                quote_bytes, transcript, nonce, expected_mr_td,
                expected_eval_key_hash, expected_input_ct_hashes,
                expected_output_ct_hash);
            auto t_verify_end = std::chrono::steady_clock::now();

            if (!ok) {
                std::cerr << "[benchmark] " << spec.id
                          << ": attestation verification FAILED (continuing)" << std::endl;
            }

            try {
                auto output_ct = deserialize_ciphertext(
                    std::string(output_ct_bytes.begin(), output_ct_bytes.end()));
                Plaintext pt_out;
                cc->Decrypt(kp.secretKey, output_ct, &pt_out);
                pt_out->SetLength(static_cast<int64_t>(spec.slots));
                auto dec = pt_out->GetCKKSPackedValue();
                std::cout << "  output[0..4] =";
                for (int i = 0; i < 5 && i < static_cast<int>(dec.size()); ++i) {
                    std::cout << " " << dec[i].real();
                }
                std::cout << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "[benchmark] " << spec.id << ": decrypt failed: " << e.what() << std::endl;
            }

            long peak_mem = get_peak_mem_kb();
            uint64_t e2e_us = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    t_e2e_end - t_e2e_start).count());
            uint64_t verify_us = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    t_verify_end - t_verify_start).count());

            csv << spec.id << ","
                << transcript.fhe_eval_us << ","
                << transcript.transcript_us << ","
                << transcript.quote_us << ","
                << verify_us << ","
                << e2e_us << ","
                << peak_mem << ","
                << transcript_json.size() << ","
                << quote_bytes.size() << "\n";

        } catch (const std::exception& e) {
            std::cerr << "[benchmark] " << spec.id << ": error: " << e.what() << std::endl;
            all_ok = false;
        }
    }

    csv.close();
    std::cout << "[benchmark] results written to " << output_path << std::endl;
    std::cout << "[benchmark] all workloads " << (all_ok ? "completed successfully" : "had errors")
              << std::endl;
    return all_ok ? 0 : 1;
}