#include <arpa/inet.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "common/attestation.h"
#include "common/h100_evidence_adapter.h"
#include "common/serialization.h"
#include "common/tcp_transport.h"
#include "openfhe/core/utils/serial.h"
extern "C" {
#include "blake3.h"
}
#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/ckksrns/ckksrns-ser.h"
#include "server/workload_registry.h"

using namespace tee;

namespace {

// Reader for the big-endian length-prefixed REQUEST payload.
class BufReader {
public:
    explicit BufReader(const std::vector<uint8_t>& buf) : buf_(buf), pos_(0) {}

    const uint8_t* read(size_t n) {
        if (pos_ + n > buf_.size()) {
            throw std::runtime_error("request truncated");
        }
        const uint8_t* p = buf_.data() + pos_;
        pos_ += n;
        return p;
    }

    uint32_t read_u32_be() {
        const uint8_t* p = read(4);
        uint32_t v = 0;
        v |= static_cast<uint32_t>(p[0]) << 24;
        v |= static_cast<uint32_t>(p[1]) << 16;
        v |= static_cast<uint32_t>(p[2]) << 8;
        v |= static_cast<uint32_t>(p[3]);
        return v;
    }

    std::vector<uint8_t> read_blob() {
        uint8_t len_bytes[8]; std::memcpy(len_bytes, buf_.data()+pos_, 8); pos_+=8; uint64_t n=0; for(int i=0;i<8;i++){n=(n<<8)|len_bytes[i];}
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

// Writer for big-endian length-prefixed RESPONSE payload.
class BufWriter {
public:
    void write_u32_be(uint32_t v) {
        uint8_t b[4];
        b[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
        b[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
        b[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
        b[3] = static_cast<uint8_t>(v & 0xFF);
        buf_.insert(buf_.end(), b, b + 4);
    }

    void write_blob(const uint8_t* data, size_t n) {
        uint64_t n64 = n; uint8_t len_bytes[8]; for(int i=7;i>=0;i--){len_bytes[i]=n64&0xFF;n64>>=8;} buf_.insert(buf_.end(), len_bytes, len_bytes+8);
        buf_.insert(buf_.end(), data, data + n);
    }

    void write_blob(const std::vector<uint8_t>& v) {
        write_blob(v.data(), v.size());
    }

    void write_string(const std::string& s) {
        write_blob(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    const std::vector<uint8_t>& data() const { return buf_; }

private:
    std::vector<uint8_t> buf_;
};

std::vector<uint8_t> build_error_response(const std::string& msg) {
    BufWriter w;
    std::vector<uint8_t> empty;
    w.write_blob(empty);  // output_ct (empty)
    std::string err_json = std::string("{\"error\":\"") + msg + "\"}";
    w.write_string(err_json);
    w.write_blob(empty);  // quote
    return w.data();
}

void handle_client(int client_fd) {
    using clock = std::chrono::steady_clock;

    std::vector<uint8_t> req;
    try {
        req = recv_message(client_fd);
    } catch (const std::exception& e) {
        std::cerr << "[server] recv failed: " << e.what() << std::endl;
        return;
    }

    std::vector<uint8_t> nonce;
    std::vector<std::vector<uint8_t>> eval_key_blobs;
    std::vector<uint8_t> eval_key_types;  // parallel: 1=mult, 2=automorphism
    std::vector<uint8_t> public_key_blob;
    std::vector<std::vector<uint8_t>> input_ct_blobs;
    std::string workload_id;
    try {
        BufReader r(req);
        nonce = r.read_blob();
        public_key_blob = r.read_blob(); // public key
        std::string eval_keys_path = r.read_string(); // path to eval keys file
        // Parse the eval key blobs from file
        {
            std::ifstream ifs(eval_keys_path, std::ios::binary);
            if (!ifs.is_open()) throw std::runtime_error("cannot open eval keys file: " + eval_keys_path);
            uint32_t num_keys_net = 0;
            ifs.read(reinterpret_cast<char*>(&num_keys_net), 4);
            uint32_t num_keys = ntohl(num_keys_net);
            eval_key_blobs.reserve(num_keys);
            eval_key_types.reserve(num_keys);
            for (uint32_t i = 0; i < num_keys; ++i) {
                uint8_t type_tag = 0;
                ifs.read(reinterpret_cast<char*>(&type_tag), 1);
                uint8_t len_bytes[8];
                ifs.read(reinterpret_cast<char*>(len_bytes), 8);
                uint64_t sz = 0;
                for (int j = 0; j < 8; j++) { sz = (sz << 8) | len_bytes[j]; }
                std::vector<uint8_t> blob(sz);
                ifs.read(reinterpret_cast<char*>(blob.data()), sz);
                eval_key_blobs.push_back(std::move(blob));
                eval_key_types.push_back(type_tag);
            }
            ifs.close();
            std::cerr << "[server] Read " << num_keys << " eval key blobs from " << eval_keys_path << std::endl;
            std::remove(eval_keys_path.c_str());
        }
        uint32_t num_cts = r.read_u32_be();
        input_ct_blobs.reserve(num_cts);
        for (uint32_t i = 0; i < num_cts; ++i) {
            input_ct_blobs.push_back(r.read_blob());
        }
        workload_id = r.read_string();
        if (r.remaining() != 0) {
            throw std::runtime_error("trailing bytes in request");
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] request parse failed: " << e.what() << std::endl;
        try {
            auto resp = build_error_response(std::string("bad request: ") + e.what());
            send_message(client_fd, resp);
        } catch (...) {}
        return;
    }

    auto& registry = get_workload_registry();
    auto it = registry.find(workload_id);
    if (it == registry.end()) {
        std::cerr << "[server] unknown workload: " << workload_id << std::endl;
        try {
            auto resp = build_error_response("unknown workload: " + workload_id);
            send_message(client_fd, resp);
        } catch (...) {}
        return;
    }
    const Workload& workload = it->second;

    // Deserialize the client's public key FIRST. Its serialization includes an
    // OpenFHE CryptoContext that must be active before eval-key deserialization.
    // We do NOT call workload.make_context() here: that would register a SECOND
    // context with identical parameters, and OpenFHE's context dedup + key
    // association then drops most deserialized automorphism keys. The GPU
    // workload uses the client public key's own context anyway.
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> client_pk;
    try {
        std::string pk_str(public_key_blob.begin(), public_key_blob.end());
        std::istringstream iss(pk_str, std::ios::binary);
        lbcrypto::Serial::Deserialize(client_pk, iss, lbcrypto::SerType::BINARY);
        tee::set_client_public_key(client_pk);
    } catch (const std::exception& e) {
        std::cerr << "[server] public key deserialization failed: " << e.what() << std::endl;
        try {
            auto resp = build_error_response(std::string("bad public key: ") + e.what());
            send_message(client_fd, resp);
        } catch (...) {}
        return;
    }

    // Deserialize eval keys into the context. Try each key type
    // (mult, sum, automorphism) for each blob; at least one must succeed.
    try {
        constexpr uint8_t kTypeMult = 1;
        constexpr uint8_t kTypeAuto = 2;
        for (size_t i = 0; i < eval_key_blobs.size(); ++i) {
            std::string s(eval_key_blobs[i].begin(), eval_key_blobs[i].end());
            uint8_t type_tag = eval_key_types[i];
            std::istringstream iss(s, std::ios::binary);
            if (type_tag == kTypeMult) {
                lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::DeserializeEvalMultKey(
                    iss, lbcrypto::SerType::BINARY);
            } else if (type_tag == kTypeAuto) {
                lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::DeserializeEvalAutomorphismKey(
                    iss, lbcrypto::SerType::BINARY);
            } else {
                throw std::runtime_error("unknown eval key blob type tag: " +
                    std::to_string(static_cast<int>(type_tag)));
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] eval key deserialization failed: " << e.what() << std::endl;
        try {
            auto resp = build_error_response(std::string("bad eval key: ") + e.what());
            send_message(client_fd, resp);
        } catch (...) {}
        return;
    }

    // Use the client public key's own crypto context for the workload. This is
    // the single context all deserialized keys are associated with, avoiding a
    // duplicate context from make_context().
    auto t_cc_start = clock::now();
    auto cc = client_pk->GetCryptoContext();
    auto t_cc_end = clock::now();

    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> inputs;
    inputs.reserve(input_ct_blobs.size());
    try {
        for (auto& cb : input_ct_blobs) {
            std::string s(cb.begin(), cb.end());
            inputs.push_back(deserialize_ciphertext(s));
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] ciphertext deserialization failed: " << e.what() << std::endl;
        try {
            auto resp = build_error_response(std::string("bad ciphertext: ") + e.what());
            send_message(client_fd, resp);
        } catch (...) {}
        return;
    }

    auto t_eval_start = clock::now();
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> output_ct;
    try {
        output_ct = workload.eval(cc, inputs);
    } catch (const std::exception& e) {
        std::cerr << "[server] eval failed: " << e.what() << std::endl;
        try {
            auto resp = build_error_response(std::string("eval failed: ") + e.what());
            send_message(client_fd, resp);
        } catch (...) {}
        return;
    }
    auto t_eval_end = clock::now();

    std::string output_str;
    auto t_outser_start = clock::now();
    try {
        output_str = serialize_ciphertext(output_ct);
    } catch (const std::exception& e) {
        std::cerr << "[server] output serialization failed: " << e.what() << std::endl;
        try {
            auto resp = build_error_response(std::string("serialize failed: ") + e.what());
            send_message(client_fd, resp);
        } catch (...) {}
        return;
    }
    auto t_outser_end = clock::now();
    std::vector<uint8_t> output_ct_bytes(output_str.begin(), output_str.end());

    // Generate transcript (without timings) and compute hash.
    auto t_transcript_start = clock::now();
    Transcript transcript = generate_transcript(nonce, eval_key_blobs, input_ct_blobs,
                                                output_ct_bytes);
    auto t_transcript_end = clock::now();

    // Set eval and transcript timing fields (metadata, not in hash).
    transcript.fhe_eval_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t_eval_end - t_eval_start).count());
    transcript.transcript_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t_transcript_end - t_transcript_start).count());

    // Compute transcript hash (timings zeroed out internally).
    auto hash = compute_transcript_hash(transcript);

    // Collect GPU evidence with client nonce (heterogeneous attestation).
    auto t_gpuev_start = clock::now();
    std::vector<uint8_t> gpu_evidence_bytes;
    try {
        H100EvidenceAdapter gpu_adapter;
        if (gpu_adapter.init()) {
            std::array<uint8_t, 32> nonce_arr{};
            size_t copy_len = std::min(nonce.size(), (size_t)32);
            std::memcpy(nonce_arr.data(), nonce.data(), copy_len);
            auto gpu_ev = gpu_adapter.collect_evidence(nonce_arr);
            gpu_evidence_bytes = gpu_ev.serialize();
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] GPU evidence failed: " << e.what() << std::endl;
    }
    auto t_gpuev_end = clock::now();

    // Generate TDX quote (heterogeneous if GPU evidence available).
    auto t_quote_start = clock::now();
    std::vector<uint8_t> quote;
    try {
        if (!gpu_evidence_bytes.empty()) {
            auto gpu_digest = compute_gpu_evidence_digest(gpu_evidence_bytes);
            quote = generate_tdx_quote_heterogeneous(hash, gpu_digest);
        } else {
            quote = generate_tdx_quote(hash);
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] TDX quote generation failed: "
                  << e.what() << std::endl;
        quote.clear();
    }
    auto t_quote_end = clock::now();

    // Set quote timing field and recompute transcript JSON with all timings.
    transcript.quote_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t_quote_end - t_quote_start).count());
    std::string transcript_json = transcript.to_json();

    BufWriter w;
    w.write_blob(output_ct_bytes);
    w.write_string(transcript_json);
    w.write_blob(gpu_evidence_bytes);
    w.write_blob(quote);

    try {
        send_message(client_fd, w.data());
    } catch (const std::exception& e) {
        std::cerr << "[server] send response failed: " << e.what() << std::endl;
    }

    using ms = std::chrono::milliseconds;
    std::cerr << "[server] workload=" << workload_id
              << "  ctx=" << std::chrono::duration_cast<ms>(t_cc_end - t_cc_start).count() << "ms"
              << "  eval=" << std::chrono::duration_cast<ms>(t_eval_end - t_eval_start).count() << "ms"
              << "  outser=" << std::chrono::duration_cast<ms>(t_outser_end - t_outser_start).count() << "ms"
              << "  transcript=" << std::chrono::duration_cast<ms>(t_transcript_end - t_transcript_start).count() << "ms"
              << "  gpuev=" << std::chrono::duration_cast<ms>(t_gpuev_end - t_gpuev_start).count() << "ms"
              << "  quote=" << std::chrono::duration_cast<ms>(t_quote_end - t_quote_start).count() << "ms"
              << std::endl;
}

void print_usage(const char* argv0) {
    std::cerr << "Usage: " << argv0 << " [--port PORT]" << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
    uint16_t port = 8080;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (a == "--help" || a == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << a << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }


    std::cerr << "[server] listening on 0.0.0.0:" << port << std::endl;
    TCPServer srv("0.0.0.0", port);
    std::cerr << "[server] bound to port " << srv.port() << std::endl;

    try {
        for (;;) {
            Socket client;
            try {
                client = srv.accept();
            } catch (const std::exception& e) {
                std::cerr << "[server] accept failed: " << e.what() << std::endl;
                break;
            }
            int fd = client.release();
            std::thread([fd]() {
                try {
                    handle_client(fd);
                } catch (const std::exception& e) {
                    std::cerr << "[server] handler exception: " << e.what() << std::endl;
                } catch (...) {
                    std::cerr << "[server] handler: unknown exception" << std::endl;
                }
                ::close(fd);
            }).detach();
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[server] fatal: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "[server] fatal: unknown exception" << std::endl;
        return 1;
    }
}
