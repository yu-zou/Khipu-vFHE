#include <arpa/inet.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "common/attestation.h"
#include "common/serialization.h"
#include "common/tcp_transport.h"
#include "server/workload_registry.h"
#include "openfhe.h"
#include "openfhe/pke/cryptocontext-ser.h"
#include "openfhe/pke/key/key-ser.h"
#include "openfhe/pke/scheme/bgvrns/bgvrns-ser.h"

using namespace tee;

namespace {

// ── Type aliases ──────────────────────────────────────────────────────────────

using CT = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using CC = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;

// ── Reader for the big-endian length-prefixed REQUEST payload ─────────────────

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
        uint8_t len_bytes[8];
        std::memcpy(len_bytes, buf_.data() + pos_, 8);
        pos_ += 8;
        uint64_t n = 0;
        for (int i = 0; i < 8; i++) { n = (n << 8) | len_bytes[i]; }
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

// ── Writer for big-endian length-prefixed RESPONSE payload ────────────────────

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
        uint64_t n64 = n;
        uint8_t len_bytes[8];
        for (int i = 7; i >= 0; i--) { len_bytes[i] = n64 & 0xFF; n64 >>= 8; }
        buf_.insert(buf_.end(), len_bytes, len_bytes + 8);
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

// ── Error response builder ────────────────────────────────────────────────────

std::vector<uint8_t> build_error_response(const std::string& msg) {
    BufWriter w;
    std::vector<uint8_t> empty;
    w.write_blob(empty);  // output_ct (empty)
    std::string err_json = std::string("{\"error\":\"") + msg + "\"}";
    w.write_string(err_json);
    w.write_blob(empty);  // quote
    return w.data();
}

// ── Client handler ────────────────────────────────────────────────────────────

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
    std::vector<std::vector<uint8_t>> input_ct_blobs;
    std::string workload_id;
    try {
        BufReader r(req);
        nonce = r.read_blob();
        uint32_t num_keys = r.read_u32_be();
        eval_key_blobs.reserve(num_keys);
        for (uint32_t i = 0; i < num_keys; ++i) {
            eval_key_blobs.push_back(r.read_blob());
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

    // ── Workload registry lookup ────────────────────────────────────────────────
    const auto& registry = get_workload_registry();
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

    auto t_cc_start = clock::now();
    auto cc = workload.make_context();
    auto t_cc_end = clock::now();

    // Deserialize eval keys into the context. Try each key type
    // (mult, sum, automorphism) for each blob; at least one must succeed.
    try {
        for (auto& kb : eval_key_blobs) {
            if (kb.empty()) continue;  // Skip empty blobs

            std::string s(kb.begin(), kb.end());
            bool deserialized = false;

            // Try EvalMultKey
            try {
                std::istringstream iss(s, std::ios::binary);
                lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::DeserializeEvalMultKey(
                    iss, lbcrypto::SerType::BINARY);
                deserialized = true;
            } catch (const std::exception&) {}

            // Try EvalSumKey
            if (!deserialized) {
                try {
                    std::istringstream iss(s, std::ios::binary);
                    lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::DeserializeEvalSumKey(
                        iss, lbcrypto::SerType::BINARY);
                    deserialized = true;
                } catch (const std::exception&) {}
            }

            // Try EvalAutomorphismKey
            if (!deserialized) {
                try {
                    std::istringstream iss(s, std::ios::binary);
                    lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::DeserializeEvalAutomorphismKey(
                        iss, lbcrypto::SerType::BINARY);
                    deserialized = true;
                } catch (const std::exception&) {}
            }

            if (!deserialized) {
                throw std::runtime_error(
                    "eval key blob deserialization failed for all key types");
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

    std::vector<CT> inputs;
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
    CT output_ct;
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

    // Generate TDX quote.
    auto t_quote_start = clock::now();
    std::vector<uint8_t> quote;
    try {
        quote = generate_tdx_quote(hash);
    } catch (const std::exception& e) {
        std::cerr << "[server] TDX quote generation failed (non-TDX env?): "
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
              << "  transcript=" << std::chrono::duration_cast<ms>(t_transcript_end - t_transcript_start).count() << "ms"
              << "  quote=" << std::chrono::duration_cast<ms>(t_quote_end - t_quote_start).count() << "ms"
              << std::endl;
}

// ── Usage ─────────────────────────────────────────────────────────────────────

void print_usage(const char* argv0) {
    std::cerr << "Usage: " << argv0 << " [--port PORT]" << std::endl;
}

}  // namespace

// ── main ──────────────────────────────────────────────────────────────────────

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