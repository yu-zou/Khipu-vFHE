#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "common/attestation.h"
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
        if (pos_ + n > buf_.size()) throw std::runtime_error("truncated");
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
    std::string read_string() { auto v = read_blob(); return std::string(v.begin(), v.end()); }
    size_t remaining() const { return buf_.size() - pos_; }
private:
    const std::vector<uint8_t>& buf_;
    size_t pos_;
};

class BufWriter {
public:
    void write_u32_be(uint32_t v) {
        uint8_t b[4] = {uint8_t(v>>24), uint8_t(v>>16), uint8_t(v>>8), uint8_t(v)};
        buf_.insert(buf_.end(), b, b+4);
    }
    void write_blob(const uint8_t* d, size_t n) { write_u32_be((uint32_t)n); buf_.insert(buf_.end(), d, d+n); }
    void write_blob(const std::vector<uint8_t>& v) { write_blob(v.data(), v.size()); }
    void write_string(const std::string& s) { write_blob((const uint8_t*)s.data(), s.size()); }
    const std::vector<uint8_t>& data() const { return buf_; }
private:
    std::vector<uint8_t> buf_;
};

void run_dispatch_one(TCPServer& srv, std::atomic<bool>& stop) {
    while (!stop.load()) {
        Socket client;
        try {
            client = srv.accept();
        } catch (const std::exception&) {
            return;
        }
        int fd = client.release();
        std::thread([fd]() {
            try {
                auto req = recv_message(fd);
                BufReader r(req);
                auto nonce = r.read_blob();
                uint32_t num_keys = r.read_u32_be();
                std::vector<std::vector<uint8_t>> eval_keys;
                eval_keys.reserve(num_keys);
                for (uint32_t i = 0; i < num_keys; ++i) eval_keys.push_back(r.read_blob());
                uint32_t num_cts = r.read_u32_be();
                std::vector<std::vector<uint8_t>> input_cts;
                input_cts.reserve(num_cts);
                for (uint32_t i = 0; i < num_cts; ++i) input_cts.push_back(r.read_blob());
                auto wid = r.read_string();

                auto& reg = get_workload_registry();
                auto it = reg.find(wid);
                if (it == reg.end()) {
                    BufWriter ew;
                    std::vector<uint8_t> empty;
                    ew.write_blob(empty);
                    ew.write_string(std::string("{\"error\":\"unknown workload: ") + wid + "\"}");
                    ew.write_blob(empty);
                    send_message(fd, ew.data());
                    ::close(fd);
                    return;
                }
                const Workload& w = it->second;
                auto cc = w.make_context();

                for (auto& kb : eval_keys) {
                    std::string s(kb.begin(), kb.end());
                    std::istringstream iss(s, std::ios::binary);
                    CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(iss, SerType::BINARY);
                }

                std::vector<Ciphertext<DCRTPoly>> inputs;
                inputs.reserve(input_cts.size());
                for (auto& cb : input_cts) {
                    std::string s(cb.begin(), cb.end());
                    inputs.push_back(deserialize_ciphertext(s));
                }

                auto out_ct = w.eval(cc, inputs);
                std::string out_str = serialize_ciphertext(out_ct);
                std::vector<uint8_t> out_bytes(out_str.begin(), out_str.end());

                auto transcript = generate_transcript(nonce, eval_keys, input_cts, out_bytes);
                std::string tjson = transcript.to_json();
                auto hash = compute_transcript_hash(transcript);
                std::vector<uint8_t> quote;
                try {
                    quote = generate_tdx_quote(hash);
                } catch (const std::exception&) {
                    quote.clear();
                }

                BufWriter rw;
                rw.write_blob(out_bytes);
                rw.write_string(tjson);
                rw.write_blob(quote);
                send_message(fd, rw.data());
            } catch (const std::exception&) {
                // client closed or protocol error; nothing useful to send.
            }
            ::close(fd);
        }).detach();
    }
}

}  // namespace

TEST(Server, NoopWorkloadEndToEnd) {
    register_all_workloads();
    TCPServer srv("127.0.0.1", 0);
    uint16_t port = srv.port();
    ASSERT_NE(port, 0);

    std::atomic<bool> stop{false};
    std::thread srv_thread(run_dispatch_one, std::ref(srv), std::ref(stop));

    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(1);
    params.SetScalingModSize(40);
    params.SetBatchSize(32);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetSecurityLevel(HEStd_128_classic);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto kp = cc->KeyGen();

    std::vector<double> vals(32, 1.0);
    auto pt = cc->MakeCKKSPackedPlaintext(vals);
    auto ct = cc->Encrypt(kp.publicKey, pt);
    std::string ct_bytes = serialize_ciphertext(ct);

    std::vector<uint8_t> nonce = {1, 2, 3};
    std::vector<uint8_t> input_ct(ct_bytes.begin(), ct_bytes.end());

    BufWriter w;
    w.write_blob(nonce);
    w.write_u32_be(0);
    w.write_u32_be(1);
    w.write_blob(input_ct);
    w.write_string("noop");

    TCPClient cli("127.0.0.1", port);
    send_message(cli.fd(), w.data());
    auto resp = recv_message(cli.fd());
    cli.close();

    stop.store(true);
    srv.close();
    try { TCPClient("127.0.0.1", port).close(); } catch (...) {}
    srv_thread.join();

    ASSERT_FALSE(resp.empty());
    BufReader rr(resp);
    auto out = rr.read_blob();
    auto tjson = rr.read_string();
    auto quote = rr.read_blob();
    EXPECT_EQ(rr.remaining(), 0u);

    EXPECT_FALSE(out.empty());
    EXPECT_FALSE(tjson.empty());
    EXPECT_NE(tjson.find("nonce"), std::string::npos);
    EXPECT_LT(quote.size(), 100u * 1024u);

    auto out_ct = deserialize_ciphertext(std::string(out.begin(), out.end()));
    Plaintext pt_out;
    cc->Decrypt(kp.secretKey, out_ct, &pt_out);
    pt_out->SetLength(32);
    auto dec = pt_out->GetCKKSPackedValue();
    for (int i = 0; i < 32; ++i) {
        EXPECT_NEAR(dec[i].real(), 1.0, 1e-3);
    }
}

TEST(Server, UnknownWorkloadReturnsErrorResponse) {
    register_all_workloads();
    TCPServer srv("127.0.0.1", 0);
    uint16_t port = srv.port();
    ASSERT_NE(port, 0);

    std::atomic<bool> stop{false};
    std::thread srv_thread(run_dispatch_one, std::ref(srv), std::ref(stop));

    std::vector<uint8_t> nonce = {9};
    BufWriter w;
    w.write_blob(nonce);
    w.write_u32_be(0);
    w.write_u32_be(0);
    w.write_string("does-not-exist");

    TCPClient cli("127.0.0.1", port);
    send_message(cli.fd(), w.data());
    auto resp = recv_message(cli.fd());
    cli.close();

    stop.store(true);
    srv.close();
    try { TCPClient("127.0.0.1", port).close(); } catch (...) {}
    srv_thread.join();

    BufReader rr(resp);
    auto out = rr.read_blob();
    auto tj = rr.read_string();
    auto q = rr.read_blob();
    EXPECT_TRUE(out.empty());
    EXPECT_NE(tj.find("error"), std::string::npos);
    EXPECT_TRUE(q.empty());
}
