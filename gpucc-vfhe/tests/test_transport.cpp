#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "common/tcp_transport.h"

using namespace tee;

// Test that payloads of 0, 1, 1024, and 102400 bytes round-trip correctly
// through an echo server.
TEST(TCPTransport, EchoRoundTrip) {
    constexpr uint16_t kPort = 0;  // OS-assigned
    std::atomic<bool> ready{false};

    TCPServer srv("127.0.0.1", kPort);
    uint16_t bound_port = srv.port();
    ASSERT_NE(bound_port, 0);

    std::thread server_thread([&srv]() {
        try {
            Socket client = srv.accept();
            for (;;) {
                std::vector<uint8_t> msg = recv_message(client.fd());
                send_message(client.fd(), msg);
            }
        } catch (const std::exception&) {
            // expected when client closes
        }
    });

    // Wait briefly for server to be ready; accept() is already blocking so
    // the port is bound and ready.
    TCPClient cli;
    cli.connect("127.0.0.1", bound_port);

    const std::vector<size_t> sizes = {0, 1, 1024, 102400};
    for (size_t sz : sizes) {
        std::vector<uint8_t> send(sz);
        for (size_t i = 0; i < sz; ++i) {
            send[i] = static_cast<uint8_t>((i * 31 + 7) & 0xFF);
        }
        send_message(cli.fd(), send);
        auto recv = recv_message(cli.fd());
        ASSERT_EQ(recv.size(), send.size()) << "size mismatch for " << sz;
        if (sz > 0) {
            EXPECT_EQ(std::memcmp(recv.data(), send.data(), sz), 0)
                << "payload mismatch for size " << sz;
        }
    }

    cli.close();
    server_thread.join();
}

// Test that a second client can connect independently after the first closes,
// i.e. the server keeps accepting and each connection gets its own socket.
TEST(TCPTransport, SecondIndependentConnection) {
    TCPServer srv("127.0.0.1", 0);
    uint16_t port = srv.port();
    ASSERT_NE(port, 0);

    // Session 1
    std::thread t1([&srv]() {
        try {
            Socket c = srv.accept();
            auto m = recv_message(c.fd());
            std::vector<uint8_t> reply = {'f', 'i', 'r', 's', 't'};
            send_message(c.fd(), reply);
            (void)m;
        } catch (const std::exception&) {}
    });

    {
        TCPClient cli("127.0.0.1", port);
        std::vector<uint8_t> hi = {'h', 'e', 'l', 'l', 'o'};
        send_message(cli.fd(), hi);
        auto reply = recv_message(cli.fd());
        std::vector<uint8_t> expected = {'f', 'i', 'r', 's', 't'};
        EXPECT_EQ(reply, expected);
    }
    t1.join();

    // Session 2 on same server port
    std::thread t2([&srv]() {
        try {
            Socket c = srv.accept();
            auto m = recv_message(c.fd());
            std::vector<uint8_t> reply = {'s', 'e', 'c', 'o', 'n', 'd'};
            send_message(c.fd(), reply);
            (void)m;
        } catch (const std::exception&) {}
    });

    {
        TCPClient cli("127.0.0.1", port);
        std::vector<uint8_t> hi2 = {'a', 'g', 'a', 'i', 'n'};
        send_message(cli.fd(), hi2);
        auto reply = recv_message(cli.fd());
        std::vector<uint8_t> expected = {'s', 'e', 'c', 'o', 'n', 'd'};
        EXPECT_EQ(reply, expected);
    }
    t2.join();
}
