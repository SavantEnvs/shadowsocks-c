// SOCKS5 address parser: ss::relay::parse_socks_addr (src/relay/socket.cpp). ss-server runs it on
// every decrypted request header (relay/tcp.cpp Connection::server_header) and on every decrypted
// UDP payload (relay/udp.cpp); ss-local runs it on the SOCKS5 CONNECT and UDP ASSOCIATE addresses
// its clients send. The input is that header, as the peer sent it.
//
// Besides ASan/UBSan, the harness checks the parser's contract the callers rely on:
//  * a complete address is at most kMaxSocksAddr bytes and at most the input, so the relay's
//    consume(target.length) and plain.subspan(target.length) stay in bounds;
//  * the TCP relay feeds the header as it arrives, so every shorter prefix of a complete address
//    must report need_more (never a different address, never invalid);
//  * the parsed fields re-encode (encode_socks_addr / encode_socks_host) to the same wire bytes.
#include <cstdint>
#include <cstring>
#include <span>

#include "relay/socket.hpp"

namespace sr = ss::relay;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    std::span<const std::uint8_t> in(data, size);
    sr::SocksTarget t{};
    const sr::ParseResult pr = sr::parse_socks_addr(in, t);
    if (pr != sr::ParseResult::complete) {
        return 0;
    }
    if (t.length > size || t.length > sr::kMaxSocksAddr || t.length < 1 + 1 + 2) {
        __builtin_trap();
    }
    for (std::size_t n = 0; n < t.length; ++n) {
        sr::SocksTarget p{};
        if (sr::parse_socks_addr(in.first(n), p) != sr::ParseResult::need_more) {
            __builtin_trap();
        }
    }
    if (t.port != static_cast<std::uint16_t>((data[t.length - 2] << 8) | data[t.length - 1])) {
        __builtin_trap();
    }

    std::uint8_t wire[sr::kMaxSocksAddr];
    const std::uint8_t type = data[0] & 0x0F;
    if (t.type != type) {
        __builtin_trap();
    }
    if (type == 1 || type == 4) {
        std::size_t n = sr::encode_socks_addr(reinterpret_cast<const sockaddr *>(&t.ip), wire);
        if (n != t.length || wire[0] != type || std::memcmp(wire + 1, data + 1, n - 1) != 0) {
            __builtin_trap();
        }
        // The text form round-trips to the same address.
        n = sr::encode_socks_host(t.host, t.port, wire);
        if (n != t.length || std::memcmp(wire + 1, data + 1, n - 1) != 0) {
            __builtin_trap();
        }
    } else {
        const std::size_t len = data[1];
        if (t.length != 2 + len + 2 || t.host[len] != '\0' || std::memcmp(t.host, data + 2, len) != 0) {
            __builtin_trap();
        }
        // A domain without NULs that is not an IP literal re-encodes byte for byte.
        const std::size_t n = std::strlen(t.host) == len ? sr::encode_socks_host(t.host, t.port, wire) : 0;
        if (n != 0 && wire[0] == 3 && (n != t.length || std::memcmp(wire + 1, data + 1, n - 1) != 0)) {
            __builtin_trap();
        }
    }
    return 0;
}
