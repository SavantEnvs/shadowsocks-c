// UDP packet decoders: classic AEAD (ss::crypto::aead_udp_open) and Shadowsocks 2022
// (udp2022_decrypt + udp2022_accept: separate header, session IDs, sliding replay window,
// padding). These run on every datagram ss-server / ss-local receive from the network.
//
// Input layout: [0] mode, then per mode
//   0 classic:   [1] method, [2] bit0 raw; then salt + payload that the harness seals with the
//                session subkey (zero nonce, as SIP004 UDP does), or the raw packet.
//   1 2022 raw:  [1] method, [2] bit0 client role; the rest is one packet.
//   2 2022 built (XChaCha20 variant): [2] bit0 client role, bit1 stamp time; up to 16 records
//                {u16 len, 24-byte nonce, plaintext = separate header + body} that the harness
//                encrypts with the PSK, delivered in order to one session (replay window).
//   3 2022 round trip: [1] method; up to 16 payloads {u16 len, bytes} sealed by a client
//                session (udp2022_seal), optionally corrupted, delivered to a server session in a
//                fuzz-chosen order, then a reply sealed by the server back to the client.
// The 2022 header timestamp must be within 30 s of now; mode 2 can stamp it (bit1) as a real
// peer does. Sessions are created per input; the keys are fixed.
#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <vector>

#include "crypto/aead.hpp"
#include "crypto/aead2022.hpp"
#include "fuzz_input.hpp"
#include "relay/socket.hpp"

namespace sc = ss::crypto;

static const char *const kAead[]  = { "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                                      "xchacha20-ietf-poly1305" };
static const char *const k2022[] = { "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                      "2022-blake3-chacha20-poly1305" };

static const sc::MasterKey &master_for(std::size_t i)
{
    static std::optional<sc::MasterKey> keys[5];
    if (!keys[i]) {
        auto spec = sc::find_aead(kAead[i]);
        if (!spec) {
            __builtin_trap();
        }
        auto key = sc::MasterKey::from_password(*spec, "mayhem-fuzz-password");
        if (!key) {
            __builtin_trap();
        }
        keys[i] = key.value();
    }
    return *keys[i];
}

static sc::Psk psk_for(std::size_t i)
{
    auto spec = sc::find_aead2022(k2022[i]);
    if (!spec) {
        __builtin_trap();
    }
    std::array<std::uint8_t, sc::kMaxKey> bytes{};
    for (std::size_t k = 0; k < bytes.size(); ++k) {
        bytes[k] = static_cast<std::uint8_t>(0x5a ^ (k * 7));
    }
    return sc::Psk(*spec, bytes);
}

// ss-server / ss-local parse the SOCKS5 address at the head of every decrypted datagram
// (relay/udp.cpp) and forward the rest.
static void parse_header(std::span<const std::uint8_t> plain)
{
    ss::relay::SocksTarget target{};
    if (ss::relay::parse_socks_addr(plain, target) == ss::relay::ParseResult::complete
        && target.length > plain.size()) {
        __builtin_trap();
    }
}

static std::uint64_t now() { return static_cast<std::uint64_t>(std::time(nullptr)); }

static void receive(const sc::Psk &psk, sc::Role role, sc::UdpSession2022 &session,
                    std::span<const std::uint8_t> packet)
{
    std::vector<std::uint8_t> out(packet.size() + 1);
    auto pkt = sc::udp2022_decrypt(psk, packet, { out.data(), out.size() });
    if (pkt) {
        auto body = sc::udp2022_accept(role, session, pkt.value(), { out.data(), out.size() }, now());
        if (body) {
            parse_header({ out.data(), body.value() });
        }
    }
}

static void classic(fuzz::Input &in)
{
    const sc::MasterKey &master = master_for(in.u8() % 5);
    const bool raw              = in.u8() & 1;
    const sc::AeadSpec &spec    = master.spec;
    std::vector<std::uint8_t> packet;
    if (raw) {
        auto r = in.rest();
        packet.assign(r.begin(), r.end());
    } else {
        auto salt = in.take(spec.key_len);
        auto body = in.rest();
        packet.assign(salt.begin(), salt.end());
        if (salt.size() == spec.key_len) {
            std::array<std::uint8_t, sc::kMaxKey> subkey{};
            sc::AeadEngine engine;
            if (!sc::derive_subkey(master, salt, { subkey.data(), spec.key_len })
                || !engine.init(spec, { subkey.data(), spec.key_len })) {
                __builtin_trap();
            }
            std::uint8_t nonce[sc::kMaxNonce] = {};
            packet.resize(spec.key_len + body.size() + sc::kTag);
            if (!engine.seal(packet.data() + spec.key_len, body, nonce)) {
                packet.resize(spec.key_len);
            }
        }
    }
    std::vector<std::uint8_t> out(packet.size() + 1);
    auto opened = sc::aead_udp_open(master, { packet.data(), packet.size() }, { out.data(), out.size() },
                                    sc::ReplayFilter{});
    if (opened) {
        parse_header({ out.data(), opened.value() });
    }
}

static void raw2022(fuzz::Input &in)
{
    const sc::Psk psk   = psk_for(in.u8() % 3);
    const sc::Role role = (in.u8() & 1) ? sc::Role::client : sc::Role::server;
    sc::UdpSession2022 session;
    receive(psk, role, session, in.rest());
}

static void built2022(fuzz::Input &in)
{
    const sc::Psk psk   = psk_for(2); // the XChaCha20 variant encrypts header and body with the PSK
    const std::uint8_t flags = in.u8();
    const sc::Role role = (flags & 1) ? sc::Role::client : sc::Role::server;
    sc::UdpSession2022 session;
    for (int i = 0; i < 16 && in.remaining() != 0; ++i) {
        std::size_t len = in.u16();
        auto nonce      = in.take(sc::kUdpXNonce);
        if (nonce.size() != sc::kUdpXNonce) {
            break;
        }
        auto plain_in = in.take(len);
        std::vector<std::uint8_t> plain(plain_in.begin(), plain_in.end());
        if ((flags & 2) && plain.size() >= sc::kUdpSepHeader + 9) {
            std::uint64_t t = now();
            for (int b = 0; b < 8; ++b) {
                plain[sc::kUdpSepHeader + 1 + b] = static_cast<std::uint8_t>(t >> (56 - 8 * b));
            }
        }
        std::vector<std::uint8_t> packet(sc::kUdpXNonce + plain.size() + sc::kTag);
        std::copy(nonce.begin(), nonce.end(), packet.begin());
        unsigned long long clen = 0;
        crypto_aead_xchacha20poly1305_ietf_encrypt(packet.data() + sc::kUdpXNonce, &clen, plain.data(),
                                                   plain.size(), nullptr, 0, nullptr, packet.data(),
                                                   psk.bytes.data());
        receive(psk, role, session, { packet.data(), packet.size() });
    }
}

static void roundtrip2022(fuzz::Input &in)
{
    const sc::Psk psk = psk_for(in.u8() % 3);
    sc::UdpSession2022 client, server;
    std::vector<std::vector<std::uint8_t>> packets;
    for (int i = 0; i < 16 && in.remaining() != 0; ++i) {
        std::size_t len = in.u16() % 2048;
        auto payload    = in.take(len);
        std::vector<std::uint8_t> out(sc::udp2022_overhead(psk, sc::Role::client) + payload.size());
        auto n = sc::udp2022_seal(psk, sc::Role::client, client, payload, { out.data(), out.size() });
        if (!n) {
            __builtin_trap(); // sealing into a buffer of udp2022_overhead()+len must succeed
        }
        out.resize(n.value());
        packets.push_back(std::move(out));
    }
    // Delivery: each control byte picks a packet (replays and reordering allowed), and may truncate
    // it or flip one byte.
    for (int i = 0; i < 32 && in.remaining() >= 3 && !packets.empty(); ++i) {
        std::vector<std::uint8_t> p = packets[in.u8() % packets.size()];
        std::uint8_t op = in.u8(), arg = in.u8();
        if (op & 1) {
            p[arg % p.size()] ^= static_cast<std::uint8_t>(op | 1);
        }
        if (op & 2) {
            p.resize(arg % (p.size() + 1));
        }
        receive(psk, sc::Role::server, server, { p.data(), p.size() });
    }
    // Reply from the server to the client.
    if (server.peer_known && !packets.empty()) {
        const std::uint8_t msg[] = "mayhem-reply";
        std::vector<std::uint8_t> out(sc::udp2022_overhead(psk, sc::Role::server) + sizeof(msg));
        auto n = sc::udp2022_seal(psk, sc::Role::server, server, msg, { out.data(), out.size() });
        if (n) {
            receive(psk, sc::Role::client, client, { out.data(), n.value() });
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    fuzz::ensure_sodium();
    fuzz::Input in(data, size);
    switch (in.u8() % 4) {
    case 0: classic(in); break;
    case 1: raw2022(in); break;
    case 2: built2022(in); break;
    default: roundtrip2022(in); break;
    }
    return 0;
}
