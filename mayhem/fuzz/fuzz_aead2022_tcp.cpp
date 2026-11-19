// Shadowsocks 2022 (SIP022) TCP stream decoder: ss::crypto::Aead2022TcpDecryptor, in the server
// role (decoding a client's request: fixed header, variable header with address, padding and
// initial payload, then chunks) and the client role (decoding a server's response, which echoes
// the request salt).
//
// Input layout:
//   [0] method (2022-blake3-aes-128-gcm, -aes-256-gcm, -chacha20-poly1305)
//   [1] flags: bit0 = client role, bit1 = raw stream, bit2 = stamp the current time into the
//       first record (see below)
//   [2] slice seed (0 = one piece), [3] output buffer size selector
//   client role: the request salt the response must echo (key length bytes)
//   then: salt (key length bytes) followed by records {u16 len, bytes} that the harness seals
//   with the session subkey, so the decoder sees an authentic stream with fuzz-controlled headers.
// The fixed header carries a Unix timestamp that must be within 30 s of the decoder's clock; no
// stored seed can satisfy that, so when bit2 is set the harness writes the current time into
// bytes 1..8 of the first record, as every real SIP022 peer does.
// Per-input state only: fresh decryptor, no salt pool (it would remember salts across inputs).
#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <vector>

#include "crypto/aead2022.hpp"
#include "fuzz_input.hpp"

namespace sc = ss::crypto;

static const char *const kMethods[] = { "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                        "2022-blake3-chacha20-poly1305" };
static constexpr std::size_t kMethodCount = sizeof(kMethods) / sizeof(kMethods[0]);

static sc::Psk psk_for(std::size_t i)
{
    auto spec = sc::find_aead2022(kMethods[i]);
    if (!spec) {
        __builtin_trap();
    }
    std::array<std::uint8_t, sc::kMaxKey> bytes{};
    for (std::size_t k = 0; k < bytes.size(); ++k) {
        bytes[k] = static_cast<std::uint8_t>(0x5a ^ (k * 7));
    }
    return sc::Psk(*spec, bytes);
}

static std::size_t out_size_for(std::uint8_t sel)
{
    static const std::size_t sizes[] = { sc::k2022MaxChunk, 1, 16, 100, 4096, sc::kMaxChunk, 0x20000 };
    return sizes[sel % (sizeof(sizes) / sizeof(sizes[0]))];
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    fuzz::ensure_sodium();
    fuzz::Input in(data, size);
    const sc::Psk psk          = psk_for(in.u8() % kMethodCount);
    const std::uint8_t flags   = in.u8();
    const std::uint8_t split   = in.u8();
    const std::size_t out_size = out_size_for(in.u8());
    const std::size_t key_len  = psk.size();
    const sc::Role role        = (flags & 1) ? sc::Role::client : sc::Role::server;

    std::span<const std::uint8_t> request_salt;
    if (role == sc::Role::client) {
        request_salt = in.take(key_len);
        if (request_salt.size() != key_len) {
            return -1;
        }
    }

    std::vector<std::uint8_t> wire;
    if (flags & 2) {
        auto raw = in.rest();
        wire.assign(raw.begin(), raw.end());
    } else {
        auto salt = in.take(key_len);
        if (salt.size() != key_len) {
            return -1;
        }
        wire.assign(salt.begin(), salt.end());
        std::array<std::uint8_t, sc::kMaxKey> subkey{};
        sc::derive_subkey_2022(psk.key(), salt, { subkey.data(), key_len });
        sc::AeadEngine engine;
        if (!engine.init(psk.spec.aead, { subkey.data(), key_len })) {
            __builtin_trap();
        }
        const bool stamp = (flags & 4) != 0;
        fuzz::seal_records(in, engine, psk.spec.aead.nonce_len, wire, 256,
                           [stamp](std::size_t index, std::vector<std::uint8_t> &plain) {
                               if (stamp && index == 0 && plain.size() >= 9) {
                                   std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));
                                   for (int b = 0; b < 8; ++b) {
                                       plain[1 + b] = static_cast<std::uint8_t>(now >> (56 - 8 * b));
                                   }
                               }
                           });
    }

    sc::Aead2022TcpDecryptor dec;
    if (!dec.init(psk, role, request_salt, nullptr)) {
        __builtin_trap();
    }
    (void)fuzz::feed(dec, { wire.data(), wire.size() }, split, out_size);
    return 0;
}
