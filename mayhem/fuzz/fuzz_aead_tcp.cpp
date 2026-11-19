// Classic AEAD TCP stream decoder (SIP004): ss::crypto::AeadTcpDecryptor, the code every
// ss-local / ss-server / ss-tunnel connection runs on the bytes it receives from its peer.
//
// Input layout:
//   [0] method (aes-128/192/256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305)
//   [1] mode: bit0 = raw (feed the rest of the input as the wire stream unchanged)
//   [2] slice seed (0 = feed in one piece), [3] output buffer size selector
//   then: salt (key length bytes) followed by records {u16 len, bytes} that the harness seals
//   with the session subkey -- so the decoder sees an authentic stream whose decrypted chunk
//   lengths and contents are fuzz-controlled.
// Per-input state only: a fresh decryptor with no replay filter (the process-wide ppbloom filter
// would make the result depend on earlier inputs). The master keys are derived once (read-only).
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "crypto/aead.hpp"
#include "fuzz_input.hpp"

namespace sc = ss::crypto;

static const char *const kMethods[] = { "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                                        "xchacha20-ietf-poly1305" };
static constexpr std::size_t kMethodCount = sizeof(kMethods) / sizeof(kMethods[0]);

static const sc::MasterKey &master_for(std::size_t i)
{
    static std::optional<sc::MasterKey> keys[kMethodCount];
    if (!keys[i]) {
        auto spec = sc::find_aead(kMethods[i]);
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

static std::size_t out_size_for(std::uint8_t sel)
{
    static const std::size_t sizes[] = { sc::kMaxChunk, 1, 16, 100, 4096, sc::kMaxChunk * 2, 0x10000 };
    return sizes[sel % (sizeof(sizes) / sizeof(sizes[0]))];
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    fuzz::ensure_sodium();
    fuzz::Input in(data, size);
    const sc::MasterKey &master = master_for(in.u8() % kMethodCount);
    const std::uint8_t mode     = in.u8();
    const std::uint8_t split    = in.u8();
    const std::size_t out_size  = out_size_for(in.u8());
    const sc::AeadSpec &spec    = master.spec;

    std::vector<std::uint8_t> wire;
    if (mode & 1) {
        auto raw = in.rest();
        wire.assign(raw.begin(), raw.end());
    } else {
        auto salt = in.take(spec.key_len);
        if (salt.size() != spec.key_len) {
            return -1;
        }
        wire.assign(salt.begin(), salt.end());
        std::array<std::uint8_t, sc::kMaxKey> subkey{};
        sc::AeadEngine engine;
        if (!sc::derive_subkey(master, salt, { subkey.data(), spec.key_len })
            || !engine.init(spec, { subkey.data(), spec.key_len })) {
            __builtin_trap(); // a fixed, valid key must always initialise
        }
        fuzz::seal_records(in, engine, spec.nonce_len, wire, 256, [](std::size_t, std::vector<std::uint8_t> &) {});
    }

    sc::AeadTcpDecryptor dec;
    if (!dec.init(master, sc::ReplayFilter{})) {
        __builtin_trap();
    }
    (void)fuzz::feed(dec, { wire.data(), wire.size() }, split, out_size);
    return 0;
}
