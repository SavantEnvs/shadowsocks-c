// Shared helpers for the shadowsocks-c harnesses: a byte reader over the fuzz input, and a
// builder that turns fuzz bytes into an AUTHENTIC encrypted TCP stream.
//
// The decryptors authenticate every chunk (AES-GCM / ChaCha20-Poly1305), so raw fuzz bytes never
// get past the first tag. To reach the code after authentication (length checks, chunk
// reassembly, SIP022 headers) the harness seals fuzz-chosen plaintext records itself, with a salt
// taken from the input and the same key the decryptor uses -- what a real peer does on the wire.
#ifndef SS_MAYHEM_FUZZ_INPUT_HPP
#define SS_MAYHEM_FUZZ_INPUT_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <sodium.h>

#include "crypto/aead.hpp"

namespace fuzz {

class Input {
public:
    Input(const std::uint8_t *data, std::size_t size) : data_(data), size_(size) {}
    std::size_t remaining() const { return size_ - pos_; }
    std::uint8_t u8()
    {
        return pos_ < size_ ? data_[pos_++] : 0;
    }
    std::uint16_t u16()
    {
        std::uint16_t hi = u8();
        return static_cast<std::uint16_t>((hi << 8) | u8());
    }
    // Up to n bytes (fewer at the end of the input).
    std::span<const std::uint8_t> take(std::size_t n)
    {
        n = n < remaining() ? n : remaining();
        std::span<const std::uint8_t> s(data_ + pos_, n);
        pos_ += n;
        return s;
    }
    std::span<const std::uint8_t> rest() { return take(remaining()); }

private:
    const std::uint8_t *data_;
    std::size_t size_;
    std::size_t pos_ = 0;
};

inline void ensure_sodium()
{
    static const int ok = sodium_init();
    (void)ok;
}

// Seals records read from `in` with `engine` (nonce starting at zero, incremented per seal, as both
// cipher families do) and appends them to `wire`. Each record is a u16 plaintext length followed
// by that many bytes. `stamp` (may be null) may rewrite a record's plaintext before it is sealed.
template <class Stamp>
void seal_records(Input &in, ss::crypto::AeadEngine &engine, std::size_t nonce_len,
                  std::vector<std::uint8_t> &wire, std::size_t max_records, Stamp stamp)
{
    std::uint8_t nonce[ss::crypto::kMaxNonce] = {};
    std::vector<std::uint8_t> plain;
    for (std::size_t i = 0; i < max_records && in.remaining() != 0; ++i) {
        std::size_t len = in.u16();
        auto bytes      = in.take(len);
        plain.assign(bytes.begin(), bytes.end());
        stamp(i, plain);
        std::size_t at = wire.size();
        wire.resize(at + plain.size() + ss::crypto::kTag);
        if (!engine.seal(wire.data() + at, { plain.data(), plain.size() }, nonce)) {
            wire.resize(at);
            return;
        }
        sodium_increment(nonce, nonce_len);
    }
}

// Feeds `wire` to a decryptor in fuzz-chosen slices with a fuzz-chosen output buffer size.
// Returns the number of plaintext bytes produced.
template <class Decryptor>
std::size_t feed(Decryptor &dec, std::span<const std::uint8_t> wire, std::uint8_t split_seed,
                 std::size_t out_size)
{
    std::vector<std::uint8_t> out(out_size);
    std::size_t produced = 0, at = 0;
    std::uint32_t lcg = split_seed | 1u;
    while (true) {
        std::size_t slice = wire.size() - at;
        if (split_seed != 0 && slice != 0) {
            lcg   = lcg * 1103515245u + 12345u;
            slice = 1 + (lcg >> 8) % (slice < 4096 ? slice : 4096);
        }
        auto r = dec.decrypt(wire.subspan(at, slice), { out.data(), out.size() });
        if (!r) {
            break;
        }
        at += r.value().consumed;
        produced += r.value().produced;
        if (r.value().consumed == 0 && r.value().produced == 0) {
            break; // drained, or no progress (output too small for the next chunk)
        }
    }
    return produced;
}

} // namespace fuzz

#endif
