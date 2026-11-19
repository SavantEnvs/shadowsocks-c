// ss:// URI parser (src/ssurl.cpp, ss_url_parse: SIP002 and legacy base64 forms, percent-decoding,
// plugin options, tag) as given to ss-local/ss-server -s/--server, plus base64_decode, which
// it uses, called directly into a small output buffer.
#include <cstdint>
#include <vector>

#include "base64.h"
#include "ssurl.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    std::vector<char> uri(data, data + size);
    uri.push_back('\0');
    ss_url_t url{};
    if (ss_url_parse(uri.data(), &url) == 0) {
        ss_url_free(&url);
    }
    std::uint8_t out[64];
    (void)base64_decode(out, uri.data(), static_cast<int>(sizeof(out)));
    return 0;
}
