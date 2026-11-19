// ACL files (src/acl.cpp init_acl: [black_list]/[white_list]/[proxy_all]/[bypass_all]/
// [reject_all]/[outbound_block_list] sections, IPv4/IPv6 CIDRs into src/ipset.cpp, domain
// rules compiled by src/rule.cpp with PCRE2), then the host matchers ss-local/ss-server run on
// every destination a client asks for.
// Input: ACL text, then a NUL, then the host to match (both optional parts).
// Per input: the ACL is written to a fresh temp file under $TMPDIR, loaded, matched, freed.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

#include "acl.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    const std::uint8_t *nul = static_cast<const std::uint8_t *>(std::memchr(data, 0, size));
    std::size_t acl_len     = nul ? static_cast<std::size_t>(nul - data) : size;
    std::string host        = nul ? std::string(reinterpret_cast<const char *>(nul + 1), size - acl_len - 1) : "";
    host = host.c_str(); // stop at an embedded NUL, as the C string APIs would

    const char *tmp = std::getenv("TMPDIR");
    std::string path = std::string(tmp && *tmp ? tmp : "/tmp") + "/fuzz_acl.XXXXXX";
    int fd = mkstemp(path.data());
    if (fd < 0) {
        return 0;
    }
    std::size_t off = 0;
    while (off < acl_len) {
        ssize_t w = write(fd, data + off, acl_len - off);
        if (w <= 0) {
            break;
        }
        off += static_cast<std::size_t>(w);
    }
    close(fd);
    int rc = init_acl(path.c_str());
    unlink(path.c_str());
    if (rc == 0) {
        static const char *const probes[] = { "127.0.0.1", "::1", "example.com", "10.1.2.3", "::ffff:1.2.3.4" };
        (void)acl_match_host(host.c_str());
        (void)outbound_block_match_host(host.c_str());
        for (const char *p : probes) {
            (void)acl_match_host(p);
            (void)outbound_block_match_host(p);
        }
        (void)get_acl_mode();
    }
    free_acl();
    return 0;
}
