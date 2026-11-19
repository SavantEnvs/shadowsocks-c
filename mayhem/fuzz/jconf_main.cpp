// File-input driver for read_jconf (src/jconf.cpp): the JSON config file every shadowsocks
// program loads with -c (servers, port_password, DSCP map, integer ranges, addresses).
// read_jconf() calls FATAL() -> exit(-1) on any invalid config, so this is an AFL target run
// once per input file (`fuzz_jconf <file>`), not an in-process harness.
#include <cstdio>

#include "netutils.h"
#include "jconf.h"

extern "C" {
int verbose = 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <config.json>\n", argv[0]);
        return 2;
    }
    jconf_t *conf = read_jconf(argv[1]);
    std::printf("remote_num=%d port_password_num=%d dscp_num=%d mode=%d\n", conf->remote_num,
                conf->port_password_num, conf->dscp_num, conf->mode);
    return 0;
}
