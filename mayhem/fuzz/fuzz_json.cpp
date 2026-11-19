// JSON parser (src/json.cpp, json_parse_ex): the parser behind config files (read_jconf) and the
// ss-manager control commands received over its UDP/unix socket.
// Input: [0] bit0 = json_enable_comments; the rest is the document (NUL-terminated copy, as
// read_jconf passes it). The resulting tree is walked and freed.
#include <cstdint>
#include <cstring>
#include <vector>

#include "json.h"

static std::size_t walk(const json_value *v, int depth)
{
    if (v == nullptr || depth > 10000) {
        return 0;
    }
    std::size_t n = 1;
    switch (v->type) {
    case json_object:
        for (unsigned i = 0; i < v->u.object.length; ++i) {
            n += std::strlen(v->u.object.values[i].name) == v->u.object.values[i].name_length;
            n += walk(v->u.object.values[i].value, depth + 1);
        }
        break;
    case json_array:
        for (unsigned i = 0; i < v->u.array.length; ++i) {
            n += walk(v->u.array.values[i], depth + 1);
        }
        break;
    case json_string:
        n += v->u.string.ptr[v->u.string.length] == '\0';
        break;
    default:
        break;
    }
    return n;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    if (size == 0) {
        return -1;
    }
    json_settings settings{};
    settings.settings = (data[0] & 1) ? json_enable_comments : 0;
    std::vector<char> doc(data + 1, data + size);
    doc.push_back('\0');
    char error[512];
    json_value *v = json_parse_ex(&settings, doc.data(), doc.size() - 1, error);
    if (v != nullptr) {
        volatile std::size_t n = walk(v, 0);
        (void)n;
        json_value_free(v);
    }
    return 0;
}
