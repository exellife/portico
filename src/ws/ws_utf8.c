/* portico — UTF-8 validation for WebSocket text frames and close reasons
 * (RFC 6455 §5.6 / §7.1.5). Branchless DFA decoder by Bjoern Hoehrmann
 * (http://bjoern.hoehrmann.de/utf-8/decoder/dfa/, MIT). It rejects overlong
 * encodings, surrogates, and code points > U+10FFFF — exactly the cases the
 * Autobahn UTF-8 suite exercises. */
#include <stddef.h>
#include <stdint.h>

#define UTF8_ACCEPT 0
#define UTF8_REJECT 12

static const uint8_t utf8d[] = {
    /* byte -> character class */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8,
    /* state + class -> next state */
    0,12,24,36,60,96,84,12,12,12,48,72, 12,12,12,12,12,12,12,12,12,12,12,12,
    12, 0,12,12,12,12,12, 0,12, 0,12,12, 12,24,12,12,12,12,12,24,12,24,12,12,
    12,12,12,12,12,12,12,24,12,12,12,12, 12,24,12,12,12,12,12,12,12,24,12,12,
    12,12,12,12,12,12,12,36,12,36,12,12, 12,36,12,12,12,12,12,36,12,36,12,12,
    12,36,12,12,12,12,12,12,12,12,12,12,
};

static inline uint32_t utf8_decode(uint32_t *state, uint32_t *codep, uint32_t byte) {
    uint32_t type = utf8d[byte];
    *codep = (*state != UTF8_ACCEPT) ? (byte & 0x3fu) | (*codep << 6)
                                     : (0xffu >> type) & byte;
    *state = utf8d[256 + *state + type];
    return *state;
}

/* True if [s, s+len) is a complete, well-formed UTF-8 string. */
int ws_utf8_valid(const uint8_t *s, size_t len) {
    uint32_t state = UTF8_ACCEPT, codep = 0;
    for (size_t i = 0; i < len; i++)
        if (utf8_decode(&state, &codep, s[i]) == UTF8_REJECT) return 0;
    return state == UTF8_ACCEPT;
}
