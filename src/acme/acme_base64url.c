/* base64url (RFC 4648 §5): base64 with the URL-safe alphabet and no padding —
 * the encoding ACME/JWS use everywhere (signatures, thumbprints, the CSR, tokens). */
#include "acme_internal.h"

#include <string.h>

static const char ENC[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int portico_b64url_encode(const unsigned char *in, size_t len, char *out, size_t outcap) {
    size_t rem = len % 3;
    size_t outlen = (len / 3) * 4 + (rem ? rem + 1 : 0);   /* no padding */
    if (outlen + 1 > outcap) return -1;

    size_t i = 0, o = 0;
    for (; i + 3 <= len; i += 3) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];
        out[o++] = ENC[(v >> 18) & 63];
        out[o++] = ENC[(v >> 12) & 63];
        out[o++] = ENC[(v >> 6) & 63];
        out[o++] = ENC[v & 63];
    }
    if (rem == 1) {
        unsigned v = (unsigned)in[i] << 16;
        out[o++] = ENC[(v >> 18) & 63];
        out[o++] = ENC[(v >> 12) & 63];
    } else if (rem == 2) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8);
        out[o++] = ENC[(v >> 18) & 63];
        out[o++] = ENC[(v >> 12) & 63];
        out[o++] = ENC[(v >> 6) & 63];
    }
    out[o] = '\0';
    return (int)o;
}

int portico_b64url_decode(const char *in, size_t len, unsigned char *out, size_t outcap) {
    signed char dec[256];
    memset(dec, -1, sizeof dec);
    for (int k = 0; k < 64; k++) dec[(unsigned char)ENC[k]] = (signed char)k;

    if (len % 4 == 1) return -1;   /* impossible base64url length */

    size_t i = 0, o = 0;
    for (; i + 4 <= len; i += 4) {
        int a = dec[(unsigned char)in[i]],     b = dec[(unsigned char)in[i + 1]],
            c = dec[(unsigned char)in[i + 2]], d = dec[(unsigned char)in[i + 3]];
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        if (o + 3 > outcap) return -1;
        unsigned v = ((unsigned)a << 18) | ((unsigned)b << 12) | ((unsigned)c << 6) | (unsigned)d;
        out[o++] = (v >> 16) & 0xff;
        out[o++] = (v >> 8) & 0xff;
        out[o++] = v & 0xff;
    }
    size_t tail = len - i;
    if (tail == 2) {
        int a = dec[(unsigned char)in[i]], b = dec[(unsigned char)in[i + 1]];
        if (a < 0 || b < 0) return -1;
        if (o + 1 > outcap) return -1;
        out[o++] = (unsigned char)(((a << 18) | (b << 12)) >> 16);
    } else if (tail == 3) {
        int a = dec[(unsigned char)in[i]], b = dec[(unsigned char)in[i + 1]], c = dec[(unsigned char)in[i + 2]];
        if (a < 0 || b < 0 || c < 0) return -1;
        if (o + 2 > outcap) return -1;
        unsigned v = ((unsigned)a << 18) | ((unsigned)b << 12) | ((unsigned)c << 6);
        out[o++] = (v >> 16) & 0xff;
        out[o++] = (v >> 8) & 0xff;
    }
    return (int)o;
}
