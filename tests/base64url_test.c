/* base64url codec (RFC 4648 §5) + cJSON vendoring sanity. No network. */
#include "acme_internal.h"
#include <cjson/cJSON.h>

#include <stdio.h>
#include <string.h>

static int ok = 0, fail = 0;
static void chk(const char *n, int c, const char *d) {
    printf("  %-5s %-34s %s\n", c ? "ok" : "FAIL", n, d ? d : "");
    if (c) ok++; else fail++;
}

/* encode(in) == want ? */
static int enc_eq(const char *in, const char *want) {
    char out[128];
    int n = portico_b64url_encode((const unsigned char *)in, strlen(in), out, sizeof out);
    return n == (int)strlen(want) && strcmp(out, want) == 0;
}

int main(void) {
    printf("== base64url + cJSON ==\n");

    /* RFC 4648 base64 vectors, padding stripped (base64url). */
    chk("'' -> ''",            enc_eq("", ""), NULL);
    chk("'f' -> Zg",           enc_eq("f", "Zg"), NULL);
    chk("'fo' -> Zm8",         enc_eq("fo", "Zm8"), NULL);
    chk("'foo' -> Zm9v",       enc_eq("foo", "Zm9v"), NULL);
    chk("'foob' -> Zm9vYg",    enc_eq("foob", "Zm9vYg"), NULL);
    chk("'fooba' -> Zm9vYmE",  enc_eq("fooba", "Zm9vYmE"), NULL);
    chk("'foobar' -> Zm9vYmFy",enc_eq("foobar", "Zm9vYmFy"), NULL);

    /* URL-safe alphabet: bytes that yield '-' (62) and '_' (63). */
    { char o[8]; unsigned char b[] = {0xFB}; portico_b64url_encode(b, 1, o, sizeof o);
      chk("0xFB -> '-w' (dash)", strcmp(o, "-w") == 0, o); }
    { char o[8]; unsigned char b[] = {0xFF}; portico_b64url_encode(b, 1, o, sizeof o);
      chk("0xFF -> '_w' (underscore)", strcmp(o, "_w") == 0, o); }
    { char o[8]; unsigned char b[] = {0xFF, 0xFF, 0xFF}; portico_b64url_encode(b, 3, o, sizeof o);
      chk("0xFFFFFF -> '____'", strcmp(o, "____") == 0, o); }

    /* Round-trip every length 0..64 (covers all len%3 cases + 62/63 producers). */
    { int all = 1;
      for (int len = 0; len <= 64; len++) {
          unsigned char in[64], dec[64]; char enc[128];
          for (int i = 0; i < len; i++) in[i] = (unsigned char)(i * 37 + 11);
          int e = portico_b64url_encode(in, (size_t)len, enc, sizeof enc);
          int d = portico_b64url_decode(enc, (size_t)e, dec, sizeof dec);
          if (e < 0 || d != len || (len && memcmp(in, dec, (size_t)len) != 0)) { all = 0; break; }
      }
      chk("round-trip lengths 0..64", all, NULL); }

    /* Decode must reject non-base64url input. */
    { unsigned char o[8];
      chk("reject '+' (std base64)", portico_b64url_decode("ab+c", 4, o, sizeof o) == -1, NULL);
      chk("reject '/' (std base64)", portico_b64url_decode("ab/c", 4, o, sizeof o) == -1, NULL);
      chk("reject '=' padding",      portico_b64url_decode("Zg==", 4, o, sizeof o) == -1, NULL);
      chk("reject len%4==1",         portico_b64url_decode("Zg9vv", 5, o, sizeof o) == -1, NULL); }

    /* cJSON vendoring + link sanity. */
    { cJSON *j = cJSON_Parse("{\"status\":\"valid\",\"n\":42}");
      cJSON *s = j ? cJSON_GetObjectItem(j, "status") : NULL;
      cJSON *n = j ? cJSON_GetObjectItem(j, "n") : NULL;
      chk("cJSON parse + fields",
          s && cJSON_IsString(s) && strcmp(s->valuestring, "valid") == 0 && n && n->valueint == 42, NULL);
      cJSON_Delete(j); }

    printf("\n%s  (%d ok, %d failed)\n", fail ? "FAIL" : "PASS", ok, fail);
    return fail ? 1 : 0;
}
