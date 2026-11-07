/* hd_sec.c — 传输加密（PROTOCOL §8）：派生与记录层 */

#include "hd_sec.h"
#include "hd_crypto.h"
#include "hd_aead.h"

#include <string.h>
#include <stdio.h>

/* ==========================================================================
 * 小工具
 * ========================================================================== */
static void be32_write(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t be32_read(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void be64_write(uint8_t* p, uint64_t v)
{
    int i;
    for (i = 7; i >= 0; i--) { p[i] = (uint8_t)(v & 0xffu); v >>= 8; }
}

static uint64_t be64_read(const uint8_t* p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void hd_sec_hex_encode(const void* in, size_t n, char* out)
{
    static const char digits[] = "0123456789abcdef";
    const unsigned char* p = (const unsigned char*)in;
    size_t i;

    if (!out) return;
    if (!in || n == 0) { out[0] = '\0'; return; }
    for (i = 0; i < n; i++) {
        out[i * 2]     = digits[(p[i] >> 4) & 0x0f];
        out[i * 2 + 1] = digits[p[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

int hd_sec_hex_decode(const char* hex, size_t n, void* out)
{
    unsigned char* p = (unsigned char*)out;
    size_t i;

    if (!hex || !out || strlen(hex) != n * 2) return -1;
    for (i = 0; i < n; i++) {
        int hi = hexval((unsigned char)hex[i * 2]);
        int lo = hexval((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        p[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

int hd_sec_ct_eq(const void* a, const void* b, size_t n)
{
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    unsigned char diff = 0;
    size_t i;

    if (!a || !b) return 0;
    for (i = 0; i < n; i++) diff |= (unsigned char)(x[i] ^ y[i]);
    return diff == 0;
}

/* ==========================================================================
 * §8.2 派生
 * ========================================================================== */
static const char INFO_AUTH[]   = "hamster-auth/v1";
static const char INFO_C2S[]    = "hamster-rec-c2s/v2";
static const char INFO_S2C[]    = "hamster-rec-s2c/v2";
static const char PREFIX_PROOF_C[] = "hamster-client-proof/v2\n";
static const char PREFIX_PROOF_S[] = "hamster-server-proof/v2\n";

void hd_sec_master(const void* secret, size_t slen,
                   const uint8_t salt[HD_SEC_SALT_LEN], uint8_t master[HD_SEC_KEY_LEN])
{
    if (!master) return;
    hd_hkdf_sha256(salt, HD_SEC_SALT_LEN, secret, slen,
                   INFO_AUTH, sizeof(INFO_AUTH) - 1, master, HD_SEC_KEY_LEN);
}

void hd_sec_proof_c(const uint8_t master[HD_SEC_KEY_LEN],
                    const char* nc_hex, const char* ns_hex, const char* device_id,
                    uint8_t out[HD_SEC_KEY_LEN])
{
    char msg[256];
    int n;

    if (!out) return;
    if (!nc_hex || !ns_hex) { memset(out, 0, HD_SEC_KEY_LEN); return; }
    /* device_id 在握手入口已限制在 63 字节以内；这里再截断一次保证不会溢出 */
    n = snprintf(msg, sizeof(msg), "%s%s\n%s\n%.96s",
                 PREFIX_PROOF_C, nc_hex, ns_hex, device_id ? device_id : "");
    if (n <= 0 || (size_t)n >= sizeof(msg)) { memset(out, 0, HD_SEC_KEY_LEN); return; }
    hd_hmac_sha256(master, HD_SEC_KEY_LEN, msg, (size_t)n, out, NULL);
}

void hd_sec_proof_s(const uint8_t master[HD_SEC_KEY_LEN],
                    const char* nc_hex, const char* ns_hex,
                    uint8_t out[HD_SEC_KEY_LEN])
{
    char msg[128];
    int n;

    if (!out) return;
    if (!nc_hex || !ns_hex) { memset(out, 0, HD_SEC_KEY_LEN); return; }
    n = snprintf(msg, sizeof(msg), "%s%s\n%s", PREFIX_PROOF_S, nc_hex, ns_hex);
    if (n <= 0 || (size_t)n >= sizeof(msg)) { memset(out, 0, HD_SEC_KEY_LEN); return; }
    hd_hmac_sha256(master, HD_SEC_KEY_LEN, msg, (size_t)n, out, NULL);
}

static void rec_key(uint8_t out[HD_SEC_KEY_LEN], const uint8_t salt[HD_SEC_SALT_LEN],
                    const uint8_t master[HD_SEC_KEY_LEN],
                    const char* info, const char* nc_hex, const char* ns_hex)
{
    /* info = 前缀 + nc + ns（按 ASCII 文本拼接，与 JS 侧一致） */
    char full[128];
    int n = snprintf(full, sizeof(full), "%s%s%s", info, nc_hex, ns_hex);

    if (n <= 0 || (size_t)n >= sizeof(full)) { memset(out, 0, HD_SEC_KEY_LEN); return; }
    hd_hkdf_sha256(salt, HD_SEC_SALT_LEN, master, HD_SEC_KEY_LEN, full, (size_t)n,
                   out, HD_SEC_KEY_LEN);
}

int hd_sec_init(hd_sec* s, const uint8_t master[HD_SEC_KEY_LEN],
                const uint8_t salt[HD_SEC_SALT_LEN],
                const char* nc_hex, const char* ns_hex, int is_server)
{
    uint8_t k_c2s[HD_SEC_KEY_LEN];
    uint8_t k_s2c[HD_SEC_KEY_LEN];

    if (!s || !master || !salt || !nc_hex || !ns_hex) return -1;
    if (strlen(nc_hex) != HD_SEC_HEX16_LEN || strlen(ns_hex) != HD_SEC_HEX16_LEN) return -1;

    rec_key(k_c2s, salt, master, INFO_C2S, nc_hex, ns_hex);
    rec_key(k_s2c, salt, master, INFO_S2C, nc_hex, ns_hex);

    memset(s, 0, sizeof(*s));
    if (is_server) {
        memcpy(s->key_out, k_s2c, HD_SEC_KEY_LEN);
        memcpy(s->key_in,  k_c2s, HD_SEC_KEY_LEN);
        s->dir_out = HD_SEC_DIR_S2C;
        s->dir_in  = HD_SEC_DIR_C2S;
    } else {
        memcpy(s->key_out, k_c2s, HD_SEC_KEY_LEN);
        memcpy(s->key_in,  k_s2c, HD_SEC_KEY_LEN);
        s->dir_out = HD_SEC_DIR_C2S;
        s->dir_in  = HD_SEC_DIR_S2C;
    }
    s->ctr_out = 0;
    s->ctr_in  = 0;
    s->active  = 1;
    return 0;
}

/* ==========================================================================
 * §8.3 记录层
 * ========================================================================== */
static void mk_nonce(uint8_t nonce[HD_AEAD_NONCE_LEN], uint64_t ctr)
{
    memset(nonce, 0, 4);
    be64_write(nonce + 4, ctr);
}

static void mk_aad(uint8_t aad[9], uint8_t dir, uint64_t ctr)
{
    aad[0] = dir;
    be64_write(aad + 1, ctr);
}

size_t hd_sec_seal(hd_sec* s, const void* plain, size_t len, void* out)
{
    uint8_t nonce[HD_AEAD_NONCE_LEN];
    uint8_t aad[9];
    uint8_t* p = (uint8_t*)out;

    if (!s || !s->active || !plain || !out) return 0;
    if (len == 0 || len > HD_SEC_MAX_PLAIN) return 0;

    mk_nonce(nonce, s->ctr_out);
    mk_aad(aad, s->dir_out, s->ctr_out);

    be32_write(p, (uint32_t)len);
    be64_write(p + 4, s->ctr_out);

    if (hd_chacha20_poly1305_seal(s->key_out, nonce, aad, sizeof(aad),
                                  plain, len, p + HD_SEC_HDR_LEN,
                                  p + HD_SEC_HDR_LEN + len) != 0) return 0;

    s->ctr_out++;
    return HD_SEC_HDR_LEN + len + HD_SEC_TAG_LEN;
}

int hd_sec_open(hd_sec* s, const void* rec, size_t reclen, void* out, size_t outcap)
{
    const uint8_t* p = (const uint8_t*)rec;
    uint8_t nonce[HD_AEAD_NONCE_LEN];
    uint8_t aad[9];
    uint32_t len;
    uint64_t ctr;

    if (!s || !s->active || !rec || !out) return -1;
    if (reclen < HD_SEC_HDR_LEN + 1 + HD_SEC_TAG_LEN) return -1;

    len = be32_read(p);
    if (len == 0 || len > HD_SEC_MAX_PLAIN) return -1;
    if (reclen != HD_SEC_HDR_LEN + (size_t)len + HD_SEC_TAG_LEN) return -1;
    if (outcap < len) return -1;

    ctr = be64_read(p + 4);
    /* TCP 有序，序号必须严格等于期望值：小于=重放，大于=丢包/乱序 */
    if (ctr != s->ctr_in) {
        return -1;
    }

    mk_nonce(nonce, ctr);
    mk_aad(aad, s->dir_in, ctr);

    if (hd_chacha20_poly1305_open(s->key_in, nonce, aad, sizeof(aad),
                                  p + HD_SEC_HDR_LEN, (size_t)len,
                                  p + HD_SEC_HDR_LEN + (size_t)len,
                                  (uint8_t*)out) != 0) {
        return -1;
    }
    s->ctr_in++;
    return (int)len;
}
