/*
 * hd_crypto.c — SHA-256 / HMAC-SHA256 实现（RFC 6234 / RFC 2104）
 * ver.0.0.8
 *
 * 正确性由 tests/test_crypto.c 里的官方向量保证：
 *   SHA-256("") / SHA-256("abc") / SHA-256(56字节串) / RFC 4231 Test Case 1,2,3
 * 任何一个常数写错都会立刻被这些向量打出来。
 */
#include "hd_crypto.h"

#include <string.h>

/* SHA-256 轮常数：前 64 个素数立方根小数部分前 32 位（FIPS 180-4） */
static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint32_t H256[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(hd_sha256* ctx, const uint8_t* p)
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

void hd_sha256_init(hd_sha256* ctx)
{
    if (!ctx) return;
    memcpy(ctx->h, H256, sizeof(H256));
    ctx->total = 0;
    ctx->buflen = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void hd_sha256_update(hd_sha256* ctx, const void* data, size_t len)
{
    const uint8_t* p = (const uint8_t*)data;

    if (!ctx || (!p && len)) return;
    ctx->total += (uint64_t)len;

    if (ctx->buflen) {
        size_t need = 64 - ctx->buflen;
        size_t take = len < need ? len : need;
        memcpy(ctx->buf + ctx->buflen, p, take);
        ctx->buflen += take;
        p += take;
        len -= take;
        if (ctx->buflen == 64) {
            sha256_block(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
    while (len >= 64) {
        sha256_block(ctx, p);
        p += 64;
        len -= 64;
    }
    if (len) {
        memcpy(ctx->buf, p, len);
        ctx->buflen = len;
    }
}

void hd_sha256_final(hd_sha256* ctx, uint8_t out[HD_SHA256_LEN])
{
    uint64_t bits;
    int i;

    if (!ctx || !out) return;
    bits = ctx->total * 8ULL;

    /* 填充：0x80，然后补零到 56 mod 64，最后 8 字节大端比特长度 */
    ctx->buf[ctx->buflen++] = 0x80;
    if (ctx->buflen > 56) {
        memset(ctx->buf + ctx->buflen, 0, 64 - ctx->buflen);
        sha256_block(ctx, ctx->buf);
        ctx->buflen = 0;
    }
    memset(ctx->buf + ctx->buflen, 0, 56 - ctx->buflen);
    for (i = 0; i < 8; i++) {
        ctx->buf[56 + i] = (uint8_t)(bits >> (56 - i * 8));
    }
    sha256_block(ctx, ctx->buf);
    ctx->buflen = 0;

    for (i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(ctx->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->h[i]);
    }
}

void hd_hex_encode(const uint8_t* in, size_t len, char* out)
{
    static const char* hex = "0123456789abcdef";
    size_t i;

    if (!out) return;
    if (!in) { out[0] = '\0'; return; }
    for (i = 0; i < len; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int hex_val(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

int hd_hex_decode(const char* hex, uint8_t* out, size_t out_cap)
{
    size_t n, i;

    if (!hex || !out) return -1;
    n = strlen(hex);
    if (n % 2 != 0) return -1;
    if (n / 2 > out_cap) return -1;
    for (i = 0; i < n / 2; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

void hd_sha256_once(const void* data, size_t len, uint8_t* digest_out, char* hex_out)
{
    hd_sha256 ctx;
    uint8_t d[HD_SHA256_LEN];

    hd_sha256_init(&ctx);
    hd_sha256_update(&ctx, data, len);
    hd_sha256_final(&ctx, d);
    if (digest_out) memcpy(digest_out, d, HD_SHA256_LEN);
    if (hex_out) hd_hex_encode(d, HD_SHA256_LEN, hex_out);
    memset(d, 0, sizeof(d));
}

void hd_hmac_sha256(const void* key, size_t keylen,
                    const void* data, size_t datalen,
                    uint8_t* digest_out, char* hex_out)
{
    uint8_t k[64];
    uint8_t pad[64];
    uint8_t inner[HD_SHA256_LEN];
    uint8_t outer[HD_SHA256_LEN];
    hd_sha256 ctx;
    size_t i;

    memset(k, 0, sizeof(k));
    if (key && keylen > 64) {
        hd_sha256_once(key, keylen, k, NULL);        /* 超长密钥先取摘要 */
    } else if (key && keylen) {
        memcpy(k, key, keylen);
    }

    /* inner = SHA256((k ^ ipad) || data) */
    for (i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x36);
    hd_sha256_init(&ctx);
    hd_sha256_update(&ctx, pad, 64);
    hd_sha256_update(&ctx, data, datalen);
    hd_sha256_final(&ctx, inner);

    /* outer = SHA256((k ^ opad) || inner) */
    for (i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x5c);
    hd_sha256_init(&ctx);
    hd_sha256_update(&ctx, pad, 64);
    hd_sha256_update(&ctx, inner, sizeof(inner));
    hd_sha256_final(&ctx, outer);

    if (digest_out) memcpy(digest_out, outer, HD_SHA256_LEN);
    if (hex_out) hd_hex_encode(outer, HD_SHA256_LEN, hex_out);

    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
    memset(inner, 0, sizeof(inner));
}

void hd_hmac_sha256v(const void* key, size_t keylen,
                     const void* d1, size_t l1,
                     const void* d2, size_t l2,
                     const void* d3, size_t l3,
                     uint8_t* digest_out, char* hex_out)
{
    uint8_t k[64];
    uint8_t pad[64];
    uint8_t inner[HD_SHA256_LEN];
    uint8_t outer[HD_SHA256_LEN];
    hd_sha256 ctx;
    size_t i;

    memset(k, 0, sizeof(k));
    if (key && keylen > 64) {
        hd_sha256_once(key, keylen, k, NULL);
    } else if (key && keylen) {
        memcpy(k, key, keylen);
    }

    for (i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x36);
    hd_sha256_init(&ctx);
    hd_sha256_update(&ctx, pad, 64);
    if (d1 && l1) hd_sha256_update(&ctx, d1, l1);
    if (d2 && l2) hd_sha256_update(&ctx, d2, l2);
    if (d3 && l3) hd_sha256_update(&ctx, d3, l3);
    hd_sha256_final(&ctx, inner);

    for (i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x5c);
    hd_sha256_init(&ctx);
    hd_sha256_update(&ctx, pad, 64);
    hd_sha256_update(&ctx, inner, sizeof(inner));
    hd_sha256_final(&ctx, outer);

    if (digest_out) memcpy(digest_out, outer, HD_SHA256_LEN);
    if (hex_out) hd_hex_encode(outer, HD_SHA256_LEN, hex_out);

    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
    memset(inner, 0, sizeof(inner));
}