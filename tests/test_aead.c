/*
 * test_aead.c — ChaCha20-Poly1305（RFC 8439）与 HKDF-SHA256（RFC 5869）官方向量
 *
 * 全部向量取自标准文档。这些向量对字节序、移位量、掩码与约减时机极度敏感，
 * 任何一处写错都会立刻失败：
 *   RFC 8439 §2.4.2 ChaCha20 块函数
 *   RFC 8439 §2.5.2 Poly1305
 *   RFC 8439 §2.8.2 AEAD 完整向量（AAD + 密文 + tag）
 *   RFC 5869 附录 A.1 / A.2 / A.3
 * 另外覆盖认证失败路径（tag/密文/AAD 被改）、空明文、空 AAD 与原地解密。
 */
#include "../Hamsterd/hd_aead.h"
#include "../Hamsterd/hd_crypto.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("  [FAIL] %s  (第 %d 行)\n", msg, __LINE__); } \
} while (0)

/* ---------------- 官方测试向量（十六进制串） ---------------- */

/* RFC 8439 §2.4.2：key = 00..1f，nonce = 000000090000004a00000000，counter = 1 */
static const char V_KEY_2_4_2[] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char V_NONCE_2_4_2[] = "000000090000004a00000000";
static const char V_BLOCK_2_4_2[] =
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";

/* 附加：全零 key / nonce、counter = 0 的密钥流 */
static const char V_BLOCK_ZERO[] =
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586";

/* RFC 8439 §2.5.2：r/s 与 "Cryptographic Forum Research Group" 的 tag */
static const char V_POLY_KEY[] =
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
static const char V_POLY_TAG[] = "a8061dc1305136c6c22b8baf0c0127a9";
static const char V_POLY_MSG[] = "Cryptographic Forum Research Group";

/* RFC 8439 §2.8.2：key 80..9f，nonce 070000004041424344454647，AAD 50515253c0c1c2c3c4c5c6c7 */
static const char V_AEAD_KEY[] =
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
static const char V_AEAD_NONCE[] = "070000004041424344454647";
static const char V_AEAD_AAD[] = "50515253c0c1c2c3c4c5c6c7";
static const char V_AEAD_PLAIN[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
    "for the future, sunscreen would be it.";
static const char V_AEAD_CT[] =
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116";
static const char V_AEAD_TAG[] = "1ae10b594f09e26a7e902ecbd0600691";

/* RFC 5869 附录 A.1 / A.2 / A.3 的 OKM */
static const char V_HKDF1_OKM[] =
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865";
static const char V_HKDF2_OKM[] =
    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
    "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
    "cc30c58179ec3e87c14c01d5c1f3434f1d87";
static const char V_HKDF3_OKM[] =
    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
    "9d201395faa4b61a96c8";

/* ---------------- 小工具 ---------------- */

/* 向量用十六进制串写：比手抄字节数组易读，也少一次抄错的机会 */
static size_t vec(const char* hex, uint8_t* out, size_t cap)
{
    int n = hd_hex_decode(hex, out, cap);

    if (n < 0) {
        g_fail++;
        printf("  [FAIL] 测试向量无法解码（奇数长度 / 非法字符 / 缓冲不足）\n");
        return 0;
    }
    return (size_t)n;
}

static void dump_hex(const uint8_t* p, size_t n, char* out)
{
    static const char* digs = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[i * 2]     = digs[(p[i] >> 4) & 15u];
        out[i * 2 + 1] = digs[p[i] & 15u];
    }
    out[n * 2] = '\0';
}

/* 本文件最长向量 114 字节，512 字节的十六进制缓冲绰绰有余 */
static void expect_bytes(const uint8_t* got, const uint8_t* want, size_t n,
                         const char* msg)
{
    char a[512], b[512];

    if (memcmp(got, want, n) == 0) { g_pass++; return; }
    g_fail++;
    dump_hex(got, n, a);
    dump_hex(want, n, b);
    printf("  [FAIL] %s\n         期望 %s\n         实得 %s\n", msg, b, a);
}

int main(void)
{
    printf("Hamster AEAD 测试（ChaCha20-Poly1305 / HKDF-SHA256）\n\n");

    /* ================= RFC 8439 §2.4.2：ChaCha20 块函数 ================= */
    printf("== ChaCha20 块函数（RFC 8439 §2.4.2）\n");
    {
        uint8_t ck[32], cn[12], got[64], want[64];

        vec(V_KEY_2_4_2, ck, sizeof(ck));
        vec(V_NONCE_2_4_2, cn, sizeof(cn));
        vec(V_BLOCK_2_4_2, want, sizeof(want));
        hd_chacha20_block(ck, 1, cn, got);
        expect_bytes(got, want, sizeof(want), "counter=1 的 64 字节密钥流");
    }
    {
        /* 全零输入能同时验证 SIGMA 常量、轮函数方向与小端序列化 */
        uint8_t zk[32], zn[12], got[64], want[64];

        memset(zk, 0, sizeof(zk));
        memset(zn, 0, sizeof(zn));
        vec(V_BLOCK_ZERO, want, sizeof(want));
        hd_chacha20_block(zk, 0, zn, got);
        expect_bytes(got, want, sizeof(want), "附加向量：全零 key/nonce、counter=0");
    }

    /* ================= RFC 8439 §2.5.2：Poly1305 ================= */
    printf("== Poly1305（RFC 8439 §2.5.2）\n");
    {
        uint8_t pk[32], got[16], want[16];

        vec(V_POLY_KEY, pk, sizeof(pk));
        vec(V_POLY_TAG, want, sizeof(want));
        hd_poly1305(pk, V_POLY_MSG, sizeof(V_POLY_MSG) - 1u, got);
        expect_bytes(got, want, sizeof(want), "\"Cryptographic Forum Research Group\" 的 tag");
    }

    /* ================= RFC 8439 §2.8.2：完整 AEAD ================= */
    printf("== AEAD 完整向量（RFC 8439 §2.8.2）\n");
    {
        uint8_t ak[32], an[12], aad[12];
        uint8_t ct[128], want_ct[128], tag[16], want_tag[16], back[128];
        size_t ptlen = sizeof(V_AEAD_PLAIN) - 1u;
        int rc;

        vec(V_AEAD_KEY, ak, sizeof(ak));
        vec(V_AEAD_NONCE, an, sizeof(an));
        vec(V_AEAD_AAD, aad, sizeof(aad));
        vec(V_AEAD_CT, want_ct, sizeof(want_ct));
        vec(V_AEAD_TAG, want_tag, sizeof(want_tag));

        CHECK(ptlen == 114u, "向量明文字节数 = 114");

        memset(ct, 0, sizeof(ct));
        rc = hd_chacha20_poly1305_seal(ak, an, aad, sizeof(aad),
                                       V_AEAD_PLAIN, ptlen, ct, tag);
        CHECK(rc == 0, "seal 返回 0");
        expect_bytes(ct, want_ct, ptlen, "密文逐字节一致");
        expect_bytes(tag, want_tag, sizeof(want_tag), "tag 逐字节一致");

        memset(back, 0, sizeof(back));
        rc = hd_chacha20_poly1305_open(ak, an, aad, sizeof(aad),
                                       ct, ptlen, tag, back);
        CHECK(rc == 0, "open 接受正确 tag");
        CHECK(memcmp(back, V_AEAD_PLAIN, ptlen) == 0, "解密恢复原文");
    }

    /* ================= 认证失败路径 ================= */
    printf("== 认证失败路径\n");
    {
        uint8_t ak[32], an[12], aad[12];
        uint8_t ct[128], tag[16], out[128];
        size_t ptlen = sizeof(V_AEAD_PLAIN) - 1u;

        vec(V_AEAD_KEY, ak, sizeof(ak));
        vec(V_AEAD_NONCE, an, sizeof(an));
        vec(V_AEAD_AAD, aad, sizeof(aad));
        CHECK(hd_chacha20_poly1305_seal(ak, an, aad, sizeof(aad),
                                        V_AEAD_PLAIN, ptlen, ct, tag) == 0,
              "准备合法密文");

        /* tag 的 128 个比特逐个翻转：必须全部被拒，且输出缓冲一个字节都不能变 */
        {
            int bit, all_rejected = 1, untouched = 1;

            for (bit = 0; bit < 128; bit++) {
                uint8_t bad[16];
                size_t k;

                memcpy(bad, tag, sizeof(bad));
                bad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
                memset(out, 0xA5, sizeof(out));

                if (hd_chacha20_poly1305_open(ak, an, aad, sizeof(aad),
                                              ct, ptlen, bad, out) != -1) {
                    all_rejected = 0;
                }
                for (k = 0; k < ptlen; k++) {
                    if (out[k] != 0xA5) { untouched = 0; break; }
                }
            }
            CHECK(all_rejected, "tag 任意一位翻转 → open 全部返回 -1");
            CHECK(untouched, "认证失败时一个明文字节都不写出");
        }

        /* 篡改密文（首字节 / 末字节），tag 保持原样 */
        {
            uint8_t badct[128];

            memcpy(badct, ct, ptlen);
            badct[0] ^= 0x01;
            memset(out, 0xA5, sizeof(out));
            CHECK(hd_chacha20_poly1305_open(ak, an, aad, sizeof(aad),
                                            badct, ptlen, tag, out) == -1,
                  "密文首字节被改 → 认证失败");
            CHECK(out[0] == 0xA5, "密文被改时不写明文");

            memcpy(badct, ct, ptlen);
            badct[ptlen - 1] ^= 0x80;
            memset(out, 0xA5, sizeof(out));
            CHECK(hd_chacha20_poly1305_open(ak, an, aad, sizeof(aad),
                                            badct, ptlen, tag, out) == -1,
                  "密文末字节被改 → 认证失败");
            CHECK(out[0] == 0xA5, "密文末尾被改时也不写明文");
        }

        /* AAD、密钥、nonce 任一不同都必须失败 */
        {
            uint8_t badaad[12];
            uint8_t wrongk[32];
            uint8_t wrongn[12];

            memcpy(badaad, aad, sizeof(badaad));
            badaad[0] ^= 0x01;
            memset(out, 0xA5, sizeof(out));
            CHECK(hd_chacha20_poly1305_open(ak, an, badaad, sizeof(badaad),
                                            ct, ptlen, tag, out) == -1,
                  "AAD 被改 → 认证失败");
            CHECK(out[0] == 0xA5, "AAD 被改时不写明文");

            memcpy(wrongk, ak, sizeof(wrongk));
            wrongk[0] ^= 0x01;
            memset(out, 0xA5, sizeof(out));
            CHECK(hd_chacha20_poly1305_open(wrongk, an, aad, sizeof(aad),
                                            ct, ptlen, tag, out) == -1,
                  "密钥错 → 认证失败");

            memcpy(wrongn, an, sizeof(wrongn));
            wrongn[11] ^= 0x80;
            memset(out, 0xA5, sizeof(out));
            CHECK(hd_chacha20_poly1305_open(ak, wrongn, aad, sizeof(aad),
                                            ct, ptlen, tag, out) == -1,
                  "nonce 错 → 认证失败");
        }
    }

    /* ================= 边界与往返 ================= */
    printf("== 边界与往返\n");
    {
        uint8_t bk[32], bn[12], tag[16];
        size_t k;

        for (k = 0; k < sizeof(bk); k++) bk[k] = (uint8_t)(0x11 + k);
        for (k = 0; k < sizeof(bn); k++) bn[k] = (uint8_t)(0x40 + k);

        /* 空明文 + 空 AAD：没有数据，但 tag 仍覆盖两个长度字段 */
        CHECK(hd_chacha20_poly1305_seal(bk, bn, NULL, 0, NULL, 0, NULL, tag) == 0,
              "空明文 / 空 AAD：seal 成功");
        CHECK(hd_chacha20_poly1305_open(bk, bn, NULL, 0, NULL, 0, tag, NULL) == 0,
              "空明文 / 空 AAD：open 成功");

        /* 空明文 + 非空 AAD：tag 必须把 AAD 算进去 */
        {
            static const uint8_t aad7[7] = { 1, 2, 3, 4, 5, 6, 7 };
            uint8_t badaad[7];

            CHECK(hd_chacha20_poly1305_seal(bk, bn, aad7, sizeof(aad7),
                                            NULL, 0, NULL, tag) == 0,
                  "空明文 + 7 字节 AAD：seal 成功");
            CHECK(hd_chacha20_poly1305_open(bk, bn, aad7, sizeof(aad7),
                                            NULL, 0, tag, NULL) == 0,
                  "空明文 + 7 字节 AAD：open 成功");

            memcpy(badaad, aad7, sizeof(badaad));
            badaad[3] ^= 0x01;
            CHECK(hd_chacha20_poly1305_open(bk, bn, badaad, sizeof(badaad),
                                            NULL, 0, tag, NULL) == -1,
                  "空明文时 AAD 被改也要拒绝");
        }

        /* 16 字节整块：覆盖"填充长度为 0"的路径 */
        {
            uint8_t msg[16], ct[16], back[16];

            for (k = 0; k < sizeof(msg); k++) msg[k] = (uint8_t)(k * 3 + 1);
            CHECK(hd_chacha20_poly1305_seal(bk, bn, NULL, 0, msg, sizeof(msg),
                                            ct, tag) == 0,
                  "16 字节明文（无填充）：seal 成功");
            CHECK(hd_chacha20_poly1305_open(bk, bn, NULL, 0, ct, sizeof(ct),
                                            tag, back) == 0,
                  "16 字节明文（无填充）：open 成功");
            CHECK(memcmp(back, msg, sizeof(msg)) == 0, "16 字节明文往返一致");
        }

        /* 37 字节：非整块、空 AAD */
        {
            uint8_t msg[37], ct[37], back[37];

            for (k = 0; k < sizeof(msg); k++) msg[k] = (uint8_t)(k * 7 + 3);
            CHECK(hd_chacha20_poly1305_seal(bk, bn, NULL, 0, msg, sizeof(msg),
                                            ct, tag) == 0,
                  "37 字节明文 / 空 AAD：seal 成功");
            CHECK(hd_chacha20_poly1305_open(bk, bn, NULL, 0, ct, sizeof(ct),
                                            tag, back) == 0,
                  "37 字节明文 / 空 AAD：open 成功");
            CHECK(memcmp(back, msg, sizeof(msg)) == 0, "37 字节明文往返一致");
        }

        /* 1000 字节：跨 16 个 ChaCha 块，确认块计数器在循环里正确递增 */
        {
            uint8_t msg[1000], ct[1000], back[1000];

            for (k = 0; k < sizeof(msg); k++) msg[k] = (uint8_t)(k * 13 + 7);
            CHECK(hd_chacha20_poly1305_seal(bk, bn, bk, 9, msg, sizeof(msg),
                                            ct, tag) == 0,
                  "1000 字节明文：seal 成功");
            CHECK(hd_chacha20_poly1305_open(bk, bn, bk, 9, ct, sizeof(ct),
                                            tag, back) == 0,
                  "1000 字节明文：open 成功");
            CHECK(memcmp(back, msg, sizeof(msg)) == 0, "1000 字节明文往返一致");
        }

        /* 原地：plain 与 cipher 同一块缓冲，加密/解密都要成立 */
        {
            uint8_t buf[100], orig[100];

            for (k = 0; k < sizeof(buf); k++) orig[k] = (uint8_t)(k ^ 0x5a);
            memcpy(buf, orig, sizeof(buf));

            CHECK(hd_chacha20_poly1305_seal(bk, bn, bk, 5, buf, sizeof(buf),
                                            buf, tag) == 0,
                  "原地加密成功");
            CHECK(memcmp(buf, orig, sizeof(buf)) != 0, "原地加密后内容确实变了");
            CHECK(hd_chacha20_poly1305_open(bk, bn, bk, 5, buf, sizeof(buf),
                                            tag, buf) == 0,
                  "原地解密成功");
            CHECK(memcmp(buf, orig, sizeof(buf)) == 0, "原地加解密往返一致");
        }
    }

    /* ================= RFC 5869：HKDF-SHA256 ================= */
    printf("== HKDF-SHA256（RFC 5869）\n");
    {
        uint8_t ikm[80], salt[80], info[80], got[82], want[82];
        size_t k;

        /* Case 1：22 字节 0x0b、13 字节 salt、10 字节 info、42 字节输出 */
        {
            uint8_t c1ikm[22], c1salt[13], c1info[10];

            memset(c1ikm, 0x0b, sizeof(c1ikm));
            vec("000102030405060708090a0b0c", c1salt, sizeof(c1salt));
            vec("f0f1f2f3f4f5f6f7f8f9", c1info, sizeof(c1info));
            vec(V_HKDF1_OKM, want, sizeof(want));

            hd_hkdf_sha256(c1salt, sizeof(c1salt), c1ikm, sizeof(c1ikm),
                           (const char*)c1info, sizeof(c1info), got, 42);
            expect_bytes(got, want, 42, "Case 1：OKM（42 字节）");
        }

        /* Case 2：80 字节递增输入 / salt / info，输出 82 字节（跨 3 个块） */
        for (k = 0; k < 80; k++) {
            ikm[k]  = (uint8_t)k;
            salt[k] = (uint8_t)(0x60 + k);
            info[k] = (uint8_t)(0xb0 + k);
        }
        vec(V_HKDF2_OKM, want, sizeof(want));
        hd_hkdf_sha256(salt, 80, ikm, 80, (const char*)info, 80, got, 82);
        expect_bytes(got, want, 82, "Case 2：OKM（80/80/80，82 字节）");

        /* Case 3：空 salt、空 info（NULL/0），输出 42 字节 */
        memset(ikm, 0x0b, 22);
        vec(V_HKDF3_OKM, want, sizeof(want));
        hd_hkdf_sha256(NULL, 0, ikm, 22, NULL, 0, got, 42);
        expect_bytes(got, want, 42, "Case 3：OKM（空 salt / 空 info）");
    }

    printf("\n=== 结果: 通过 %d, 失败 %d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
