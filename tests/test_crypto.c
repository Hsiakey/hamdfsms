/*
 * test_crypto.c — SHA-256 / HMAC-SHA256 官方测试向量
 *
 * 全部向量来自标准文档，任何一个常数或移位写错都会立刻失败：
 *   FIPS 180-4 / RFC 6234 附录（SHA-256）
 *   RFC 4231（HMAC-SHA256）
 */
#include "../Hamsterd/hd_crypto.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("  [FAIL] %s  (第 %d 行)\n", msg, __LINE__); } \
} while (0)

static void expect_hex(const char* got, const char* want, const char* msg)
{
    if (strcmp(got, want) == 0) { g_pass++; return; }
    g_fail++;
    printf("  [FAIL] %s\n         期望 %s\n         实得 %s\n", msg, want, got);
}

int main(void)
{
    char hex[HD_SHA256_HEX];
    uint8_t dig[HD_SHA256_LEN];

    printf("Hamster 密码学原语测试（SHA-256 / HMAC-SHA256）\n\n");

    /* ---------- SHA-256 官方向量 ---------- */
    printf("== SHA-256\n");
    hd_sha256_once("", 0, NULL, hex);
    expect_hex(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256(\"\")");

    hd_sha256_once("abc", 3, NULL, hex);
    expect_hex(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256(\"abc\")");

    hd_sha256_once("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, NULL, hex);
    expect_hex(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "SHA-256(56 字节向量)");

    /* 一百万次 'a'：覆盖多块与长度累加的边界 */
    {
        hd_sha256 ctx;
        char block[1000];
        int i;
        memset(block, 'a', sizeof(block));
        hd_sha256_init(&ctx);
        for (i = 0; i < 1000; i++) hd_sha256_update(&ctx, block, sizeof(block));
        hd_sha256_final(&ctx, dig);
        hd_hex_encode(dig, HD_SHA256_LEN, hex);
        expect_hex(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256(1,000,000 × 'a')");
    }

    /* 分段更新必须等价于一次性输入 */
    {
        char one[HD_SHA256_HEX], multi[HD_SHA256_HEX];
        hd_sha256 ctx;
        hd_sha256_once("hello hamster world", 19, NULL, one);
        hd_sha256_init(&ctx);
        hd_sha256_update(&ctx, "hello ", 6);
        hd_sha256_update(&ctx, "hamster", 7);
        hd_sha256_update(&ctx, " world", 6);
        hd_sha256_final(&ctx, dig);
        hd_hex_encode(dig, HD_SHA256_LEN, multi);
        expect_hex(multi, one, "分段 update 与一次性一致");
    }

    /* ---------- HMAC-SHA256（RFC 4231） ---------- */
    printf("== HMAC-SHA256\n");
    {
        uint8_t key[20];
        memset(key, 0x0b, sizeof(key));
        hd_hmac_sha256(key, sizeof(key), "Hi There", 8, NULL, hex);
        expect_hex(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                   "RFC 4231 TC1（20 字节 0x0b）");
    }
    {
        hd_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, NULL, hex);
        expect_hex(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                   "RFC 4231 TC2（Jefe）");
    }
    {
        uint8_t key[20], data[50];
        memset(key, 0xaa, sizeof(key));
        memset(data, 0xdd, sizeof(data));
        hd_hmac_sha256(key, sizeof(key), data, sizeof(data), NULL, hex);
        expect_hex(hex, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                   "RFC 4231 TC3（20×0xaa / 50×0xdd）");
    }
    {
        /* 密钥长度超过分块（64 字节）：必须先哈希 */
        uint8_t key[131];
        memset(key, 0xaa, sizeof(key));
        hd_hmac_sha256(key, sizeof(key), "Test Using Larger Than Block-Size Key - Hash Key First", 54, NULL, hex);
        expect_hex(hex, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                   "RFC 4231 TC6（131 字节密钥）");
    }
    {
        hd_hmac_sha256("key", 3, "The quick brown fox jumps over the lazy dog", 43, NULL, hex);
        expect_hex(hex, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
                   "HMAC(key, fox) 经典向量");
    }

    /* 三段式封装必须等价于拼接后一次算 */
    {
        char joined[HD_SHA256_HEX], parts[HD_SHA256_HEX];
        hd_hmac_sha256("secret", 6, "part1|part2|part3", 17, NULL, joined);
        hd_hmac_sha256v("secret", 6, "part1|", 6, "part2|", 6, "part3", 5, NULL, parts);
        expect_hex(parts, joined, "hd_hmac_sha256v 三段拼接等价");
    }

    /* 密钥或数据差一个字节，摘要必须完全不同 */
    {
        char a[HD_SHA256_HEX], b[HD_SHA256_HEX];
        hd_hmac_sha256("secret", 6, "payload", 7, NULL, a);
        hd_hmac_sha256("secreT", 6, "payload", 7, NULL, b);
        CHECK(strcmp(a, b) != 0, "密钥变化一个字符 → 摘要不同");
        hd_hmac_sha256("secret", 6, "payloaD", 7, NULL, b);
        CHECK(strcmp(a, b) != 0, "数据变化一个字符 → 摘要不同");
    }

    /* ---------- 十六进制编解码 ---------- */
    printf("== hex\n");
    {
        uint8_t raw[4] = { 0x00, 0x7f, 0xa5, 0xff };
        uint8_t back[4];
        char s[9];
        hd_hex_encode(raw, 4, s);
        expect_hex(s, "007fa5ff", "hex 编码（小写、含 0 与 0xff）");
        CHECK(hd_hex_decode(s, back, sizeof(back)) == 4, "hex 解码长度");
        CHECK(memcmp(raw, back, 4) == 0, "hex 编解码往返一致");
        CHECK(hd_hex_decode("abc", back, sizeof(back)) == -1, "奇数长度被拒");
        CHECK(hd_hex_decode("zz", back, sizeof(back)) == -1, "非法字符被拒");
        CHECK(hd_hex_decode("0011223344", back, sizeof(back)) == -1, "超出缓冲被拒");
    }

    printf("\n=== 结果: 通过 %d, 失败 %d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
