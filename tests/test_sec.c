/*
 * test_sec.c — 传输加密（PROTOCOL §8）的 C 侧测试
 *
 * 重点不是"能跑通"，而是**跨实现一致性**：
 *   · §8.2 的五组已知答案逐字节比对（JS 侧 hamster-aead.js 的 selfTest 用同一组值）
 *   · 一条固定的记录字节流（由 JS 侧产出，见 tests/aead-js.js 的向量）必须被 C 解开
 *   · 记录层的边界与拒绝路径：counter 跳跃/重放、tag 篡改、方向反射、长度越界
 */
#include "../Hamsterd/hd_sec.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("  [FAIL] %s  (第 %d 行)\n", msg, __LINE__); } \
} while (0)

static int hexeq(const uint8_t* bin, const char* want, size_t n)
{
    char got[256];
    if (n * 2 + 1 > sizeof(got)) return 0;
    hd_sec_hex_encode(bin, n, got);
    return strcmp(got, want) == 0;
}

static void show(const char* name, const uint8_t* bin, size_t n)
{
    char got[256];
    hd_sec_hex_encode(bin, n, got);
    printf("     %s = %s\n", name, got);
}

/* ---------------- PROTOCOL §8.2 的已知答案 ---------------- */
static const char K_CODEWORD[] = "hamster-e05258d0ff46edc9601c2b3d585d463d";
static const char K_NC[]  = "00112233445566778899aabbccddeeff";
static const char K_SALT[] = "aabbccddeeff00112233445566778899";
static const char K_NS[]  = "ffeeddccbbaa99887766554433221100";
static const char K_DEVICE[] = "fedcba9876543210";

static const char K_MASTER[] =
    "b70bcc8b6faaad27101a4fa3924bb179df10f6c1eb683c401ebd5899315b4093";
static const char K_PROOF_C[] =
    "b85d15d5ad541d3767c635503c4c6964d23c6df8814eb3367b8c9c3eea84b4f8";
static const char K_PROOF_S[] =
    "4d37e2d5947a1266f607dc980a33802553547924f4edefdf00397f3c33d35405";
static const char K_KEY_C2S[] =
    "0afb9175f1763c701d993ca436c99fee97b2cc4bd46202cd07fcc8e0e197ed9a";
static const char K_KEY_S2C[] =
    "912dfe620fcd01e26e12df77ff0bfaedf5a788d975732e14ddfd037bf2843866";

/*
 * 跨语言记录向量：JS 侧用 key_c2s / dir=c2s / counter=0 加密 "hamster-interop-vector"
 * 产出的完整记录字节。C 必须逐字节解开；反过来 C 封出来的也必须与它完全相同
 * （因为 ChaCha20-Poly1305 是确定性的，nonce/AAD 都由 counter 决定）。
 */
static const char X_RECORD[] =
    "0000001600000000000000009ce1a63ce456aa4daf9fa9a793e18801d750ccbd"
    "b2d56f8f1df473107be2361294d7523b599f";

static void test_hex(void)
{
    uint8_t bin[4];
    char hex[9];

    hd_sec_hex_encode("\xde\xad\xbe\xef", 4, hex);
    CHECK(strcmp(hex, "deadbeef") == 0, "hex 编码小写无前缀");

    CHECK(hd_sec_hex_decode("deadbeef", 4, bin) == 0, "hex 解码成功");
    CHECK(bin[0] == 0xde && bin[1] == 0xad && bin[2] == 0xbe && bin[3] == 0xef, "hex 解码字节正确");
    CHECK(hd_sec_hex_decode("DEADBEEF", 4, bin) == 0, "hex 解码接受大写");
    CHECK(hd_sec_hex_decode("deadbeeg", 4, bin) != 0, "hex 拒绝非法字符");
    CHECK(hd_sec_hex_decode("deadbee", 4, bin) != 0, "hex 拒绝长度不足");
    CHECK(hd_sec_hex_decode("deadbeef00", 4, bin) != 0, "hex 拒绝长度超出");

    hd_sec_hex_encode("", 0, hex);
    CHECK(hex[0] == '\0', "hex 编码空串");
}

static void test_derive(void)
{
    uint8_t salt[HD_SEC_SALT_LEN];
    uint8_t master[HD_SEC_KEY_LEN];
    uint8_t pc[HD_SEC_KEY_LEN];
    uint8_t ps[HD_SEC_KEY_LEN];
    hd_sec srv, cli;

    CHECK(hd_sec_hex_decode(K_SALT, HD_SEC_SALT_LEN, salt) == 0, "salt 解码");

    hd_sec_master(K_CODEWORD, strlen(K_CODEWORD), salt, master);
    CHECK(hexeq(master, K_MASTER, 32), "§8.2 master 与 PROTOCOL 一致");

    hd_sec_proof_c(master, K_NC, K_NS, K_DEVICE, pc);
    CHECK(hexeq(pc, K_PROOF_C, 32), "§8.2 proof_C 与 PROTOCOL 一致");

    hd_sec_proof_s(master, K_NC, K_NS, ps);
    CHECK(hexeq(ps, K_PROOF_S, 32), "§8.2 proof_S 与 PROTOCOL 一致");

    /* 服务端视角：发送密钥 = s2c，接收密钥 = c2s */
    CHECK(hd_sec_init(&srv, master, salt, K_NC, K_NS, 1) == 0, "服务端初始化");
    CHECK(hexeq(srv.key_out, K_KEY_S2C, 32), "服务端 key_out = key_s2c");
    CHECK(hexeq(srv.key_in,  K_KEY_C2S, 32), "服务端 key_in  = key_c2s");
    CHECK(srv.dir_out == HD_SEC_DIR_S2C && srv.dir_in == HD_SEC_DIR_C2S, "服务端方向正确");
    CHECK(srv.ctr_out == 0 && srv.ctr_in == 0 && srv.active == 1, "服务端计数器从 0 开始");

    CHECK(hd_sec_init(&cli, master, salt, K_NC, K_NS, 0) == 0, "客户端初始化");
    CHECK(hexeq(cli.key_out, K_KEY_C2S, 32), "客户端 key_out = key_c2s");
    CHECK(hexeq(cli.key_in,  K_KEY_S2C, 32), "客户端 key_in  = key_s2c");

    /* device_id 必须进 proof_C，且不进 proof_S */
    {
        uint8_t pc2[HD_SEC_KEY_LEN];
        hd_sec_proof_c(master, K_NC, K_NS, "another-device", pc2);
        CHECK(memcmp(pc, pc2, 32) != 0, "device_id 影响 proof_C");
    }

    /* nc / ns 变化必须改变记录密钥 */
    {
        hd_sec a, b;
        hd_sec_init(&a, master, salt, K_NC, K_NS, 1);
        hd_sec_init(&b, master, salt, "00000000000000000000000000000000", K_NS, 1);
        CHECK(memcmp(a.key_out, b.key_out, 32) != 0, "nc 变化 → 记录密钥变化");
    }

    /* 参数校验 */
    CHECK(hd_sec_init(&srv, master, salt, "abcd", K_NS, 1) == -1, "拒绝短 nc");
    CHECK(hd_sec_init(&srv, master, salt, K_NC, "zz", 1) == -1, "拒绝非 hex ns");
}

static void test_record_roundtrip(void)
{
    uint8_t salt[HD_SEC_SALT_LEN];
    uint8_t master[HD_SEC_KEY_LEN];
    hd_sec srv, cli;
    uint8_t rec[HD_SEC_REC_MAX];
    uint8_t out[HD_SEC_MAX_PLAIN];
    size_t rl;
    int n;

    hd_sec_hex_decode(K_SALT, HD_SEC_SALT_LEN, salt);
    hd_sec_master(K_CODEWORD, strlen(K_CODEWORD), salt, master);
    hd_sec_init(&srv, master, salt, K_NC, K_NS, 1);
    hd_sec_init(&cli, master, salt, K_NC, K_NS, 0);

    /* 服务端 → 客户端 */
    rl = hd_sec_seal(&srv, "hello", 5, rec);
    CHECK(rl == HD_SEC_HDR_LEN + 5 + HD_SEC_TAG_LEN, "记录长度 = 12 + 明文 + 16");
    CHECK(((uint32_t)rec[0] << 24 | rec[1] << 16 | rec[2] << 8 | rec[3]) == 5, "len 字段 = 明文字节数");
    CHECK(rec[11] == 0, "第一条记录 counter = 0");

    n = hd_sec_open(&cli, rec, rl, out, sizeof(out));
    CHECK(n == 5 && memcmp(out, "hello", 5) == 0, "客户端解出服务端记录");
    CHECK(cli.ctr_in == 1, "客户端接收计数推进");

    /* 客户端 → 服务端，序号各自独立 */
    rl = hd_sec_seal(&cli, "world", 5, rec);
    CHECK(rec[11] == 0, "客户端第一条记录 counter 也是 0");
    n = hd_sec_open(&srv, rec, rl, out, sizeof(out));
    CHECK(n == 5 && memcmp(out, "world", 5) == 0, "服务端解出客户端记录");

    /* 64 KiB 边界 */
    {
        static uint8_t big[HD_SEC_MAX_PLAIN];
        static uint8_t big_out[HD_SEC_MAX_PLAIN];
        memset(big, 0x5a, sizeof(big));
        rl = hd_sec_seal(&srv, big, HD_SEC_MAX_PLAIN, rec);
        CHECK(rl == HD_SEC_HDR_LEN + HD_SEC_MAX_PLAIN + HD_SEC_TAG_LEN, "64 KiB 记录长度正确");
        n = hd_sec_open(&cli, rec, rl, big_out, sizeof(big_out));
        CHECK(n == (int)HD_SEC_MAX_PLAIN, "64 KiB 记录解密长度正确");
        CHECK(memcmp(big, big_out, sizeof(big)) == 0, "64 KiB 记录内容一致");
    }

    /* 空明文不允许（§8.3：len 取值 1..65536） */
    CHECK(hd_sec_seal(&srv, "x", 0, rec) == 0, "拒绝空明文");
    CHECK(hd_sec_seal(&srv, "x", HD_SEC_MAX_PLAIN + 1, rec) == 0, "拒绝超过 64 KiB 的明文");

    /* 未 active 的会话不工作 */
    {
        hd_sec off;
        memset(&off, 0, sizeof(off));
        CHECK(hd_sec_seal(&off, "x", 1, rec) == 0, "未激活会话拒绝封包");
    }
}

static void test_record_reject(void)
{
    uint8_t salt[HD_SEC_SALT_LEN];
    uint8_t master[HD_SEC_KEY_LEN];
    hd_sec srv, cli;
    uint8_t rec[HD_SEC_REC_MAX];
    uint8_t out[HD_SEC_MAX_PLAIN];
    size_t rl;

    hd_sec_hex_decode(K_SALT, HD_SEC_SALT_LEN, salt);
    hd_sec_master(K_CODEWORD, strlen(K_CODEWORD), salt, master);

    /* 篡改密文 / tag */
    hd_sec_init(&srv, master, salt, K_NC, K_NS, 1);
    hd_sec_init(&cli, master, salt, K_NC, K_NS, 0);
    rl = hd_sec_seal(&srv, "tamper", 6, rec);
    rec[HD_SEC_HDR_LEN] ^= 0xff;
    CHECK(hd_sec_open(&cli, rec, rl, out, sizeof(out)) == -1, "篡改密文 → 拒绝");
    CHECK(cli.ctr_in == 0, "失败后接收计数不推进");

    hd_sec_init(&srv, master, salt, K_NC, K_NS, 1);
    hd_sec_init(&cli, master, salt, K_NC, K_NS, 0);
    rl = hd_sec_seal(&srv, "tamper", 6, rec);
    rec[rl - 1] ^= 0x01;
    CHECK(hd_sec_open(&cli, rec, rl, out, sizeof(out)) == -1, "篡改 tag → 拒绝");

    /* 篡改 counter（AAD 绑定） */
    hd_sec_init(&srv, master, salt, K_NC, K_NS, 1);
    hd_sec_init(&cli, master, salt, K_NC, K_NS, 0);
    rl = hd_sec_seal(&srv, "ctr", 3, rec);
    rec[11] = 9;
    CHECK(hd_sec_open(&cli, rec, rl, out, sizeof(out)) == -1, "counter 不连续 → 拒绝");

    /* 重放同一条记录 */
    hd_sec_init(&srv, master, salt, K_NC, K_NS, 1);
    hd_sec_init(&cli, master, salt, K_NC, K_NS, 0);
    rl = hd_sec_seal(&srv, "once", 4, rec);
    CHECK(hd_sec_open(&cli, rec, rl, out, sizeof(out)) == 4, "第一次接收成功");
    CHECK(hd_sec_open(&cli, rec, rl, out, sizeof(out)) == -1, "重放同一条记录 → 拒绝");

    /* 方向反射：把客户端自己的 c2s 记录回敬给客户端 */
    {
        uint8_t c2s[HD_SEC_REC_MAX];
        size_t cl;
        hd_sec_init(&srv, master, salt, K_NC, K_NS, 1);
        hd_sec_init(&cli, master, salt, K_NC, K_NS, 0);
        cl = hd_sec_seal(&cli, "reflected", 9, c2s);
        CHECK(hd_sec_open(&cli, c2s, cl, out, sizeof(out)) == -1, "方向反射 → 拒绝");
    }

    /* 长度字段被改大 / 改小 */
    hd_sec_init(&srv, master, salt, K_NC, K_NS, 1);
    hd_sec_init(&cli, master, salt, K_NC, K_NS, 0);
    rl = hd_sec_seal(&srv, "len", 3, rec);
    {
        uint8_t bad[HD_SEC_REC_MAX];
        memcpy(bad, rec, rl);
        bad[3] = 4;                       /* 声明 4 字节，但记录只有 3 字节明文 */
        CHECK(hd_sec_open(&cli, bad, rl, out, sizeof(out)) == -1, "len 与实际不符 → 拒绝");

        memcpy(bad, rec, rl);
        bad[0] = 0; bad[1] = 0; bad[2] = 0; bad[3] = 0;
        CHECK(hd_sec_open(&cli, bad, rl, out, sizeof(out)) == -1, "len = 0 → 拒绝");

        memcpy(bad, rec, rl);
        bad[0] = 0; bad[1] = 1; bad[2] = 0; bad[3] = 1;     /* 65537 */
        CHECK(hd_sec_open(&cli, bad, rl, out, sizeof(out)) == -1, "len > 64 KiB → 拒绝");
    }

    /* 记录被截断 */
    CHECK(hd_sec_open(&cli, rec, HD_SEC_HDR_LEN, out, sizeof(out)) == -1, "只有头 → 拒绝");
    CHECK(hd_sec_open(&cli, rec, rl - 1, out, sizeof(out)) == -1, "少一个字节 → 拒绝");
}

/* 跨语言：JS 产出的固定记录必须被 C 解开，且 C 重新封出来的字节完全相同 */
static void test_interop_vector(void)
{
    uint8_t salt[HD_SEC_SALT_LEN];
    uint8_t master[HD_SEC_KEY_LEN];
    hd_sec srv, cli;
    uint8_t want[HD_SEC_REC_MAX];
    uint8_t out[HD_SEC_MAX_PLAIN];
    uint8_t mine[HD_SEC_REC_MAX];
    size_t wl, ml;
    int n;
    const char* plain = "hamster-interop-vector";

    if (hd_sec_hex_decode(K_SALT, HD_SEC_SALT_LEN, salt) != 0) { CHECK(0, "向量 salt 解码"); return; }
    hd_sec_master(K_CODEWORD, strlen(K_CODEWORD), salt, master);
    /* 该向量是客户端→服务端，所以解它的一方必须是"服务端"角色 */
    hd_sec_init(&srv, master, salt, K_NC, K_NS, 1);

    /* 先自检向量长度：12 + 明文 + 16 */
    wl = strlen(X_RECORD) / 2;
    CHECK(wl == HD_SEC_HDR_LEN + strlen(plain) + HD_SEC_TAG_LEN, "跨语言向量长度自洽");
    if (wl > sizeof(want)) { CHECK(0, "向量缓冲"); return; }
    hd_sec_hex_decode(X_RECORD, wl, want);

    n = hd_sec_open(&srv, want, wl, out, sizeof(out));
    CHECK(n == (int)strlen(plain), "C 能解开 JS 产出的记录");
    CHECK(n > 0 && memcmp(out, plain, (size_t)n) == 0, "JS 记录解密内容正确");

    /* 反向：C 用同样的密钥/序号封同一条明文，字节必须与 JS 完全一致 */
    hd_sec_init(&cli, master, salt, K_NC, K_NS, 0);
    ml = hd_sec_seal(&cli, plain, strlen(plain), mine);
    CHECK(ml == wl, "C 封出的记录长度与 JS 相同");
    CHECK(ml == wl && memcmp(mine, want, wl) == 0, "C 封出的记录与 JS 逐字节相同");
    if (ml != wl || memcmp(mine, want, wl) != 0) {
        show("JS", want, wl);
        show("C ", mine, ml);
    }
}

int main(void)
{
    printf("=== hd_sec 测试（传输加密 §8） ===\n");

    printf("[1] 十六进制\n");
    test_hex();

    printf("[2] §8.2 派生（跨实现锚点）\n");
    test_derive();

    printf("[3] §8.3 记录层往返\n");
    test_record_roundtrip();

    printf("[4] §8.3 拒绝路径\n");
    test_record_reject();

    printf("[5] 跨语言向量（JS ⇄ C）\n");
    test_interop_vector();

    printf("\n=== 通过 %d, 失败 %d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
