/*
 * test_disc.c — 发现协议的纯函数层测试（PROTOCOL §7）
 * ver.0.0.8
 *
 * 这一层不碰 socket，所以可以离线验证三件最容易出错、也最致命的事：
 *   1. 帧里的 MAC 到底覆盖了哪些字节（原文必须在测试里**再写一遍**，
 *      这样任何人改动 hd_disc.c 的拼串都会立刻被这里挡住）；
 *   2. 暗号不对 / 字段被篡改 / 版本不符 / 截断 / 内嵌 NUL —— 必须一律判失败；
 *   3. 应答 MAC 绑定探测方 id，因此捕获到的应答无法重放给另一个客户端。
 *
 * 真实 UDP 行为（静默丢弃、限速、重放窗口）由 tests/discovery.ps1 在回环上验证。
 */
#include "hd_disc.h"
#include "hd_crypto.h"
#include "jsonx.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (cond) { g_pass++; printf("  ok   %s\n", msg); }                  \
        else { g_fail++; printf("  FAIL %s   (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

#define CW   "hamster-e05258d0ff46edc9601c2b3d585d463d"
#define SELF "0123456789abcdef"
#define PEER "fedcba9876543210"
#define NONCE "00112233445566778899aabbccddeeff"

int main(void)
{
    char probe[HD_DISC_FRAME_MAX + 1];
    int  plen;

    printf("=== 发现协议纯函数测试 ===\n");

    /* ---------------- 标识与十六进制校验 ---------------- */
    printf("== 字段校验\n");
    CHECK(hd_disc_valid_id("0123456789abcdef") == 1, "16 位十六进制标识合法");
    CHECK(hd_disc_valid_id("abc-def_123") == 1, "允许 - 与 _");
    CHECK(hd_disc_valid_id("short") == 0, "过短（<8）被拒");
    CHECK(hd_disc_valid_id("") == 0, "空串被拒");
    CHECK(hd_disc_valid_id("has space") == 0, "空格被拒");
    CHECK(hd_disc_valid_id("quote\"inside") == 0, "引号被拒");
    CHECK(hd_disc_valid_id(NULL) == 0, "NULL 被拒");
    {
        char long_id[80];
        memset(long_id, 'a', sizeof(long_id) - 1);
        long_id[sizeof(long_id) - 1] = '\0';
        CHECK(hd_disc_valid_id(long_id) == 0, "超长（63+）被拒");
    }
    CHECK(hd_disc_is_hex(NONCE, 32) == 1, "32 位十六进制被接受");
    CHECK(hd_disc_is_hex(NONCE, 31) == 0, "长度不符被拒");
    CHECK(hd_disc_is_hex("zz112233445566778899aabbccddeeff", 32) == 0, "非十六进制字符被拒");

    /* ---------------- nonce 生成 ---------------- */
    printf("== nonce\n");
    {
        char a[HD_DISC_NONCE_MAX], b[HD_DISC_NONCE_MAX];
        CHECK(hd_disc_make_nonce(a) == 0, "生成成功");
        CHECK(hd_disc_is_hex(a, 32) == 1, "生成结果是 32 位十六进制");
        CHECK(hd_disc_make_nonce(b) == 0, "再次生成成功");
        CHECK(strcmp(a, b) != 0, "两次生成不重复");
    }

    /* ---------------- 探测帧：构造与校验 ---------------- */
    printf("== 探测帧\n");
    plen = hd_disc_build_probe(CW, PEER, NONCE, probe, sizeof(probe));
    CHECK(plen > 0, "构造探测帧成功");
    {
        char t[8], id[HD_DISC_ID_MAX], n[HD_DISC_NONCE_MAX], m[HD_DISC_MAC_MAX];
        char want[HD_DISC_MAC_MAX];
        char msg[256];
        int  ml;

        CHECK(jx_is_object(probe) == 1, "探测帧是合法 JSON 对象");
        CHECK(jx_get_str(probe, "t", t, sizeof(t)) == 1 && strcmp(t, "hp") == 0, "t=hp");
        CHECK(jx_get_str(probe, "id", id, sizeof(id)) == 1 && strcmp(id, PEER) == 0, "id 原样写入");
        CHECK(jx_get_str(probe, "n", n, sizeof(n)) == 1 && strcmp(n, NONCE) == 0, "n 原样写入");
        CHECK(jx_get_str(probe, "m", m, sizeof(m)) == 1, "m 存在");
        CHECK((int)strlen(m) == HD_DISC_MAC_HEX, "m 长度 64");

        /* 原文在测试里独立再写一遍：这是对"线格式"的钉子 */
        ml = snprintf(msg, sizeof(msg), "hamster-disc-probe/v1\n%s\n%s", PEER, NONCE);
        hd_hmac_sha256(CW, strlen(CW), msg, (size_t)ml, NULL, want);
        CHECK(strcmp(want, m) == 0, "MAC 原文 == hamster-disc-probe/v1\\n<id>\\n<n>");
    }
    {
        char id[HD_DISC_ID_MAX], n[HD_DISC_NONCE_MAX];
        CHECK(hd_disc_parse_probe(CW, probe, plen, id, sizeof(id), n, sizeof(n)) == 0, "正确暗号校验通过");
        CHECK(strcmp(id, PEER) == 0 && strcmp(n, NONCE) == 0, "回填的 id/n 正确");
    }

    /* ---------------- 探测帧：必须失败的用例 ---------------- */
    printf("== 探测帧拒绝路径\n");
    {
        char id[HD_DISC_ID_MAX], n[HD_DISC_NONCE_MAX];
        const char* wrong = "hamster-0000000000000000000000000000000";

        CHECK(hd_disc_parse_probe(wrong, probe, plen, id, sizeof(id), n, sizeof(n)) != 0,
              "暗号不对 → 拒绝（对应静默丢弃）");
        CHECK(hd_disc_parse_probe("", probe, plen, id, sizeof(id), n, sizeof(n)) != 0,
              "空暗号 → 拒绝");
        CHECK(hd_disc_parse_probe(NULL, probe, plen, id, sizeof(id), n, sizeof(n)) != 0,
              "NULL 暗号 → 拒绝（不崩）");

        /* 篡改 nonce：MAC 覆盖了 n，必须失败 */
        {
            char  bad[HD_DISC_FRAME_MAX + 1];
            char* p;
            snprintf(bad, sizeof(bad), "%s", probe);
            p = strstr(bad, NONCE);
            CHECK(p != NULL, "（定位到 n 字段）");
            if (p) p[0] = (p[0] == '0') ? '1' : '0';
            CHECK(hd_disc_parse_probe(CW, bad, (int)strlen(bad), id, sizeof(id), n, sizeof(n)) != 0,
                  "篡改 nonce → MAC 不符，拒绝");
        }
        /* 篡改 id */
        {
            char  bad[HD_DISC_FRAME_MAX + 1];
            char* p;
            snprintf(bad, sizeof(bad), "%s", probe);
            p = strstr(bad, PEER);
            CHECK(p != NULL, "（定位到 id 字段）");
            if (p) p[0] = (p[0] == 'f') ? 'e' : 'f';
            CHECK(hd_disc_parse_probe(CW, bad, (int)strlen(bad), id, sizeof(id), n, sizeof(n)) != 0,
                  "篡改 id → MAC 不符，拒绝");
        }
        /* 篡改 m 的最后一个十六进制字符（L-1 是 '}'，L-2 是 '"'，L-3 才是 m 的末位） */
        {
            char   bad[HD_DISC_FRAME_MAX + 1];
            size_t L;
            snprintf(bad, sizeof(bad), "%s", probe);
            L = strlen(bad);
            bad[L - 3] = (bad[L - 3] == '0') ? '1' : '0';
            CHECK(hd_disc_parse_probe(CW, bad, (int)strlen(bad), id, sizeof(id), n, sizeof(n)) != 0,
                  "篡改 MAC → 拒绝");
        }
        /* 版本不符 */
        {
            char  bad[HD_DISC_FRAME_MAX + 1];
            char* p;
            snprintf(bad, sizeof(bad), "%s", probe);
            p = strstr(bad, "\"v\":1");
            CHECK(p != NULL, "（定位到 v 字段）");
            if (p) p[4] = '2';
            CHECK(hd_disc_parse_probe(CW, bad, (int)strlen(bad), id, sizeof(id), n, sizeof(n)) != 0,
                  "版本 v=2 → 拒绝");
        }
        /* 类型不符：拿应答帧当探测帧 */
        {
            char rep[HD_DISC_FRAME_MAX + 1];
            int  rlen = hd_disc_build_reply(CW, PEER, NONCE, SELF, "host-a", 9100, "0.0.8",
                                            rep, sizeof(rep));
            CHECK(rlen > 0, "（构造应答帧用于交叉验证）");
            CHECK(hd_disc_parse_probe(CW, rep, rlen, id, sizeof(id), n, sizeof(n)) != 0,
                  "应答帧塞进探测解析 → 拒绝");
        }

        CHECK(hd_disc_parse_probe(CW, probe, 0, id, sizeof(id), n, sizeof(n)) != 0, "长度 0 → 拒绝");
        CHECK(hd_disc_parse_probe(CW, probe, -5, id, sizeof(id), n, sizeof(n)) != 0, "负长度 → 拒绝");
        CHECK(hd_disc_parse_probe(CW, probe, HD_DISC_FRAME_MAX + 1, id, sizeof(id), n, sizeof(n)) != 0,
              "超长帧 → 拒绝");
        CHECK(hd_disc_parse_probe(CW, NULL, 10, id, sizeof(id), n, sizeof(n)) != 0, "NULL 帧 → 拒绝");

        /* 截断：JSON 不完整 */
        {
            int cut = (int)strlen(probe) - 10;
            CHECK(hd_disc_parse_probe(CW, probe, cut, id, sizeof(id), n, sizeof(n)) != 0,
                  "截断的 JSON → 拒绝");
        }
        /* 内嵌 NUL：攻击者常用手法，必须按长度判定为非法 */
        {
            char bad[64];
            memset(bad, 'A', sizeof(bad));
            bad[10] = '\0';
            CHECK(hd_disc_parse_probe(CW, bad, 32, id, sizeof(id), n, sizeof(n)) != 0,
                  "帧内含 NUL → 拒绝");
        }
        /* 非 JSON */
        {
            const char* junk = "GET / HTTP/1.1\r\n\r\n";
            CHECK(hd_disc_parse_probe(CW, junk, (int)strlen(junk), id, sizeof(id), n, sizeof(n)) != 0,
                  "非 JSON → 拒绝");
        }
        /* 缺字段 */
        {
            char  bad[HD_DISC_FRAME_MAX + 1];
            char* p;
            snprintf(bad, sizeof(bad), "%s", probe);
            p = strstr(bad, "\"n\":\"");
            CHECK(p != NULL, "（定位到 n 键）");
            if (p) memcpy(p, "\"x\":\"", 5);          /* 改键名，等价于缺 n */
            CHECK(hd_disc_parse_probe(CW, bad, (int)strlen(bad), id, sizeof(id), n, sizeof(n)) != 0,
                  "缺 n 字段 → 拒绝");
        }
    }

    /* ---------------- 构造探测帧的参数校验 ---------------- */
    printf("== 探测帧构造拒绝路径\n");
    {
        char out[HD_DISC_FRAME_MAX + 1];
        CHECK(hd_disc_build_probe("", PEER, NONCE, out, sizeof(out)) < 0, "空暗号 → 构造失败");
        CHECK(hd_disc_build_probe(NULL, PEER, NONCE, out, sizeof(out)) < 0, "NULL 暗号 → 构造失败");
        CHECK(hd_disc_build_probe(CW, "bad id", NONCE, out, sizeof(out)) < 0, "非法 id → 构造失败");
        CHECK(hd_disc_build_probe(CW, PEER, "0011", out, sizeof(out)) < 0, "nonce 过短 → 构造失败");
        CHECK(hd_disc_build_probe(CW, PEER, NONCE, NULL, 0) < 0, "NULL 输出 → 构造失败");
        CHECK(hd_disc_build_probe(CW, PEER, NONCE, out, 16) < 0, "缓冲过小 → 构造失败");
    }

    /* ---------------- 应答帧 ---------------- */
    printf("== 应答帧\n");
    {
        char rep[HD_DISC_FRAME_MAX + 1];
        char nonce[HD_DISC_NONCE_MAX], id[HD_DISC_ID_MAX], name[HD_DISC_NAME_MAX], ver[32];
        int  port = 0, rlen;

        rlen = hd_disc_build_reply(CW, PEER, NONCE, SELF, "my-pc", 9100, "0.0.8", rep, sizeof(rep));
        CHECK(rlen > 0, "构造应答帧成功");
        CHECK(jx_is_object(rep) == 1, "应答帧是合法 JSON 对象");

        {
            char m[HD_DISC_MAC_MAX], want[HD_DISC_MAC_MAX], msg[384];
            int  ml;
            CHECK(jx_get_str(rep, "m", m, sizeof(m)) == 1, "应答含 m");
            ml = snprintf(msg, sizeof(msg), "hamster-disc-reply/v1\n%s\n%s\n%s\n%d",
                          PEER, NONCE, SELF, 9100);
            hd_hmac_sha256(CW, strlen(CW), msg, (size_t)ml, NULL, want);
            CHECK(strcmp(want, m) == 0, "MAC 原文 == hamster-disc-reply/v1\\n<probe>\\n<n>\\n<self>\\n<port>");
        }

        CHECK(hd_disc_parse_reply(CW, PEER, rep, rlen, nonce, sizeof(nonce),
                                  id, sizeof(id), &port, name, sizeof(name),
                                  ver, sizeof(ver)) == 0, "客户端校验应答通过");
        CHECK(strcmp(nonce, NONCE) == 0, "nonce 原样回显");
        CHECK(strcmp(id, SELF) == 0, "服务端 id 正确");
        CHECK(port == 9100, "端口正确");
        CHECK(strcmp(name, "my-pc") == 0, "显示名正确");
        CHECK(strcmp(ver, "0.0.8") == 0, "版本正确");

        /* 关键：换个 my_id 校验，必须失败——否则捕获的应答能被重放给别人 */
        CHECK(hd_disc_parse_reply(CW, "aaaaaaaaaaaaaaaa", rep, rlen, nonce, sizeof(nonce),
                                  id, sizeof(id), &port, name, sizeof(name),
                                  ver, sizeof(ver)) != 0, "换一个探测方 id → MAC 不符，拒绝（防重放）");

        /* 自己 id == 服务端 id：同机自打自收，丢弃 */
        CHECK(hd_disc_parse_reply(CW, SELF, rep, rlen, nonce, sizeof(nonce),
                                  id, sizeof(id), &port, name, sizeof(name),
                                  ver, sizeof(ver)) != 0, "服务端 id == 本机 id → 拒绝");

        CHECK(hd_disc_parse_reply("wrong", PEER, rep, rlen, nonce, sizeof(nonce),
                                  id, sizeof(id), &port, name, sizeof(name),
                                  ver, sizeof(ver)) != 0, "暗号不对 → 拒绝");

        /* 篡改端口：MAC 覆盖 port */
        {
            char  bad[HD_DISC_FRAME_MAX + 1];
            char* p;
            snprintf(bad, sizeof(bad), "%s", rep);
            p = strstr(bad, "\"port\":9100");
            CHECK(p != NULL, "（定位到 port 字段）");
            if (p) memcpy(p + 8, "9200", 4);
            CHECK(hd_disc_parse_reply(CW, PEER, bad, (int)strlen(bad), nonce, sizeof(nonce),
                                      id, sizeof(id), &port, name, sizeof(name),
                                      ver, sizeof(ver)) != 0, "篡改端口 → 拒绝");
        }
    }

    /* 显示名里的引号与反斜杠必须被转义后仍能原样取回 */
    {
        char rep[HD_DISC_FRAME_MAX + 1];
        char name[HD_DISC_NAME_MAX], nonce[HD_DISC_NONCE_MAX], id[HD_DISC_ID_MAX], ver[32];
        const char* weird = "a\"b\\c";
        int  port = 0, rlen;

        rlen = hd_disc_build_reply(CW, PEER, NONCE, SELF, weird, 9100, "0.0.8", rep, sizeof(rep));
        CHECK(rlen > 0, "含引号/反斜杠的显示名可构造");
        CHECK(hd_disc_parse_reply(CW, PEER, rep, rlen, nonce, sizeof(nonce),
                                  id, sizeof(id), &port, name, sizeof(name),
                                  ver, sizeof(ver)) == 0, "并能被正确校验");
        CHECK(strcmp(name, weird) == 0, "显示名转义/反转义往返一致");
    }

    /* 应答构造的参数校验 */
    {
        char rep[HD_DISC_FRAME_MAX + 1];
        CHECK(hd_disc_build_reply(CW, PEER, NONCE, SELF, "h", 0, "0.0.8", rep, sizeof(rep)) < 0,
              "端口 0 → 构造失败");
        CHECK(hd_disc_build_reply(CW, PEER, NONCE, SELF, "h", 70000, "0.0.8", rep, sizeof(rep)) < 0,
              "端口越界 → 构造失败");
        CHECK(hd_disc_build_reply("", PEER, NONCE, SELF, "h", 9100, "0.0.8", rep, sizeof(rep)) < 0,
              "空暗号 → 构造失败");
        CHECK(hd_disc_build_reply(CW, "bad", NONCE, SELF, "h", 9100, "0.0.8", rep, sizeof(rep)) < 0,
              "非法探测方 id → 构造失败");
    }

    /* 探测帧与应答帧的 MAC 域必须不同（不能拿探测帧冒充应答） */
    {
        char rep[HD_DISC_FRAME_MAX + 1];
        char nonce[HD_DISC_NONCE_MAX], id[HD_DISC_ID_MAX], name[HD_DISC_NAME_MAX], ver[32];
        int  port = 0, rlen;
        rlen = hd_disc_build_reply(CW, PEER, NONCE, SELF, "h", 9100, "0.0.8", rep, sizeof(rep));
        CHECK(hd_disc_parse_reply(CW, PEER, probe, plen, nonce, sizeof(nonce),
                                  id, sizeof(id), &port, name, sizeof(name),
                                  ver, sizeof(ver)) != 0, "探测帧塞进应答解析 → 拒绝");
        CHECK(rlen > 0, "（应答帧构造正常）");
    }

    printf("\n=== 结果: 通过 %d, 失败 %d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
