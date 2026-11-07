/*
 * 单元测试：jsonx（严格 JSON）与 hd_util 的路径安全判定
 *
 * 覆盖审查报告中被点名的两类缺陷：
 *   P2-5  旧版 strstr 手抠 JSON：字符串里出现 '}' 或转义引号就解析错
 *   P0-1/P0-7  路径白名单：必须拒绝 .. 逃逸、绝对路径、盘符、UNC
 *
 * 运行: mingw32-make test
 */

#include <stdio.h>
#include <string.h>

#include "../Hamsterd/jsonx.h"
#include "../Hamsterd/hd_util.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, what) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("  [FAIL] %s  (%s:%d)\n", what, __FILE__, __LINE__); } \
} while (0)

#define CHECK_STR(got, want, what) do { \
    if (strcmp((got), (want)) == 0) { g_pass++; } \
    else { g_fail++; printf("  [FAIL] %s\n         期望: %s\n         实际: %s  (%s:%d)\n", \
                            what, (want), (got), __FILE__, __LINE__); } \
} while (0)

/* ============================ JSON 解析 ============================ */
static void test_json_basic(void)
{
    const char* req = "{\"type\":\"request\",\"id\":\"r-1\",\"action\":\"search\","
                      "\"params\":{\"q\":\"report\",\"limit\":50,\"deep\":true}}";
    char buf[256];
    int64_t n = 0;
    int b = 0;

    printf("[json] 基本取值\n");
    CHECK(jx_is_object(req) == 1, "合法对象应被接受");
    CHECK_STR(jx_get_str(req, "id", buf, sizeof(buf)) == 1 ? buf : "", "r-1", "取 id");
    CHECK_STR(jx_get_str(req, "action", buf, sizeof(buf)) == 1 ? buf : "", "search", "取 action");

    /* params 是嵌套对象：键必须能在其中直接取到，而不是从顶层 */
    CHECK(jx_find_raw(req, "params", buf, sizeof(buf)) == 1, "取 params 原始片段");
    CHECK_STR(buf, "{\"q\":\"report\",\"limit\":50,\"deep\":true}", "params 片段内容");
    {
        char q[64];
        CHECK_STR(jx_get_str(buf, "q", q, sizeof(q)) == 1 ? q : "", "report", "取 params.q");
    }

    /* 注意：不要把 out 与输入缓冲混用后继续读同一缓冲（这里用独立输出变量） */
    CHECK(jx_get_i64(buf, "limit", &n) == 1 && n == 50, "取 params.limit");
    CHECK(jx_get_bool(buf, "deep", &b) == 1 && b == 1, "取 params.deep=true");
    CHECK(jx_get_bool(buf, "missing", &b) == 0, "缺失键返回 0");
}

static void test_json_tricky(void)
{
    char buf[512];
    const char* p;

    printf("[json] 旧版会解析错的输入\n");

    /* 1) 字符串里含右花括号——旧版 params 括号匹配会在这里提前结束 */
    p = "{\"id\":\"a}\",\"params\":{\"q\":\"x}y\",\"note\":\"a}b\"}}";
    CHECK(jx_is_object(p) == 1, "含 } 的字符串仍是合法 JSON");
    CHECK_STR(jx_get_str(p, "id", buf, sizeof(buf)) == 1 ? buf : "", "a}", "字符串里的 } 不当结构");
    CHECK(jx_find_raw(p, "params", buf, sizeof(buf)) == 1, "取含 } 的 params");
    CHECK_STR(jx_get_str(buf, "q", buf, sizeof(buf)) == 1 ? buf : "", "x}y", "params 里的 }");

    /* 2) 转义引号与反斜杠（Windows 路径） */
    p = "{\"params\":{\"path\":\"C:\\\\Users\\\\me\\\\a \\\"b\\\".txt\"}}";
    CHECK(jx_find_raw(p, "params", buf, sizeof(buf)) == 1, "取含转义反斜杠的 params");
    CHECK_STR(jx_get_str(buf, "path", buf, sizeof(buf)) == 1 ? buf : "",
              "C:\\Users\\me\\a \"b\".txt", "反转义反斜杠与引号");

    /* 3) \uXXXX 与代理对（中文文件名） */
    p = "{\"params\":{\"q\":\"\\u62a5\\u544a\"}}";
    CHECK(jx_find_raw(p, "params", buf, sizeof(buf)) == 1, "取含 \\u 的 params");
    CHECK_STR(jx_get_str(buf, "q", buf, sizeof(buf)) == 1 ? buf : "", "报告", "\\uXXXX 解码");

    p = "{\"params\":{\"q\":\"\\ud83d\\ude00\"}}";
    CHECK(jx_find_raw(p, "params", buf, sizeof(buf)) == 1, "取含代理对的 params");
    CHECK(jx_get_str(buf, "q", buf, sizeof(buf)) == 1, "代理对解码为 UTF-8");

    /* 4) 嵌套对象/数组里的同名键不得污染顶层 */
    p = "{\"outer\":{\"id\":\"WRONG\"},\"id\":\"RIGHT\"}";
    CHECK_STR(jx_get_str(p, "id", buf, sizeof(buf)) == 1 ? buf : "", "RIGHT", "只匹配顶层键");

    p = "{\"list\":[1,2,{\"action\":\"WRONG\"}],\"action\":\"RIGHT\"}";
    CHECK_STR(jx_get_str(p, "action", buf, sizeof(buf)) == 1 ? buf : "", "RIGHT", "跳过数组内同名键");

    /* 5) 类型严格性 */
    p = "{\"n\":\"50\",\"s\":\"true\",\"t\":true}";
    {
        int64_t n = 0;
        int b = 0;
        CHECK(jx_get_i64(p, "n", &n) == 0, "字符串形式的数字不算数字");
        CHECK(jx_get_bool(p, "s", &b) == 0, "字符串形式的 true 不算布尔");
        CHECK(jx_get_bool(p, "t", &b) == 1 && b == 1, "真正的 true");
        CHECK(jx_get_str(p, "t", buf, sizeof(buf)) == 0, "布尔不被当字符串");
    }

    /* 6) 非法输入必须被拒绝，而不是被猜着解析 */
    printf("[json] 非法输入拒绝\n");
    CHECK(jx_is_object("") == 0, "空串非法");
    CHECK(jx_is_object("{") == 0, "未闭合非法");
    CHECK(jx_is_object("[]") == 0, "数组不是对象");
    CHECK(jx_is_object("{\"a\":}") == 0, "缺值非法");
    CHECK(jx_is_object("{\"a\":1,}") == 0, "尾逗号非法");
    CHECK(jx_is_object("{\"a\" 1}") == 0, "缺冒号非法");
    CHECK(jx_is_object("{\"a\":\"unterminated}") == 0, "未闭合字符串非法");
}

static void test_json_escape(void)
{
    char out[256];

    printf("[json] 转义\n");
    CHECK(jx_escape("a\"b\\c", out, sizeof(out)) >= 0, "转义成功");
    CHECK_STR(out, "a\\\"b\\\\c", "引号与反斜杠");

    jx_escape("line1\nline2\ttab", out, sizeof(out));
    CHECK_STR(out, "line1\\nline2\\ttab", "控制字符转义");

    /* 控制字符必须走 \u00XX，否则输出不是合法 JSON */
    {
        char raw[4];
        raw[0] = 'a'; raw[1] = 0x01; raw[2] = 'b'; raw[3] = '\0';
        jx_escape(raw, out, sizeof(out));
        CHECK_STR(out, "a\\u0001b", "0x01 转成 \\u0001");
    }

    /* 缓冲不足必须返回 -1 且仍是合法 NUL 结尾串（绝不越界） */
    {
        int r = jx_escape("aaaaaaaaaaaaaaaaaaaaaaaaaaaa", out, 8);
        CHECK(r == -1, "空间不足返回 -1");
        CHECK(strlen(out) < 8, "截断后不越界");
    }
}

/* ============================ 路径安全 ============================ */
static void test_path_within(void)
{
    char root[HD_PATH_MAX];
    char child[HD_PATH_MAX];

    printf("[path] 白名单判定\n");
    CHECK(hd_path_abs("C:/work/data", root, sizeof(root)) == 0 ||
          hd_path_abs("/work/data", root, sizeof(root)) == 0, "规范化根目录");

    /* 根目录本身 */
    snprintf(child, sizeof(child), "%s", root);
    CHECK(hd_path_within(child, root) == 1, "根目录本身算在内");

    /* 子路径（用平台分隔符拼接） */
    hd_path_join(child, sizeof(child), root, "a.txt");
    CHECK(hd_path_within(child, root) == 1, "直接子文件在内");

    hd_path_join(child, sizeof(child), root, "sub");
    hd_path_join(child, sizeof(child), child, "b.txt");
    CHECK(hd_path_within(child, root) == 1, "深层子文件在内");

    /* 关键：前缀相同但不是子目录，必须被拒绝（/data vs /database） */
    {
        char sibling[HD_PATH_MAX + 8];
        snprintf(sibling, sizeof(sibling), "%sX", root);
        CHECK(hd_path_within(sibling, root) == 0, "前缀相同但不是子目录 → 拒绝");
    }
    {
        char sibling2[HD_PATH_MAX + 8];
        char parent[HD_PATH_MAX + 8];
        snprintf(parent, sizeof(parent), "%s", root);
        {
            char* sep = strrchr(parent, HD_PATH_SEP);
            if (sep) *sep = '\0';
        }
        snprintf(sibling2, sizeof(sibling2), "%s", parent);
        CHECK(hd_path_within(sibling2, root) == 0, "父目录不在其内");
    }
}

static void test_path_escape(void)
{
    char out[HD_PATH_MAX];

    printf("[path] 越权路径拒绝\n");
    /* 上跳 */
    CHECK(hd_path_sanitize_rel("../secret.txt", out, sizeof(out)) == 0, "拒绝 ../");
    CHECK(hd_path_sanitize_rel("a/../../secret.txt", out, sizeof(out)) == 0, "拒绝 a/../../");
    CHECK(hd_path_sanitize_rel("..", out, sizeof(out)) == 0, "拒绝 ..");
    CHECK(hd_path_sanitize_rel("a/..", out, sizeof(out)) == 0, "拒绝 a/..");
    CHECK(hd_path_sanitize_rel("a\\..\\..\\b", out, sizeof(out)) == 0, "反斜杠形式的上跳也拒绝");

    /* 绝对路径与盘符、UNC */
    CHECK(hd_path_sanitize_rel("/etc/passwd", out, sizeof(out)) == 0, "拒绝绝对路径");
    CHECK(hd_path_sanitize_rel("\\windows\\system32", out, sizeof(out)) == 0, "拒绝根相对路径");
    CHECK(hd_path_sanitize_rel("C:/Windows/win.ini", out, sizeof(out)) == 0, "拒绝盘符");
    CHECK(hd_path_sanitize_rel("c:win.ini", out, sizeof(out)) == 0, "拒绝盘符相对路径");
    CHECK(hd_path_sanitize_rel("//server/share/x", out, sizeof(out)) == 0, "拒绝 UNC");
    CHECK(hd_path_sanitize_rel("a:b.txt", out, sizeof(out)) == 0, "拒绝 ADS 冒号");

    /* 控制字符 */
    CHECK(hd_path_sanitize_rel("a\nb.txt", out, sizeof(out)) == 0, "拒绝控制字符");

    /* 合法输入必须通过，并规范化分隔符 */
    CHECK(hd_path_sanitize_rel("a.txt", out, sizeof(out)) == 1, "接受普通文件名");
    CHECK_STR(out, "a.txt", "普通文件名原样");
    CHECK(hd_path_sanitize_rel("sub/dir/a.txt", out, sizeof(out)) == 1, "接受子目录");
    CHECK(hd_path_sanitize_rel("./sub//a.txt", out, sizeof(out)) == 1, "折叠 . 与重复分隔符");
    CHECK_STR(out, HD_PATH_SEP == '\\' ? "sub\\a.txt" : "sub/a.txt", "规范化结果");
    CHECK(hd_path_sanitize_rel("目录/文件.txt", out, sizeof(out)) == 1, "接受中文路径");
}

static void test_path_abs(void)
{
    char a[HD_PATH_MAX];
    char b[HD_PATH_MAX];
    char c[HD_PATH_MAX];

    printf("[path] 绝对化与折叠\n");
    CHECK(hd_path_abs("a/b", a, sizeof(a)) == 0, "相对路径绝对化");
    CHECK(a[0] == HD_PATH_SEP || (a[1] == ':' && HD_PATH_SEP == '\\'), "结果是绝对路径");

    /* a/b/../c 应折叠为 a/c */
    CHECK(hd_path_abs("a/b/../c", b, sizeof(b)) == 0, "含 .. 的路径规范化");
    CHECK(hd_path_abs("a/c", c, sizeof(c)) == 0, "参照路径");
    CHECK(strcmp(b, c) == 0, "a/b/../c 折叠为 a/c");

    /* 过度上跳应停在根，不产生非法路径 */
    CHECK(hd_path_abs("../../../../x", b, sizeof(b)) == 0, "过度上跳不崩溃");
    CHECK(strstr(b, "..") == NULL, "结果不含 ..");
}

/*
 * 别名安全回归：这些函数都曾经因为"先把 out 清零/写入，再读入参"而在
 * hd_path_abs(buf, buf, ...) 这类调用下把合法输入清空（真实 bug，已修）。
 */
static void test_alias_safety(void)
{
    char buf[HD_PATH_MAX];
    char ref[HD_PATH_MAX];

    printf("[alias] 输入输出同一缓冲\n");

    /* hd_path_abs(buf, buf) */
    snprintf(buf, sizeof(buf), "sub/dir");
    CHECK(hd_path_abs("sub/dir", ref, sizeof(ref)) == 0, "参照绝对化");
    CHECK(hd_path_abs(buf, buf, sizeof(buf)) == 0, "别名调用返回成功");
    CHECK(strcmp(buf, ref) == 0, "别名调用结果与分离缓冲一致");

    /* hd_path_sanitize_rel(buf, buf) */
    snprintf(buf, sizeof(buf), "a/b.txt");
    CHECK(hd_path_sanitize_rel(buf, buf, sizeof(buf)) == 1, "净化别名调用成功");
    CHECK_STR(buf, HD_PATH_SEP == '\\' ? "a\\b.txt" : "a/b.txt", "净化别名调用结果正确");

    /* hd_path_join(buf, buf, "x") */
    snprintf(buf, sizeof(buf), "base");
    hd_path_join(buf, sizeof(buf), buf, "x");
    CHECK_STR(buf, HD_PATH_SEP == '\\' ? "base\\x" : "base/x", "拼接别名调用结果正确");

    /* jx_get_str(obj, key, obj) */
    snprintf(buf, sizeof(buf), "{\"k\":\"value\"}");
    {
        char got[64];
        CHECK(jx_get_str(buf, "k", got, sizeof(got)) == 1, "JSON 取值参照");
        CHECK(jx_get_str(buf, "k", buf, sizeof(buf)) == 1, "JSON 取值别名调用成功");
        CHECK_STR(buf, "value", "JSON 取值别名调用结果正确");
    }
}

static void test_codeword(void)
{
    char c1[64], c2[64], k1[96], k2[96];

    printf("[sec] 口令生成\n");
    hd_generate_codeword(c1, sizeof(c1));
    hd_generate_codeword(c2, sizeof(c2));
    CHECK(strncmp(c1, "hamster-", 8) == 0, "前缀正确");
    CHECK(strlen(c1) == 8 + 32, "32 位十六进制");
    CHECK(strcmp(c1, c2) != 0, "两次生成不相同（修可预测口令）");

    hd_generate_api_key(k1, sizeof(k1));
    hd_generate_api_key(k2, sizeof(k2));
    CHECK(strncmp(k1, "hk_", 3) == 0, "API 密钥前缀");
    CHECK(strcmp(k1, k2) != 0, "两次生成不相同");

    CHECK(hd_ct_equal("abc", "abc") == 1, "常量时间比较：相等");
    CHECK(hd_ct_equal("abc", "abd") == 0, "常量时间比较：不等");
    CHECK(hd_ct_equal("abc", "abcd") == 0, "长度不同视为不等");
    CHECK(hd_ct_equal("", "") == 1, "空串相等");
}

int main(void)
{
    printf("=== jsonx / 路径安全 单元测试 ===\n\n");
    test_json_basic();
    test_json_tricky();
    test_json_escape();
    test_path_within();
    test_path_escape();
    test_path_abs();
    test_alias_safety();
    test_codeword();

    printf("\n=== 结果: 通过 %d, 失败 %d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
