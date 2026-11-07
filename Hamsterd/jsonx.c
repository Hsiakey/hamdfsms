/* jsonx — 严格 JSON 子集工具，实现见 jsonx.h 的说明 */

#include "jsonx.h"

#include <string.h>
#include <stdlib.h>

/* ==========================================================================
 * 内部扫描器（严格校验，不做"括号配平就算合法"的宽松跳过）
 * ========================================================================== */

static const char* skip_ws(const char* p, const char* end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

static int is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* 严格扫描字符串（p 指向起始引号），返回闭合引号之后的位置 */
static const char* scan_string(const char* p, const char* end)
{
    if (p >= end || *p != '"') return NULL;
    p++;
    while (p < end) {
        unsigned char c = (unsigned char)*p;
        if (c == '"') return p + 1;
        if (c == '\\') {
            if (p + 1 >= end) return NULL;
            switch (p[1]) {
                case '"': case '\\': case '/': case 'b':
                case 'f': case 'n': case 'r': case 't':
                    p += 2;
                    break;
                case 'u':
                    if (p + 5 >= end) return NULL;
                    if (!is_hex(p[2]) || !is_hex(p[3]) || !is_hex(p[4]) || !is_hex(p[5])) return NULL;
                    p += 6;
                    break;
                default:
                    return NULL;                    /* 未知转义 → 非法 */
            }
            continue;
        }
        if (c < 0x20) return NULL;                  /* 原始控制字符 → 非法 */
        p++;
    }
    return NULL;
}

/* 严格扫描数字：-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)? */
static const char* scan_number(const char* p, const char* end)
{
    if (p < end && *p == '-') p++;
    if (p >= end) return NULL;

    if (*p == '0') { p++; }
    else if (*p >= '1' && *p <= '9') { while (p < end && *p >= '0' && *p <= '9') p++; }
    else return NULL;

    if (p < end && *p == '.') {
        p++;
        if (p >= end || *p < '0' || *p > '9') return NULL;
        while (p < end && *p >= '0' && *p <= '9') p++;
    }
    if (p < end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < end && (*p == '+' || *p == '-')) p++;
        if (p >= end || *p < '0' || *p > '9') return NULL;
        while (p < end && *p >= '0' && *p <= '9') p++;
    }
    return p;
}

static const char* scan_value(const char* p, const char* end);

static const char* scan_object(const char* p, const char* end)
{
    if (p >= end || *p != '{') return NULL;
    p = skip_ws(p + 1, end);
    if (p < end && *p == '}') return p + 1;

    for (;;) {
        p = scan_string(p, end);
        if (!p) return NULL;
        p = skip_ws(p, end);
        if (p >= end || *p != ':') return NULL;
        p = scan_value(p + 1, end);
        if (!p) return NULL;
        p = skip_ws(p, end);
        if (p >= end) return NULL;
        if (*p == ',') { p = skip_ws(p + 1, end); continue; }
        if (*p == '}') return p + 1;
        return NULL;
    }
}

static const char* scan_array(const char* p, const char* end)
{
    if (p >= end || *p != '[') return NULL;
    p = skip_ws(p + 1, end);
    if (p < end && *p == ']') return p + 1;

    for (;;) {
        p = scan_value(p, end);
        if (!p) return NULL;
        p = skip_ws(p, end);
        if (p >= end) return NULL;
        if (*p == ',') { p = skip_ws(p + 1, end); continue; }
        if (*p == ']') return p + 1;
        return NULL;
    }
}

static const char* scan_value(const char* p, const char* end)
{
    p = skip_ws(p, end);
    if (p >= end) return NULL;

    switch (*p) {
        case '"': return scan_string(p, end);
        case '{': return scan_object(p, end);
        case '[': return scan_array(p, end);
        case 't': return (end - p >= 4 && memcmp(p, "true", 4) == 0)  ? p + 4 : NULL;
        case 'f': return (end - p >= 5 && memcmp(p, "false", 5) == 0) ? p + 5 : NULL;
        case 'n': return (end - p >= 4 && memcmp(p, "null", 4) == 0)  ? p + 4 : NULL;
        default:  return scan_number(p, end);
    }
}

/* 解析键名（反转义常用形式），返回闭合引号之后的位置 */
static const char* read_key(const char* p, const char* end, char* buf, size_t n)
{
    const char* e;
    const char* q;
    size_t i = 0;

    if (p >= end || *p != '"') return NULL;
    e = scan_string(p, end);
    if (!e) return NULL;
    e = e - 1;                          /* 指回闭合引号 */

    q = p + 1;
    while (q < e && i + 1 < n) {
        if (*q == '\\' && q + 1 < e) {
            q++;
            switch (*q) {
                case 'n':  buf[i++] = '\n'; break;
                case 't':  buf[i++] = '\t'; break;
                case 'r':  buf[i++] = '\r'; break;
                case 'b':  buf[i++] = '\b'; break;
                case 'f':  buf[i++] = '\f'; break;
                case '/':  buf[i++] = '/';  break;
                case '"':  buf[i++] = '"';  break;
                case '\\': buf[i++] = '\\'; break;
                default:   buf[i++] = *q;   break;   /* \uXXXX 在键名中极罕见，按字面处理 */
            }
            q++;
        } else {
            buf[i++] = *q++;
        }
    }
    buf[i] = '\0';
    return e + 1;
}

/*
 * 在深度 1 查找键，输出值的起止位置。
 * 返回 1=找到，0=未找到，-1=输入非法。
 */
static int find_value(const char* obj, const char* key,
                      const char** vstart, const char** vend)
{
    const char* p;
    const char* end;
    size_t klen;

    if (!obj || !key) return -1;
    end = obj + strlen(obj);
    p = skip_ws(obj, end);
    if (p >= end || *p != '{') return -1;
    p++;
    p = skip_ws(p, end);

    klen = strlen(key);

    for (;;) {
        char kbuf[256];
        const char* vs;
        const char* ve;

        p = skip_ws(p, end);
        if (p >= end) return -1;
        if (*p == '}') return 0;                    /* 对象结束，没找到 */

        p = read_key(p, end, kbuf, sizeof(kbuf));
        if (!p) return -1;

        p = skip_ws(p, end);
        if (p >= end || *p != ':') return -1;
        p++;

        vs = skip_ws(p, end);
        ve = scan_value(vs, end);
        if (!ve) return -1;

        if (strlen(kbuf) == klen && memcmp(kbuf, key, klen) == 0) {
            *vstart = vs;
            *vend = ve;
            return 1;
        }
        p = skip_ws(ve, end);
        if (p < end && *p == ',') { p++; continue; }
        if (p < end && *p == '}') return 0;
        return -1;
    }
}

/* ==========================================================================
 * 公开接口
 * ========================================================================== */

int jx_is_object(const char* s)
{
    const char* p;
    const char* end;
    if (!s) return 0;
    end = s + strlen(s);
    p = skip_ws(s, end);
    if (p >= end || *p != '{') return 0;
    p = scan_value(p, end);
    if (!p) return 0;
    p = skip_ws(p, end);
    return (p == end) ? 1 : 0;
}

int jx_has(const char* obj, const char* key)
{
    const char* a;
    const char* b;
    return find_value(obj, key, &a, &b) == 1;
}

int jx_find_raw(const char* obj, const char* key, char* out, size_t n)
{
    const char* a;
    const char* b;
    size_t len;
    int found;

    if (!out || n == 0) return -1;

    /* 先定位再写 out：允许调用方把 out 与 obj 传成同一缓冲 */
    found = find_value(obj, key, &a, &b);
    if (found != 1) { out[0] = '\0'; return 0; }

    if (*a == '"') {
        char tmp[4096];
        size_t tlen = (size_t)((b - 1) - (a + 1));
        if (tlen >= sizeof(tmp)) { out[0] = '\0'; return -1; }
        memmove(tmp, a + 1, tlen);
        tmp[tlen] = '\0';
        if (jx_unescape(tmp, out, n) < 0) return -1;
        return 1;
    }

    len = (size_t)(b - a);
    if (len + 1 > n) {
        if (n > 1) { memmove(out, a, n - 1); out[n - 1] = '\0'; }
        return -1;
    }
    memmove(out, a, len);
    out[len] = '\0';
    return 1;
}

int jx_get_str(const char* obj, const char* key, char* out, size_t n)
{
    const char* a;
    const char* b;
    char tmp[4096];
    size_t tlen;
    int found;

    if (!out || n == 0) return -1;

    found = find_value(obj, key, &a, &b);
    if (found != 1) { out[0] = '\0'; return 0; }
    if (*a != '"')  { out[0] = '\0'; return 0; }        /* 类型不符 */

    tlen = (size_t)((b - 1) - (a + 1));
    if (tlen >= sizeof(tmp)) { out[0] = '\0'; return -1; }
    memmove(tmp, a + 1, tlen);
    tmp[tlen] = '\0';
    if (jx_unescape(tmp, out, n) < 0) return -1;
    return 1;
}

int jx_get_i64(const char* obj, const char* key, int64_t* out)
{
    const char* a;
    const char* b;
    char buf[40];
    size_t len;
    char* stop = NULL;
    int64_t v;
    int found;

    if (!out) return 0;
    found = find_value(obj, key, &a, &b);
    if (found != 1) return 0;
    if (*a == '"') return 0;

    len = (size_t)(b - a);
    if (len == 0 || len >= sizeof(buf)) return 0;
    memcpy(buf, a, len);
    buf[len] = '\0';

    v = strtoll(buf, &stop, 10);
    if (stop == buf || (stop && *stop != '\0')) return 0;
    *out = v;
    return 1;
}

int jx_get_int(const char* obj, const char* key, int* out)
{
    int64_t v;
    if (!out) return 0;
    if (jx_get_i64(obj, key, &v) != 1) return 0;
    if (v < -2147483647LL - 1 || v > 2147483647LL) return 0;
    *out = (int)v;
    return 1;
}

int jx_get_bool(const char* obj, const char* key, int* out)
{
    const char* a;
    const char* b;
    if (!out) return 0;
    if (find_value(obj, key, &a, &b) != 1) return 0;
    if ((size_t)(b - a) == 4 && memcmp(a, "true", 4) == 0)  { *out = 1; return 1; }
    if ((size_t)(b - a) == 5 && memcmp(a, "false", 5) == 0) { *out = 0; return 1; }
    return 0;
}

int jx_escape(const char* in, char* out, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    size_t i = 0;
    size_t w = 0;
    int truncated = 0;

    if (!out || n == 0) return -1;
    if (!in) { out[0] = '\0'; return 0; }

    for (i = 0; in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        const char* rep = NULL;
        char ubuf[8];

        switch (c) {
            case '"':  rep = "\\\""; break;
            case '\\': rep = "\\\\"; break;
            case '\b': rep = "\\b";  break;
            case '\f': rep = "\\f";  break;
            case '\n': rep = "\\n";  break;
            case '\r': rep = "\\r";  break;
            case '\t': rep = "\\t";  break;
            default:
                if (c < 0x20) {
                    ubuf[0] = '\\'; ubuf[1] = 'u'; ubuf[2] = '0'; ubuf[3] = '0';
                    ubuf[4] = hex[(c >> 4) & 0xF];
                    ubuf[5] = hex[c & 0xF];
                    ubuf[6] = '\0';
                    rep = ubuf;
                }
                break;
        }

        if (rep) {
            size_t rl = strlen(rep);
            if (w + rl + 1 > n) { truncated = 1; break; }
            memcpy(out + w, rep, rl);
            w += rl;
        } else {
            if (w + 2 > n) { truncated = 1; break; }
            out[w++] = (char)c;
        }
    }

    out[w] = '\0';
    return truncated ? -1 : (int)w;
}

int jx_unescape(const char* in, char* out, size_t n)
{
    size_t i = 0;
    size_t w = 0;

    if (!out || n == 0) return -1;
    if (!in) { out[0] = '\0'; return 0; }

    while (in[i]) {
        unsigned char c = (unsigned char)in[i];

        if (c != '\\') {
            if (w + 1 >= n) { out[w] = '\0'; return -1; }
            out[w++] = (char)c;
            i++;
            continue;
        }

        i++;
        if (!in[i]) break;

        switch (in[i]) {
            case '"':  if (w + 1 >= n) goto overflow; out[w++] = '"';  i++; break;
            case '\\': if (w + 1 >= n) goto overflow; out[w++] = '\\'; i++; break;
            case '/':  if (w + 1 >= n) goto overflow; out[w++] = '/';  i++; break;
            case 'b':  if (w + 1 >= n) goto overflow; out[w++] = '\b'; i++; break;
            case 'f':  if (w + 1 >= n) goto overflow; out[w++] = '\f'; i++; break;
            case 'n':  if (w + 1 >= n) goto overflow; out[w++] = '\n'; i++; break;
            case 'r':  if (w + 1 >= n) goto overflow; out[w++] = '\r'; i++; break;
            case 't':  if (w + 1 >= n) goto overflow; out[w++] = '\t'; i++; break;
            case 'u': {
                unsigned int cp = 0;
                int k;
                int bad = 0;

                i++;
                for (k = 0; k < 4; k++) {
                    char h = in[i + k];
                    unsigned int d;
                    if (h >= '0' && h <= '9') d = (unsigned int)(h - '0');
                    else if (h >= 'a' && h <= 'f') d = (unsigned int)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') d = (unsigned int)(h - 'A' + 10);
                    else { bad = 1; break; }
                    cp = (cp << 4) | d;
                }
                if (bad) {
                    cp = 0xFFFD;
                } else {
                    i += 4;
                    /* 代理对：\uD800-\uDBFF 后紧跟 \uDC00-\uDFFF */
                    if (cp >= 0xD800 && cp <= 0xDBFF && in[i] == '\\' && in[i + 1] == 'u') {
                        unsigned int lo = 0;
                        int ok = 1;
                        for (k = 0; k < 4; k++) {
                            char h = in[i + 2 + k];
                            unsigned int d;
                            if (h >= '0' && h <= '9') d = (unsigned int)(h - '0');
                            else if (h >= 'a' && h <= 'f') d = (unsigned int)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') d = (unsigned int)(h - 'A' + 10);
                            else { ok = 0; break; }
                            lo = (lo << 4) | d;
                        }
                        if (ok && lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            i += 6;
                        }
                    }
                }

                if (cp < 0x80) {
                    if (w + 1 >= n) goto overflow;
                    out[w++] = (char)cp;
                } else if (cp < 0x800) {
                    if (w + 2 >= n) goto overflow;
                    out[w++] = (char)(0xC0 | (cp >> 6));
                    out[w++] = (char)(0x80 | (cp & 0x3F));
                } else if (cp < 0x10000) {
                    if (w + 3 >= n) goto overflow;
                    out[w++] = (char)(0xE0 | (cp >> 12));
                    out[w++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[w++] = (char)(0x80 | (cp & 0x3F));
                } else {
                    if (w + 4 >= n) goto overflow;
                    out[w++] = (char)(0xF0 | (cp >> 18));
                    out[w++] = (char)(0x80 | ((cp >> 12) & 0x3F));
                    out[w++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[w++] = (char)(0x80 | (cp & 0x3F));
                }
                break;
            }
            default:
                /* 未知转义：按字面保留 */
                if (w + 1 >= n) goto overflow;
                out[w++] = in[i];
                i++;
                break;
        }
    }

    out[w] = '\0';
    return (int)w;

overflow:
    out[w] = '\0';
    return -1;
}