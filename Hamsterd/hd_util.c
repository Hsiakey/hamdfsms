/* hd_util — 平台适配、日志、时间、随机数、字符串构建、路径安全、文件与哈希 */

#ifdef _WIN32
    #define _CRT_RAND_S          /* 启用 rand_s（CSPRNG），必须在包含 stdlib.h 之前 */
#endif

#include "hd_util.h"
#include "jsonx.h"
#include "xxhash.h"

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
    #include <process.h>
    #include <direct.h>
    #include <io.h>
    #include <sys/stat.h>       /* _wstat64 / _S_IFDIR */
    #include <sys/types.h>
#else
    #include <sys/random.h>
#endif

/* ==========================================================================
 * 全局
 * ========================================================================== */
hd_config    g_cfg;
volatile int g_stop = 0;

/* ==========================================================================
 * 日志
 * ========================================================================== */
#define HD_LOG_ROTATE_BYTES (8 * 1024 * 1024)

static FILE*    s_log_fp      = NULL;
static int      s_log_stdout  = 1;
static int      s_log_level   = HD_LOG_INFO;
static hd_mutex s_log_mtx;
static int      s_log_mtx_ok  = 0;
static char     s_log_path[HD_PATH_MAX];
static long long s_log_bytes  = 0;

const char* hd_log_file_path(void) { return s_log_path; }

void hd_log_init(const char* file_path, int also_stdout, int level)
{
    hd_mutex_init(&s_log_mtx);
    s_log_mtx_ok = 1;
    s_log_stdout = also_stdout ? 1 : 0;
    s_log_level  = level;

    if (file_path && file_path[0]) {
        snprintf(s_log_path, sizeof(s_log_path), "%s", file_path);
        /* 超过上限则轮转一次，保留上一份历史 */
        hd_file_info info;
        if (hd_stat64(s_log_path, &info) == 0 && info.size > HD_LOG_ROTATE_BYTES) {
            char old[HD_PATH_MAX + 8];
            snprintf(old, sizeof(old), "%s.1", s_log_path);
            hd_remove_file(old);
            hd_rename(s_log_path, old);
        }
        s_log_fp = hd_fopen(s_log_path, "ab");
        if (s_log_fp) {
            if (hd_stat64(s_log_path, &info) == 0) s_log_bytes = info.size;
            fprintf(s_log_fp, "\xEF\xBB\xBF");   /* BOM：便于 Windows 记事本识别 UTF-8 */
            fflush(s_log_fp);
        }
    }
}

void hd_log_shutdown(void)
{
    if (s_log_fp) { fclose(s_log_fp); s_log_fp = NULL; }
    if (s_log_mtx_ok) { hd_mutex_destroy(&s_log_mtx); s_log_mtx_ok = 0; }
}

static void log_rotate_if_needed(void)
{
    if (!s_log_fp) return;
    if (s_log_bytes < HD_LOG_ROTATE_BYTES) return;

    fclose(s_log_fp);
    s_log_fp = NULL;

    {
        char old[HD_PATH_MAX + 8];
        snprintf(old, sizeof(old), "%s.1", s_log_path);
        hd_remove_file(old);
        hd_rename(s_log_path, old);
    }
    s_log_fp = hd_fopen(s_log_path, "ab");
    s_log_bytes = 0;
}

void hd_logf(int level, const char* tag, const char* fmt, ...)
{
    char      body[2048];
    char      stamp[32];
    va_list   ap;

    if (level > s_log_level) return;

    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    hd_iso_local(stamp, sizeof(stamp));

    if (s_log_mtx_ok) hd_mutex_lock(&s_log_mtx);

    if (s_log_stdout) {
        fprintf(stdout, "[%s] %-5s %s\n", stamp, tag ? tag : "-", body);
        fflush(stdout);
    }
    if (s_log_fp) {
        int n = fprintf(s_log_fp, "[%s] %-5s %s\n", stamp, tag ? tag : "-", body);
        if (n > 0) s_log_bytes += n;
        fflush(s_log_fp);
        log_rotate_if_needed();
    }

    if (s_log_mtx_ok) hd_mutex_unlock(&s_log_mtx);
}

/* ==========================================================================
 * 时间
 * ========================================================================== */
int64_t hd_now_ms(void)
{
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (int64_t)(u.QuadPart / 10000ULL) - 11644473600000LL;   /* 1601→1970 */
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

void hd_iso_local(char* out, size_t n)
{
    time_t t = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    strftime(out, n, "%Y-%m-%dT%H:%M:%S", &tmv);
}

void hd_sleep_ms(int ms)
{
    if (ms <= 0) return;
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    usleep((useconds_t)ms * 1000);
#endif
}

int hd_wait_ms(int ms)
{
    /* 分片等待，保证停止请求最多 100ms 内被响应 */
    while (ms > 0) {
        int step = ms > 100 ? 100 : ms;
        if (g_stop) return 1;
        hd_sleep_ms(step);
        ms -= step;
    }
    return g_stop ? 1 : 0;
}

/* ==========================================================================
 * 随机数（CSPRNG）与常量时间比较
 * ========================================================================== */
int hd_random_bytes(void* out, size_t n)
{
    unsigned char* p = (unsigned char*)out;
    size_t i = 0;
    if (!out) return -1;

#ifdef _WIN32
    while (i < n) {
        unsigned int v = 0;
        if (rand_s(&v) != 0) break;
        for (int k = 0; k < 4 && i < n; k++) p[i++] = (unsigned char)(v >> (8 * k));
    }
#else
    {
        ssize_t r = getrandom(p, n, 0);
        if (r == (ssize_t)n) return 0;
        i = (r > 0) ? (size_t)r : 0;
    }
    if (i < n) {
        FILE* fp = fopen("/dev/urandom", "rb");
        if (fp) {
            size_t got = fread(p + i, 1, n - i, fp);
            fclose(fp);
            i += got;
        }
    }
#endif

    /* 兜底：不足以 xxhash 派生（绝不用可预测序列直接当密钥） */
    if (i < n) {
        uint64_t seed = (uint64_t)hd_now_ms() ^ ((uint64_t)(uintptr_t)&p) ^
                        ((uint64_t)rand() << 32) ^ (uint64_t)rand();
        while (i < n) {
            XXH64_hash_t h = XXH64(&seed, sizeof(seed), (XXH64_hash_t)(i * 0x9E3779B97F4A7C15ULL));
            size_t take = (n - i) < sizeof(h) ? (n - i) : sizeof(h);
            memcpy(p + i, &h, take);
            i += take;
            seed++;
        }
    }
    return 0;
}

void hd_generate_codeword(char* out, size_t n)
{
    unsigned char raw[16];
    static const char hex[] = "0123456789abcdef";
    size_t need = 8 + 1 + 32 + 1;   /* "hamster-" + 32 hex + NUL */
    size_t i;

    if (!out || n < need) { if (out && n) out[0] = '\0'; return; }
    hd_random_bytes(raw, sizeof(raw));

    memcpy(out, "hamster-", 8);
    for (i = 0; i < sizeof(raw); i++) {
        out[8 + i * 2]     = hex[(raw[i] >> 4) & 0xF];
        out[8 + i * 2 + 1] = hex[raw[i] & 0xF];
    }
    out[8 + 32] = '\0';
}

void hd_generate_api_key(char* out, size_t n)
{
    unsigned char raw[24];
    static const char hex[] = "0123456789abcdef";
    size_t need = 3 + 1 + 48 + 1;   /* "hk_" + 48 hex + NUL */
    size_t i;

    if (!out || n < need) { if (out && n) out[0] = '\0'; return; }
    hd_random_bytes(raw, sizeof(raw));

    memcpy(out, "hk_", 3);
    for (i = 0; i < sizeof(raw); i++) {
        out[3 + i * 2]     = hex[(raw[i] >> 4) & 0xF];
        out[3 + i * 2 + 1] = hex[raw[i] & 0xF];
    }
    out[3 + 48] = '\0';
}

int hd_ct_equal(const char* a, const char* b)
{
    size_t la, lb, i, m;
    unsigned char diff = 0;

    if (!a || !b) return 0;
    la = strlen(a);
    lb = strlen(b);
    m  = (la > lb) ? la : lb;

    for (i = 0; i < m; i++) {
        unsigned char ca = (i < la) ? (unsigned char)a[i] : 0;
        unsigned char cb = (i < lb) ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }
    /* 长度不同也视为不等 */
    diff |= (unsigned char)((la == lb) ? 0 : 1);
    return diff == 0;
}

/* ==========================================================================
 * 字符串构建器
 * ========================================================================== */
void hd_sb_init(hd_sb* sb, char* buf, size_t cap)
{
    sb->buf = buf;
    sb->cap = cap;
    sb->len = 0;
    sb->overflow = 0;
    if (cap) buf[0] = '\0';
}

int hd_sb_ok(const hd_sb* sb) { return sb->overflow ? 0 : 1; }
size_t hd_sb_len(const hd_sb* sb) { return sb->len; }

void hd_sb_putc(hd_sb* sb, char c)
{
    if (sb->len + 1 >= sb->cap) { sb->overflow = 1; return; }
    sb->buf[sb->len++] = c;
    sb->buf[sb->len] = '\0';
}

void hd_sb_puts(hd_sb* sb, const char* s)
{
    size_t l;
    if (!s) return;
    l = strlen(s);
    if (sb->len + l + 1 > sb->cap) {
        size_t room = (sb->cap > sb->len + 1) ? (sb->cap - sb->len - 1) : 0;
        if (room) { memcpy(sb->buf + sb->len, s, room); sb->len += room; sb->buf[sb->len] = '\0'; }
        sb->overflow = 1;
        return;
    }
    memcpy(sb->buf + sb->len, s, l);
    sb->len += l;
    sb->buf[sb->len] = '\0';
}

void hd_sb_printf(hd_sb* sb, const char* fmt, ...)
{
    va_list ap;
    int n;
    size_t room;

    if (sb->overflow) return;
    room = (sb->cap > sb->len + 1) ? (sb->cap - sb->len) : 0;
    if (room == 0) { sb->overflow = 1; return; }

    va_start(ap, fmt);
    n = vsnprintf(sb->buf + sb->len, room, fmt, ap);
    va_end(ap);

    if (n < 0) { sb->overflow = 1; return; }
    if ((size_t)n >= room) {
        sb->len = sb->cap - 1;      /* vsnprintf 已按 room 截断并补 NUL */
        sb->overflow = 1;
        return;
    }
    sb->len += (size_t)n;
}

void hd_sb_json(hd_sb* sb, const char* s)
{
    /* 分块转义：单字节最坏展开为 \u00XX（6 字节），块大小取 512 输入 → 3072 输出 */
    char chunk_in[513];
    char chunk_out[512 * 6 + 1];

    if (!s) return;
    while (*s) {
        size_t take = 0;
        while (s[take] && take < sizeof(chunk_in) - 1) take++;
        memcpy(chunk_in, s, take);
        chunk_in[take] = '\0';
        chunk_out[0] = '\0';
        if (jx_escape(chunk_in, chunk_out, sizeof(chunk_out)) < 0) {
            sb->overflow = 1;
            return;
        }
        hd_sb_puts(sb, chunk_out);
        s += take;
    }
}

/* ==========================================================================
 * 路径
 * ========================================================================== */
static int is_sep(char c) { return (c == '/' || c == '\\'); }

#ifdef _WIN32
static int to_wide(const char* in, wchar_t* out, int out_count)
{
    if (!in) return -1;
    return MultiByteToWideChar(CP_UTF8, 0, in, -1, out, out_count);
}

static int to_utf8(const wchar_t* in, char* out, int out_size)
{
    int n;
    if (!in) return -1;
    n = WideCharToMultiByte(CP_UTF8, 0, in, -1, out, out_size, NULL, NULL);
    if (n <= 0) { if (out_size > 0) out[0] = '\0'; return -1; }
    return 0;
}
#endif

static void strip_trailing_sep(char* path)
{
    size_t l = strlen(path);
    while (l > 1 && is_sep(path[l - 1])) {
        /* 保留 "C:\" 与 "/" 这种根形式 */
#ifdef _WIN32
        if (l == 3 && path[1] == ':') break;
#endif
        path[--l] = '\0';
    }
}

int hd_path_abs(const char* in, char* out, size_t n)
{
    /*
     * 全程在局部缓冲里计算，最后才写 out。
     * 这允许调用方写成 hd_path_abs(buf, buf, sizeof(buf))：
     * 若一进来就 out[0]='\0'，会把输入清空，从而把合法路径判成非法。
     */
    char result[HD_PATH_MAX];

    if (!in || !out || n < 2) return -1;

#ifdef _WIN32
    {
        wchar_t win[HD_PATH_MAX];
        wchar_t wout[HD_PATH_MAX];
        DWORD   len;

        if (to_wide(in, win, HD_PATH_MAX) <= 0) return -1;
        len = GetFullPathNameW(win, HD_PATH_MAX, wout, NULL);
        if (len == 0 || len >= HD_PATH_MAX) return -1;
        if (to_utf8(wout, result, (int)sizeof(result)) != 0) return -1;
    }
#else
    {
        char tmp[HD_PATH_MAX];
        char cwd[HD_PATH_MAX];
        /* 显式长度检查：宁可明确失败，也不要静默截断成另一个路径 */
        if (strlen(in) >= sizeof(tmp)) return -1;
        if (in[0] == '/') {
            snprintf(tmp, sizeof(tmp), "%s", in);
        } else {
            size_t cl, il;
            if (!getcwd(cwd, sizeof(cwd))) return -1;
            cl = strlen(cwd);
            il = strlen(in);
            if (cl + 1 + il >= sizeof(tmp)) return -1;
            /* 显式拼接：长度已校验，避免依赖 snprintf 的隐式截断 */
            memcpy(tmp, cwd, cl);
            tmp[cl] = '/';
            memcpy(tmp + cl + 1, in, il + 1);
        }
        /* 规范化：逐组件处理 . 与 .. */
        {
            char work[HD_PATH_MAX];
            char* seg;
            char* save = NULL;
            size_t rlen = 1;

            snprintf(work, sizeof(work), "%s", tmp);
            result[0] = '/';
            result[1] = '\0';

            for (seg = strtok_r(work, "/", &save); seg; seg = strtok_r(NULL, "/", &save)) {
                if (strcmp(seg, ".") == 0) continue;
                if (strcmp(seg, "..") == 0) {
                    while (rlen > 1 && result[rlen - 1] != '/') rlen--;
                    if (rlen > 1) rlen--;                 /* 去掉分隔符本身 */
                    result[rlen] = '\0';
                    if (rlen == 0) { result[0] = '/'; result[1] = '\0'; rlen = 1; }
                    continue;
                }
                if (rlen > 1) { if (rlen + 1 < sizeof(result)) result[rlen++] = '/'; }
                {
                    size_t sl = strlen(seg);
                    if (rlen + sl >= sizeof(result)) return -1;
                    memcpy(result + rlen, seg, sl);
                    rlen += sl;
                    result[rlen] = '\0';
                }
            }
            if (rlen == 0) { result[0] = '/'; result[1] = '\0'; }
        }
    }
#endif

    /* 统一分隔符并去掉结尾分隔符 */
    {
        char* p;
        for (p = result; *p; p++) if (is_sep(*p)) *p = HD_PATH_SEP;
        strip_trailing_sep(result);
    }

    snprintf(out, n, "%s", result);
    return 0;
}

#ifdef _WIN32
static int path_char_eq(char a, char b)
{
    if (is_sep(a)) a = HD_PATH_SEP;
    if (is_sep(b)) b = HD_PATH_SEP;
    return tolower((unsigned char)a) == tolower((unsigned char)b);
}
#else
static int path_char_eq(char a, char b) { return a == b; }
#endif

int hd_path_within(const char* child_abs, const char* root_abs)
{
    size_t rl, i;

    if (!child_abs || !root_abs) return 0;
    if (!child_abs[0] || !root_abs[0]) return 0;

    rl = strlen(root_abs);
    for (i = 0; i < rl; i++) {
        if (!child_abs[i]) return 0;
        if (!path_char_eq(child_abs[i], root_abs[i])) return 0;
    }

    /* child 恰好等于 root */
    if (child_abs[rl] == '\0') return 1;
    /* root 以分隔符结尾（如 "C:\"）时，前缀吻合即在其内 */
    if (is_sep(root_abs[rl - 1])) return 1;
    /* 否则必须紧跟分隔符，避免 /data 匹配到 /database */
    return is_sep(child_abs[rl]) ? 1 : 0;
}

void hd_path_join(char* out, size_t n, const char* dir, const char* name)
{
    char tmp[HD_PATH_MAX + 64];
    size_t dl;

    if (!out || n == 0) return;
    if (!dir) dir = "";
    if (!name) name = "";

    /* 先完整构造，再写 out：out 与 dir 允许是同一块内存 */
    dl = strlen(dir);
    if (dl == 0)                 snprintf(tmp, sizeof(tmp), "%s", name);
    else if (is_sep(dir[dl - 1])) snprintf(tmp, sizeof(tmp), "%s%s", dir, name);
    else                         snprintf(tmp, sizeof(tmp), "%s%c%s", dir, HD_PATH_SEP, name);

    snprintf(out, n, "%s", tmp);
}

void hd_path_native(char* path)
{
    char* p;
    if (!path) return;
    for (p = path; *p; p++) if (is_sep(*p)) *p = HD_PATH_SEP;
}

int hd_path_sanitize_rel(const char* rel, char* out, size_t n)
{
    /* 在局部缓冲里构造，最后才写 out：允许 out 与 rel 是同一块内存 */
    char clean[HD_PATH_MAX];
    size_t w = 0;
    const char* p;

    if (!out || n < 2) return 0;
    if (!rel || rel[0] == '\0') { out[0] = '\0'; return 0; }

    /* 绝对路径 / UNC / 盘符 / 相对跳转一律拒绝 */
    if (is_sep(rel[0])) { out[0] = '\0'; return 0; }
    if (rel[1] == ':' && isalpha((unsigned char)rel[0])) { out[0] = '\0'; return 0; }

    p = rel;
    while (*p) {
        /* 取一个组件 */
        const char* s = p;
        size_t clen;
        while (*p && !is_sep(*p)) {
            unsigned char c = (unsigned char)*p;
            if (c < 0x20 || c == ':') goto reject;   /* 控制字符与 ADS/盘符 */
            p++;
        }
        clen = (size_t)(p - s);

        if (clen == 0) {                              /* 重复分隔符：折叠 */
            while (*p && is_sep(*p)) p++;
            if (!*p) break;
            continue;
        }
        if (clen == 1 && s[0] == '.') {               /* 当前目录：跳过 */
            while (*p && is_sep(*p)) p++;
            continue;
        }
        if (clen == 2 && s[0] == '.' && s[1] == '.') goto reject;   /* 上跳：拒绝 */

        if (w) { if (w + 1 >= sizeof(clean)) goto reject; clean[w++] = HD_PATH_SEP; }
        if (w + clen >= sizeof(clean)) goto reject;
        memcpy(clean + w, s, clen);
        w += clen;
        clean[w] = '\0';

        while (*p && is_sep(*p)) p++;
    }

    if (w == 0) goto reject;
    snprintf(out, n, "%s", clean);
    return 1;

reject:
    out[0] = '\0';
    return 0;
}

const char* hd_basename(const char* path)
{
    const char* p;
    const char* last = NULL;
    if (!path) return "";
    for (p = path; *p; p++) if (is_sep(*p)) last = p;
    return last ? last + 1 : path;
}

void hd_ext_lower(const char* filename, char* out, size_t n)
{
    const char* dot;
    size_t i;
    if (!out || n == 0) return;
    out[0] = '\0';
    if (!filename) return;
    dot = strrchr(filename, '.');
    if (!dot || !dot[1]) return;
    for (i = 0; dot[1 + i] && i + 1 < n; i++) out[i] = (char)tolower((unsigned char)dot[1 + i]);
    out[i] = '\0';
}

/* ==========================================================================
 * 文件
 * ========================================================================== */
int hd_stat64(const char* path, hd_file_info* info)
{
    if (!path || !info) return -1;
    memset(info, 0, sizeof(*info));

#ifdef _WIN32
    {
        wchar_t wpath[HD_PATH_MAX];
        struct _stat64 st;
        if (to_wide(path, wpath, HD_PATH_MAX) <= 0) return -1;
        if (_wstat64(wpath, &st) != 0) return -1;
        info->size  = (int64_t)st.st_size;
        info->mtime = (int64_t)st.st_mtime;
        info->is_dir = (st.st_mode & _S_IFDIR) ? 1 : 0;
    }
#else
    {
        struct stat st;
        if (stat(path, &st) != 0) return -1;
        info->size  = (int64_t)st.st_size;
        info->mtime = (int64_t)st.st_mtime;
        info->is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
    }
#endif
    return 0;
}

int hd_exists(const char* path)
{
    hd_file_info info;
    return hd_stat64(path, &info) == 0;
}

FILE* hd_fopen(const char* path, const char* mode)
{
    if (!path || !mode) return NULL;
#ifdef _WIN32
    {
        wchar_t wpath[HD_PATH_MAX];
        wchar_t wmode[16];
        if (to_wide(path, wpath, HD_PATH_MAX) <= 0) return NULL;
        if (to_wide(mode, wmode, 16) <= 0) return NULL;
        return _wfopen(wpath, wmode);
    }
#else
    return fopen(path, mode);
#endif
}

int hd_remove_file(const char* path)
{
    if (!path) return -1;
#ifdef _WIN32
    {
        wchar_t wpath[HD_PATH_MAX];
        if (to_wide(path, wpath, HD_PATH_MAX) <= 0) return -1;
        if (DeleteFileW(wpath)) return 0;
        if (RemoveDirectoryW(wpath)) return 0;       /* 空目录也可删 */
        return -1;
    }
#else
    return remove(path);
#endif
}

int hd_rename(const char* from, const char* to)
{
    if (!from || !to) return -1;
#ifdef _WIN32
    {
        wchar_t wfrom[HD_PATH_MAX];
        wchar_t wto[HD_PATH_MAX];
        if (to_wide(from, wfrom, HD_PATH_MAX) <= 0) return -1;
        if (to_wide(to, wto, HD_PATH_MAX) <= 0) return -1;
        return MoveFileExW(wfrom, wto, MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
    }
#else
    return rename(from, to);
#endif
}

int hd_mkdirs(const char* abs_dir_path)
{
    char work[HD_PATH_MAX];
    size_t i;

    if (!abs_dir_path || !abs_dir_path[0]) return -1;
    snprintf(work, sizeof(work), "%s", abs_dir_path);
    strip_trailing_sep(work);

    for (i = 1; work[i]; i++) {
        if (!is_sep(work[i])) continue;
        {
            char save = work[i];
            work[i] = '\0';
#ifdef _WIN32
            {
                wchar_t w[HD_PATH_MAX];
                if (to_wide(work, w, HD_PATH_MAX) > 0) _wmkdir(w);
            }
#else
            mkdir(work, 0777);
#endif
            work[i] = save;
        }
    }
#ifdef _WIN32
    {
        wchar_t w[HD_PATH_MAX];
        if (to_wide(work, w, HD_PATH_MAX) > 0) _wmkdir(w);
    }
#else
    mkdir(work, 0777);
#endif

    return hd_exists(work) ? 0 : -1;
}

int hd_mkdirs_for_file(const char* abs_file_path)
{
    char work[HD_PATH_MAX];
    char* p;
    size_t l;

    if (!abs_file_path) return -1;
    snprintf(work, sizeof(work), "%s", abs_file_path);
    l = strlen(work);
    /* 找到最后一个分隔符，截断为目录 */
    for (p = work + l; p > work; p--) {
        if (is_sep(*p)) { *p = '\0'; break; }
    }
    if (strlen(work) == 0) return 0;
    return hd_mkdirs(work);
}

int hd_rmdir(const char* abs_dir_path)
{
    if (!abs_dir_path) return -1;
#ifdef _WIN32
    {
        wchar_t w[HD_PATH_MAX];
        if (to_wide(abs_dir_path, w, HD_PATH_MAX) <= 0) return -1;
        return RemoveDirectoryW(w) ? 0 : -1;
    }
#else
    return rmdir(abs_dir_path);
#endif
}

int hd_is_artifact_name(const char* name)
{
    if (!name || !name[0]) return 0;
    if (strstr(name, ".part-") != NULL) return 1;                 /* 上传中转文件 */
    if (strncmp(name, "hamster.db", 10) == 0) return 1;           /* 主库 / -wal / -shm */
    if (strncmp(name, "hamsterd.log", 12) == 0) return 1;         /* 日志及其轮转副本 */
    return 0;
}

int hd_hash_fd(FILE* fp, char* out_hex33, int64_t* bytes_read)
{
    XXH3_state_t* state;
    unsigned char* buf;
    size_t n;
    XXH128_hash_t hash;
    int64_t total = 0;

    if (!fp || !out_hex33) return -1;
    out_hex33[0] = '\0';

    state = XXH3_createState();
    if (!state) return -1;
    XXH3_128bits_reset(state);

    buf = (unsigned char*)malloc(HD_CHUNK);
    if (!buf) { XXH3_freeState(state); return -1; }

    while ((n = fread(buf, 1, HD_CHUNK, fp)) > 0) {
        if (ferror(fp)) { free(buf); XXH3_freeState(state); return -1; }
        XXH3_128bits_update(state, buf, n);
        total += (int64_t)n;
    }
    free(buf);
    if (ferror(fp)) { XXH3_freeState(state); return -1; }

    hash = XXH3_128bits_digest(state);
    XXH3_freeState(state);

    snprintf(out_hex33, 33, "%016llx%016llx",
             (unsigned long long)hash.high64, (unsigned long long)hash.low64);
    if (bytes_read) *bytes_read = total;
    return 0;
}

int hd_hash_file(const char* path, char* out_hex33)
{
    FILE* fp;
    int r;
    if (!path || !out_hex33) return -1;
    fp = hd_fopen(path, "rb");
    if (!fp) return -1;
    r = hd_hash_fd(fp, out_hex33, NULL);
    fclose(fp);
    return r;
}

/* ==========================================================================
 * 流式哈希
 * ========================================================================== */
struct hd_hasher {
    XXH3_state_t* state;
};

hd_hasher* hd_hash_new(void)
{
    hd_hasher* h = (hd_hasher*)calloc(1, sizeof(hd_hasher));
    if (!h) return NULL;
    h->state = XXH3_createState();
    if (!h->state) { free(h); return NULL; }
    XXH3_128bits_reset(h->state);
    return h;
}

void hd_hash_update(hd_hasher* h, const void* data, size_t n)
{
    if (!h || !h->state || !data || n == 0) return;
    XXH3_128bits_update(h->state, data, n);
}

void hd_hash_finish(hd_hasher* h, char* out_hex33)
{
    XXH128_hash_t hash;
    if (!out_hex33) return;
    out_hex33[0] = '\0';
    if (!h || !h->state) return;
    hash = XXH3_128bits_digest(h->state);
    snprintf(out_hex33, 33, "%016llx%016llx",
             (unsigned long long)hash.high64, (unsigned long long)hash.low64);
}

void hd_hash_free(hd_hasher* h)
{
    if (!h) return;
    if (h->state) XXH3_freeState(h->state);
    free(h);
}

/* ==========================================================================
 * socket 错误
 * ========================================================================== */
int hd_sock_error(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

int hd_sock_error_is_timeout(int err)
{
#ifdef _WIN32
    return (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK);
#else
    return (err == EAGAIN || err == EWOULDBLOCK || err == EINTR);
#endif
}

/* ==========================================================================
 * 线程与互斥
 * ========================================================================== */
int hd_thread_start(hd_thread* t, hd_thread_fn fn, void* arg)
{
    if (!t || !fn) return -1;
#ifdef _WIN32
    {
        unsigned tid = 0;
        uintptr_t h = _beginthreadex(NULL, 0, fn, arg, 0, &tid);
        if (!h) return -1;
        *t = (HANDLE)h;
        return 0;
    }
#else
    return pthread_create(t, NULL, fn, arg);
#endif
}

void hd_thread_join(hd_thread* t)
{
    if (!t) return;
#ifdef _WIN32
    if (*t) { WaitForSingleObject(*t, INFINITE); CloseHandle(*t); *t = NULL; }
#else
    if (*t) { pthread_join(*t, NULL); *t = 0; }
#endif
}

void hd_thread_dispose(hd_thread* t)
{
    if (!t) return;
#ifdef _WIN32
    if (*t) { CloseHandle(*t); *t = NULL; }
#else
    if (*t) { pthread_detach(*t); *t = 0; }
#endif
}

int hd_mutex_init(hd_mutex* m)
{
    if (!m) return -1;
#ifdef _WIN32
    *m = CreateMutex(NULL, FALSE, NULL);
    return *m ? 0 : -1;
#else
    return pthread_mutex_init(m, NULL);
#endif
}

void hd_mutex_destroy(hd_mutex* m)
{
    if (!m) return;
#ifdef _WIN32
    if (*m) { CloseHandle(*m); *m = NULL; }
#else
    pthread_mutex_destroy(m);
#endif
}

void hd_mutex_lock(hd_mutex* m)
{
    if (!m) return;
#ifdef _WIN32
    if (*m) WaitForSingleObject(*m, INFINITE);
#else
    pthread_mutex_lock(m);
#endif
}

void hd_mutex_unlock(hd_mutex* m)
{
    if (!m) return;
#ifdef _WIN32
    if (*m) ReleaseMutex(*m);
#else
    pthread_mutex_unlock(m);
#endif
}

int hd_mutex_trylock(hd_mutex* m)
{
    if (!m) return 0;
#ifdef _WIN32
    if (!*m) return 0;
    return WaitForSingleObject(*m, 0) == WAIT_OBJECT_0 ? 1 : 0;
#else
    return pthread_mutex_trylock(m) == 0 ? 1 : 0;
#endif
}
