/* hd_net — TCP :9100 协议实现 */

#include "hd_net.h"
#include "hd_db.h"
#include "jsonx.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _WIN32
    #include <dirent.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
#endif

#define HD_MAX_CONN     64
#define HD_OUT_MAX      (1024 * 1024)   /* 单条响应上限 */
#define HD_IDLE_MS      (240 * 1000)    /* 无任何数据的空闲上限 */
#define HD_IO_TIMEOUT   20              /* socket 收发超时（秒） */

/* ==========================================================================
 * 连接对象
 * ========================================================================== */
typedef struct hd_conn {
    hd_socket   fd;
    hd_mutex    wlk;            /* 串行化写入，防止事件与响应交错 */
    int         wlk_ok;
    hd_thread   th;
    int         th_started;
    int         authed;
    volatile int closing;
    char        id[64];
    char        host[64];
    int64_t     last_ms;
    int         auth_fails;
    char*       out;            /* 响应缓冲，HD_OUT_MAX */
    struct hd_conn* next;
} hd_conn;

static hd_conn*  s_conns    = NULL;
static int       s_conn_cnt = 0;
static hd_mutex  s_conn_lk;
static int       s_conn_lk_ok = 0;
static hd_socket s_listen   = HD_INVALID_SOCK;
static hd_thread s_accept_th;
static int       s_accept_started = 0;
static int       s_max_clients = 16;
static unsigned long long s_event_seq = 0;

/* 前向声明：供各命令处理函数在触发文件事件时跳过发起者自己 */
static void file_event_except(hd_conn* except, const char* event, const char* abs_path);

/* ==========================================================================
 * socket 小工具
 * ========================================================================== */
static int send_all(hd_socket fd, const void* data, size_t len)
{
    const char* p = (const char*)data;
    size_t sent = 0;
    while (sent < len) {
        int n = send(fd, p + sent, (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static void conn_tune_socket(hd_socket fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&one, sizeof(one));
#ifdef _WIN32
    {
        DWORD tv = HD_IO_TIMEOUT * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    }
#else
    {
        struct timeval tv;
        tv.tv_sec = HD_IO_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    }
#endif
}

/* ==========================================================================
 * 连接注册表
 * ========================================================================== */
static void conn_list_add(hd_conn* c)
{
    if (s_conn_lk_ok) hd_mutex_lock(&s_conn_lk);
    c->next = s_conns;
    s_conns = c;
    s_conn_cnt++;
    if (s_conn_lk_ok) hd_mutex_unlock(&s_conn_lk);
}

static void conn_list_remove(hd_conn* c)
{
    hd_conn** pp;
    if (s_conn_lk_ok) hd_mutex_lock(&s_conn_lk);
    for (pp = &s_conns; *pp; pp = &(*pp)->next) {
        if (*pp == c) { *pp = c->next; s_conn_cnt--; break; }
    }
    if (s_conn_lk_ok) hd_mutex_unlock(&s_conn_lk);
}

int hd_net_client_count(void)
{
    int n;
    if (s_conn_lk_ok) hd_mutex_lock(&s_conn_lk);
    n = s_conn_cnt;
    if (s_conn_lk_ok) hd_mutex_unlock(&s_conn_lk);
    return n;
}

/* ==========================================================================
 * 带缓冲的读取器
 * ========================================================================== */
typedef struct {
    hd_conn*      c;
    unsigned char buf[HD_CHUNK];
    size_t        len;
    size_t        pos;
    int           eof;
} hd_reader;

/* 返回 >0 读到的字节数 / 0 对端关闭 / -1 超时（可恢复） / -2 硬错误 */
static int rd_fill(hd_reader* r)
{
    int n;
    r->pos = 0;
    r->len = 0;
    if (r->eof) return 0;
    n = recv(r->c->fd, (char*)r->buf, (int)sizeof(r->buf), 0);
    if (n > 0) { r->len = (size_t)n; return n; }
    if (n == 0) { r->eof = 1; return 0; }
    if (hd_sock_error_is_timeout(hd_sock_error())) return -1;
    return -2;
}

/* 读入最多 want 字节，返回实际字节数；0=EOF，-1=超时/错误 */
static int rd_read_some(hd_reader* r, void* out, size_t want)
{
    size_t take;
    if (want == 0) return 0;
    if (r->pos >= r->len) {
        int f = rd_fill(r);
        if (f <= 0) return f;
    }
    take = r->len - r->pos;
    if (take > want) take = want;
    memcpy(out, r->buf + r->pos, take);
    r->pos += take;
    return (int)take;
}

/*
 * 丢弃 n 字节负载。
 * 用于"明明要拒绝这个请求，但对方已经把负载发过来了"的场景：
 * 带着未读数据关闭连接会触发 RST，把刚发出的错误响应一起冲掉。
 * 返回 0=排空成功，-1=流出错。
 */
static int rd_discard(hd_reader* r, int64_t n)
{
    char sink[4096];
    while (n > 0) {
        size_t want = (n > (int64_t)sizeof(sink)) ? sizeof(sink) : (size_t)n;
        int got = rd_read_some(r, sink, want);
        if (got <= 0) return -1;
        n -= got;
    }
    return 0;
}

/* 精确读满 n 字节 */

/*
 * 读取一行（不含换行）。
 * 返回 1=成功，2=超长（内容已截断并丢弃到行尾），0=对端关闭，-1=超时，-2=错误
 */
static int rd_read_line(hd_reader* r, char* out, size_t cap, int* too_long)
{
    size_t w = 0;
    int overflow = 0;
    size_t discarded = 0;
    const size_t discard_limit = (size_t)HD_LINE_MAX * 8;   /* 防止无限灌数据撑死连接 */

    if (too_long) *too_long = 0;
    if (cap) out[0] = '\0';

    for (;;) {
        if (r->pos >= r->len) {
            int f = rd_fill(r);
            if (f == 0) return (w > 0) ? 1 : 0;
            if (f < 0) return f;
        }
        {
            unsigned char* p    = r->buf + r->pos;
            size_t         avail = r->len - r->pos;
            unsigned char* nl    = (unsigned char*)memchr(p, '\n', avail);
            size_t         take  = nl ? (size_t)(nl - p) : avail;

            if (!overflow) {
                if (w + take + 1 > cap) {
                    size_t room = (cap > w + 1) ? (cap - w - 1) : 0;
                    if (room) { memcpy(out + w, p, room); w += room; out[w] = '\0'; }
                    overflow = 1;
                } else {
                    memcpy(out + w, p, take);
                    w += take;
                    out[w] = '\0';
                }
            } else {
                discarded += take;
                if (discarded > discard_limit) return -2;    /* 灌太多：只能断开 */
            }
            r->pos += take;

            if (nl) {
                r->pos++;                       /* 吃掉 '\n' */
                if (overflow) { if (too_long) *too_long = 1; return 2; }
                if (w > 0 && out[w - 1] == '\r') out[--w] = '\0';
                return 1;
            }
        }
    }
}

/* ==========================================================================
 * 发送
 * ========================================================================== */
static void conn_close_socket(hd_conn* c)
{
    if (!c) return;
    c->closing = 1;
    if (c->fd != HD_INVALID_SOCK) {
#ifdef _WIN32
        shutdown(c->fd, SD_BOTH);
#else
        shutdown(c->fd, SHUT_RDWR);
#endif
        hd_sock_close(c->fd);
        c->fd = HD_INVALID_SOCK;
    }
}

/* 一次持锁发出多段内容，保证一条消息不被事件行切断 */
static int conn_send_parts(hd_conn* c, const char* const* parts, int n)
{
    int i;
    int rc = 0;
    if (!c || c->fd == HD_INVALID_SOCK) return -1;
    if (c->wlk_ok) hd_mutex_lock(&c->wlk);
    for (i = 0; i < n && rc == 0; i++) {
        if (!parts[i]) continue;
        if (send_all(c->fd, parts[i], strlen(parts[i])) != 0) rc = -1;
    }
    if (c->wlk_ok) hd_mutex_unlock(&c->wlk);
    if (rc != 0) c->closing = 1;
    return rc;
}

/*
 * 成功响应。data_json 可能是 MB 级（search/list/stats），
 * 因此必须分段发送，不能先拼进固定缓冲（修"大响应被静默截断"）。
 */
static void resp_ok(hd_conn* c, const char* id, const char* data_json)
{
    char idbuf[400];
    const char* parts[5];

    jx_escape(id && id[0] ? id : "", idbuf, sizeof(idbuf));

    parts[0] = "{\"type\":\"response\",\"id\":\"";
    parts[1] = idbuf;
    parts[2] = "\",\"status\":\"ok\",\"data\":";
    parts[3] = (data_json && data_json[0]) ? data_json : "{}";
    parts[4] = "}\n";
    conn_send_parts(c, parts, 5);
}

static void resp_error(hd_conn* c, const char* id, const char* code, const char* detail)
{
    char idbuf[400];
    char codebuf[200];
    char detailbuf[HD_PATH_MAX + 64];
    const char* parts[8];

    jx_escape(id && id[0] ? id : "", idbuf, sizeof(idbuf));
    jx_escape(code ? code : "error", codebuf, sizeof(codebuf));

    parts[0] = "{\"type\":\"response\",\"id\":\"";
    parts[1] = idbuf;
    parts[2] = "\",\"status\":\"error\",\"data\":{\"error\":\"";
    parts[3] = codebuf;

    if (detail && detail[0]) {
        jx_escape(detail, detailbuf, sizeof(detailbuf));
        parts[4] = "\",\"detail\":\"";
        parts[5] = detailbuf;
        parts[6] = "\"}}\n";
        parts[7] = NULL;
        conn_send_parts(c, parts, 7);
    } else {
        parts[4] = "\"}}\n";
        parts[5] = NULL;
        conn_send_parts(c, parts, 5);
    }
    HD_LOGD("NET", "错误响应 fd=%d code=%s", (int)c->fd, code ? code : "?");
}

/* ==========================================================================
 * 路径解析：把请求中的路径映射到监控根目录之内
 * ========================================================================== */
static int is_abs_path(const char* p)
{
    if (!p || !p[0]) return 0;
    if (p[0] == '/' || p[0] == '\\') return 1;
#ifdef _WIN32
    if (p[1] == ':' && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z'))) return 1;
#endif
    return 0;
}

/* 返回 0=成功（out 为受控绝对路径），-1=越权或非法 */
static int resolve_under_root(const char* in, char* out, size_t n)
{
    char abs[HD_PATH_MAX];

    if (!in || !in[0] || !out) return -1;

    if (is_abs_path(in)) {
        if (hd_path_abs(in, abs, sizeof(abs)) != 0) return -1;
    } else {
        char rel[HD_PATH_MAX];
        if (!hd_path_sanitize_rel(in, rel, sizeof(rel))) {
            HD_LOGW("PATH", "净化失败 in=[%s]", in);
            return -1;
        }
        hd_path_join(abs, sizeof(abs), g_cfg.monitor_path, rel);
        if (hd_path_abs(abs, abs, sizeof(abs)) != 0) {
            HD_LOGW("PATH", "绝对化失败 joined=[%s]", abs);
            return -1;
        }
    }

    if (!hd_path_within(abs, g_cfg.monitor_path)) {
        HD_LOGW("PATH", "越权判定: child=[%s] root=[%s]", abs, g_cfg.monitor_path);
        return -1;
    }
    snprintf(out, n, "%s", abs);
    return 0;
}

/* ==========================================================================
 * 二进制负载发送（下载 / 同步数据库）
 * ========================================================================== */
static int send_file_payload(hd_conn* c, const char* id, const char* action,
                            const char* abs_path, const char* index_hash)
{
    hd_file_info info;
    FILE* fp;
    char* header;
    char* chunk;
    char real_hash[33];
    int64_t sent = 0;
    int rc = 0;

    real_hash[0] = '\0';

    /*
     * 先算出"即将发送的字节"的权威哈希，再 stat、再发送。
     * 客户端据此可以做到真正的端到端校验（不必自己实现 xxHash）：
     *   源端下载 hash  ==  目标端上传后返回的 hash
     * 多读一遍文件的代价换来可验证的完整性，符合"安全 > 质量 > 性能"的取舍。
     */
    if (hd_hash_file(abs_path, real_hash) != 0) real_hash[0] = '\0';

    if (hd_stat64(abs_path, &info) != 0) { resp_error(c, id, "file_not_found", abs_path); return -1; }
    if (info.is_dir)                     { resp_error(c, id, "is_directory", abs_path); return -1; }
    if (g_cfg.max_transfer_mb > 0 &&
        info.size > (int64_t)g_cfg.max_transfer_mb * 1024 * 1024) {
        resp_error(c, id, "too_large", "超过 max_transfer_mb 限制");
        return -1;
    }

    fp = hd_fopen(abs_path, "rb");
    if (!fp) { resp_error(c, id, "open_failed", abs_path); return -1; }

    header = (char*)malloc(HD_PATH_MAX * 2 + 512);
    chunk  = (char*)malloc(HD_CHUNK);
    if (!header || !chunk) { free(header); free(chunk); fclose(fp); resp_error(c, id, "oom", NULL); return -1; }

    {
        hd_sb sb;
        hd_sb_init(&sb, header, HD_PATH_MAX * 2 + 512);
        hd_sb_puts(&sb, "{\"type\":\"response\",\"id\":\"");
        hd_sb_json(&sb, id ? id : "");
        hd_sb_puts(&sb, "\",\"status\":\"ok\",\"data\":{\"action\":\"");
        hd_sb_json(&sb, action);
        hd_sb_puts(&sb, "\",\"name\":\"");
        /* sync-database 发的是内部快照文件（xxx.db.snap-<ms>），对外仍叫 hamster.db */
        hd_sb_json(&sb, strcmp(action, "sync-database") == 0 ? "hamster.db" : hd_basename(abs_path));
        hd_sb_puts(&sb, "\",\"path\":\"");
        hd_sb_json(&sb, abs_path);
        hd_sb_puts(&sb, "\",\"hash\":\"");
        hd_sb_json(&sb, real_hash);
        hd_sb_puts(&sb, "\",\"index_hash\":\"");
        hd_sb_json(&sb, index_hash ? index_hash : "");
        hd_sb_printf(&sb, "\",\"size\":%lld,\"payload_bytes\":%lld,\"framing\":\"raw\"}}",
                     (long long)info.size, (long long)info.size);
        if (!hd_sb_ok(&sb)) { free(header); free(chunk); fclose(fp); resp_error(c, id, "response_too_large", NULL); return -1; }
    }

    /* 整个"头 + 负载"必须一次持锁完成，否则事件行会插进负载中间 */
    if (c->wlk_ok) hd_mutex_lock(&c->wlk);
    if (send_all(c->fd, header, strlen(header)) != 0 || send_all(c->fd, "\n", 1) != 0) {
        rc = -1;
    } else {
        size_t n;
        while ((n = fread(chunk, 1, HD_CHUNK, fp)) > 0) {
            if (send_all(c->fd, chunk, n) != 0) { rc = -1; break; }
            sent += (int64_t)n;
            if (g_stop || c->closing) { rc = -1; break; }
        }
        if (ferror(fp)) rc = -1;
    }
    if (c->wlk_ok) hd_mutex_unlock(&c->wlk);

    if (rc == 0 && sent != info.size) {
        HD_LOGE("NET", "发送字节数与声明不符: %s 声明=%lld 实际=%lld",
                abs_path, (long long)info.size, (long long)sent);
        rc = -1;
    }
    if (rc != 0) c->closing = 1;      /* 让客户端以"读取长度不足"感知失败 */

    HD_LOGI("NET", "%s 已发送 %s (%lld 字节)", action, abs_path, (long long)sent);

    free(header);
    free(chunk);
    fclose(fp);
    return rc;
}

/* ==========================================================================
 * 二进制负载接收（上传）
 * ========================================================================== */
static int handle_upload(hd_conn* c, hd_reader* rd, const char* id, const char* params,
                         int64_t payload_bytes, int* consumed)
{
    char rel[HD_PATH_MAX];
    char abs[HD_PATH_MAX];
    char part[HD_PATH_MAX + 64];
    char want_hash[40];
    char got_hash[33];
    char* chunk;
    FILE* fp;
    hd_hasher* hasher;
    int64_t remaining;
    int overwrite = 0, mkdir_ok = 0;
    int64_t declared = payload_bytes;
    int ok = 0;

    want_hash[0] = '\0';
    got_hash[0]  = '\0';

    /* consumed=0 表示负载没被读完，调用方必须关闭连接 */
    if (consumed) *consumed = 0;

    if (jx_get_str(params, "hash", want_hash, sizeof(want_hash)) != 1) want_hash[0] = '\0';
    if (jx_get_str(params, "path", rel, sizeof(rel)) != 1) {
        resp_error(c, id, "missing_path", NULL);
        goto reject;
    }
    {
        int v = 0;
        if (jx_get_bool(params, "overwrite", &v) == 1) overwrite = v;
        if (jx_get_bool(params, "mkdir", &v) == 1) mkdir_ok = v;
    }
    if (jx_get_i64(params, "size", &declared) != 1) declared = payload_bytes;
    if (declared != payload_bytes) {
        resp_error(c, id, "bad_size", "size 与 payload_bytes 不一致");
        goto reject;
    }
    if (declared < 0 || (g_cfg.max_transfer_mb > 0 &&
                         declared > (int64_t)g_cfg.max_transfer_mb * 1024 * 1024)) {
        resp_error(c, id, "too_large", "超过 max_transfer_mb 限制");
        goto reject;
    }

    /* 只接受相对于监控根的路径；绝对路径同样要走白名单 */
    if (resolve_under_root(rel, abs, sizeof(abs)) != 0) {
        HD_LOGW("UP", "拒绝越权上传路径: %s", rel);
        resp_error(c, id, "path_denied", rel);
        goto reject;
    }

    if (hd_exists(abs)) {
        hd_file_info ex;
        hd_stat64(abs, &ex);
        if (ex.is_dir) { resp_error(c, id, "is_directory", abs); goto reject; }
        if (!overwrite) { resp_error(c, id, "exists", abs); goto reject; }
    }

    if (mkdir_ok) {
        if (hd_mkdirs_for_file(abs) != 0) { resp_error(c, id, "mkdir_failed", abs); goto reject; }
    }

    snprintf(part, sizeof(part), "%s.part-%lu", abs, (unsigned long)hd_now_ms());

    chunk = (char*)malloc(HD_CHUNK);
    if (!chunk) { resp_error(c, id, "oom", NULL); return -1; }

    fp = hd_fopen(part, "wb");
    if (!fp) { free(chunk); resp_error(c, id, "open_failed", part); return -1; }

    hasher = hd_hash_new();
    if (!hasher) { fclose(fp); free(chunk); hd_remove_file(part); resp_error(c, id, "oom", NULL); return -1; }

    remaining = declared;
    while (remaining > 0) {
        size_t want = (remaining > HD_CHUNK) ? HD_CHUNK : (size_t)remaining;
        int got = rd_read_some(rd, chunk, want);
        if (got <= 0) {
            HD_LOGW("UP", "负载未接收完整: 剩余 %lld 字节", (long long)remaining);
            break;
        }
        if (fwrite(chunk, 1, (size_t)got, fp) != (size_t)got) break;
        hd_hash_update(hasher, chunk, (size_t)got);
        remaining -= got;
    }

    fclose(fp);
    free(chunk);

    /* 恰好读满声明长度才算消费完；此后无论校验是否通过，流都是对齐的 */
    if (consumed) *consumed = (remaining == 0 ? 1 : 0);

    if (remaining != 0) {
        hd_hash_free(hasher);
        hd_remove_file(part);
        c->closing = 1;                  /* 流已错位，只能关闭连接 */
        resp_error(c, id, "payload_incomplete", "负载长度不足");
        return -1;
    }

    hd_hash_finish(hasher, got_hash);
    hd_hash_free(hasher);

    if (want_hash[0] && !hd_ct_equal(want_hash, got_hash)) {
        hd_remove_file(part);
        HD_LOGW("UP", "哈希校验失败: %s 期望=%s 实际=%s", abs, want_hash, got_hash);
        resp_error(c, id, "hash_mismatch", NULL);
        return -1;
    }

    if (hd_rename(part, abs) != 0) {
        /* Windows 上 rename 会因瞬时共享冲突失败（索引服务/杀毒/扫描正持有目标）。
           重试几次再放弃，避免把可恢复的冲突报成上传失败。 */
        int attempt;
        int moved = 0;
        for (attempt = 0; attempt < 5 && !moved; attempt++) {
            hd_sleep_ms(60 * (attempt + 1));
            if (hd_rename(part, abs) == 0) moved = 1;
        }
        if (!moved) {
            hd_remove_file(part);
            HD_LOGW("UP", "重命名失败: %s（已重试 5 次）", abs);
            resp_error(c, id, "rename_failed", abs);
            return -1;
        }
    }

    hd_db_upsert_file(abs, got_hash);
    hd_net_file_event("file_added", abs);

    {
        char data[HD_PATH_MAX * 2 + 256];
        hd_sb sb;
        hd_sb_init(&sb, data, sizeof(data));
        hd_sb_puts(&sb, "{\"path\":\"");
        hd_sb_json(&sb, abs);
        hd_sb_puts(&sb, "\",\"name\":\"");
        hd_sb_json(&sb, hd_basename(abs));
        hd_sb_printf(&sb, "\",\"size\":%lld,\"hash\":\"%s\"}", (long long)declared, got_hash);
        if (hd_sb_ok(&sb)) { resp_ok(c, id, data); ok = 1; }
    }

    HD_LOGI("UP", "已接收 %s (%lld 字节, hash=%s)", abs, (long long)declared, got_hash);
    return ok ? 0 : -1;

reject:
    /*
     * 已经拒绝了这个请求，但对方通常已经把声明的负载发出来了。
     * 必须把它排空：带着未读数据关闭连接会产生 RST，客户端刚收到的错误响应会一起丢失。
     * 排空上限取 max_transfer_mb，超限则交给调用方关闭连接。
     */
    if (declared > 0) {
        int64_t cap = (int64_t)g_cfg.max_transfer_mb * 1024 * 1024;
        if (cap <= 0) cap = 64 * 1024 * 1024;
        if (declared <= cap) {
            if (rd_discard(rd, declared) == 0) {
                if (consumed) *consumed = 1;      /* 流仍然对齐，连接可继续使用 */
                HD_LOGD("UP", "已丢弃被拒请求的负载 %lld 字节", (long long)declared);
            } else {
                c->closing = 1;
            }
        } else {
            c->closing = 1;                       /* 负载过大，不值得为它排空 */
        }
    } else {
        if (consumed) *consumed = 1;
    }
    return -1;
}

/* ==========================================================================
 * 目录列举（供 UI 浏览与迁移选源）
 * ========================================================================== */
static void handle_list(hd_conn* c, const char* id, const char* params)
{
    char rel[HD_PATH_MAX];
    char abs[HD_PATH_MAX];
    int limit = 200, offset = 0;
    int first = 1;
    int total = 0;

    rel[0] = '\0';
    jx_get_str(params, "path", rel, sizeof(rel));
    jx_get_int(params, "limit", &limit);
    jx_get_int(params, "offset", &offset);
    if (limit <= 0 || limit > HD_SEARCH_MAX) limit = 200;

    /* 空路径与 "." 都表示监控根目录：文件浏览器（含迁移页）需要从根开始浏览。
       注意这里只放宽 list；download/delete 等仍走 resolve_under_root，"." 不会变成"删除根目录"。 */
    if (rel[0] == '\0' || strcmp(rel, ".") == 0 || strcmp(rel, "./") == 0)
        snprintf(abs, sizeof(abs), "%s", g_cfg.monitor_path);
    else if (resolve_under_root(rel, abs, sizeof(abs)) != 0) { resp_error(c, id, "path_denied", rel); return; }

    {
        hd_file_info info;
        if (hd_stat64(abs, &info) != 0) { resp_error(c, id, "not_found", abs); return; }
        if (!info.is_dir)               { resp_error(c, id, "not_a_directory", abs); return; }
    }

    {
        hd_sb sb;
        hd_sb_init(&sb, c->out, HD_OUT_MAX);
        hd_sb_puts(&sb, "{\"path\":\"");
        hd_sb_json(&sb, abs);
        hd_sb_puts(&sb, "\",\"entries\":[");

#ifdef _WIN32
        {
            wchar_t wdir[HD_PATH_MAX], wsearch[HD_PATH_MAX + 4];
            WIN32_FIND_DATAW fd;
            HANDLE h;
            int seen = 0;

            if (MultiByteToWideChar(CP_UTF8, 0, abs, -1, wdir, HD_PATH_MAX) <= 0) {
                resp_error(c, id, "bad_path", abs);
                return;
            }
            _snwprintf(wsearch, HD_PATH_MAX + 4, L"%s\\*", wdir);
            h = FindFirstFileW(wsearch, &fd);
            if (h == INVALID_HANDLE_VALUE) { resp_error(c, id, "open_failed", abs); return; }

            do {
                char name[1024];
                char full[HD_PATH_MAX];
                hd_file_info fi;

                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                if (WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, name, sizeof(name), NULL, NULL) <= 0) continue;

                total++;
                if (seen < offset) { seen++; continue; }
                if (total - offset > limit) continue;
                seen++;

                hd_path_join(full, sizeof(full), abs, name);
                if (hd_stat64(full, &fi) != 0) continue;

                if (!first) hd_sb_puts(&sb, ",");
                first = 0;
                hd_sb_puts(&sb, "{\"name\":\"");
                hd_sb_json(&sb, name);
                hd_sb_puts(&sb, "\",\"path\":\"");
                hd_sb_json(&sb, full);
                hd_sb_printf(&sb, "\",\"dir\":%d,\"size\":%lld,\"mtime\":%lld}",
                             fi.is_dir, (long long)fi.size, (long long)fi.mtime);
                if (!hd_sb_ok(&sb)) break;
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
#else
        {
            DIR* d = opendir(abs);
            struct dirent* e;
            int seen = 0;
            if (!d) { resp_error(c, id, "open_failed", abs); return; }
            while ((e = readdir(d)) != NULL) {
                char full[HD_PATH_MAX];
                hd_file_info fi;
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
                total++;
                if (seen < offset) { seen++; continue; }
                if (total - offset > limit) continue;
                seen++;
                hd_path_join(full, sizeof(full), abs, e->d_name);
                if (hd_stat64(full, &fi) != 0) continue;
                if (!first) hd_sb_puts(&sb, ",");
                first = 0;
                hd_sb_puts(&sb, "{\"name\":\"");
                hd_sb_json(&sb, e->d_name);
                hd_sb_puts(&sb, "\",\"path\":\"");
                hd_sb_json(&sb, full);
                hd_sb_printf(&sb, "\",\"dir\":%d,\"size\":%lld,\"mtime\":%lld}",
                             fi.is_dir, (long long)fi.size, (long long)fi.mtime);
                if (!hd_sb_ok(&sb)) break;
            }
            closedir(d);
        }
#endif
        hd_sb_printf(&sb, "],\"total\":%d,\"limit\":%d,\"offset\":%d}", total, limit, offset);
        if (!hd_sb_ok(&sb)) { resp_error(c, id, "response_too_large", "请减小 limit"); return; }
        resp_ok(c, id, c->out);
    }
}

/* ==========================================================================
 * 命令分发
 * ========================================================================== */
static int action_is_public(const char* a)
{
    return strcmp(a, "hello") == 0 || strcmp(a, "ping") == 0 || strcmp(a, "info") == 0;
}

static void server_info_json(char* out, size_t n, const char* conn_id)
{
    hd_sb sb;
    hd_sb_init(&sb, out, n);
    hd_sb_puts(&sb, "{\"server\":\"hamsterd\",\"version\":\"");
    hd_sb_json(&sb, hd_app_version());
    hd_sb_printf(&sb, "\",\"auth_required\":%d,\"monitor_path\":\"", g_cfg.require_auth ? 1 : 0);
    hd_sb_json(&sb, g_cfg.monitor_path);
    hd_sb_printf(&sb, "\",\"heartbeat\":%d,\"uptime_ms\":%lld,\"clients\":%d,\"peers\":%d,\"features\":[",
                 g_cfg.heartbeat_time, (long long)hd_app_uptime_sec() * 1000,
                 hd_net_client_count(), hd_app_peer_count());
    hd_sb_puts(&sb, "\"search\",\"download\",\"upload\",\"list\",\"mkdir\",\"delete\","
                    "\"sync-database\",\"verify\",\"rescan\",\"sync\",\"keys\",\"framing:raw\"");
    hd_sb_puts(&sb, "]");
    if (conn_id && conn_id[0]) { hd_sb_puts(&sb, ",\"connection_id\":\""); hd_sb_json(&sb, conn_id); hd_sb_puts(&sb, "\""); }
    hd_sb_puts(&sb, "}");
}

static void handle_hello(hd_conn* c, const char* id, const char* params)
{
    char code[160];
    char api_key[160];
    char dev_id[64];
    char dev_host[128];
    int ok = 0;

    code[0] = api_key[0] = dev_id[0] = dev_host[0] = '\0';
    jx_get_str(params, "codeword", code, sizeof(code));
    jx_get_str(params, "api_key", api_key, sizeof(api_key));
    jx_get_str(params, "device_id", dev_id, sizeof(dev_id));
    jx_get_str(params, "hostname", dev_host, sizeof(dev_host));

    if (!g_cfg.require_auth) {
        ok = 1;
    } else {
        if (code[0] && g_cfg.codeword[0] && hd_ct_equal(code, g_cfg.codeword)) ok = 1;
        if (!ok && api_key[0] && hd_db_key_check(api_key)) ok = 1;
    }

    if (!ok) {
        c->auth_fails++;
        HD_LOGW("AUTH", "认证失败 fd=%d id=%s（第 %d 次）", (int)c->fd, dev_id[0] ? dev_id : "?", c->auth_fails);
        /* 递增延迟，抬高暴力猜测成本 */
        hd_sleep_ms(200 * (c->auth_fails > 5 ? 5 : c->auth_fails));
        resp_error(c, id, "invalid_credential", NULL);
        c->closing = 1;
        return;
    }

    c->authed = 1;
    snprintf(c->id, sizeof(c->id), "%s", dev_id[0] ? dev_id : "unknown");
    snprintf(c->host, sizeof(c->host), "%s", dev_host[0] ? dev_host : "unknown");

    {
        char data[2048];
        server_info_json(data, sizeof(data), NULL);
        resp_ok(c, id, data);
    }
    HD_LOGI("AUTH", "认证通过 fd=%d id=%s host=%s", (int)c->fd, c->id, c->host);
}

static void handle_stats(hd_conn* c, const char* id)
{
    size_t used;

    if (hd_db_stats_json(c->out, HD_OUT_MAX) != 0) {
        resp_error(c, id, "response_too_large", NULL);
        return;
    }

    /* hd_db_stats_json 已把对象写进 c->out；这里在闭合括号前追加 peers/clients */
    used = strlen(c->out);
    if (used > 0 && c->out[used - 1] == '}' && used + 4096 < HD_OUT_MAX) {
        hd_sb sb;
        c->out[used - 1] = '\0';
        hd_sb_init(&sb, c->out + used - 1, HD_OUT_MAX - (used - 1));
        hd_sb_puts(&sb, ",\"peers\":[");
        hd_app_peers_json(&sb);
        hd_sb_printf(&sb, "],\"clients\":%d}", hd_net_client_count());
        if (!hd_sb_ok(&sb)) { resp_error(c, id, "response_too_large", NULL); return; }
    }
    resp_ok(c, id, c->out);
}

static void handle_search(hd_conn* c, const char* id, const char* params)
{
    hd_search_query q;
    char qbuf[512] = "";
    char tbuf[128] = "";
    char sbuf[32] = "";
    int limit = 0, offset = 0;

    memset(&q, 0, sizeof(q));
    jx_get_str(params, "q", qbuf, sizeof(qbuf));
    jx_get_str(params, "type", tbuf, sizeof(tbuf));
    jx_get_str(params, "sort", sbuf, sizeof(sbuf));
    jx_get_int(params, "limit", &limit);
    jx_get_int(params, "offset", &offset);
    jx_get_i64(params, "size_min", &q.size_min);
    jx_get_i64(params, "size_max", &q.size_max);

    q.q        = qbuf;
    q.type     = tbuf;
    q.sort     = sbuf;
    q.limit    = limit;
    q.offset   = offset;

    if (hd_db_search_json(&q, c->out, HD_OUT_MAX) != 0) {
        resp_error(c, id, "response_too_large", "请降低 limit 或缩小关键词");
        return;
    }
    resp_ok(c, id, c->out);
}

static void handle_verify(hd_conn* c, const char* id, const char* params)
{
    int run = 0;
    jx_get_bool(params, "run", &run);

    if (run) {
        int total = 0, ok = 0, corrupt = 0, missing = 0;
        HD_LOGI("VERIFY", "按请求执行完整性校验");
        hd_db_integrity_check(&total, &ok, &corrupt, &missing, g_cfg.prune_missing);
        hd_db_record_verify(total, ok, corrupt, missing, g_cfg.verify_interval);
        hd_net_broadcast("verify_done", "{\"reason\":\"manual\"}");
    }

    if (hd_db_verify_json(c->out, HD_OUT_MAX) != 0) {
        resp_error(c, id, "response_too_large", NULL);
        return;
    }
    resp_ok(c, id, c->out);
}

static void handle_health(hd_conn* c, const char* id)
{
    char data[1024];
    char stamp[64];
    hd_sb sb;

    hd_iso_local(stamp, sizeof(stamp));
    hd_sb_init(&sb, data, sizeof(data));
    hd_sb_puts(&sb, "{\"status\":\"ok\",\"time\":\"");
    hd_sb_json(&sb, stamp);
    hd_sb_printf(&sb, "\",\"version\":\"%s\",\"uptime_ms\":%lld,\"clients\":%d,\"auth_required\":%d,\"monitor_path\":\"",
                 hd_app_version(), (long long)hd_app_uptime_sec() * 1000, hd_net_client_count(),
                 g_cfg.require_auth ? 1 : 0);
    hd_sb_json(&sb, g_cfg.monitor_path);
    hd_sb_puts(&sb, "\"}");
    if (!hd_sb_ok(&sb)) { resp_error(c, id, "response_too_large", NULL); return; }
    resp_ok(c, id, data);
}

static void handle_mkdir(hd_conn* c, const char* id, const char* params)
{
    char rel[HD_PATH_MAX];
    char abs[HD_PATH_MAX];

    if (jx_get_str(params, "path", rel, sizeof(rel)) != 1) { resp_error(c, id, "missing_path", NULL); return; }
    if (resolve_under_root(rel, abs, sizeof(abs)) != 0)    { resp_error(c, id, "path_denied", rel); return; }
    if (hd_mkdirs(abs) != 0)                               { resp_error(c, id, "mkdir_failed", abs); return; }

    {
        char data[HD_PATH_MAX + 32];
        hd_sb sb;
        hd_sb_init(&sb, data, sizeof(data));
        hd_sb_puts(&sb, "{\"path\":\"");
        hd_sb_json(&sb, abs);
        hd_sb_puts(&sb, "\"}");
        resp_ok(c, id, data);
    }
    HD_LOGI("MKDIR", "%s", abs);
}

static void handle_delete(hd_conn* c, const char* id, const char* params)
{
    char rel[HD_PATH_MAX];
    char abs[HD_PATH_MAX];
    int confirm = 0;
    hd_file_info info;

    if (jx_get_str(params, "path", rel, sizeof(rel)) != 1) { resp_error(c, id, "missing_path", NULL); return; }
    if (jx_get_bool(params, "confirm", &confirm) != 1 || !confirm) {
        resp_error(c, id, "confirm_required", "删除必须显式携带 confirm=true");
        return;
    }
    if (resolve_under_root(rel, abs, sizeof(abs)) != 0) { resp_error(c, id, "path_denied", rel); return; }
    if (strcmp(abs, g_cfg.monitor_path) == 0)           { resp_error(c, id, "path_denied", "不能删除监控根目录"); return; }
    if (hd_stat64(abs, &info) != 0)                     { resp_error(c, id, "not_found", abs); return; }

    if (info.is_dir) {
        if (hd_rmdir(abs) != 0) { resp_error(c, id, "dir_not_empty", abs); return; }
        hd_db_delete_dir(abs);
    } else {
        if (hd_remove_file(abs) != 0) { resp_error(c, id, "remove_failed", abs); return; }
        hd_db_delete_file(abs);
    }
    hd_net_file_event("file_removed", abs);

    {
        char data[HD_PATH_MAX + 32];
        hd_sb sb;
        hd_sb_init(&sb, data, sizeof(data));
        hd_sb_puts(&sb, "{\"path\":\"");
        hd_sb_json(&sb, abs);
        hd_sb_puts(&sb, "\"}");
        resp_ok(c, id, data);
    }
    HD_LOGW("DEL", "已删除 %s", abs);
}

static void handle_keys(hd_conn* c, const char* id, const char* action, const char* params)
{
    if (strcmp(action, "key:add") == 0) {
        char label[128] = "";
        char key[80];
        jx_get_str(params, "label", label, sizeof(label));
        if (hd_db_key_add(label, key, sizeof(key)) != 0) { resp_error(c, id, "key_add_failed", NULL); return; }
        {
            char data[256];
            hd_sb sb;
            hd_sb_init(&sb, data, sizeof(data));
            hd_sb_puts(&sb, "{\"api_key\":\"");
            hd_sb_json(&sb, key);
            hd_sb_puts(&sb, "\",\"note\":\"该密钥只显示这一次\"}");
            resp_ok(c, id, data);
        }
        return;
    }
    if (strcmp(action, "key:list") == 0) {
        if (hd_db_key_list(c->out, HD_OUT_MAX) != 0) { resp_error(c, id, "response_too_large", NULL); return; }
        resp_ok(c, id, c->out);
        return;
    }
    if (strcmp(action, "key:revoke") == 0) {
        int kid = 0;
        if (jx_get_int(params, "id", &kid) != 1) { resp_error(c, id, "missing_id", NULL); return; }
        if (hd_db_key_revoke(kid) != 0)          { resp_error(c, id, "key_not_found", NULL); return; }
        resp_ok(c, id, "{\"revoked\":true}");
        return;
    }
    resp_error(c, id, "unknown_action", action);
}

static void handle_request(hd_conn* c, hd_reader* rd, const char* line)
{
    char id[160];
    char action[64];
    char* params;
    int64_t payload_bytes = 0;
    int has_payload = 0;

    id[0] = action[0] = '\0';

    if (!jx_is_object(line)) {
        resp_error(c, NULL, "malformed_json", NULL);
        return;
    }
    jx_get_str(line, "id", id, sizeof(id));
    if (jx_get_str(line, "action", action, sizeof(action)) != 1 || !action[0]) {
        resp_error(c, id, "missing_action", NULL);
        return;
    }
    if (jx_get_i64(line, "payload_bytes", &payload_bytes) == 1 && payload_bytes > 0) has_payload = 1;

    params = (char*)malloc(HD_LINE_MAX);
    if (!params) { resp_error(c, id, "oom", NULL); return; }
    if (jx_find_raw(line, "params", params, HD_LINE_MAX) != 1) snprintf(params, 16, "{}");

    /* 认证闸门：未认证只放行 hello / ping / info */
    if (!c->authed && !action_is_public(action)) {
        int allowed = 0;
        if (!g_cfg.require_auth) {
            allowed = 1;                       /* 显式关闭认证（配置或 --auth=off） */
        } else if (g_cfg.allow_loopback_noauth &&
                   (strcmp(c->host, "127.0.0.1") == 0 || strcmp(c->host, "::1") == 0)) {
            allowed = 1;                       /* 仅调试用的回环豁免 */
        }
        if (!allowed) {
            HD_LOGW("AUTH", "未认证请求被拒: action=%s fd=%d host=%s", action, (int)c->fd, c->host);
            free(params);
            resp_error(c, id, "unauthenticated", "请先发送 hello 并携带 codeword 或 api_key");
            return;
        }
        if (!c->authed) {
            c->authed = 1;
            snprintf(c->id, sizeof(c->id), "loopback-noauth");
            HD_LOGW("AUTH", "连接免认证通过（host=%s action=%s）——不建议长期开启", c->host, action);
        }
    }

    HD_LOGD("CMD", "action=%s id=%s fd=%d%s", action, id, (int)c->fd, has_payload ? " (带负载)" : "");

    if (strcmp(action, "hello") == 0) {
        handle_hello(c, id, params);
    } else if (strcmp(action, "ping") == 0) {
        char data[64];
        snprintf(data, sizeof(data), "{\"pong\":true,\"time\":%lld}", (long long)(hd_now_ms() / 1000));
        resp_ok(c, id, data);
    } else if (strcmp(action, "info") == 0) {
        char data[1024];
        server_info_json(data, sizeof(data), NULL);
        resp_ok(c, id, data);
    } else if (strcmp(action, "health") == 0) {
        handle_health(c, id);
    } else if (strcmp(action, "stats") == 0) {
        handle_stats(c, id);
    } else if (strcmp(action, "search") == 0) {
        handle_search(c, id, params);
    } else if (strcmp(action, "verify") == 0) {
        handle_verify(c, id, params);
    } else if (strcmp(action, "list") == 0) {
        handle_list(c, id, params);
    } else if (strcmp(action, "mkdir") == 0) {
        handle_mkdir(c, id, params);
    } else if (strcmp(action, "delete") == 0) {
        handle_delete(c, id, params);
    } else if (strcmp(action, "rescan") == 0) {
        hd_app_request_rescan();
        resp_ok(c, id, "{\"status\":\"rescan_requested\"}");
    } else if (strcmp(action, "sync") == 0) {
        hd_app_request_sync();
        resp_ok(c, id, "{\"status\":\"sync_requested\"}");
    } else if (strcmp(action, "download") == 0) {
        char rel[HD_PATH_MAX];
        char abs[HD_PATH_MAX];
        char idx[33];
        if (jx_get_str(params, "path", rel, sizeof(rel)) != 1) {
            resp_error(c, id, "missing_path", NULL);
        } else if (resolve_under_root(rel, abs, sizeof(abs)) != 0) {
            HD_LOGW("DL", "拒绝越权路径: %s", rel);       /* 关键安全日志 */
            resp_error(c, id, "path_denied", rel);
        } else {
            idx[0] = '\0';
            hd_db_file_hash(abs, idx);
            send_file_payload(c, id, "download", abs, idx);
        }
    } else if (strcmp(action, "sync-database") == 0) {
        /*
         * 不能直接把活动的库文件流出去：WAL 里还有最新记录，而且发送过程中别的线程
         * （或另一台客户端同时同步）可能再 checkpoint，把页写回主库 —— 客户端就会
         * 收到"半新半旧"的库，且字节数对得上、无从发现。因此先让 SQLite 生成一个
         * 不可变的一致快照，再发快照（发送期间它不会再变，头发里的 hash 才是权威值）。
         */
        char snap[HD_PATH_MAX + 96];
        /* 名字必须全局唯一：只靠毫秒会在"同毫秒并发同步"时撞车（实测出现过），
           第二个连接会把第一个还在发送的快照文件覆盖掉。fd 在同进程里唯一，够用。 */
        snprintf(snap, sizeof(snap), "%s.snap-%lld-%llu", hd_db_path(),
                 (long long)hd_now_ms(), (unsigned long long)c->fd);
        if (hd_db_snapshot(snap) != 0) {
            resp_error(c, id, "snapshot_failed", "无法生成数据库一致快照（库被其它进程锁住？）");
        } else {
            char idx[33];
            idx[0] = '\0';
            send_file_payload(c, id, "sync-database", snap, idx);
            remove(snap);
        }
    } else if (strcmp(action, "upload") == 0) {
        int consumed = 0;
        if (!has_payload) {
            resp_error(c, id, "missing_payload", "上传必须携带 payload_bytes");
        } else {
            handle_upload(c, rd, id, params, payload_bytes, &consumed);
            if (!consumed) c->closing = 1;      /* 负载没读完，流不再可信 */
        }
    } else if (strncmp(action, "key:", 4) == 0) {
        handle_keys(c, id, action, params);
    } else {
        resp_error(c, id, "unknown_action", action);
    }

    free(params);

    /* 其它命令不该带负载；带了就必须关闭，否则下一行会读到二进制垃圾 */
    if (has_payload && strcmp(action, "upload") != 0) c->closing = 1;
}

/* ==========================================================================
 * 连接线程
 * ========================================================================== */
static HD_THREAD_RET HD_THREAD_CALL conn_thread(void* arg)
{
    hd_conn* c = (hd_conn*)arg;
    hd_reader* rd = (hd_reader*)calloc(1, sizeof(hd_reader));
    char* line = (char*)malloc(HD_LINE_MAX);

    if (!rd || !line) {
        free(rd); free(line);
        conn_close_socket(c);
        return (HD_THREAD_RET)0;
    }
    rd->c = c;

    while (!g_stop && !c->closing) {
        int too_long = 0;
        int r = rd_read_line(rd, line, HD_LINE_MAX, &too_long);

        if (r == 1 || r == 2) {
            c->last_ms = hd_now_ms();
            if (too_long) {
                /* 超长行已被丢弃到行尾，流仍是对齐的：报错后保持连接可用 */
                resp_error(c, NULL, "line_too_long", "单行 JSON 超过上限，已丢弃该行");
                continue;
            }
            if (line[0] == '\0') continue;      /* 心跳空行 */
            handle_request(c, rd, line);
            continue;
        }
        if (r == 0) break;                      /* 对端关闭 */
        if (r == -1) {                          /* 超时：空闲检查 */
            if (hd_now_ms() - c->last_ms > HD_IDLE_MS) {
                HD_LOGD("NET", "空闲超时，关闭 fd=%d", (int)c->fd);
                break;
            }
            continue;
        }
        break;                                  /* 硬错误 */
    }

    free(rd);
    free(line);

    conn_list_remove(c);
    conn_close_socket(c);
    {
        char idbuf[64];
        snprintf(idbuf, sizeof(idbuf), "%s", c->id);
        HD_LOGI("NET", "连接结束 id=%s", idbuf[0] ? idbuf : "-");
    }
    if (c->wlk_ok) hd_mutex_destroy(&c->wlk);
    free(c->out);
    free(c);
    return (HD_THREAD_RET)0;
}

/* ==========================================================================
 * 接受线程
 * ========================================================================== */
static HD_THREAD_RET HD_THREAD_CALL accept_thread(void* arg)
{
    int backoff_ms = 100;

    (void)arg;
    while (!g_stop) {
        fd_set rfds;
        struct timeval tv;
        int sel;

        if (s_listen == HD_INVALID_SOCK) break;

        FD_ZERO(&rfds);
        FD_SET(s_listen, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        sel = select((int)s_listen + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            int err = hd_sock_error();
            if (hd_sock_error_is_timeout(err)) continue;
            HD_LOGW("NET", "select 失败 err=%d", err);
            hd_sleep_ms(backoff_ms);
            if (backoff_ms < 2000) backoff_ms *= 2;
            continue;
        }
        if (sel == 0) continue;

        {
            struct sockaddr_in ca;
            socklen_t al = sizeof(ca);
            hd_socket fd = accept(s_listen, (struct sockaddr*)&ca, &al);
            hd_conn* c;

            if (fd == HD_INVALID_SOCK) {
                int err = hd_sock_error();
                /* accept 的可恢复错误不得终止监听（修 P1-4） */
                if (hd_sock_error_is_timeout(err)) continue;
                HD_LOGW("NET", "accept 失败 err=%d，继续监听", err);
                hd_sleep_ms(100);
                continue;
            }
            backoff_ms = 100;

            if (hd_net_client_count() >= s_max_clients) {
                const char* busy = "{\"type\":\"response\",\"status\":\"error\",\"data\":{\"error\":\"too_many_clients\"}}\n";
                send_all(fd, busy, strlen(busy));
                hd_sock_close(fd);
                HD_LOGW("NET", "连接数已达上限 %d，拒绝新连接", s_max_clients);
                continue;
            }

            conn_tune_socket(fd);

            c = (hd_conn*)calloc(1, sizeof(hd_conn));
            if (!c) { hd_sock_close(fd); continue; }

            c->fd = fd;
            c->out = (char*)malloc(HD_OUT_MAX);
            c->last_ms = hd_now_ms();
            if (hd_mutex_init(&c->wlk) != 0 || !c->out) {
                if (c->wlk_ok) hd_mutex_destroy(&c->wlk);
                free(c->out);
                free(c);
                hd_sock_close(fd);
                continue;
            }
            c->wlk_ok = 1;

            snprintf(c->host, sizeof(c->host), "%.63s", inet_ntoa(ca.sin_addr));
            conn_list_add(c);

            if (hd_thread_start(&c->th, conn_thread, c) != 0) {
                conn_list_remove(c);
                hd_mutex_destroy(&c->wlk);
                free(c->out);
                free(c);
                hd_sock_close(fd);
                continue;
            }
            c->th_started = 1;
            hd_thread_dispose(&c->th);      /* 线程自管生命周期，不 join */
        }
    }
    return (HD_THREAD_RET)0;
}

/* ==========================================================================
 * 启停
 * ========================================================================== */
int hd_net_start(const char* bind_addr, int port, int max_clients)
{
    struct sockaddr_in a;
    int opt = 1;

    if (!s_conn_lk_ok) {
        if (hd_mutex_init(&s_conn_lk) != 0) return -1;
        s_conn_lk_ok = 1;
    }
    s_max_clients = (max_clients > 0 && max_clients <= HD_MAX_CONN) ? max_clients : 16;

    s_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (s_listen == HD_INVALID_SOCK) {
        HD_LOGE("NET", "socket() 失败 err=%d", hd_sock_error());
        return -1;
    }

#ifdef _WIN32
    /* Windows 下 SO_REUSEADDR 允许端口劫持，必须用 SO_EXCLUSIVEADDRUSE（修 P1-5） */
    setsockopt(s_listen, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&opt, sizeof(opt));
#else
    setsockopt(s_listen, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#endif

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons((unsigned short)port);
    if (!bind_addr || !bind_addr[0] || strcmp(bind_addr, "0.0.0.0") == 0) {
        a.sin_addr.s_addr = INADDR_ANY;
    } else {
#ifdef _WIN32
        if (InetPtonA(AF_INET, bind_addr, &a.sin_addr) != 1) a.sin_addr.s_addr = inet_addr(bind_addr);
#else
        if (inet_pton(AF_INET, bind_addr, &a.sin_addr) != 1) a.sin_addr.s_addr = inet_addr(bind_addr);
#endif
    }

    if (bind(s_listen, (struct sockaddr*)&a, sizeof(a)) == HD_SOCK_ERR) {
        HD_LOGE("NET", "绑定 %s:%d 失败 err=%d", bind_addr ? bind_addr : "0.0.0.0", port, hd_sock_error());
        hd_sock_close(s_listen);
        s_listen = HD_INVALID_SOCK;
        return -1;
    }
    if (listen(s_listen, 16) == HD_SOCK_ERR) {
        HD_LOGE("NET", "listen 失败 err=%d", hd_sock_error());
        hd_sock_close(s_listen);
        s_listen = HD_INVALID_SOCK;
        return -1;
    }

    if (hd_thread_start(&s_accept_th, accept_thread, NULL) != 0) {
        HD_LOGE("NET", "接受线程创建失败");
        hd_sock_close(s_listen);
        s_listen = HD_INVALID_SOCK;
        return -1;
    }
    s_accept_started = 1;
    HD_LOGI("NET", "监听 %s:%d（最大连接 %d，认证=%s）",
            bind_addr ? bind_addr : "0.0.0.0", port, s_max_clients,
            g_cfg.require_auth ? "必需" : "关闭");
    return 0;
}

void hd_net_stop(void)
{
    int waited;

    g_stop = 1;

    if (s_listen != HD_INVALID_SOCK) {
        hd_sock_close(s_listen);
        s_listen = HD_INVALID_SOCK;
    }

    /* 在持有注册表锁的情况下 shutdown：线程释放连接对象也要拿这把锁，
       因此这里不会与 free 竞争（修停止路径的 use-after-free） */
    if (s_conn_lk_ok) hd_mutex_lock(&s_conn_lk);
    {
        hd_conn* p;
        for (p = s_conns; p; p = p->next) {
            p->closing = 1;
            if (p->fd != HD_INVALID_SOCK) {
#ifdef _WIN32
                shutdown(p->fd, SD_BOTH);
#else
                shutdown(p->fd, SHUT_RDWR);
#endif
            }
        }
    }
    if (s_conn_lk_ok) hd_mutex_unlock(&s_conn_lk);

    if (s_accept_started) {
        hd_thread_join(&s_accept_th);
        s_accept_started = 0;
    }

    /* 连接线程自行释放对象；等到全部退出 */
    for (waited = 0; waited < 250 && hd_net_client_count() > 0; waited++) hd_sleep_ms(20);

    if (hd_net_client_count() > 0)
        HD_LOGW("NET", "仍有 %d 个连接未退出", hd_net_client_count());

    HD_LOGI("NET", "已停止");
}

/* ==========================================================================
 * 事件广播
 * ========================================================================== */
/*
 * 事件广播的内部实现。
 * except 用于跳过"触发该事件的连接"：上传/删除的执行者会先收到自己的事件再收到响应，
 * 那会让客户端不得不做消息分流（我们仍然要求客户端能分流，但不主动制造这种噪声）。
 */
static void broadcast_internal(hd_conn* except, const char* event, const char* data_json)
{
    char line[8192];
    struct { hd_socket fd; hd_mutex* lk; } snap[HD_MAX_CONN];
    int n = 0, i;

    snprintf(line, sizeof(line),
             "{\"type\":\"event\",\"event\":\"%s\",\"data\":%s,\"seq\":%llu,\"time\":%lld}",
             event ? event : "unknown",
             (data_json && data_json[0]) ? data_json : "{}",
             ++s_event_seq,
             (long long)(hd_now_ms() / 1000));

    /* 锁内只做快照 */
    if (s_conn_lk_ok) hd_mutex_lock(&s_conn_lk);
    {
        hd_conn* p;
        for (p = s_conns; p && n < HD_MAX_CONN; p = p->next) {
            if (p == except) continue;
            if (!p->authed || p->closing) continue;
            snap[n].fd = p->fd;
            snap[n].lk = &p->wlk;
            n++;
        }
    }
    if (s_conn_lk_ok) hd_mutex_unlock(&s_conn_lk);

    /* 锁外逐个发送：慢客户端只拖住广播线程自己，不再拖住整个服务 */
    for (i = 0; i < n; i++) {
        if (snap[i].fd == HD_INVALID_SOCK) continue;
        /* 正在传输负载的连接跳过：该事件对它丢失，客户端可凭 seq 跳号察觉 */
        if (snap[i].lk && !hd_mutex_trylock(snap[i].lk)) continue;
        if (send_all(snap[i].fd, line, strlen(line)) != 0 ||
            send_all(snap[i].fd, "\n", 1) != 0) {
            HD_LOGW("BCAST", "向 fd=%d 发送事件失败，标记待关闭", (int)snap[i].fd);
            if (s_conn_lk_ok) hd_mutex_lock(&s_conn_lk);
            {
                hd_conn* p;
                for (p = s_conns; p; p = p->next) {
                    if (p->fd == snap[i].fd) { p->closing = 1; break; }
                }
            }
            if (s_conn_lk_ok) hd_mutex_unlock(&s_conn_lk);
        }
        if (snap[i].lk) hd_mutex_unlock(snap[i].lk);
    }

    HD_LOGD("BCAST", "%s -> %s", event ? event : "?", data_json ? data_json : "{}");
}

void hd_net_broadcast(const char* event, const char* data_json)
{
    broadcast_internal(NULL, event, data_json);
}

static void file_event_except(hd_conn* except, const char* event, const char* abs_path)
{
    char data[HD_PATH_MAX * 2 + 128];
    hd_sb sb;

    hd_sb_init(&sb, data, sizeof(data));
    hd_sb_puts(&sb, "{\"path\":\"");
    hd_sb_json(&sb, abs_path);
    hd_sb_puts(&sb, "\",\"name\":\"");
    hd_sb_json(&sb, hd_basename(abs_path));
    hd_sb_puts(&sb, "\",\"dir\":\"");
    {
        char dir[HD_PATH_MAX];
        const char* base = hd_basename(abs_path);
        size_t dl = (size_t)(base - abs_path);
        if (dl > 0 && dl < sizeof(dir)) {
            memcpy(dir, abs_path, dl);
            dir[dl] = '\0';
        } else {
            dir[0] = '\0';
        }
        hd_sb_json(&sb, dir);
    }
    hd_sb_puts(&sb, "\"}");

    if (hd_sb_ok(&sb)) broadcast_internal(except, event, data);
}

void hd_net_file_event(const char* event, const char* abs_path)
{
    file_event_except(NULL, event, abs_path);
}