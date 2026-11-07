/*
 * hd_disc.c — 局域网发现：服务端被动应答（PROTOCOL §7）
 * ver.0.0.8
 *
 * 帧（UDP 一行 JSON，无换行）：
 *   探测  {"t":"hp","v":1,"id":"<client>","n":"<32hex>","m":"<64hex>"}
 *   应答  {"t":"hr","v":1,"id":"<self>","n":"<回显>","m":"<64hex>","name":"...","port":9100,"ver":"0.0.8"}
 *
 * MAC 的原文（UTF-8，'\n' 分隔，末尾无换行）：
 *   probe: "hamster-disc-probe/v1\n" + id + "\n" + n
 *   reply: "hamster-disc-reply/v1\n" + probe_id + "\n" + n + "\n" + self_id + "\n" + port
 *
 * 为什么 MAC 覆盖这些字段：
 *   · probe 里的 id/n 被覆盖 → 探测帧不能被篡改（改了 id 就换了对方算 MAC 的原文）；
 *   · reply 里带 probe_id → 捕获到的应答无法重放给另一个客户端；
 *   · reply 里带 self_id/port → 中间人不能把应答改指到另一台机器；
 *   · n 原样回显 → 客户端能把应答配回某一轮探测，旧的应答不会污染新结果。
 */
#include "hd_disc.h"
#include "hd_crypto.h"
#include "jsonx.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

/* ==========================================================================
 * 常量
 * ========================================================================== */
#define DISC_PROBE_PREFIX  "hamster-disc-probe/v1\n"
#define DISC_REPLY_PREFIX  "hamster-disc-reply/v1\n"

/* 限速：每源 IP 20 次/秒，突发 40 次 */
#define DISC_RL_IPS        64
#define DISC_RL_PER_MS     (20.0 / 1000.0)
#define DISC_RL_BURST      40.0

/* 重放窗口：最近 256 组 (IP, nonce)，年龄 < 120s */
#define DISC_NONCE_KEEP    256
#define DISC_NONCE_TTL_MS  120000

/* MAC 校验失败的告警节流：60s 一条，避免被人拿去刷日志 */
#define DISC_WARN_EVERY_MS 60000

/* ==========================================================================
 * 配置副本（启动时复制，此后只读）
 * ========================================================================== */
static char  g_cw[512];
static char  g_self_id[HD_DISC_ID_MAX];
static char  g_self_name[HD_DISC_NAME_MAX];
static char  g_ver[32];
static int   g_port = 0;
static int   g_respond = 1;
static int   g_tcp_port = 9100;

static volatile long g_reply_cnt = 0;
static long  g_bad_mac_cnt = 0;
static int64_t g_last_warn_ms = 0;

/* ==========================================================================
 * 纯函数层
 * ========================================================================== */

int hd_disc_valid_id(const char* s)
{
    size_t i, n;
    if (!s) return 0;
    n = strlen(s);
    if (n < 8 || n > HD_DISC_ID_MAX - 1) return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return 0;
    }
    return 1;
}

int hd_disc_is_hex(const char* s, size_t n)
{
    size_t i;
    if (!s || strlen(s) != n) return 0;
    for (i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

int hd_disc_make_nonce(char out[HD_DISC_NONCE_MAX])
{
    unsigned char raw[16];
    if (!out) return -1;
    if (hd_random_bytes(raw, sizeof(raw)) != 0) return -1;
    hd_hex_encode(raw, sizeof(raw), out);
    return 0;
}

/* 组 probe 的 MAC 原文并算出十六进制 MAC */
static int probe_mac(const char* codeword, const char* id, const char* nonce_hex, char hex[HD_DISC_MAC_MAX])
{
    char msg[256];
    int  n;

    n = snprintf(msg, sizeof(msg), "%s%s\n%s", DISC_PROBE_PREFIX, id, nonce_hex);
    if (n <= 0 || (size_t)n >= sizeof(msg)) return -1;
    hd_hmac_sha256(codeword, strlen(codeword), msg, (size_t)n, NULL, hex);
    return 0;
}

static int reply_mac(const char* codeword, const char* probe_id, const char* nonce_hex,
                     const char* self_id, int tcp_port, char hex[HD_DISC_MAC_MAX])
{
    char msg[384];
    int  n;

    n = snprintf(msg, sizeof(msg), "%s%s\n%s\n%s\n%d",
                 DISC_REPLY_PREFIX, probe_id, nonce_hex, self_id, tcp_port);
    if (n <= 0 || (size_t)n >= sizeof(msg)) return -1;
    hd_hmac_sha256(codeword, strlen(codeword), msg, (size_t)n, NULL, hex);
    return 0;
}

int hd_disc_build_probe(const char* codeword, const char* id, const char* nonce_hex,
                        char* out, size_t cap)
{
    char mac[HD_DISC_MAC_MAX];
    int  n;

    if (!codeword || !codeword[0]) return -1;
    if (!hd_disc_valid_id(id)) return -1;
    if (!hd_disc_is_hex(nonce_hex, HD_DISC_NONCE_HEX)) return -1;
    if (!out || cap < 64) return -1;
    if (probe_mac(codeword, id, nonce_hex, mac) != 0) return -1;

    n = snprintf(out, cap,
                 "{\"t\":\"hp\",\"v\":%d,\"id\":\"%s\",\"n\":\"%s\",\"m\":\"%s\"}",
                 HD_DISC_MAGIC_V, id, nonce_hex, mac);
    if (n <= 0 || (size_t)n >= cap) return -1;
    return n;
}

int hd_disc_parse_probe(const char* codeword, const char* frame, int len,
                        char* id_out, size_t id_cap,
                        char* nonce_out, size_t nonce_cap)
{
    char buf[HD_DISC_FRAME_MAX + 1];
    char t[16], id[HD_DISC_ID_MAX], nonce[HD_DISC_NONCE_MAX], mac[HD_DISC_MAC_MAX];
    char want[HD_DISC_MAC_MAX];
    int  v = 0;

    if (!codeword || !codeword[0]) return -1;
    if (!frame || len <= 0 || len > HD_DISC_FRAME_MAX) return -1;
    /* 帧内的 NUL 只可能是攻击者构造的截断把戏 */
    if (memchr(frame, 0, (size_t)len) != NULL) return -1;

    memcpy(buf, frame, (size_t)len);
    buf[len] = '\0';

    if (jx_is_object(buf) != 1) return -1;
    if (jx_get_str(buf, "t", t, sizeof(t)) != 1 || strcmp(t, "hp") != 0) return -1;
    if (jx_get_int(buf, "v", &v) != 1 || v != HD_DISC_MAGIC_V) return -1;
    if (jx_get_str(buf, "id", id, sizeof(id)) != 1 || !hd_disc_valid_id(id)) return -1;
    if (jx_get_str(buf, "n", nonce, sizeof(nonce)) != 1 ||
        !hd_disc_is_hex(nonce, HD_DISC_NONCE_HEX)) return -1;
    if (jx_get_str(buf, "m", mac, sizeof(mac)) != 1 ||
        !hd_disc_is_hex(mac, HD_DISC_MAC_HEX)) return -1;

    if (probe_mac(codeword, id, nonce, want) != 0) return -1;
    if (!hd_ct_equal(want, mac)) return -1;                 /* 常量时间比较 */

    if (id_out && id_cap)       snprintf(id_out, id_cap, "%s", id);
    if (nonce_out && nonce_cap) snprintf(nonce_out, nonce_cap, "%s", nonce);
    return 0;
}

int hd_disc_build_reply(const char* codeword,
                        const char* probe_id, const char* nonce_hex,
                        const char* self_id, const char* self_name,
                        int tcp_port, const char* version,
                        char* out, size_t cap)
{
    char mac[HD_DISC_MAC_MAX];
    char name[HD_DISC_NAME_MAX * 2];
    int  n;

    if (!codeword || !codeword[0]) return -1;
    if (!hd_disc_valid_id(probe_id) || !hd_disc_valid_id(self_id)) return -1;
    if (!hd_disc_is_hex(nonce_hex, HD_DISC_NONCE_HEX)) return -1;
    if (tcp_port <= 0 || tcp_port > 65535) return -1;
    if (!out || cap < 96) return -1;

    if (reply_mac(codeword, probe_id, nonce_hex, self_id, tcp_port, mac) != 0) return -1;
    if (jx_escape(self_name ? self_name : "", name, sizeof(name)) < 0) {
        snprintf(name, sizeof(name), "hamster");
    }

    n = snprintf(out, cap,
                 "{\"t\":\"hr\",\"v\":%d,\"id\":\"%s\",\"n\":\"%s\",\"m\":\"%s\","
                 "\"name\":\"%s\",\"port\":%d,\"ver\":\"%s\"}",
                 HD_DISC_MAGIC_V, self_id, nonce_hex, mac,
                 name, tcp_port, version ? version : "");
    if (n <= 0 || (size_t)n >= cap) return -1;
    return n;
}

int hd_disc_parse_reply(const char* codeword, const char* my_id,
                        const char* frame, int len,
                        char* nonce_out, size_t nonce_cap,
                        char* id_out, size_t id_cap,
                        int* port_out,
                        char* name_out, size_t name_cap,
                        char* version_out, size_t version_cap)
{
    char buf[HD_DISC_FRAME_MAX + 1];
    char t[16], id[HD_DISC_ID_MAX], nonce[HD_DISC_NONCE_MAX], mac[HD_DISC_MAC_MAX];
    char name[HD_DISC_NAME_MAX], ver[32];
    char want[HD_DISC_MAC_MAX];
    int  v = 0, port = 0;

    if (!codeword || !codeword[0]) return -1;
    if (!frame || len <= 0 || len > HD_DISC_FRAME_MAX) return -1;
    if (memchr(frame, 0, (size_t)len) != NULL) return -1;

    memcpy(buf, frame, (size_t)len);
    buf[len] = '\0';

    if (jx_is_object(buf) != 1) return -1;
    if (jx_get_str(buf, "t", t, sizeof(t)) != 1 || strcmp(t, "hr") != 0) return -1;
    if (jx_get_int(buf, "v", &v) != 1 || v != HD_DISC_MAGIC_V) return -1;
    if (jx_get_str(buf, "id", id, sizeof(id)) != 1 || !hd_disc_valid_id(id)) return -1;
    if (jx_get_str(buf, "n", nonce, sizeof(nonce)) != 1 ||
        !hd_disc_is_hex(nonce, HD_DISC_NONCE_HEX)) return -1;
    if (jx_get_str(buf, "m", mac, sizeof(mac)) != 1 ||
        !hd_disc_is_hex(mac, HD_DISC_MAC_HEX)) return -1;
    if (jx_get_int(buf, "port", &port) != 1 || port <= 0 || port > 65535) return -1;
    if (jx_get_str(buf, "name", name, sizeof(name)) != 1) name[0] = '\0';
    if (jx_get_str(buf, "ver", ver, sizeof(ver)) != 1) ver[0] = '\0';

    /* 自己发的广播可能被本机另一实例回给本机：直接当无效 */
    if (my_id && my_id[0] && strcmp(id, my_id) == 0) return -1;

    if (reply_mac(codeword, my_id ? my_id : "", nonce, id, port, want) != 0) return -1;
    if (!hd_ct_equal(want, mac)) return -1;

    if (nonce_out && nonce_cap)     snprintf(nonce_out, nonce_cap, "%s", nonce);
    if (id_out && id_cap)           snprintf(id_out, id_cap, "%s", id);
    if (port_out)                   *port_out = port;
    if (name_out && name_cap)       snprintf(name_out, name_cap, "%s", name);
    if (version_out && version_cap) snprintf(version_out, version_cap, "%s", ver);
    return 0;
}

/* ==========================================================================
 * 线程层：限速 + 重放窗口
 * ========================================================================== */
typedef struct {
    uint32_t ip;            /* 主机字节序，便于比较与打印 */
    double   tokens;
    int64_t  last_ms;
    int      in_use;
} disc_rl_ent;

typedef struct {
    uint32_t ip;
    char     nonce[HD_DISC_NONCE_MAX];
    int64_t  ms;
} disc_nonce_ent;

static disc_rl_ent    g_rl[DISC_RL_IPS];
static disc_nonce_ent g_nc[DISC_NONCE_KEEP];
static int            g_nc_next = 0;

/* 令牌桶。返回 1=放行，0=超速（调用方静默丢弃）。 */
static int rl_allow(uint32_t ip)
{
    int64_t now = hd_now_ms();
    int i, slot = -1, lru = -1;

    for (i = 0; i < DISC_RL_IPS; i++) {
        disc_rl_ent* e = &g_rl[i];
        if (!e->in_use) { if (slot < 0) slot = i; continue; }
        if (e->ip == ip) {
            double dt = (double)(now - e->last_ms);
            if (dt > 0) {
                e->tokens += dt * DISC_RL_PER_MS;
                if (e->tokens > DISC_RL_BURST) e->tokens = DISC_RL_BURST;
                e->last_ms = now;
            }
            if (e->tokens < 1.0) return 0;
            e->tokens -= 1.0;
            return 1;
        }
        if (lru < 0 || e->last_ms < g_rl[lru].last_ms) lru = i;
    }

    if (slot < 0) slot = lru;
    if (slot < 0) return 0;                       /* 表满且无 LRU（不可能） */
    g_rl[slot].in_use  = 1;
    g_rl[slot].ip      = ip;
    g_rl[slot].tokens  = DISC_RL_BURST - 1.0;     /* 首个包也扣一次 */
    g_rl[slot].last_ms = now;
    return 1;
}

static int nonce_seen(uint32_t ip, const char* n)
{
    int64_t now = hd_now_ms();
    int i;
    for (i = 0; i < DISC_NONCE_KEEP; i++) {
        if (g_nc[i].ms == 0 || g_nc[i].ip != ip) continue;
        if (strcmp(g_nc[i].nonce, n) != 0) continue;
        if (now - g_nc[i].ms < DISC_NONCE_TTL_MS) return 1;
    }
    return 0;
}

static void nonce_remember(uint32_t ip, const char* n)
{
    disc_nonce_ent* e = &g_nc[g_nc_next];
    e->ip = ip;
    snprintf(e->nonce, sizeof(e->nonce), "%s", n);
    e->ms = hd_now_ms();
    g_nc_next = (g_nc_next + 1) % DISC_NONCE_KEEP;
}

long hd_disc_reply_count(void)
{
    return g_reply_cnt;
}

/* 处理一个探测帧。所有"不该回应"的分支都必须 return 而不 sendto。 */
static void disc_handle(hd_socket s, const char* buf, int len, const struct sockaddr_in* from)
{
    uint32_t ip = (uint32_t)ntohl(from->sin_addr.s_addr);
    char id[HD_DISC_ID_MAX], nonce[HD_DISC_NONCE_MAX];
    char out[HD_DISC_FRAME_MAX + 1];
    int  n;

    if (!rl_allow(ip)) return;                    /* 限速：连 HMAC 都不算 */

    if (hd_disc_parse_probe(g_cw, buf, len, id, sizeof(id), nonce, sizeof(nonce)) != 0) {
        int64_t now = hd_now_ms();
        g_bad_mac_cnt++;
        if (now - g_last_warn_ms > DISC_WARN_EVERY_MS) {   /* 节流告警，避免刷日志 */
            HD_LOGW("DISC", "探测帧校验未通过（累计 %ld 条），已静默丢弃；"
                            "若为正常用户，请检查两侧 codeword 是否一致", g_bad_mac_cnt);
            g_last_warn_ms = now;
            g_bad_mac_cnt = 0;
        }
        return;
    }

    if (nonce_seen(ip, nonce)) {                  /* 重放 */
        HD_LOGD("DISC", "重放的探测帧被丢弃");
        return;
    }
    nonce_remember(ip, nonce);

    if (!g_respond) return;                       /* 收得到但不回应 */

    n = hd_disc_build_reply(g_cw, id, nonce, g_self_id, g_self_name,
                            g_tcp_port, g_ver, out, sizeof(out));
    if (n <= 0) return;

    if (sendto(s, out, n, 0, (const struct sockaddr*)from, sizeof(*from)) > 0) {
        g_reply_cnt++;
        HD_LOGD("DISC", "已应答探测 ip=%u.%u.%u.%u id=%s",
                (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff, id);
    }
}

static HD_THREAD_RET HD_THREAD_CALL disc_main(void* arg)
{
    hd_socket s;
    struct sockaddr_in bind_addr;
    char buf[HD_DISC_FRAME_MAX + 1];

    (void)arg;

    if (g_port <= 0) {
        HD_LOGI("DISC", "局域网发现已禁用（discovery_port=0）");
        return (HD_THREAD_RET)0;
    }
    if (!g_cw[0]) {
        HD_LOGW("DISC", "未配置 codeword，发现已禁用（算不出 MAC 就无法认证探测）");
        return (HD_THREAD_RET)0;
    }

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == HD_INVALID_SOCK) {
        HD_LOGE("DISC", "UDP socket 创建失败 err=%d", (int)hd_sock_error());
        return (HD_THREAD_RET)1;
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons((unsigned short)g_port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == HD_SOCK_ERR) {
        /* 端口被占用（同机已有一个实例）不应拖垮守护进程：发现功能降级，其余照常 */
        HD_LOGW("DISC", "绑定 UDP :%d 失败 err=%d，发现功能不可用", g_port, (int)hd_sock_error());
        hd_sock_close(s);
        return (HD_THREAD_RET)0;
    }

#ifdef _WIN32
    {
        DWORD tv = 500;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    }
#else
    {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    }
#endif

    HD_LOGI("DISC", "监听 UDP :%d，等待客户端探测（应答=%s，服务标识=%s，TCP=%d）",
            g_port, g_respond ? "开" : "关", g_self_id, g_tcp_port);

    while (!g_stop) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int r;

        memset(&from, 0, sizeof(from));
        r = recvfrom(s, buf, (int)(sizeof(buf) - 1), 0, (struct sockaddr*)&from, &from_len);
        if (r <= 0) continue;                     /* 超时或错误：回到循环顶部看 g_stop */
        if (from.sin_family != AF_INET) continue;
        buf[r] = '\0';
        disc_handle(s, buf, r, &from);
    }

    hd_sock_close(s);
    HD_LOGI("DISC", "发现线程已退出（累计应答 %ld 次）", g_reply_cnt);
    return (HD_THREAD_RET)0;
}

int hd_disc_start(hd_thread* out, const hd_disc_cfg* cfg)
{
    if (!out || !cfg) return -1;

    snprintf(g_cw, sizeof(g_cw), "%s", cfg->codeword ? cfg->codeword : "");
    snprintf(g_self_id, sizeof(g_self_id), "%s", cfg->instance_id ? cfg->instance_id : "");
    snprintf(g_self_name, sizeof(g_self_name), "%s", cfg->local_name ? cfg->local_name : "hamster");
    snprintf(g_ver, sizeof(g_ver), "%s", cfg->version ? cfg->version : "");
    g_port     = cfg->port;
    g_respond  = cfg->respond ? 1 : 0;
    g_tcp_port = cfg->tcp_port;

    if (!hd_disc_valid_id(g_self_id)) {
        HD_LOGE("DISC", "服务标识不合法（%s），拒绝启动发现", g_self_id);
        return -1;
    }

    return hd_thread_start(out, disc_main, NULL);
}
