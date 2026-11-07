/*
 * Hamster Manager — Electron 网络层 / 启动器
 * ver.0.0.8
 *
 * 两种启动方式：
 *   启动器模式（无参数，双击）：启动代理线程 → 拉起 Electron → 等待其退出 → 收尾
 *   代理模式（--proxy-only）：只运行代理线程（由 Electron 主进程 spawn），不自己拉 UI
 *
 * 数据通路：
 *   Electron --(:9102 JSON 行协议)--> 本进程 --(:9100 JSON 行协议)--> hamsterd
 *
 * 本版修掉的历史问题（对应审查报告编号）：
 *   P0-9  在全局锁内做阻塞 send → 锁内只取快照，锁外发送；客户端 fd 设收发超时
 *   P1-1  硬编码发送长度 58（字面量实为 57 字节，越界读）→ 一律用 strlen
 *   P1-2  任何 "status":"error" 都当作口令错误并永久停止重连 → 只精确匹配错误码，
 *         失败后退避重试并重新读取配置（改好口令无需重启进程）
 *   P1-4  accept 出错即退出服务 → 可恢复错误继续监听
 *   P1-5  SO_REUSEADDR 允许端口劫持 → SO_EXCLUSIVEADDRUSE + 单实例互斥
 *   P1-19 第 9 个客户端起 socket/线程永久泄漏 → 槽满时明确拒绝并关闭
 *   另：send 短写、返回值不检查、端口 atoi 无校验、句柄泄漏等一并修正
 */

#ifdef _WIN32
    #define _CRT_SECURE_NO_WARNINGS
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <bcrypt.h>
    #include <process.h>
    #include <direct.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <pthread.h>
    #include <errno.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

#include "jsonx.h"
#include "hd_sec.h"

#define MG_VERSION           "0.0.9"
#define MG_PATH_MAX          2048
#define MG_LINE_MAX          (256 * 1024)
#define MG_MAX_CLIENTS       16
#define MG_DEFAULT_HAMD_PORT 9100
#define MG_DEFAULT_IPC_PORT  9102
#define MG_IDLE_OFFLINE_MS   10000      /* 多久没收到数据判定离线 */
#define MG_STABLE_MS         10000      /* 连接存活超过它才复位退避 */

#ifdef _WIN32
typedef SOCKET   mg_socket;
typedef HANDLE   mg_thread;
typedef HANDLE   mg_mutex;
#define MG_INVALID_SOCK INVALID_SOCKET
#define MG_SOCK_ERR     SOCKET_ERROR
#define mg_close(s)     closesocket(s)
#else
typedef int          mg_socket;
typedef pthread_t    mg_thread;
typedef pthread_mutex_t mg_mutex;
#define MG_INVALID_SOCK (-1)
#define MG_SOCK_ERR     (-1)
#define mg_close(s)     close(s)
#endif

/* ==========================================================================
 * 配置
 * ========================================================================== */
typedef struct {
    int  hamd_port;
    int  ipc_port;
    int  heartbeat_time;
    char codeword[768];
    int  hamd_encrypt;      /* §8：与 hamsterd 之间走加密记录层 */
    char ui_dir[MG_PATH_MAX + 64];
    char electron_exe[MG_PATH_MAX + 64];
    int  proxy_only;        /* 不自己拉起 Electron */
    int  follow_stdin;      /* stdin 关闭即退出（由父进程监督） */
} mg_config;

static mg_config    g_cfg;
static char         g_base_dir[MG_PATH_MAX];
static volatile int g_stop = 0;
static int64_t      g_start_ms = 0;

/* ==========================================================================
 * 基础工具
 * ========================================================================== */
static int mg_sock_error(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static int mg_err_retryable(int err)
{
#ifdef _WIN32
    return (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK || err == WSAEINTR ||
            err == WSAECONNABORTED || err == WSAENOBUFS);
#else
    return (err == EAGAIN || err == EWOULDBLOCK || err == EINTR);
#endif
}

static void mg_log(const char* tag, const char* fmt, ...)
{
    va_list ap;
    printf("[%s] ", tag ? tag : "-");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

static int64_t mg_now_ms(void)
{
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (int64_t)(u.QuadPart / 10000ULL) - 11644473600000LL;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

static void mg_sleep_ms(int ms)
{
    if (ms <= 0) return;
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    usleep((useconds_t)ms * 1000);
#endif
}

/* 可被停止标志打断的等待（分片，最多 100ms 响应一次） */
static int mg_wait_ms(int ms)
{
    while (ms > 0) {
        int step = ms > 100 ? 100 : ms;
        if (g_stop) return 1;
        mg_sleep_ms(step);
        ms -= step;
    }
    return g_stop ? 1 : 0;
}

static int mg_send_all(mg_socket fd, const void* data, size_t len)
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

/* 发一行；长度一律 strlen，不再出现手写魔数 */
static int mg_send_line(mg_socket fd, const char* json)
{
    if (fd == MG_INVALID_SOCK || !json) return -1;
    if (mg_send_all(fd, json, strlen(json)) != 0) return -1;
    return mg_send_all(fd, "\n", 1);
}

static void mg_set_timeouts(mg_socket fd, int ms)
{
#ifdef _WIN32
    DWORD tv = (DWORD)ms;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif
}

static void mg_set_nodelay(mg_socket fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&one, sizeof(one));
}

static int mg_mutex_init(mg_mutex* m)
{
#ifdef _WIN32
    *m = CreateMutex(NULL, FALSE, NULL);
    return *m ? 0 : -1;
#else
    return pthread_mutex_init(m, NULL);
#endif
}
static void mg_mutex_destroy(mg_mutex* m)
{
#ifdef _WIN32
    if (*m) { CloseHandle(*m); *m = NULL; }
#else
    pthread_mutex_destroy(m);
#endif
}
static void mg_mutex_lock(mg_mutex* m)
{
    if (!m) return;
#ifdef _WIN32
    if (*m) WaitForSingleObject(*m, INFINITE);
#else
    pthread_mutex_lock(m);
#endif
}
static void mg_mutex_unlock(mg_mutex* m)
{
    if (!m) return;
#ifdef _WIN32
    if (*m) ReleaseMutex(*m);
#else
    pthread_mutex_unlock(m);
#endif
}

#ifdef _WIN32
typedef unsigned (__stdcall *mg_thread_fn)(void*);
#define MG_THREAD_RET unsigned
#define MG_THREAD_CALL __stdcall
#else
typedef void* (*mg_thread_fn)(void*);
#define MG_THREAD_RET void*
#define MG_THREAD_CALL
#endif

static int mg_thread_start(mg_thread* t, mg_thread_fn fn, void* arg)
{
#ifdef _WIN32
    unsigned tid = 0;
    uintptr_t h = _beginthreadex(NULL, 0, fn, arg, 0, &tid);
    if (!h) return -1;
    *t = (HANDLE)h;
    return 0;
#else
    return pthread_create(t, NULL, fn, arg);
#endif
}

static void mg_thread_join(mg_thread* t)
{
    if (!t) return;
#ifdef _WIN32
    if (*t) { WaitForSingleObject(*t, INFINITE); CloseHandle(*t); *t = NULL; }
#else
    if (*t) { pthread_join(*t, NULL); *t = 0; }
#endif
}

static void mg_thread_dispose(mg_thread* t)
{
    if (!t) return;
#ifdef _WIN32
    if (*t) { CloseHandle(*t); *t = NULL; }
#else
    if (*t) { pthread_detach(*t); *t = 0; }
#endif
}

/* ==========================================================================
 * :9102 客户端表
 * ========================================================================== */
typedef struct {
    mg_socket fd;
    mg_mutex  wlk;          /* 写串行化 */
    int       wlk_ok;
} mg_client;

static mg_client g_clients[MG_MAX_CLIENTS];
static mg_mutex  g_clients_lk;
static int       g_clients_lk_ok = 0;

static void clients_init(void)
{
    int i;
    for (i = 0; i < MG_MAX_CLIENTS; i++) {
        g_clients[i].fd = MG_INVALID_SOCK;
        g_clients[i].wlk_ok = (mg_mutex_init(&g_clients[i].wlk) == 0) ? 1 : 0;
    }
}

static void clients_destroy(void)
{
    int i;
    for (i = 0; i < MG_MAX_CLIENTS; i++) {
        if (g_clients[i].wlk_ok) { mg_mutex_destroy(&g_clients[i].wlk); g_clients[i].wlk_ok = 0; }
    }
}

/* 返回槽位下标，-1 表示已满（调用方必须关闭 fd） */
static int clients_add(mg_socket fd)
{
    int i, slot = -1;
    mg_mutex_lock(&g_clients_lk);
    for (i = 0; i < MG_MAX_CLIENTS; i++) {
        if (g_clients[i].fd == MG_INVALID_SOCK) { g_clients[i].fd = fd; slot = i; break; }
    }
    mg_mutex_unlock(&g_clients_lk);
    return slot;
}

static void clients_remove(mg_socket fd)
{
    int i;
    mg_mutex_lock(&g_clients_lk);
    for (i = 0; i < MG_MAX_CLIENTS; i++) {
        if (g_clients[i].fd == fd) { g_clients[i].fd = MG_INVALID_SOCK; break; }
    }
    mg_mutex_unlock(&g_clients_lk);
}

static int clients_count(void)
{
    int i, n = 0;
    mg_mutex_lock(&g_clients_lk);
    for (i = 0; i < MG_MAX_CLIENTS; i++) if (g_clients[i].fd != MG_INVALID_SOCK) n++;
    mg_mutex_unlock(&g_clients_lk);
    return n;
}

/* ==========================================================================
 * :9100 连接 + 转发
 * ========================================================================== */
static mg_socket g_hamd_fd = MG_INVALID_SOCK;
static mg_mutex  g_hamd_lk;
static int       g_hamd_lk_ok = 0;
static volatile int g_online = 0;

/* 加锁 + 按需加密地发一行到 hamsterd（定义在下面的 §8 传输加密一节） */
static int mg_hamd_send_line(const char* json);

/*
 * 把一行 JSON 发给所有 :9102 客户端（修 P0-9）。
 * 锁内只做 fd/锁指针快照，发送在锁外逐个进行：
 * 一个不读数据的客户端最多阻塞它自己的那次 send（受 SO_SNDTIMEO 限制），
 * 不会把整个中间层和心跳线程一起卡死。
 */
static void forward_electron(const char* json)
{
    struct { mg_socket fd; mg_mutex* lk; } snap[MG_MAX_CLIENTS];
    int n = 0, i;

    if (!json) return;

    mg_mutex_lock(&g_clients_lk);
    for (i = 0; i < MG_MAX_CLIENTS; i++) {
        if (g_clients[i].fd != MG_INVALID_SOCK) {
            snap[n].fd = g_clients[i].fd;
            snap[n].lk = &g_clients[i].wlk;
            n++;
        }
    }
    mg_mutex_unlock(&g_clients_lk);

    for (i = 0; i < n; i++) {
        if (snap[i].lk) mg_mutex_lock(snap[i].lk);
        if (mg_send_line(snap[i].fd, json) != 0) {
            mg_log("IPC", "向 electron 发送失败 fd=%d，标记该连接待关闭", (int)snap[i].fd);
            mg_close(snap[i].fd);
            clients_remove(snap[i].fd);
        }
        if (snap[i].lk) mg_mutex_unlock(snap[i].lk);
    }
}

static void forward_hamsterd(const char* json)
{
    int online = 0;

    mg_mutex_lock(&g_hamd_lk);
    online = (g_hamd_fd != MG_INVALID_SOCK);
    mg_mutex_unlock(&g_hamd_lk);

    if (!online) {
        mg_log("HAMD", "未连接 hamsterd，丢弃该请求");
        return;
    }
    /* 发送本身在 mg_hamd_send_line 里加锁并（按需）加密 */
    if (mg_hamd_send_line(json) != 0) {
        mg_log("HAMD", "转发失败，判定连接已断");
    }
}

static void report_online(int online)
{
    char line[128];
    if (online == (int)g_online) return;
    g_online = online;
    snprintf(line, sizeof(line),
             "{\"type\":\"event\",\"event\":\"connection_status\",\"data\":\"%s\"}",
             online ? "online" : "offline");
    forward_electron(line);
    mg_log("HAMD", "连接状态: %s", online ? "ONLINE" : "OFFLINE");
}

/* ==========================================================================
 * 配置读写
 * ========================================================================== */
static int parse_int_range(const char* v, int lo, int hi, int* out)
{
    char* stop = NULL;
    long n;
    if (!v || !*v) return -1;
    n = strtol(v, &stop, 10);
    if (stop == v || (stop && *stop != '\0')) return -1;
    if (n < lo || n > hi) return -1;
    *out = (int)n;
    return 0;
}

static const char* manager_conf_path(void)
{
    static char p[MG_PATH_MAX + 64];
    snprintf(p, sizeof(p), "%s/hamster_manager.conf", g_base_dir);
    return p;
}

static const char* daemon_conf_path(void)
{
    static char p[MG_PATH_MAX + 64];
    static int done = 0;

    /*
     * 两种布局都要能找到 hamsterd.conf：
     *   仓库布局   Hamster Manager/hamster_manager.exe → ../Hamsterd/hamsterd.conf
     *   部署/测试  两个 exe 与两份 conf 放在同一个目录
     * 以前只认第一种，导致测试环境里"继承守护进程设置"静默失效。
     */
    if (!done) {
        FILE* fp;

        snprintf(p, sizeof(p), "%s/hamsterd.conf", g_base_dir);
        fp = fopen(p, "rb");
        if (fp) {
            fclose(fp);
        } else {
            snprintf(p, sizeof(p), "%s/../Hamsterd/hamsterd.conf", g_base_dir);
        }
        done = 1;
    }
    return p;
}

/* 从指定 conf 读某个键（就地返回），成功返回 1 */
static int conf_get_value(const char* path, const char* want_key, char* out, size_t n)
{
    FILE* fp = fopen(path, "rb");
    char line[1024];
    out[0] = '\0';
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp)) {
        char key[128] = "", val[768] = "";
        char* p = line;
        char* hash;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\r' || *p == '\n' || *p == '\0') continue;
        hash = strchr(p, '#');
        if (hash && hash > p && hash[-1] == ' ') *hash = '\0';

        if (sscanf(p, "%127[^:]: %767[^\r\n]", key, val) != 2 &&
            sscanf(p, "%127s %767[^\r\n]", key, val) != 2) continue;

        {
            size_t vl = strlen(val);
            while (vl > 0 && (val[vl - 1] == ' ' || val[vl - 1] == '\t')) val[--vl] = '\0';
        }
        if (strcmp(key, want_key) == 0) {
            snprintf(out, n, "%s", val);
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int parse_bool(const char* v)
{
    if (!v) return 0;
    if (strcmp(v, "on") == 0 || strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0) return 1;
    if (strcmp(v, "off") == 0 || strcmp(v, "false") == 0 || strcmp(v, "0") == 0 || strcmp(v, "no") == 0) return 0;
    return atoi(v) != 0;
}

static void load_config(void)
{
    const char* cp = manager_conf_path();
    char v[768];
    g_cfg.hamd_port = MG_DEFAULT_HAMD_PORT;
    g_cfg.ipc_port = MG_DEFAULT_IPC_PORT;
    g_cfg.heartbeat_time = 3;
    g_cfg.codeword[0] = '\0';

    if (conf_get_value(cp, "hamd_port", v, sizeof(v))) {
        int p;
        if (parse_int_range(v, 1, 65535, &p) == 0) g_cfg.hamd_port = p;
        else mg_log("CFG", "hamd_port 非法(%s)，沿用 %d", v, g_cfg.hamd_port);
    }
    if (conf_get_value(cp, "ipc_port", v, sizeof(v))) {
        int p;
        if (parse_int_range(v, 1, 65535, &p) == 0) g_cfg.ipc_port = p;
        else mg_log("CFG", "ipc_port 非法(%s)，沿用 %d", v, g_cfg.ipc_port);
    }
    if (conf_get_value(cp, "heartbeat_time", v, sizeof(v))) {
        int p;
        if (parse_int_range(v, 1, 3600, &p) == 0) g_cfg.heartbeat_time = p;
    }
    if (conf_get_value(cp, "hamd_codeword", v, sizeof(v))) {
        snprintf(g_cfg.codeword, sizeof(g_cfg.codeword), "%s", v);
    }

    /* §8 开关：显式配置优先；否则跟随 hamsterd.conf 的 encrypt_transport；
       两处都没写时按**开**处理（守护进程 0.0.9 的默认也是开）。 */
    g_cfg.hamd_encrypt = 1;
    if (conf_get_value(cp, "hamd_encrypt", v, sizeof(v))) {
        g_cfg.hamd_encrypt = parse_bool(v);
    } else if (conf_get_value(daemon_conf_path(), "encrypt_transport", v, sizeof(v))) {
        g_cfg.hamd_encrypt = parse_bool(v);
        mg_log("CFG", "本配置未设 hamd_encrypt，已跟随 hamsterd.conf: encrypt_transport=%s",
               g_cfg.hamd_encrypt ? "on" : "off");
    }

    /* 口令留空时回退去读 hamsterd.conf，避免两处配置不同步导致连不上 */
    if (g_cfg.codeword[0] == '\0') {
        if (conf_get_value(daemon_conf_path(), "codeword", v, sizeof(v)) && v[0]) {
            snprintf(g_cfg.codeword, sizeof(g_cfg.codeword), "%s", v);
            mg_log("CFG", "本配置未设口令，已从 %s 读取", daemon_conf_path());
        }
    }

    mg_log("CFG", "profile=%s hamd=%d ipc=%d heartbeat=%ds 加密=%s codeword=%s",
           cp, g_cfg.hamd_port, g_cfg.ipc_port, g_cfg.heartbeat_time,
           g_cfg.hamd_encrypt ? "on" : "off",
           g_cfg.codeword[0] ? "(已设置)" : "(未设置，hamsterd 会拒绝认证)");
}

/* ==========================================================================
 * §8 传输加密：本进程 ↔ hamsterd
 *
 * 代理是"Electron 的明文 ↔ 守护进程的密文"之间的转换点：
 *   · 到 hamsterd 的连接先跑 §8.2 握手，之后每条报文都走 §8.3 记录层；
 *   · 到 Electron 的 :9102 仍然是一行一个 JSON（本机 IPC，不在 §8 范围内）。
 * 加密由 hamd_encrypt 打开（缺省继承 hamsterd.conf 的 encrypt_transport），
 * 关掉时完整保留 0.0.8 的明文 hello 流程。
 * ========================================================================== */
static hd_sec        g_sec;
static int           g_sec_on = 0;
static unsigned char g_wbuf[HD_SEC_REC_MAX];       /* 发送封包暂存（g_hamd_lk 保护） */
static unsigned char g_rx[HD_SEC_REC_MAX];         /* 接收密文累积（只在客户端线程用） */
static size_t        g_rx_len = 0;
static char          g_hs[2048];                   /* 握手阶段的明文行缓冲 */
static size_t        g_hs_len = 0;

static int mg_rand_bytes(void* out, size_t n)
{
#ifdef _WIN32
    return BCryptGenRandom(NULL, (PUCHAR)out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    {
        FILE* f = fopen("/dev/urandom", "rb");
        size_t got;
        if (!f) return -1;
        got = fread(out, 1, n, f);
        fclose(f);
        return got == n ? 0 : -1;
    }
#endif
}

static int mg_sec_send_all(mg_socket fd, const void* data, size_t len)
{
    const unsigned char* p = (const unsigned char*)data;

    if (!g_sec_on) return mg_send_all(fd, data, len);
    while (len > 0) {
        size_t n = (len > HD_SEC_MAX_PLAIN) ? HD_SEC_MAX_PLAIN : len;
        size_t rl = hd_sec_seal(&g_sec, p, n, g_wbuf);
        if (rl == 0) return -1;
        if (mg_send_all(fd, g_wbuf, rl) != 0) return -1;
        p   += n;
        len -= n;
    }
    return 0;
}

/* 加密模式下的"收一块明文"；返回 0=对端关闭，-1=可重试，-2=协议错误（必须断开） */
static int mg_sec_recv(mg_socket fd, char* out, int cap)
{
    for (;;) {
        if (g_rx_len >= HD_SEC_HDR_LEN) {
            uint32_t len = ((uint32_t)g_rx[0] << 24) | ((uint32_t)g_rx[1] << 16) |
                           ((uint32_t)g_rx[2] << 8) | (uint32_t)g_rx[3];
            size_t total;
            if (len == 0 || len > HD_SEC_MAX_PLAIN) return -2;
            if ((int)len > cap) return -2;          /* 单行超过缓冲：流已不可信 */
            total = HD_SEC_HDR_LEN + (size_t)len + HD_SEC_TAG_LEN;
            if (g_rx_len >= total) {
                int pl = hd_sec_open(&g_sec, g_rx, total, out, (size_t)cap);
                if (pl <= 0) return -2;
                if (g_rx_len > total) memmove(g_rx, g_rx + total, g_rx_len - total);
                g_rx_len -= total;
                return pl;
            }
        }
        if (g_rx_len >= sizeof(g_rx)) return -2;
        {
            int n = recv(fd, (char*)g_rx + g_rx_len, (int)(sizeof(g_rx) - g_rx_len), 0);
            if (n > 0) { g_rx_len += (size_t)n; continue; }
            if (n == 0) return 0;
            return -1;
        }
    }
}

static int mg_plain_send(mg_socket fd, const char* json)
{
    if (mg_send_all(fd, json, strlen(json)) != 0) return -1;
    return mg_send_all(fd, "\n", 1);
}

static int mg_hs_read_line(mg_socket fd, char* out, size_t cap)
{
    for (;;) {
        char* nl = (char*)memchr(g_hs, '\n', g_hs_len);
        if (nl) {
            size_t n = (size_t)(nl - g_hs);
            if (n >= cap) return -1;
            memcpy(out, g_hs, n);
            out[n] = '\0';
            memmove(g_hs, nl + 1, g_hs_len - n - 1);
            g_hs_len -= n + 1;
            return 0;
        }
        if (g_hs_len >= sizeof(g_hs)) return -1;
        {
            int r = recv(fd, g_hs + g_hs_len, (int)(sizeof(g_hs) - g_hs_len), 0);
            if (r <= 0) return -1;
            g_hs_len += (size_t)r;
        }
    }
}

/*
 * §8.2 客户端握手。返回 0=成功（g_sec 已激活），-1=失败。
 * out_auth_fail=1 表示"口令不被接受"（守护进程静默关闭），用于退避策略。
 */
static int mg_handshake(mg_socket fd, const char* codeword, const char* device_id,
                        int* out_auth_fail)
{
    uint8_t salt[HD_SEC_SALT_LEN], ns[HD_SEC_SALT_LEN], nc[HD_SEC_NONCE_LEN];
    uint8_t master[HD_SEC_KEY_LEN], proof[HD_SEC_KEY_LEN];
    char nc_hex[33], mac_hex[65], line[1200];
    char challenge[1200];
    int v = 0;
    char type[16] = "", step[24] = "", alg[32] = "", kdf[32] = "";
    char salt_hex[33], ns_hex[33], mac[65];

    if (out_auth_fail) *out_auth_fail = 0;
    if (!codeword || !codeword[0]) return -1;

    g_hs_len = 0;
    g_rx_len = 0;

    if (mg_rand_bytes(nc, sizeof(nc)) != 0) return -1;
    hd_sec_hex_encode(nc, sizeof(nc), nc_hex);

    snprintf(line, sizeof(line),
             "{\"type\":\"auth\",\"step\":\"hello\",\"v\":2,\"device_id\":\"%s\",\"hostname\":\"manager\",\"nc\":\"%s\"}",
             device_id, nc_hex);
    if (mg_plain_send(fd, line) != 0) return -1;

    if (mg_hs_read_line(fd, challenge, sizeof(challenge)) != 0) return -1;
    jx_get_str(challenge, "type", type, sizeof(type));
    jx_get_str(challenge, "step", step, sizeof(step));
    jx_get_int(challenge, "v", &v);
    jx_get_str(challenge, "alg", alg, sizeof(alg));
    jx_get_str(challenge, "kdf", kdf, sizeof(kdf));
    jx_get_str(challenge, "salt", salt_hex, sizeof(salt_hex));
    jx_get_str(challenge, "ns", ns_hex, sizeof(ns_hex));

    if (strcmp(type, "auth") != 0 || strcmp(step, "challenge") != 0 || v != 2) return -1;
    if (strcmp(alg, "chacha20poly1305") != 0 || strcmp(kdf, "hkdf-sha256") != 0) return -1;
    if (strlen(salt_hex) != HD_SEC_HEX16_LEN || strlen(ns_hex) != HD_SEC_HEX16_LEN) return -1;
    if (hd_sec_hex_decode(salt_hex, HD_SEC_SALT_LEN, salt) != 0) return -1;
    if (hd_sec_hex_decode(ns_hex, HD_SEC_SALT_LEN, ns) != 0) return -1;

    hd_sec_master(codeword, strlen(codeword), salt, master);
    hd_sec_proof_c(master, nc_hex, ns_hex, device_id, proof);
    hd_sec_hex_encode(proof, sizeof(proof), mac_hex);

    snprintf(line, sizeof(line), "{\"type\":\"auth\",\"step\":\"proof\",\"mac\":\"%s\"}", mac_hex);
    if (mg_plain_send(fd, line) != 0) return -1;

    /* 守护进程认证失败时直接关连接：这里读到 EOF/错误就是"口令不对" */
    if (mg_hs_read_line(fd, line, sizeof(line)) != 0) {
        if (out_auth_fail) *out_auth_fail = 1;
        return -1;
    }
    type[0] = step[0] = mac[0] = '\0';
    jx_get_str(line, "type", type, sizeof(type));
    jx_get_str(line, "step", step, sizeof(step));
    jx_get_str(line, "mac", mac, sizeof(mac));
    if (strcmp(type, "auth") != 0 || strcmp(step, "ok") != 0) return -1;
    if (strlen(mac) != HD_SEC_HEX32_LEN) return -1;

    /* 先验服务端，再敢发任何命令（§8.2） */
    {
        uint8_t got[HD_SEC_KEY_LEN];
        uint8_t want[HD_SEC_KEY_LEN];
        if (hd_sec_hex_decode(mac, HD_SEC_KEY_LEN, got) != 0) return -1;
        hd_sec_proof_s(master, nc_hex, ns_hex, want);
        if (!hd_sec_ct_eq(got, want, HD_SEC_KEY_LEN)) return -1;
    }

    if (hd_sec_init(&g_sec, master, salt, nc_hex, ns_hex, 0) != 0) return -1;
    g_sec_on = 1;

    /* ok 之后对端可能紧跟记录：残留明文缓冲里的字节属于密文流 */
    if (g_hs_len) {
        if (g_hs_len > sizeof(g_rx)) return -1;
        memcpy(g_rx, g_hs, g_hs_len);
        g_rx_len = g_hs_len;
        g_hs_len = 0;
    }
    return 0;
}

/* 加锁发送一行到 hamsterd；返回 0=已发出，-1=未连接/发送失败 */
static int mg_hamd_send_line(const char* json)
{
    int rc = -1;

    mg_mutex_lock(&g_hamd_lk);
    if (g_hamd_fd != MG_INVALID_SOCK) {
        if (mg_sec_send_all(g_hamd_fd, json, strlen(json)) == 0 &&
            mg_sec_send_all(g_hamd_fd, "\n", 1) == 0) {
            rc = 0;
        } else {
            mg_log("HAMD", "转发失败，判定连接已断");
            g_hamd_fd = MG_INVALID_SOCK;
        }
    }
    mg_mutex_unlock(&g_hamd_lk);
    return rc;
}

/* ==========================================================================
 * 线程 1：hamsterd 客户端
 * ========================================================================== */
static MG_THREAD_RET MG_THREAD_CALL hamd_client_thread(void* arg)
{
    int retry_ms = 1000;
    int auth_fail_streak = 0;

    (void)arg;
    mg_log("HAMD", "客户端线程启动");

    while (!g_stop) {
        mg_socket fd;
        struct sockaddr_in a;
        int64_t connected_at;
        int drop = 0;            /* 认证被拒：重读配置后再试，而不是永久停止 */

        if (g_hamd_fd != MG_INVALID_SOCK) {
            mg_mutex_lock(&g_hamd_lk);
            if (g_hamd_fd != MG_INVALID_SOCK) { mg_close(g_hamd_fd); g_hamd_fd = MG_INVALID_SOCK; }
            mg_mutex_unlock(&g_hamd_lk);
        }

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == MG_INVALID_SOCK) {
            mg_log("HAMD", "socket() 失败 err=%d", mg_sock_error());
            if (mg_wait_ms(retry_ms)) break;
            retry_ms = retry_ms < 30000 ? retry_ms * 2 : 30000;
            continue;
        }
        mg_set_timeouts(fd, 5000);
        mg_set_nodelay(fd);

        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons((unsigned short)g_cfg.hamd_port);
        a.sin_addr.s_addr = inet_addr("127.0.0.1");

        if (connect(fd, (struct sockaddr*)&a, sizeof(a)) != 0) {
            mg_log("HAMD", "连接 127.0.0.1:%d 失败 err=%d，%dms 后重试",
                   g_cfg.hamd_port, mg_sock_error(), retry_ms);
            mg_close(fd);
            if (mg_wait_ms(retry_ms)) break;
            retry_ms = retry_ms < 30000 ? retry_ms * 2 : 30000;
            continue;
        }

        g_sec_on = 0;
        g_rx_len = 0;
        g_hs_len = 0;

        if (g_cfg.hamd_encrypt) {
            /* §8.2：先握手；失败就当"认证被拒"处理，退避后重读配置再试 */
            int auth_fail = 0;
            if (mg_handshake(fd, g_cfg.codeword, "manager", &auth_fail) != 0) {
                mg_close(fd);
                if (g_stop) break;
                if (auth_fail) {
                    auth_fail_streak++;
                    auth_fail_streak = auth_fail_streak > 10 ? 10 : auth_fail_streak;
                    mg_log("HAMD", "握手被拒（第 %d 次）：请检查 hamster_manager.conf 的 hamd_codeword "
                                   "与 hamsterd.conf 的 codeword 是否一致", auth_fail_streak);
                    if (mg_wait_ms(10000 * auth_fail_streak)) break;
                    load_config();
                    retry_ms = 1000;
                } else {
                    mg_log("HAMD", "握手失败（非口令原因），%dms 后重试", retry_ms);
                    if (mg_wait_ms(retry_ms)) break;
                    retry_ms = retry_ms < 30000 ? retry_ms * 2 : 30000;
                }
                continue;
            }
        } else {
            /* 明文模式（0.0.8 兼容）：hello 口令必须转义后再拼进 JSON */
            char esc[400] = "";
            char hello[768];
            if (g_cfg.codeword[0]) jx_escape(g_cfg.codeword, esc, sizeof(esc));
            snprintf(hello, sizeof(hello),
                     "{\"type\":\"request\",\"id\":\"conn\",\"action\":\"hello\","
                     "\"params\":{\"device_id\":\"manager\",\"hostname\":\"manager\",\"codeword\":\"%s\"}}",
                     esc);
            if (mg_send_line(fd, hello) != 0) {
                mg_log("HAMD", "hello 发送失败");
                mg_close(fd);
                continue;
            }
        }

        mg_mutex_lock(&g_hamd_lk);
        g_hamd_fd = fd;
        mg_mutex_unlock(&g_hamd_lk);

        connected_at = mg_now_ms();
        report_online(1);
        mg_log("HAMD", "已连接 127.0.0.1:%d（%s）", g_cfg.hamd_port,
               g_cfg.hamd_encrypt ? "§8 握手完成，此后全程加密" : "明文模式，hello 已发送");

        {
            char* buf = (char*)malloc(MG_LINE_MAX);
            int   pos = 0;
            int64_t last_data = mg_now_ms();
            int64_t last_ping = 0;

            if (!buf) { mg_close(fd); continue; }

            while (!g_stop) {
                int r = g_sec_on ? mg_sec_recv(fd, buf + pos, MG_LINE_MAX - pos - 1)
                                 : recv(fd, buf + pos, MG_LINE_MAX - pos - 1, 0);

                if (r > 0) {
                    char* lp;
                    last_data = mg_now_ms();
                    pos += r;
                    buf[pos] = '\0';

                    lp = buf;
                    for (;;) {
                        char* nl = strchr(lp, '\n');
                        if (!nl) break;
                        *nl = '\0';
                        if (*lp) {
                            forward_electron(lp);
                            /* 只精确匹配认证错误的错误码（修 P1-2）：
                               以前把任何 "status":"error" 都当成口令错误并永久停止重连，
                               于是一条 unknown_action 就能打死整个代理。 */
                            if (strstr(lp, "\"invalid_credential\"") ||
                                strstr(lp, "\"invalid_codeword\"")) {
                                auth_fail_streak++;
                                mg_log("HAMD", "认证被拒（第 %d 次）：请检查 hamster_manager.conf 的 "
                                               "hamd_codeword 与 hamsterd.conf 的 codeword 是否一致",
                                       auth_fail_streak);
                                drop = 1;
                            }
                        }
                        lp = nl + 1;
                    }
                    {
                        int remain = (int)(buf + pos - lp);
                        if (remain > 0) { memmove(buf, lp, (size_t)remain); pos = remain; }
                        else pos = 0;
                    }
                    if (drop) break;
                } else {
                    int err = mg_sock_error();
                    if (r == -2) {
                        /* §8.3：记录层不对就断开重连，不解释原因 */
                        mg_log("HAMD", "记录层错误（长度/序号/认证失败），断开重连");
                        break;
                    }
                    if (mg_err_retryable(err)) {
                        int64_t now = mg_now_ms();
                        if (now - last_data > MG_IDLE_OFFLINE_MS) {
                            mg_log("HAMD", "超过 %dms 未收到数据（心跳超时）", MG_IDLE_OFFLINE_MS);
                            break;
                        }
                        if (now - last_ping >= (int64_t)g_cfg.heartbeat_time * 1000) {
                            const char* ka = "{\"type\":\"request\",\"id\":\"ka\",\"action\":\"ping\",\"params\":{}}";
                            if (mg_hamd_send_line(ka) != 0) {
                                mg_log("HAMD", "心跳发送失败");
                                break;
                            }
                            last_ping = now;
                        }
                        continue;
                    }
                    mg_log("HAMD", "recv 错误 err=%d，断开重连", err);
                    break;
                }
            }
            free(buf);
        }

        mg_mutex_lock(&g_hamd_lk);
        if (g_hamd_fd == fd) g_hamd_fd = MG_INVALID_SOCK;
        mg_mutex_unlock(&g_hamd_lk);
        mg_close(fd);
        report_online(0);

        if (g_stop) break;

        /* 退避策略：只有"稳定连接过一段时间"才复位，
           否则连上 1 秒就断的设备会永远 1 秒重连一次（修 P1-2 的连带问题） */
        if (mg_now_ms() - connected_at >= MG_STABLE_MS) retry_ms = 1000;
        else retry_ms = retry_ms < 30000 ? retry_ms * 2 : 30000;

        if (drop) {
            /* 认证失败：等待较长时间并重新读取配置，用户改好口令后无需重启代理 */
            auth_fail_streak = auth_fail_streak > 10 ? 10 : auth_fail_streak;
            mg_log("HAMD", "认证失败，%d 秒后重新读取配置再试",
                   10 * auth_fail_streak);
            if (mg_wait_ms(10000 * auth_fail_streak)) break;
            load_config();
            retry_ms = 1000;
        } else {
            mg_log("HAMD", "连接断开，%dms 后重连", retry_ms);
            if (mg_wait_ms(retry_ms)) break;
        }
    }

    mg_log("HAMD", "客户端线程退出");
    return (MG_THREAD_RET)0;
}

/* ==========================================================================
 * 线程 2：:9102 接受（Electron 命令）
 * ========================================================================== */
static MG_THREAD_RET MG_THREAD_CALL ipc_recv_thread(void* arg)
{
    mg_socket fd = (mg_socket)(intptr_t)arg;
    char* buf = (char*)malloc(MG_LINE_MAX);
    int pos = 0;

    if (!buf) { mg_close(fd); return (MG_THREAD_RET)0; }

    while (!g_stop) {
        int r = recv(fd, buf + pos, MG_LINE_MAX - pos - 1, 0);

        if (r > 0) {
            char* lp;
            pos += r;
            buf[pos] = '\0';

            lp = buf;
            for (;;) {
                char* nl = strchr(lp, '\n');
                if (!nl) break;
                *nl = '\0';
                if (*lp) {
                    if (!jx_is_object(lp)) {
                        mg_log("IPC", "来自 electron 的非法 JSON，已忽略该行");
                    } else {
                        forward_hamsterd(lp);
                    }
                }
                lp = nl + 1;
            }
            {
                int remain = (int)(buf + pos - lp);
                if (remain > 0) { memmove(buf, lp, (size_t)remain); pos = remain; }
                else pos = 0;
            }
        } else {
            int err = mg_sock_error();
            if (mg_err_retryable(err)) continue;      /* 超时：继续等 */
            break;
        }
    }

    free(buf);
    clients_remove(fd);
    mg_close(fd);
    mg_log("IPC", "客户端断开 fd=%d（剩余 %d）", (int)fd, clients_count());
    return (MG_THREAD_RET)0;
}

static MG_THREAD_RET MG_THREAD_CALL ipc_accept_thread(void* arg)
{
    mg_socket srv;
    struct sockaddr_in a;
    int opt = 1;
    int backoff_ms = 100;

    (void)arg;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == MG_INVALID_SOCK) {
        mg_log("IPC", "socket() 失败 err=%d", mg_sock_error());
        return (MG_THREAD_RET)1;
    }

#ifdef _WIN32
    /* Windows 下 SO_REUSEADDR 允许别的进程抢占同一端口，必须用独占绑定（修 P1-5） */
    setsockopt(srv, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&opt, sizeof(opt));
#else
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#endif

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)g_cfg.ipc_port);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(srv, (struct sockaddr*)&a, sizeof(a)) == MG_SOCK_ERR) {
        mg_log("IPC", "绑定 127.0.0.1:%d 失败 err=%d（端口被占用？）",
               g_cfg.ipc_port, mg_sock_error());
        mg_close(srv);
        return (MG_THREAD_RET)2;
    }
    if (listen(srv, 8) == MG_SOCK_ERR) {
        mg_log("IPC", "listen 失败 err=%d", mg_sock_error());
        mg_close(srv);
        return (MG_THREAD_RET)3;
    }
    mg_log("IPC", "正在监听 127.0.0.1:%d", g_cfg.ipc_port);

    while (!g_stop) {
        fd_set rfds;
        struct timeval tv;
        int sel;
        mg_socket fd;

        FD_ZERO(&rfds);
        FD_SET(srv, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        sel = select((int)srv + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            int err = mg_sock_error();
            if (mg_err_retryable(err)) continue;
            mg_log("IPC", "select 失败 err=%d，%dms 后重试", err, backoff_ms);
            mg_sleep_ms(backoff_ms);
            if (backoff_ms < 2000) backoff_ms *= 2;
            continue;
        }
        if (sel == 0) continue;
        backoff_ms = 100;

        {
            struct sockaddr_in ca;
            socklen_t al = sizeof(ca);
            fd = accept(srv, (struct sockaddr*)&ca, &al);
        }
        if (fd == MG_INVALID_SOCK) {
            int err = mg_sock_error();
            /* 可恢复错误绝不能终止监听循环（修 P1-4） */
            if (mg_err_retryable(err)) { mg_sleep_ms(50); continue; }
            mg_log("IPC", "accept 失败 err=%d，继续监听", err);
            mg_sleep_ms(200);
            continue;
        }

        if (clients_add(fd) < 0) {
            /* 槽满：明确拒绝并关闭，不留下孤儿 socket/线程（修 P1-19） */
            const char* busy = "{\"type\":\"event\",\"event\":\"overloaded\","
                               "\"data\":\"manager 连接数已满\"}";
            mg_send_line(fd, busy);
            mg_close(fd);
            mg_log("IPC", "连接数已达上限 %d，拒绝新连接", MG_MAX_CLIENTS);
            continue;
        }

        mg_set_timeouts(fd, 1000);      /* 1s 超时用于定期检查停止标志 */
        mg_set_nodelay(fd);
        mg_log("IPC", "electron 已接入 fd=%d（当前 %d）", (int)fd, clients_count());

        {
            mg_thread th;
            if (mg_thread_start(&th, ipc_recv_thread, (void*)(intptr_t)fd) != 0) {
                mg_log("IPC", "无法创建接收线程，关闭该连接");
                clients_remove(fd);
                mg_close(fd);
                continue;
            }
            mg_thread_dispose(&th);
        }
    }

    mg_close(srv);
    mg_log("IPC", "接受线程退出");
    return (MG_THREAD_RET)0;
}

/* ==========================================================================
 * 启动 Electron（启动器模式）
 * ========================================================================== */
static int run_electron(void)
{
#ifdef _WIN32
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmdline[MG_PATH_MAX * 2 + 256];
    DWORD code = 0;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    snprintf(cmdline, sizeof(cmdline), "\"%s\" \"%s\" --disable-gpu --disable-software-rasterizer",
             g_cfg.electron_exe, g_cfg.ui_dir);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, DETACHED_PROCESS,
                        NULL, g_cfg.ui_dir, &si, &pi)) {
        mg_log("UI", "无法启动 Electron (错误码 %lu)", GetLastError());
        mg_log("UI", "electron 路径: %s", g_cfg.electron_exe);
        mg_log("UI", "界面目录: %s", g_cfg.ui_dir);
        return -1;
    }
    mg_log("UI", "Electron 已启动 (pid=%lu)，等待其退出", (unsigned long)pi.dwProcessId);
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    /* 检查退出码：以前这里只看是否启动成功，UI 崩溃时无从察觉（修 P1-18） */
    if (GetExitCodeProcess(pi.hProcess, &code)) {
        mg_log("UI", "Electron 退出，退出码=%lu", (unsigned long)code);
    }
    CloseHandle(pi.hProcess);
    return (int)code;
#else
    mg_log("UI", "非 Windows 平台不负责拉起 Electron，请自行运行 electron");
    return 0;
#endif
}

static MG_THREAD_RET MG_THREAD_CALL stdin_watch_thread(void* arg)
{
    char buf[256];
    (void)arg;
    /* 父进程（Electron）退出后管道关闭 → 读到 EOF → 让本进程也退出 */
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), stdin);
        if (n == 0) break;
    }
    if (!g_stop) {
        mg_log("SUP", "stdin 已关闭（父进程退出），准备退出");
        g_stop = 1;
    }
    return (MG_THREAD_RET)0;
}

/* ==========================================================================
 * 生命周期
 * ========================================================================== */
#ifdef _WIN32
static HANDLE g_instance_mutex = NULL;
static BOOL WINAPI console_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT ||
        type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        g_stop = 1;
        return TRUE;
    }
    return FALSE;
}
#else
static void posix_signal(int s) { (void)s; g_stop = 1; }
#endif

static int instance_acquire(void)
{
#ifdef _WIN32
    g_instance_mutex = CreateMutexA(NULL, FALSE, "Local\\HamsterManager_SingleInstance");
    if (!g_instance_mutex) return -1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    return 1;
#else
    return 1;
#endif
}

static void print_usage(const char* prog)
{
    printf("Hamster Manager ver.%s — Electron 网络层 / 启动器\n\n", MG_VERSION);
    printf("用法: %s [选项]\n\n", prog);
    printf("  （无参数）        启动代理并拉起 Electron（双击行为）\n");
    printf("  --proxy-only      只运行代理，不拉起 Electron（供 Electron 自己 spawn）\n");
    printf("  --follow-stdin    与 --proxy-only 配合：stdin 关闭即退出（父进程监督）\n");
    printf("  --hamd-port=N     hamsterd 端口（默认读配置，缺省 9100）\n");
    printf("  --ipc-port=N      监听端口（默认读配置，缺省 9102）\n");
    printf("  --ui-dir=PATH     Electron 界面目录\n");
    printf("  --electron=PATH   electron.exe 路径\n");
    printf("  --version | --help\n");
    printf("\n配置文件: <程序目录>/hamster_manager.conf\n");
    printf("  hamd_port / ipc_port / hamd_codeword / heartbeat_time\n");
    printf("  口令留空时会自动回退读取 ../Hamsterd/hamsterd.conf 的 codeword\n");
}

int main(int argc, char* argv[])
{
    int i;
    mg_thread th_hamd, th_ipc, th_stdin;
    int th_hamd_ok = 0, th_ipc_ok = 0, th_stdin_ok = 0;
    int rc = 0;

    g_start_ms = mg_now_ms();

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    {
        char exe[MG_PATH_MAX];
        DWORD n = GetModuleFileNameA(NULL, exe, sizeof(exe));
        if (n == 0 || n >= sizeof(exe)) { fprintf(stderr, "无法获取程序路径\n"); return 1; }
        snprintf(g_base_dir, sizeof(g_base_dir), "%s", exe);
        {
            char* sep = strrchr(g_base_dir, '\\');
            if (sep) *sep = '\0';
        }
    }
#else
    {
        char exe[MG_PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (n <= 0) { fprintf(stderr, "无法获取程序路径\n"); return 1; }
        exe[n] = '\0';
        snprintf(g_base_dir, sizeof(g_base_dir), "%s", exe);
        {
            char* sep = strrchr(g_base_dir, '/');
            if (sep) *sep = '\0';
        }
    }
#endif

    /* 默认界面与 electron 路径 */
    snprintf(g_cfg.ui_dir, sizeof(g_cfg.ui_dir),
             "%s/module/hamster_manager_ui", g_base_dir);
    snprintf(g_cfg.electron_exe, sizeof(g_cfg.electron_exe),
             "%s/module/electron/dist/electron.exe", g_base_dir);

    /* 顺序很重要：先读配置文件，再解析命令行。
       反过来的话 load_config() 会用配置无条件盖掉 --hamd-port/--ipc-port，
       命令行参数就成了死参数（实测过）。 */
    load_config();

    for (i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (strcmp(a, "--proxy-only") == 0 || strcmp(a, "--no-ui") == 0) {
            g_cfg.proxy_only = 1;
        } else if (strcmp(a, "--follow-stdin") == 0) {
            g_cfg.follow_stdin = 1;
        } else if (strncmp(a, "--hamd-port=", 12) == 0) {
            int p;
            if (parse_int_range(a + 12, 1, 65535, &p) == 0) g_cfg.hamd_port = p;
            else { fprintf(stderr, "非法 --hamd-port: %s\n", a + 12); return 1; }
        } else if (strncmp(a, "--ipc-port=", 11) == 0) {
            int p;
            if (parse_int_range(a + 11, 1, 65535, &p) == 0) g_cfg.ipc_port = p;
            else { fprintf(stderr, "非法 --ipc-port: %s\n", a + 11); return 1; }
        } else if (strncmp(a, "--ui-dir=", 9) == 0) {
            snprintf(g_cfg.ui_dir, sizeof(g_cfg.ui_dir), "%s", a + 9);
        } else if (strncmp(a, "--electron=", 11) == 0) {
            snprintf(g_cfg.electron_exe, sizeof(g_cfg.electron_exe), "%s", a + 11);
        } else if (strcmp(a, "--version") == 0 || strcmp(a, "-v") == 0) {
            printf("Hamster Manager ver.%s\n", MG_VERSION);
            return 0;
        } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "未知参数: %s\n\n", a);
            print_usage(argv[0]);
            return 1;
        }
    }

#ifdef _WIN32
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "WSAStartup 失败\n");
            return 1;
        }
        SetConsoleCtrlHandler(console_handler, TRUE);
#else
    {
        signal(SIGINT, posix_signal);
        signal(SIGTERM, posix_signal);
#endif
        /* 注意：instance_acquire 成功返回 1，不能复用 rc（rc 同时用于判断"是否启动成功"） */
        int inst = instance_acquire();
        if (inst == 0) {
            mg_log("APP", "已有一个 Hamster Manager 在运行，本次退出");
            return 2;                       /* 2 = 已有实例，便于脚本区分 */
        }
        if (inst < 0) {
            mg_log("APP", "单实例检查失败");
            return 1;
        }
    }

    if (mg_mutex_init(&g_hamd_lk) != 0) { mg_log("APP", "初始化锁失败"); return 1; }
    g_hamd_lk_ok = 1;
    if (mg_mutex_init(&g_clients_lk) != 0) { mg_log("APP", "初始化锁失败"); return 1; }
    g_clients_lk_ok = 1;
    clients_init();

    mg_log("APP", "启动 ver=%s 模式=%s hamd=:%d ipc=:%d",
           MG_VERSION, g_cfg.proxy_only ? "proxy-only" : "launcher",
           g_cfg.hamd_port, g_cfg.ipc_port);

    if (mg_thread_start(&th_hamd, hamd_client_thread, NULL) == 0) th_hamd_ok = 1;
    else { mg_log("APP", "无法启动 hamsterd 客户端线程"); rc = 4; }

    if (mg_thread_start(&th_ipc, ipc_accept_thread, NULL) == 0) th_ipc_ok = 1;
    else { mg_log("APP", "无法启动 IPC 接受线程"); rc = 5; }

    if (g_cfg.follow_stdin && mg_thread_start(&th_stdin, stdin_watch_thread, NULL) == 0) {
        th_stdin_ok = 1;
    }

    if (rc == 0) {
        if (g_cfg.proxy_only) {
            /* 代理模式：等停止信号 */
            mg_log("APP", "代理模式运行中（端口 %d），等待停止", g_cfg.ipc_port);
            while (!g_stop) mg_sleep_ms(200);
        } else {
            /* 启动器模式：拉起 UI 并等它退出 */
            int code = run_electron();
            if (code < 0) rc = 6;
            else if (code != 0) mg_log("APP", "UI 以非零退出码结束: %d", code);
            g_stop = 1;
        }
    } else {
        g_stop = 1;
    }

    /* 收尾：先让线程看到停止标志，再关闭套接字解除阻塞，最后 join */
    g_stop = 1;
    {
        int i2;
        mg_mutex_lock(&g_hamd_lk);
        if (g_hamd_fd != MG_INVALID_SOCK) {
#ifdef _WIN32
            shutdown(g_hamd_fd, SD_BOTH);
#else
            shutdown(g_hamd_fd, SHUT_RDWR);
#endif
        }
        mg_mutex_unlock(&g_hamd_lk);

        mg_mutex_lock(&g_clients_lk);
        for (i2 = 0; i2 < MG_MAX_CLIENTS; i2++) {
            if (g_clients[i2].fd != MG_INVALID_SOCK) {
#ifdef _WIN32
                shutdown(g_clients[i2].fd, SD_BOTH);
#else
                shutdown(g_clients[i2].fd, SHUT_RDWR);
#endif
            }
        }
        mg_mutex_unlock(&g_clients_lk);
    }

    if (th_ipc_ok)    mg_thread_join(&th_ipc);
    if (th_hamd_ok)   mg_thread_join(&th_hamd);
    if (th_stdin_ok)  mg_thread_dispose(&th_stdin);

    {
        int i2;
        mg_mutex_lock(&g_clients_lk);
        for (i2 = 0; i2 < MG_MAX_CLIENTS; i2++) {
            if (g_clients[i2].fd != MG_INVALID_SOCK) {
                mg_close(g_clients[i2].fd);
                g_clients[i2].fd = MG_INVALID_SOCK;
            }
        }
        mg_mutex_unlock(&g_clients_lk);
    }
    clients_destroy();

    if (g_clients_lk_ok) { mg_mutex_destroy(&g_clients_lk); g_clients_lk_ok = 0; }
    if (g_hamd_lk_ok)    { mg_mutex_destroy(&g_hamd_lk);    g_hamd_lk_ok = 0; }

#ifdef _WIN32
    if (g_instance_mutex) { CloseHandle(g_instance_mutex); g_instance_mutex = NULL; }
    WSACleanup();
#endif

    mg_log("APP", "已退出 (rc=%d, 运行 %lldms)", rc, (long long)(mg_now_ms() - g_start_ms));
    return rc;
}
