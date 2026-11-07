/*
 * Hamsterd — Hamster 统一守护进程
 * ver.0.0.8
 *
 * 单一 TCP 端口（默认 :9100）。控制消息是一行一个 JSON 对象；
 * 二进制负载采用"头里声明 payload_bytes + 紧随 N 字节裸数据"的显式分帧。
 *
 * 模块划分：
 *   jsonx.c    严格 JSON 子集工具（替代 strstr 手抠）
 *   hd_util.c  平台适配、日志、路径安全、文件与哈希
 *   hd_db.c    SQLite 索引、查询、校验记录、API 密钥
 *   hd_net.c   协议实现（认证、命令、传输、事件）
 *   hamsterd.c 配置、监控、后台线程、局域网发现、CLI 与生命周期
 *
 * 使用:
 *   hamsterd start            后台启动
 *   hamsterd --console-log    前台启动并把日志打到控制台
 *   hamsterd stop             平滑停止
 *   hamsterd restart          重启
 *   hamsterd status           查看运行状态
 *   hamsterd rotate-codeword  重新生成连接口令并写入配置
 *   hamsterd reset database   重置索引数据库
 *   hamsterd reset config     删除配置文件（下次启动重建默认配置）
 *   hamsterd version | help
 */

#include "hd_util.h"
#include "hd_db.h"
#include "hd_net.h"
#include "hd_disc.h"
#include "jsonx.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <ctype.h>

#ifndef _WIN32
    #include <sys/file.h>
    #include <fcntl.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
#endif

#define HD_VERSION        "0.0.8"
#define HD_INTERNAL_LOG   "hamsterd.log"
#define HD_DEFAULT_PORT   9100
#define HD_EVENT_Q_MAX    20000
#define HD_WATCHDOG_STALL_MS 15000

/* 前向声明 */
static void config_save_codeword(void);
static int  config_load(int allow_generate);

/* ==========================================================================
 * 全局状态
 * ========================================================================== */
static char     g_base_dir[HD_PATH_MAX];
static int      g_console_log = 0;
static int      g_daemon_child = 0;      /* 由父进程以 --daemon-child 拉起，不再自我 spawn */
static int64_t  g_start_ms = 0;

/* 主循环与线程间的请求标志 */
static volatile int g_rescan_req = 0;
static volatile int g_sync_req   = 0;
static volatile int g_full_scan_req = 0;

/* 监控线程心跳：每秒自增，看门狗据此判断线程是否卡死 */
static volatile long g_monitor_tick = 0;

/* 各后台线程句柄，关机时统一 join */
static hd_thread g_th_monitor, g_th_worker, g_th_rescan, g_th_verify, g_th_discovery;
static int       g_th_monitor_ok = 0, g_th_worker_ok = 0, g_th_rescan_ok = 0,
                 g_th_verify_ok = 0, g_th_discovery_ok = 0;

/* 文件夹事件工作队列 */
typedef struct hd_evnode {
    char    action[16];     /* ADDED / REMOVED / MODIFIED / RESCAN */
    char*   path;
    struct hd_evnode* next;
} hd_evnode;

static hd_evnode* g_q_head = NULL;
static hd_evnode* g_q_tail = NULL;
static int        g_q_cnt  = 0;
static hd_mutex   g_q_lk;
static int        g_q_lk_ok = 0;

/* 局域网发现（PROTOCOL §7）：服务端不再保存任何对端信息，只保留本机标识 */
static char     g_instance_id[32];
static char     g_local_name[128];

/* 单实例与停止信号 */
#ifdef _WIN32
static HANDLE g_instance_mutex = NULL;
static HANDLE g_stop_event = NULL;
static BOOL WINAPI console_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT ||
        type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        g_stop = 1;
        if (g_stop_event) SetEvent(g_stop_event);
        return TRUE;
    }
    return FALSE;
}
#else
static int    g_instance_fd = -1;
static void posix_signal_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}
#endif

const char* hd_app_version(void) { return HD_VERSION; }
int hd_app_uptime_sec(void) { return (int)((hd_now_ms() - g_start_ms) / 1000); }

void hd_app_request_rescan(void)
{
    g_rescan_req = 1;
    g_full_scan_req = 1;
    HD_LOGI("APP", "收到重扫请求");
}

void hd_app_request_sync(void)
{
    g_sync_req = 1;
}

/* ==========================================================================
 * 事件工作队列
 * ========================================================================== */
static void ev_enqueue(const char* action, const char* path)
{
    hd_evnode* n;

    if (!action || !path || !path[0]) return;
    if (!g_q_lk_ok) return;

    n = (hd_evnode*)calloc(1, sizeof(hd_evnode));
    if (!n) return;
    snprintf(n->action, sizeof(n->action), "%s", action);
    n->path = strdup(path);
    if (!n->path) { free(n); return; }

    hd_mutex_lock(&g_q_lk);
    if (g_q_cnt >= HD_EVENT_Q_MAX) {
        /* 队列满：丢弃最旧的一条，保证监控线程永不阻塞 */
        hd_evnode* old = g_q_head;
        if (old) {
            g_q_head = old->next;
            if (!g_q_head) g_q_tail = NULL;
            g_q_cnt--;
            free(old->path);
            free(old);
        }
    }
    if (g_q_tail) g_q_tail->next = n; else g_q_head = n;
    g_q_tail = n;
    g_q_cnt++;
    hd_mutex_unlock(&g_q_lk);
}

static hd_evnode* ev_dequeue(void)
{
    hd_evnode* n = NULL;
    if (!g_q_lk_ok) return NULL;
    hd_mutex_lock(&g_q_lk);
    if (g_q_head) {
        n = g_q_head;
        g_q_head = n->next;
        if (!g_q_head) g_q_tail = NULL;
        g_q_cnt--;
        n->next = NULL;
    }
    hd_mutex_unlock(&g_q_lk);
    return n;
}

/* 该路径是否属于自身内部文件（日志/数据库），需要排除，避免自激事件环 */
static int is_internal_path(const char* abs_path)
{
    char log_dir[HD_PATH_MAX + 64];
    const char* base;

    if (!g_cfg.exclude_internal) return 0;

    if (g_cfg.log_dir[0]) snprintf(log_dir, sizeof(log_dir), "%s", g_cfg.log_dir);
    else                  snprintf(log_dir, sizeof(log_dir), "%s", g_base_dir);

    if (hd_path_within(abs_path, log_dir)) return 1;

    base = hd_basename(abs_path);
    if (strncmp(base, "hamster.db", 10) == 0) return 1;      /* hamster.db / -wal / -shm */
    if (strncmp(base, HD_INTERNAL_LOG, strlen(HD_INTERNAL_LOG)) == 0) return 1;
    if (strstr(base, ".part-") != NULL) return 1;   /* 上传中转文件，不该产生事件也不该入库 */
    return 0;
}

/* ==========================================================================
 * 文件索引动作（在工作线程里执行，绝不在监控回调里做）
 * ========================================================================== */
static void do_index_file(const char* abs_path)
{
    hd_file_info info;
    char hash[33];

    if (hd_stat64(abs_path, &info) != 0) return;
    if (info.is_dir) {
        hd_scan_stat st;
        hd_db_scan_all(abs_path, &st);
        return;
    }
    if (hd_hash_file(abs_path, hash) != 0) {
        HD_LOGW("IDX", "哈希失败: %s", abs_path);
        return;
    }
    if (hd_db_upsert_file(abs_path, hash) == 0) {
        HD_LOGD("IDX", "已入库 %s", abs_path);
        hd_net_file_event("file_changed", abs_path);
    }
}

static void do_remove_path(const char* abs_path)
{
    if (hd_db_delete_file(abs_path) == 0) {
        hd_net_file_event("file_removed", abs_path);
    }
    hd_db_delete_dir(abs_path);          /* 目录被删：连带清掉其下记录 */
}

static HD_THREAD_RET HD_THREAD_CALL worker_thread(void* arg)
{
    (void)arg;
    while (!g_stop) {
        hd_evnode* n = ev_dequeue();
        if (!n) { hd_sleep_ms(30); continue; }

        if (strcmp(n->action, "REMOVED") == 0)      do_remove_path(n->path);
        else if (strcmp(n->action, "RESCAN") == 0)  g_full_scan_req = 1;
        else                                        do_index_file(n->path);

        free(n->path);
        free(n);
    }
    return (HD_THREAD_RET)0;
}

/* ==========================================================================
 * 目录监控 — Windows（ReadDirectoryChangesW + APC）
 * ========================================================================== */
#ifdef _WIN32
typedef struct {
    OVERLAPPED ov;
    HANDLE     hDir;
    DWORD      bytes;                 /* 供重叠 I/O 写回，必须活到完成 */
    char       buffer[HD_CHUNK];
    char       root[HD_PATH_MAX];
} hd_monitor;

static void CALLBACK dir_change_cb(DWORD err, DWORD bytes, OVERLAPPED* ov)
{
    hd_monitor* m = (hd_monitor*)((char*)ov - offsetof(hd_monitor, ov));
    FILE_NOTIFY_INFORMATION* p;
    DWORD offset = 0;

    InterlockedIncrement(&g_monitor_tick);

    if (err == ERROR_NOTIFY_ENUM_DIR) {
        HD_LOGW("MON", "变更缓冲区溢出，安排全量重扫");
        g_full_scan_req = 1;
        goto rearm;
    }
    if (err != ERROR_SUCCESS || bytes == 0) goto rearm;

    /* 严格按 bytes 边界遍历，并校验每条记录的自洽性（修 P1-16） */
    p = (FILE_NOTIFY_INFORMATION*)m->buffer;
    while (offset < bytes) {
        char name[1024];
        char full[HD_PATH_MAX];
        const char* action = NULL;
        int conv;

        if (offset + sizeof(DWORD) * 3 > bytes) break;                    /* 头都不完整 */
        if (p->FileNameLength == 0 || p->FileNameLength > 4096) break;
        if (offset + offsetof(FILE_NOTIFY_INFORMATION, FileName) + p->FileNameLength > bytes) break;

        conv = WideCharToMultiByte(CP_UTF8, 0, p->FileName, (int)(p->FileNameLength / sizeof(WCHAR)),
                                   name, sizeof(name) - 1, NULL, NULL);
        if (conv <= 0) break;
        name[conv] = '\0';

        hd_path_join(full, sizeof(full), m->root, name);

        switch (p->Action) {
            case FILE_ACTION_ADDED:            action = "ADDED";    break;
            case FILE_ACTION_REMOVED:          action = "REMOVED";  break;
            case FILE_ACTION_MODIFIED:         action = "MODIFIED"; break;
            case FILE_ACTION_RENAMED_NEW_NAME: action = "ADDED";    break;
            case FILE_ACTION_RENAMED_OLD_NAME: action = "REMOVED";  break;
            default: break;
        }
        if (action && !is_internal_path(full)) ev_enqueue(action, full);

        if (p->NextEntryOffset == 0) break;
        offset += p->NextEntryOffset;
        p = (FILE_NOTIFY_INFORMATION*)((char*)p + p->NextEntryOffset);
    }

rearm:
    /* 立刻重新挂起请求，目录变更由工作线程处理，回调保持极短 */
    if (!g_stop && m->hDir != INVALID_HANDLE_VALUE) {
        if (!ReadDirectoryChangesW(m->hDir, m->buffer, sizeof(m->buffer), TRUE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                   FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                                   &m->bytes, &m->ov, dir_change_cb)) {
            HD_LOGW("MON", "重新挂起监控失败 err=%lu", GetLastError());
        }
    }
}

static HD_THREAD_RET HD_THREAD_CALL monitor_thread(void* arg)
{
    hd_monitor* m = (hd_monitor*)calloc(1, sizeof(hd_monitor));
    if (!m) return (HD_THREAD_RET)1;

    snprintf(m->root, sizeof(m->root), "%s", g_cfg.monitor_path);

    /* 转宽字符后打开，支持中文路径 */
    {
        wchar_t wroot[HD_PATH_MAX];
        if (MultiByteToWideChar(CP_UTF8, 0, m->root, -1, wroot, HD_PATH_MAX) <= 0) {
            HD_LOGE("MON", "路径转宽字符失败: %s", m->root);
            free(m);
            return (HD_THREAD_RET)1;
        }
        m->hDir = CreateFileW(wroot, FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    }
    if (m->hDir == INVALID_HANDLE_VALUE) {
        HD_LOGE("MON", "无法打开监控目录: %s (err=%lu)", m->root, GetLastError());
        free(m);
        return (HD_THREAD_RET)1;
    }

    if (!ReadDirectoryChangesW(m->hDir, m->buffer, sizeof(m->buffer), TRUE,
                               FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                               FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                               &m->bytes, &m->ov, dir_change_cb)) {
        HD_LOGE("MON", "挂起监控失败 err=%lu", GetLastError());
        CloseHandle(m->hDir);
        free(m);
        return (HD_THREAD_RET)1;
    }
    HD_LOGI("MON", "已开始监控: %s", m->root);

    /* 每秒跳一次心跳，保证看门狗判断的是"线程活着"而不是"目录有变化" */
    while (!g_stop) {
        DWORD w = WaitForSingleObjectEx(g_stop_event, 1000, TRUE);   /* TRUE=可被 APC 唤醒 */
        if (w == WAIT_OBJECT_0) break;
        g_monitor_tick++;
    }

    /* 取消并等待重叠 I/O 真正完成后再释放对象（修 P1-17） */
    CancelIoEx(m->hDir, &m->ov);
    {
        int i;
        for (i = 0; i < 500; i++) {
            if (HasOverlappedIoCompleted(&m->ov)) break;
            hd_sleep_ms(10);
        }
        if (i >= 500) HD_LOGW("MON", "重叠 I/O 未在 5 秒内结束");
    }
    CloseHandle(m->hDir);
    free(m);
    HD_LOGI("MON", "监控线程已退出");
    return (HD_THREAD_RET)0;
}

#else   /* ============================ Linux / inotify ============================ */

#include <sys/inotify.h>
#include <poll.h>
#include <dirent.h>

#define INOTIFY_MASK (IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_CLOSE_WRITE)

static int inotify_add_recursive(int ino, const char* path)
{
    DIR* d;
    struct dirent* e;
    int added = 0;

    inotify_add_watch(ino, path, INOTIFY_MASK);
    d = opendir(path);
    if (!d) return 0;
    while ((e = readdir(d)) != NULL) {
        char full[HD_PATH_MAX];
        hd_file_info info;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        hd_path_join(full, sizeof(full), path, e->d_name);
        if (hd_stat64(full, &info) != 0 || !info.is_dir) continue;
        if (is_internal_path(full)) continue;
        added += inotify_add_recursive(ino, full);
    }
    closedir(d);
    return added;
}

static HD_THREAD_RET HD_THREAD_CALL monitor_thread(void* arg)
{
    int ino;
    int wd_root;
    char buf[64 * 1024] __attribute__((aligned(8)));

    (void)arg;
    ino = inotify_init1(IN_NONBLOCK);
    if (ino < 0) {
        HD_LOGE("MON", "inotify_init1 失败: %s", strerror(errno));
        return (HD_THREAD_RET)1;
    }
    wd_root = inotify_add_watch(ino, g_cfg.monitor_path, INOTIFY_MASK);
    if (wd_root < 0) {
        HD_LOGE("MON", "无法监控 %s: %s", g_cfg.monitor_path, strerror(errno));
        close(ino);
        return (HD_THREAD_RET)1;
    }
    inotify_add_recursive(ino, g_cfg.monitor_path);
    HD_LOGI("MON", "已开始监控(inotify): %s", g_cfg.monitor_path);

    while (!g_stop) {
        struct pollfd pfd;
        int pr;

        pfd.fd = ino;
        pfd.events = POLLIN;
        pr = poll(&pfd, 1, 1000);
        g_monitor_tick++;
        if (pr <= 0) continue;

        for (;;) {
            ssize_t n = read(ino, buf, sizeof(buf));
            ssize_t off = 0;
            if (n <= 0) break;
            while (off < n) {
                struct inotify_event* ev = (struct inotify_event*)(buf + off);
                char full[HD_PATH_MAX];
                const char* action = NULL;

                if (ev->len > 0) {
                    /* inotify 只给名字，这里用 wd→路径需要额外维护；简化处理：
                       在根目录与子目录都用 fd 遍历一次成本高，因此依靠 ev->wd 对应关系
                       由 root 前缀 + 名字近似定位，仅用于事件通知（不用于入库路径）。 */
                    hd_path_join(full, sizeof(full), g_cfg.monitor_path, ev->name);
                } else {
                    full[0] = '\0';
                }

                if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
                    action = "ADDED";
                    if (ev->mask & IN_ISDIR) inotify_add_recursive(ino, full);
                } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                    action = "REMOVED";
                } else {
                    action = "MODIFIED";
                }

                if (action && full[0] && !is_internal_path(full)) ev_enqueue(action, full);
                off += sizeof(struct inotify_event) + ev->len;
            }
        }
    }

    close(ino);
    HD_LOGI("MON", "监控线程已退出");
    return (HD_THREAD_RET)0;
}
#endif

/* ==========================================================================
 * 重扫线程 / 校验线程 / 看门狗
 * ========================================================================== */
static void do_full_scan(const char* reason)
{
    hd_scan_stat st;
    int64_t t0 = hd_now_ms();

    HD_LOGI("SCAN", "开始全量扫描（%s）", reason ? reason : "手动");
    hd_db_scan_all(g_cfg.monitor_path, &st);
    HD_LOGI("SCAN", "全量扫描结束: 访问=%d 入库=%d 失败=%d 耗时=%lldms",
            st.visited, st.indexed, st.failed, (long long)(hd_now_ms() - t0));

    {
        int total = 0, ok = 0, corrupt = 0, missing = 0;
        hd_db_integrity_check(&total, &ok, &corrupt, &missing, g_cfg.prune_missing);
        hd_db_record_verify(total, ok, corrupt, missing, g_cfg.verify_interval);
    }
    hd_net_broadcast("scan_done", "{\"reason\":\"full_scan\"}");
}

static HD_THREAD_RET HD_THREAD_CALL rescan_thread(void* arg)
{
    int64_t interval_ms;
    int64_t last = hd_now_ms();

    (void)arg;
    if (!g_cfg.rescan_enabled) {
        HD_LOGI("RESCAN", "定期重扫已禁用");
        while (!g_stop) {
            hd_wait_ms(500);
            if (g_full_scan_req) { g_full_scan_req = 0; do_full_scan("请求触发"); last = hd_now_ms(); }
        }
        return (HD_THREAD_RET)0;
    }

    interval_ms = ((int64_t)g_cfg.rescan_day * 24 * 60 + g_cfg.rescan_hour * 60 + g_cfg.rescan_minute) * 60 * 1000;
    if (interval_ms <= 0) interval_ms = 3600 * 1000;

    while (!g_stop) {
        hd_wait_ms(500);
        if (g_stop) break;

        if (g_full_scan_req) {
            g_full_scan_req = 0;
            do_full_scan("请求触发");
            last = hd_now_ms();
            continue;
        }
        if (hd_now_ms() - last >= interval_ms) {
            do_full_scan("定时触发");
            last = hd_now_ms();
        }
    }
    return (HD_THREAD_RET)0;
}

static HD_THREAD_RET HD_THREAD_CALL verify_thread(void* arg)
{
    int64_t interval_ms;
    int64_t elapsed = 0;

    (void)arg;
    if (!g_cfg.verify_enabled) {
        HD_LOGI("VERIFY", "定期完整性校验已禁用");
        return (HD_THREAD_RET)0;
    }

    interval_ms = (int64_t)g_cfg.verify_interval * 60 * 1000;   /* 用 64 位算，避免 int 溢出 */
    HD_LOGI("VERIFY", "定期完整性校验间隔 %d 分钟", g_cfg.verify_interval);

    while (!g_stop) {
        /* 按 1 小时分片等待，保证停止请求能及时响应 */
        if (hd_wait_ms(3600000)) break;
        elapsed += 3600000;

        if (elapsed >= interval_ms) {
            int total = 0, ok = 0, corrupt = 0, missing = 0;
            elapsed = 0;
            HD_LOGI("VERIFY", "开始定期完整性校验");
            hd_db_integrity_check(&total, &ok, &corrupt, &missing, g_cfg.prune_missing);
            hd_db_record_verify(total, ok, corrupt, missing, g_cfg.verify_interval);
            {
                char data[256];
                snprintf(data, sizeof(data),
                         "{\"total\":%d,\"ok\":%d,\"corrupt\":%d,\"missing\":%d,\"reason\":\"scheduled\"}",
                         total, ok, corrupt, missing);
                hd_net_broadcast("verify_done", data);
            }
        }
    }
    return (HD_THREAD_RET)0;
}

/* ==========================================================================
 * 局域网发现（PROTOCOL §7）
 *
 * 0.0.8 起发现反过来做：客户端广播探测、服务端**只在暗号对上时**单播应答，
 * 对不上一个字节都不回。服务端因此不再维护 peer 表，也没有东西可广播。
 * 具体实现在 hd_disc.c；这里只保留两个给 hd_net.c 用的兼容桩。
 * ========================================================================== */
int hd_app_peer_count(void)
{
    return 0;               /* 恒为 0：发现结果只在客户端侧存在 */
}

void hd_app_peers_json(hd_sb* sb)
{
    (void)sb;               /* 恒为空数组，保留字段仅为协议兼容 */
}

/* ==========================================================================
 * 配置
 * ========================================================================== */
static void config_defaults(void)
{
    memset(&g_cfg, 0, sizeof(g_cfg));
    snprintf(g_cfg.monitor_path, sizeof(g_cfg.monitor_path), "%s", g_base_dir);
    snprintf(g_cfg.host, sizeof(g_cfg.host), "127.0.0.1");   /* 默认只监听本机 */
    g_cfg.port = HD_DEFAULT_PORT;
    g_cfg.rescan_day = 0; g_cfg.rescan_hour = 0; g_cfg.rescan_minute = 30;
    g_cfg.rescan_enabled = 1;
    g_cfg.heartbeat_time = 3;
    g_cfg.verify_interval = 4320;
    g_cfg.verify_enabled = 1;
    g_cfg.discovery_port = 9110;
    g_cfg.discovery_respond = 1;
    g_cfg.codeword[0] = '\0';
    g_cfg.require_auth = 1;
    g_cfg.allow_loopback_noauth = 0;
    g_cfg.max_clients = 16;
    g_cfg.max_transfer_mb = 8192;
    g_cfg.prune_missing = 0;
    g_cfg.log_level = HD_LOG_INFO;
    snprintf(g_cfg.log_dir, sizeof(g_cfg.log_dir), "%s/logs", g_base_dir);
    g_cfg.exclude_internal = 1;
}

static const char* config_path(void)
{
    static char p[HD_PATH_MAX + 64];
    snprintf(p, sizeof(p), "%s/hamsterd.conf", g_base_dir);
    return p;
}

static void config_write_template(void)
{
    FILE* fp = hd_fopen(config_path(), "wb");
    if (!fp) {
        HD_LOGW("CFG", "无法写入配置模板: %s", config_path());
        return;
    }
    fprintf(fp,
        "# Hamsterd 配置（本文件由 hamsterd 在首次启动时生成）\n"
        "# 格式: key: value\n"
        "############################################################\n"
        "# 监控目录（必填，可写相对路径，相对于 hamsterd.exe 所在目录）\n"
        "monitor_path: %s\n"
        "\n"
        "# 监听地址。默认 127.0.0.1 仅本机可连；\n"
        "# 改成 0.0.0.0 会暴露到局域网，务必同时设置强口令。\n"
        "ipv4_addr: %s\n"
        "ipv4_addr_port: %d\n"
        "\n"
        "# 连接口令：hello 时必须携带。留空会在下次启动时自动生成强随机口令。\n"
        "codeword: %s\n"
        "\n"
        "############################################################\n"
        "# 安全\n"
        "# 是否要求所有数据命令（搜索/下载/上传/删除等）都必须先通过 hello 认证\n"
        "require_auth: %s\n"
        "# 是否允许来自本机回环地址的连接免认证（默认 off，仅调试用）\n"
        "allow_loopback_noauth: %s\n"
        "# 单次上传/下载大小上限（MB）\n"
        "max_transfer_mb: %d\n"
        "# 同时连接数上限\n"
        "max_clients: %d\n"
        "\n"
        "############################################################\n"
        "# 扫描与校验\n"
        "# 定时全量重扫 (天,小时,分钟)，0,0,0 = 禁用\n"
        "rescan_date: %d,%d,%d\n"
        "# 完整性校验周期（分钟，0=禁用）\n"
        "verify_interval: %d\n"
        "# 校验时是否删除索引里已不存在的文件记录（off=只统计不删除）\n"
        "prune_missing: %s\n"
        "\n"
        "############################################################\n"
        "# 局域网发现（PROTOCOL §7：客户端广播探测，本服务只在暗号对上时回应）\n"
        "# UDP 发现端口（0=禁用）。同机多实例请各用不同端口\n"
        "discovery_port: %d\n"
        "# 是否回应探测（off=收得到但不回应，效果等同于对无口令者隐身）\n"
        "discovery_respond: %s\n"
        "# 心跳间隔（秒）\n"
        "heartbeat_time: %d\n"
        "\n"
        "############################################################\n"
        "# 日志\n"
        "# 级别: error | warn | info | debug\n"
        "log_level: info\n"
        "# 日志目录（默认在程序目录下的 logs/，该目录不会被自身监控）\n"
        "log_dir: logs\n"
        "# 是否排除自身日志与数据库（强烈建议 on，否则会造成事件自激）\n"
        "exclude_internal: on\n",
        g_cfg.monitor_path, g_cfg.host, g_cfg.port, g_cfg.codeword,
        g_cfg.require_auth ? "on" : "off",
        g_cfg.allow_loopback_noauth ? "on" : "off",
        g_cfg.max_transfer_mb, g_cfg.max_clients,
        g_cfg.rescan_day, g_cfg.rescan_hour, g_cfg.rescan_minute,
        g_cfg.verify_interval, g_cfg.prune_missing ? "on" : "off",
        g_cfg.discovery_port, g_cfg.discovery_respond ? "on" : "off",
        g_cfg.heartbeat_time);
    fclose(fp);
    HD_LOGI("CFG", "已生成配置模板: %s", config_path());
}

static int parse_bool(const char* v)
{
    if (!v) return 0;
    if (strcmp(v, "on") == 0 || strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0) return 1;
    if (strcmp(v, "off") == 0 || strcmp(v, "false") == 0 || strcmp(v, "0") == 0 || strcmp(v, "no") == 0) return 0;
    return atoi(v) != 0;
}

static int parse_int_range(const char* v, int lo, int hi, int* out)
{
    char* stop = NULL;
    long n = strtol(v, &stop, 10);
    if (stop == v || (stop && *stop != '\0')) return -1;
    if (n < lo || n > hi) return -1;
    *out = (int)n;
    return 0;
}

static int config_load(int allow_generate)
{
    FILE* fp;
    char line[1024];

    fp = hd_fopen(config_path(), "rb");
    if (!fp) {
        HD_LOGW("CFG", "未找到配置文件，使用默认值并生成模板: %s", config_path());
        if (allow_generate) {
            if (!g_cfg.codeword[0]) hd_generate_codeword(g_cfg.codeword, sizeof(g_cfg.codeword));
            config_write_template();
        }
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        char key[128] = "", val[768] = "";
        char* p;
        char* hash;

        for (p = line; *p == ' ' || *p == '\t'; p++) {}
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;

        hash = strchr(p, '#');
        if (hash && hash > p && hash[-1] == ' ') *hash = '\0';

        if (sscanf(p, "%127[^:]: %767[^\r\n]", key, val) != 2) continue;
        {
            size_t vl = strlen(val);
            while (vl > 0 && (val[vl - 1] == ' ' || val[vl - 1] == '\t')) val[--vl] = '\0';
        }

        if (strcmp(key, "monitor_path") == 0) {
            snprintf(g_cfg.monitor_path, sizeof(g_cfg.monitor_path), "%s", val);
        } else if (strcmp(key, "ipv4_addr") == 0) {
            snprintf(g_cfg.host, sizeof(g_cfg.host), "%s", val);
        } else if (strcmp(key, "ipv4_addr_port") == 0) {
            if (parse_int_range(val, 1, 65535, &g_cfg.port) != 0) {
                HD_LOGW("CFG", "ipv4_addr_port 非法(%s)，沿用 %d", val, g_cfg.port);
            }
        } else if (strcmp(key, "codeword") == 0) {
            snprintf(g_cfg.codeword, sizeof(g_cfg.codeword), "%s", val);
        } else if (strcmp(key, "require_auth") == 0) {
            g_cfg.require_auth = parse_bool(val);
        } else if (strcmp(key, "allow_loopback_noauth") == 0) {
            g_cfg.allow_loopback_noauth = parse_bool(val);
        } else if (strcmp(key, "max_transfer_mb") == 0) {
            if (parse_int_range(val, 1, 1024 * 1024, &g_cfg.max_transfer_mb) != 0) g_cfg.max_transfer_mb = 8192;
        } else if (strcmp(key, "max_clients") == 0) {
            if (parse_int_range(val, 1, 64, &g_cfg.max_clients) != 0) g_cfg.max_clients = 16;
        } else if (strcmp(key, "rescan_date") == 0) {
            int d = 0, h = 0, m = 0;
            if (sscanf(val, "%d,%d,%d", &d, &h, &m) == 3) {
                g_cfg.rescan_day = d; g_cfg.rescan_hour = h; g_cfg.rescan_minute = m;
                g_cfg.rescan_enabled = (d > 0 || h > 0 || m > 0) ? 1 : 0;
            }
        } else if (strcmp(key, "verify_interval") == 0) {
            int v = 0;
            if (parse_int_range(val, 0, 1000000, &v) == 0) {
                g_cfg.verify_interval = v;
                g_cfg.verify_enabled = (v > 0) ? 1 : 0;
            }
        } else if (strcmp(key, "prune_missing") == 0) {
            g_cfg.prune_missing = parse_bool(val);
        } else if (strcmp(key, "discovery_port") == 0) {
            if (parse_int_range(val, 0, 65535, &g_cfg.discovery_port) != 0) g_cfg.discovery_port = 9110;
        } else if (strcmp(key, "heartbeat_time") == 0) {
            if (parse_int_range(val, 1, 3600, &g_cfg.heartbeat_time) != 0) g_cfg.heartbeat_time = 3;
        } else if (strcmp(key, "discovery_respond") == 0) {
            g_cfg.discovery_respond = parse_bool(val);
        } else if (strcmp(key, "log_level") == 0) {
            if (strcmp(val, "error") == 0) g_cfg.log_level = HD_LOG_ERROR;
            else if (strcmp(val, "warn") == 0) g_cfg.log_level = HD_LOG_WARN;
            else if (strcmp(val, "debug") == 0) g_cfg.log_level = HD_LOG_DEBUG;
            else g_cfg.log_level = HD_LOG_INFO;
        } else if (strcmp(key, "log_dir") == 0) {
            if (val[0]) {
                char abs[HD_PATH_MAX];
                if (val[0] == '/' || val[0] == '\\' ||
                    (val[1] == ':' && isalpha((unsigned char)val[0]))) {
                    if (hd_path_abs(val, abs, sizeof(abs)) == 0) snprintf(g_cfg.log_dir, sizeof(g_cfg.log_dir), "%s", abs);
                } else {
                    char joined[HD_PATH_MAX];
                    hd_path_join(joined, sizeof(joined), g_base_dir, val);
                    if (hd_path_abs(joined, abs, sizeof(abs)) == 0) snprintf(g_cfg.log_dir, sizeof(g_cfg.log_dir), "%s", abs);
                }
            }
        } else if (strcmp(key, "exclude_internal") == 0) {
            g_cfg.exclude_internal = parse_bool(val);
        } else {
            HD_LOGW("CFG", "未知配置项: %s", key);
        }
    }
    fclose(fp);

    /* 口令留空则生成强随机口令并回写，不再使用可预测的 rand()（修 P0-2） */
    if (!g_cfg.codeword[0] && allow_generate) {
        hd_generate_codeword(g_cfg.codeword, sizeof(g_cfg.codeword));
        HD_LOGW("CFG", "配置中未设置口令，已自动生成并写回配置");
        config_save_codeword();
    }
    return 0;
}

static void config_save_codeword(void)
{
    char tmp[HD_PATH_MAX + 128];
    char line[1024];
    FILE* in;
    FILE* out;
    int replaced = 0;

    snprintf(tmp, sizeof(tmp), "%s.tmp", config_path());

    in = hd_fopen(config_path(), "rb");
    out = hd_fopen(tmp, "wb");
    if (!out) { if (in) fclose(in); return; }

    if (in) {
        while (fgets(line, sizeof(line), in)) {
            char key[128] = "";
            if (sscanf(line, "%127[^:]:", key) == 1 && strcmp(key, "codeword") == 0) {
                fprintf(out, "codeword: %s\n", g_cfg.codeword);
                replaced = 1;
            } else {
                fputs(line, out);
            }
        }
        fclose(in);
    }
    if (!replaced) fprintf(out, "\ncodeword: %s\n", g_cfg.codeword);
    fclose(out);

    /* 原子替换，避免写一半损坏配置（修 P1 类问题） */
    if (hd_rename(tmp, config_path()) != 0) {
        HD_LOGW("CFG", "配置回写失败: %s", config_path());
        hd_remove_file(tmp);
    }
}

/* ==========================================================================
 * CLI：单实例与停止信号
 * ========================================================================== */
static int instance_acquire(void)
{
#ifdef _WIN32
    g_instance_mutex = CreateMutexA(NULL, FALSE, "Local\\Hamsterd_SingleInstance");
    if (!g_instance_mutex) return -1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    return 1;
#else
    char path[HD_PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/hamsterd.pid", g_base_dir);
    g_instance_fd = open(path, O_CREAT | O_RDWR, 0644);
    if (g_instance_fd < 0) return -1;
    if (flock(g_instance_fd, LOCK_EX | LOCK_NB) != 0) { close(g_instance_fd); g_instance_fd = -1; return 0; }
    ftruncate(g_instance_fd, 0);
    {
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
        if (write(g_instance_fd, buf, (size_t)n) != n) { /* 忽略 */ }
    }
    return 1;
#endif
}

static int instance_is_running(void)
{
#ifdef _WIN32
    HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, "Local\\Hamsterd_SingleInstance");
    if (h) { CloseHandle(h); return 1; }
    return 0;
#else
    char path[HD_PATH_MAX + 32];
    int fd;
    snprintf(path, sizeof(path), "%s/hamsterd.pid", g_base_dir);
    fd = open(path, O_RDWR, 0644);
    if (fd < 0) return 0;
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        flock(fd, LOCK_UN);
        close(fd);
        return 0;                      /* 能拿到锁说明没人在跑 */
    }
    close(fd);
    return 1;
#endif
}

static int cmd_stop(void)
{
#ifdef _WIN32
    HANDLE h = OpenEventA(EVENT_MODIFY_STATE, FALSE, "Local\\Hamsterd_Stop");
    if (!h) {
        printf("Hamsterd 未在运行（找不到停止事件）\n");
        return 1;
    }
    SetEvent(h);
    CloseHandle(h);
    printf("已发送停止信号\n");
#else
    char path[HD_PATH_MAX + 32];
    FILE* fp;
    int pid = 0;
    snprintf(path, sizeof(path), "%s/hamsterd.pid", g_base_dir);
    fp = fopen(path, "r");
    if (!fp || fscanf(fp, "%d", &pid) != 1 || pid <= 0) {
        if (fp) fclose(fp);
        printf("Hamsterd 未在运行（读不到 pid）\n");
        return 1;
    }
    fclose(fp);
    if (kill(pid, SIGTERM) != 0) { printf("发送 SIGTERM 失败\n"); return 1; }
    printf("已向 pid %d 发送停止信号\n", pid);
#endif
    return 0;
}

/* ==========================================================================
 * 运行
 * ========================================================================== */
static void join_workers(void)
{
    if (g_th_worker_ok)    { hd_thread_join(&g_th_worker);    g_th_worker_ok = 0; }
    if (g_th_monitor_ok)   { hd_thread_join(&g_th_monitor);   g_th_monitor_ok = 0; }
    if (g_th_rescan_ok)    { hd_thread_join(&g_th_rescan);    g_th_rescan_ok = 0; }
    if (g_th_verify_ok)    { hd_thread_join(&g_th_verify);    g_th_verify_ok = 0; }
    if (g_th_discovery_ok) { hd_thread_join(&g_th_discovery); g_th_discovery_ok = 0; }
}

static void shutdown_all(void)
{
    HD_LOGI("APP", "开始关闭流程");

    g_stop = 1;                      /* 先让所有循环退出 */
    hd_net_stop();                   /* 停监听并等待连接线程退出 */

    /* 唤醒可能还在等待的监控线程 */
#ifdef _WIN32
    if (g_stop_event) SetEvent(g_stop_event);
#endif

    join_workers();
    HD_LOGI("APP", "所有线程已退出");

    hd_db_checkpoint();
    hd_db_close();

    if (g_q_lk_ok)   { hd_mutex_destroy(&g_q_lk);    g_q_lk_ok = 0; }

#ifdef _WIN32
    if (g_instance_mutex) { CloseHandle(g_instance_mutex); g_instance_mutex = NULL; }
    if (g_stop_event)     { CloseHandle(g_stop_event);     g_stop_event = NULL; }
#endif

    HD_LOGI("APP", "Hamsterd 已停止");
    hd_log_shutdown();
}

static int run_daemon(void)
{
    char db_path[HD_PATH_MAX + 64];
    char log_path[HD_PATH_MAX + 128];
    char monitor_abs[HD_PATH_MAX];
    int rc;
    int64_t last_tick = 0;
    int64_t last_watchdog = 0;

    /* 1) 单实例（句柄保持到进程结束，修 P1-3） */
    rc = instance_acquire();
    if (rc == 0) { printf("Hamsterd 已在运行\n"); return 0; }
    if (rc < 0)  { fprintf(stderr, "单实例检查失败\n"); return 1; }

    g_start_ms = hd_now_ms();

    /* 2) 建立日志（先于其它子系统，保证早期错误可见） */
    hd_mkdirs(g_cfg.log_dir);
    snprintf(log_path, sizeof(log_path), "%s/%s", g_cfg.log_dir, HD_INTERNAL_LOG);
    hd_log_init(log_path, g_console_log || 1, g_cfg.log_level);

    /* 3) 网络子系统初始化：必须在任何网络线程之前（修 P1：WSAStartup 竞态） */
#ifdef _WIN32
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "WSAStartup 失败\n");
            return 1;
        }
    }
#endif

    /* 4) 规范化监控目录并校验存在性 */
    if (hd_path_abs(g_cfg.monitor_path, monitor_abs, sizeof(monitor_abs)) != 0) {
        HD_LOGE("APP", "监控路径非法: %s", g_cfg.monitor_path);
        return 1;
    }
    snprintf(g_cfg.monitor_path, sizeof(g_cfg.monitor_path), "%s", monitor_abs);
    {
        hd_file_info mi;
        if (hd_stat64(g_cfg.monitor_path, &mi) != 0 || !mi.is_dir) {
            HD_LOGE("APP", "监控目录不存在或不是目录: %s", g_cfg.monitor_path);
            fprintf(stderr, "监控目录不存在或不是目录: %s\n请修改 %s 中的 monitor_path\n",
                    g_cfg.monitor_path, config_path());
            return 1;
        }
    }

    /* 5) 打开数据库 */
    snprintf(db_path, sizeof(db_path), "%s/hamster.db", g_base_dir);
    if (hd_db_open(db_path) != 0) {
        HD_LOGE("APP", "数据库打开失败: %s", db_path);
        return 1;
    }
    hd_db_set_scan_interval(g_cfg.rescan_enabled
        ? g_cfg.rescan_day * 24 * 60 + g_cfg.rescan_hour * 60 + g_cfg.rescan_minute
        : 0);

    /* 6) 队列与互斥 */
    if (hd_mutex_init(&g_q_lk) == 0) g_q_lk_ok = 1;

#ifdef _WIN32
    g_stop_event = CreateEventA(NULL, TRUE, FALSE, "Local\\Hamsterd_Stop");
    if (!g_stop_event) { HD_LOGE("APP", "创建停止事件失败"); return 1; }
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, posix_signal_handler);
    signal(SIGTERM, posix_signal_handler);
#endif

    /* 7) 实例标识与主机名 */
    {
        unsigned char rnd[8];
        hd_random_bytes(rnd, sizeof(rnd));
        snprintf(g_instance_id, sizeof(g_instance_id), "%02x%02x%02x%02x%02x%02x%02x%02x",
                 rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7]);
        if (gethostname(g_local_name, sizeof(g_local_name)) != 0)
            snprintf(g_local_name, sizeof(g_local_name), "hamster");
    }

    /* 8) 启动横幅 */
    printf("\n========== Hamsterd ver.%s ==========\n", HD_VERSION);
    printf("  监控目录: %s\n", g_cfg.monitor_path);
    printf("  监听地址: %s:%d（认证: %s）\n", g_cfg.host, g_cfg.port,
           g_cfg.require_auth ? "必需" : "已关闭");
    printf("  定时重扫: %s\n", g_cfg.rescan_enabled ? "启用" : "禁用");
    printf("  完整性校验: %s\n", g_cfg.verify_enabled ? "启用" : "禁用");
    printf("  数据库: %s\n", db_path);
    printf("  日志: %s\n", log_path);
    printf("  局域网发现: UDP %d（应答=%s）\n", g_cfg.discovery_port,
           g_cfg.discovery_respond ? "开" : "关");
    printf("=====================================\n");
    if (g_cfg.host[0] == '0' && !g_cfg.require_auth)
        printf("  ⚠ 警告: 正在监听所有网卡且未启用认证，任何可达主机都能读取文件！\n");
    fflush(stdout);

    HD_LOGI("APP", "启动 ver=%s monitor=%s listen=%s:%d auth=%d",
            HD_VERSION, g_cfg.monitor_path, g_cfg.host, g_cfg.port, g_cfg.require_auth);

    /* 9) 首次全量扫描 */
    do_full_scan("首次启动");

    /* 10) 启动工作线程 */
    if (hd_thread_start(&g_th_worker, worker_thread, NULL) == 0) g_th_worker_ok = 1;
    else HD_LOGE("APP", "无法启动事件工作线程");

    if (hd_thread_start(&g_th_monitor, monitor_thread, NULL) == 0) g_th_monitor_ok = 1;
    else HD_LOGE("APP", "无法启动监控线程");

    if (hd_thread_start(&g_th_rescan, rescan_thread, NULL) == 0) g_th_rescan_ok = 1;
    if (hd_thread_start(&g_th_verify, verify_thread, NULL) == 0) g_th_verify_ok = 1;
    {
        hd_disc_cfg dcfg;
        memset(&dcfg, 0, sizeof(dcfg));
        dcfg.port        = g_cfg.discovery_port;
        dcfg.respond     = g_cfg.discovery_respond;
        dcfg.codeword    = g_cfg.codeword;
        dcfg.instance_id = g_instance_id;
        dcfg.local_name  = g_local_name;
        dcfg.tcp_port    = g_cfg.port;
        dcfg.version     = HD_VERSION;
        if (hd_disc_start(&g_th_discovery, &dcfg) == 0) g_th_discovery_ok = 1;
        else HD_LOGW("APP", "发现线程未能启动，局域网发现不可用");
    }

    /* 11) 启动网络服务 */
    if (hd_net_start(g_cfg.host, g_cfg.port, g_cfg.max_clients) != 0) {
        HD_LOGE("APP", "网络服务启动失败，进程退出");
        shutdown_all();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    HD_LOGI("APP", "就绪");

    /* 12) 主循环：处理重扫/同步请求，兼作看门狗 */
    while (!g_stop) {
#ifdef _WIN32
        DWORD w = WaitForSingleObject(g_stop_event, 500);
        if (w == WAIT_OBJECT_0) break;
#else
        hd_sleep_ms(500);
#endif
        if (g_stop) break;

        if (g_sync_req) {
            g_sync_req = 0;
            hd_db_checkpoint();
            HD_LOGI("APP", "已按请求同步数据库");
        }

        /* 看门狗：心跳长时间不跳＝监控线程真的卡住（修 P1-19）。
           注意判据是"心跳计数不变"，而不是"目录没有变化"。 */
        {
            long tick = g_monitor_tick;
            int64_t now = hd_now_ms();
            if (tick != last_tick) {
                last_tick = tick;
                last_watchdog = now;
            } else if (last_watchdog == 0) {
                last_watchdog = now;
            } else if (now - last_watchdog > HD_WATCHDOG_STALL_MS) {
                HD_LOGW("WDOG", "监控心跳停滞 %lldms，触发重扫",
                        (long long)(now - last_watchdog));
                g_full_scan_req = 1;
                last_watchdog = now;          /* 冷却：避免每 15 秒重复触发 */
            }
        }
    }

    /* 13) 关闭 */
    shutdown_all();

#ifdef _WIN32
    WSACleanup();
#endif
    if (g_console_log) hd_sleep_ms(500);
    return 0;
}

/* ==========================================================================
 * CLI
 * ========================================================================== */
static void print_usage(const char* prog)
{
    printf("Hamsterd ver.%s — Hamster 统一守护进程\n\n", HD_VERSION);
    printf("用法: %s [命令] [选项]\n\n", prog);
    printf("命令:\n");
    printf("  start             启动守护（默认；Windows 下转入后台）\n");
    printf("  --console-log     前台运行，日志同时打到控制台\n");
    printf("  stop              平滑停止运行中的守护\n");
    printf("  restart           重启\n");
    printf("  status            查看运行状态\n");
    printf("  rotate-codeword   重新生成连接口令并写回配置\n");
    printf("  reset database    重置索引数据库（需先停止守护）\n");
    printf("  reset config      删除配置文件（下次启动重建）\n");
    printf("  version           显示版本\n");
    printf("  help              显示本帮助\n\n");
    printf("选项（覆盖配置文件）:\n");
    printf("  --port=N          监听端口\n");
    printf("  --bind=ADDR       监听地址（默认 127.0.0.1）\n");
    printf("  --monitor=PATH    监控目录\n");
    printf("  --auth=on|off     是否要求认证\n");
    printf("  --level=LVL       日志级别 error|warn|info|debug\n");
}

static int cmd_status(void)
{
    int running = instance_is_running();
    printf("运行状态: %s\n", running ? "运行中" : "未运行");
    printf("程序目录: %s\n", g_base_dir);
    printf("配置文件: %s\n", config_path());
    printf("监控目录: %s\n", g_cfg.monitor_path);
    printf("监听地址: %s:%d\n", g_cfg.host, g_cfg.port);
    printf("认证要求: %s\n", g_cfg.require_auth ? "必需" : "已关闭");
    return running ? 0 : 3;
}

static int cmd_reset_database(void)
{
    char db[HD_PATH_MAX + 64], wal[HD_PATH_MAX + 64], shm[HD_PATH_MAX + 64];
    int deleted = 0;

    if (instance_is_running()) {
        printf("Hamsterd 正在运行，请先执行: %s stop\n", "hamsterd");
        return 1;
    }

    snprintf(db,  sizeof(db),  "%s/hamster.db",      g_base_dir);
    snprintf(wal, sizeof(wal), "%s/hamster.db-wal",  g_base_dir);
    snprintf(shm, sizeof(shm), "%s/hamster.db-shm",  g_base_dir);

    if (hd_remove_file(db) == 0)  { printf("  已删除: %s\n", db);  deleted++; }
    else if (!hd_exists(db))      { printf("  不存在: %s\n", db); }
    else                          { printf("  删除失败: %s（可能被占用）\n", db); }

    if (hd_remove_file(wal) == 0) deleted++;
    if (hd_remove_file(shm) == 0) deleted++;

    if (deleted > 0) printf("数据库已重置，下次启动将重建索引并全量扫描。\n");
    else             printf("没有需要删除的数据库文件。\n");
    return 0;
}

static int cmd_reset_config(void)
{
    if (instance_is_running()) {
        printf("Hamsterd 正在运行，请先停止后再重置配置\n");
        return 1;
    }
    if (hd_remove_file(config_path()) == 0) {
        printf("已删除配置: %s\n下次启动将使用默认值并重新生成模板。\n", config_path());
        return 0;
    }
    printf("配置文件不存在，无需重置。\n");
    return 0;
}

static int cmd_rotate_codeword(void)
{
    hd_generate_codeword(g_cfg.codeword, sizeof(g_cfg.codeword));
    config_save_codeword();
    printf("新的连接口令已写入 %s:\n\n  %s\n\n", config_path(), g_cfg.codeword);
    printf("请把同一口令填到 Hamster Manager 的 hamster_manager.conf (hamd_codeword)，\n");
    printf("或留空让客户端自动从 hamsterd.conf 读取。\n");
    return 0;
}

/* ==========================================================================
 * main
 * ========================================================================== */
int main(int argc, char* argv[])
{
    int i;
    int want_start = 0, want_console = 0, want_restart = 0;    const char* cli_port = NULL;
    const char* cli_bind = NULL;
    const char* cli_monitor = NULL;
    const char* cli_auth = NULL;
    const char* cli_level = NULL;

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    {
        char exe[HD_PATH_MAX];
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
        char exe[HD_PATH_MAX];
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

    {
        char abs[HD_PATH_MAX];
        if (hd_path_abs(g_base_dir, abs, sizeof(abs)) == 0)
            snprintf(g_base_dir, sizeof(g_base_dir), "%s", abs);
    }

    config_defaults();

    if (argc == 1) want_start = 1;

    for (i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (strcmp(a, "start") == 0 || strcmp(a, "--daemon") == 0) want_start = 1;
        else if (strcmp(a, "--daemon-child") == 0) { want_start = 1; g_daemon_child = 1; }
        else if (strcmp(a, "--console-log") == 0 || strcmp(a, "console") == 0) { want_console = 1; want_start = 1; }
        else if (strcmp(a, "restart") == 0) { want_restart = 1; want_start = 1; }
        else if (strcmp(a, "stop") == 0)    return cmd_stop();
        else if (strcmp(a, "version") == 0 || strcmp(a, "--version") == 0 || strcmp(a, "-v") == 0) {
            printf("Hamsterd ver.%s\n", HD_VERSION);
            return 0;
        }
        else if (strcmp(a, "help") == 0 || strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0 || strcmp(a, "/?") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(a, "status") == 0)          { config_load(0); return cmd_status(); }
        else if (strcmp(a, "rotate-codeword") == 0) { config_load(0); return cmd_rotate_codeword(); }
        else if (strcmp(a, "reset") == 0 && i + 1 < argc) {
            config_load(0);
            if (strcmp(argv[i + 1], "database") == 0) return cmd_reset_database();
            if (strcmp(argv[i + 1], "config") == 0)   return cmd_reset_config();
            print_usage(argv[0]);
            return 1;
        }
        else if (strncmp(a, "--port=", 7) == 0)    cli_port = a + 7;
        else if (strncmp(a, "--bind=", 7) == 0)    cli_bind = a + 7;
        else if (strncmp(a, "--monitor=", 10) == 0) cli_monitor = a + 10;
        else if (strncmp(a, "--auth=", 7) == 0)    cli_auth = a + 7;
        else if (strncmp(a, "--level=", 8) == 0)   cli_level = a + 8;
        else {
            fprintf(stderr, "未知参数: %s\n\n", a);
            print_usage(argv[0]);
            return 1;
        }
    }

    config_load(1);

    /* 命令行覆盖（便于调试，不写回配置） */
    if (cli_port)    { int v = 0; if (parse_int_range(cli_port, 1, 65535, &v) == 0) g_cfg.port = v; }
    if (cli_bind)    snprintf(g_cfg.host, sizeof(g_cfg.host), "%s", cli_bind);
    if (cli_monitor) snprintf(g_cfg.monitor_path, sizeof(g_cfg.monitor_path), "%s", cli_monitor);
    if (cli_auth)    g_cfg.require_auth = parse_bool(cli_auth);
    if (cli_level) {
        if (strcmp(cli_level, "error") == 0) g_cfg.log_level = HD_LOG_ERROR;
        else if (strcmp(cli_level, "warn") == 0) g_cfg.log_level = HD_LOG_WARN;
        else if (strcmp(cli_level, "debug") == 0) g_cfg.log_level = HD_LOG_DEBUG;
        else g_cfg.log_level = HD_LOG_INFO;
    }

    if (want_console) g_console_log = 1;

    if (want_restart) {
        cmd_stop();
        hd_sleep_ms(1500);
    }

    if (!want_start) {
        print_usage(argv[0]);
        return 0;
    }

    /* Windows 非控制台模式：转入后台子进程（子进程带 --daemon-child，不再自我 spawn） */
#ifdef _WIN32
    if (!want_console && !g_daemon_child) {
        char exe[HD_PATH_MAX];
        char cmdline[HD_PATH_MAX * 2 + 32];
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;

        GetModuleFileNameA(NULL, exe, sizeof(exe));
        snprintf(cmdline, sizeof(cmdline), "\"%s\" --daemon-child", exe);

        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));

        if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                           DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                           NULL, g_base_dir, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            printf("Hamsterd 已在后台启动（日志: %s\\logs\\%s）\n", g_base_dir, HD_INTERNAL_LOG);
            return 0;
        }
        fprintf(stderr, "后台启动失败 (错误码 %lu)，转前台运行\n", GetLastError());
    }
#endif

    return run_daemon();
}