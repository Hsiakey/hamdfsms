/*
 * hd_util — 平台适配、日志、时间、随机数、字符串构建、路径安全、文件与哈希
 *
 * 本文件是"安全边界"所在地：
 *   - hd_path_abs()      规范化成绝对路径（折叠 . / .. / 重复分隔符）
 *   - hd_path_within()   判定是否位于监控根目录之内（下载/上传/删除的白名单）
 *   - hd_path_sanitize_rel() 拒绝绝对路径、盘符、.. 组件的相对路径
 *   - hd_ct_equal()      常量时间口令比较（避免时序侧信道）
 *   - hd_random_bytes()  CSPRNG（BCryptGenRandom / getrandom）
 */
#ifndef HAMSTER_HD_UTIL_H
#define HAMSTER_HD_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

/* ==========================================================================
 * 平台基础类型
 * ========================================================================== */
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>       /* 必须先于 windows.h，否则会被 winsock.h 抢先定义 */
    #include <ws2tcpip.h>
    #include <windows.h>
    typedef SOCKET   hd_socket;
    typedef HANDLE   hd_mutex;
    typedef HANDLE   hd_thread;
    #define HD_INVALID_SOCK INVALID_SOCKET
    #define HD_SOCK_ERR     SOCKET_ERROR
    #define hd_sock_close(s) closesocket(s)
    #define HD_PATH_SEP '\\'
    #define HD_THREAD_RET  unsigned
    #define HD_THREAD_CALL __stdcall
#else
    #include <pthread.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <errno.h>
    typedef int          hd_socket;
    typedef pthread_mutex_t hd_mutex;
    typedef pthread_t    hd_thread;
    #define HD_INVALID_SOCK (-1)
    #define HD_SOCK_ERR     (-1)
    #define hd_sock_close(s) close(s)
    #define HD_PATH_SEP '/'
    #define HD_THREAD_RET  void*
    #define HD_THREAD_CALL
#endif

/* ==========================================================================
 * 常量
 * ========================================================================== */
#define HD_PATH_MAX   2048
#define HD_LINE_MAX   (256 * 1024)      /* 入站单行 JSON 上限 */
#define HD_CHUNK      (64 * 1024)       /* 传输分块 */
#define HD_SEARCH_MAX 1000              /* 单次 search 返回上限 */

/* ==========================================================================
 * 全局配置与停止标志
 * ========================================================================== */
typedef struct {
    char monitor_path[HD_PATH_MAX];   /* 已规范化的绝对路径 */
    char host[64];
    int  port;
    int  rescan_day, rescan_hour, rescan_minute, rescan_enabled;
    int  heartbeat_time;              /* 秒 */
    int  verify_interval;             /* 分钟，0=禁用 */
    int  verify_enabled;
    int  discovery_port;
    int  discovery_respond;
    char codeword[128];
    int  require_auth;                /* 1=所有数据命令需认证（默认 1） */
    int  allow_loopback_noauth;       /* 1=回环连接免认证（默认 0） */
    int  encrypt_transport;           /* 1=§8 握手 + 记录层（0.0.9 默认开；迁移期可为 0） */
    int  max_clients;
    int  max_transfer_mb;             /* 单次上传/下载大小上限（MB） */
    int  prune_missing;               /* 完整性校验时删除已消失的记录 */
    int  log_level;                   /* 0=error 1=warn 2=info 3=debug */
    char log_dir[HD_PATH_MAX + 64];
    int  exclude_internal;            /* 排除自身日志/数据库，默认 1 */
} hd_config;

extern hd_config    g_cfg;
extern volatile int g_stop;           /* 1=收到停止请求 */

/* ==========================================================================
 * 日志
 * ========================================================================== */
#define HD_LOG_ERROR 0
#define HD_LOG_WARN  1
#define HD_LOG_INFO  2
#define HD_LOG_DEBUG 3

void hd_log_init(const char* file_path, int also_stdout, int level);
void hd_log_shutdown(void);
void hd_logf(int level, const char* tag, const char* fmt, ...);
const char* hd_log_file_path(void);

#define HD_LOGE(tag, ...) hd_logf(HD_LOG_ERROR, tag, __VA_ARGS__)
#define HD_LOGW(tag, ...) hd_logf(HD_LOG_WARN,  tag, __VA_ARGS__)
#define HD_LOGI(tag, ...) hd_logf(HD_LOG_INFO,  tag, __VA_ARGS__)
#define HD_LOGD(tag, ...) hd_logf(HD_LOG_DEBUG, tag, __VA_ARGS__)

/* ==========================================================================
 * 时间 / 随机 / 比较
 * ========================================================================== */
int64_t hd_now_ms(void);
void    hd_iso_local(char* out, size_t n);
void    hd_sleep_ms(int ms);
/* 可被停止标志打断的等待：返回 1=收到停止，0=正常到时 */
int     hd_wait_ms(int ms);

int  hd_random_bytes(void* out, size_t n);
void hd_generate_codeword(char* out, size_t n);   /* "hamster-<32hex>" */
void hd_generate_api_key(char* out, size_t n);    /* "hk_<48hex>" */
int  hd_ct_equal(const char* a, const char* b);

/* ==========================================================================
 * 字符串构建器（定长缓冲，永不越界；溢出后置 overflow 标志）
 * ========================================================================== */
typedef struct {
    char*  buf;
    size_t cap;
    size_t len;
    int    overflow;
} hd_sb;

void hd_sb_init(hd_sb* sb, char* buf, size_t cap);
void hd_sb_puts(hd_sb* sb, const char* s);
void hd_sb_putc(hd_sb* sb, char c);
void hd_sb_printf(hd_sb* sb, const char* fmt, ...);
void hd_sb_json(hd_sb* sb, const char* s);          /* 转义后追加字符串内容 */
int  hd_sb_ok(const hd_sb* sb);
size_t hd_sb_len(const hd_sb* sb);

/* ==========================================================================
 * 路径
 * ========================================================================== */
/* 规范化为绝对路径（折叠 . / .. / 重复分隔符，去掉结尾分隔符） */
int  hd_path_abs(const char* in, char* out, size_t n);
/* child 是否等于 root 或位于其下（要求两者均已规范化绝对） */
int  hd_path_within(const char* child_abs, const char* root_abs);
/* 目录 + 名字 拼接（按平台分隔符，自动补齐） */
void hd_path_join(char* out, size_t n, const char* dir, const char* name);
/* 把 '/' 统一为平台分隔符（原地） */
void hd_path_native(char* path);
/* 客户端给的相对路径净化：拒绝绝对路径、盘符、UNC、..、控制字符。返回 1=通过 */
int  hd_path_sanitize_rel(const char* rel, char* out, size_t n);
const char* hd_basename(const char* path);
/* 去掉扩展名后的类型名（小写），无扩展名则空串 */
void hd_ext_lower(const char* filename, char* out, size_t n);

/* ==========================================================================
 * 文件
 * ========================================================================== */
typedef struct {
    int64_t size;
    int64_t mtime;      /* Unix 秒 */
    int     is_dir;
} hd_file_info;

int   hd_stat64(const char* path, hd_file_info* info);      /* 0=成功 */
int   hd_exists(const char* path);
FILE* hd_fopen(const char* path, const char* mode);          /* UTF-8 路径 */
int   hd_remove_file(const char* path);                      /* 0=成功 */
int   hd_rename(const char* from, const char* to);           /* 0=成功 */
int   hd_mkdirs(const char* abs_dir_path);                   /* 递归创建，0=成功 */
int   hd_mkdirs_for_file(const char* abs_file_path);
int   hd_rmdir(const char* abs_dir_path);                    /* 仅空目录 */

/*
 * 是否是"运行时产物"而非用户文件：上传中转文件（*.part-*）与自身日志/数据库。
 * 扫描与监控都必须跳过它们，否则会出现两类事故：
 *   1) 把正在写入的 .part 文件入库；
 *   2) 扫描打开 .part 文件的同时上传线程要 rename 它 → Windows 共享冲突 → rename 失败。
 */
int   hd_is_artifact_name(const char* name);

/* xxHash3_128 → 32 位十六进制小写字符串（33 字节含 NUL） */
int   hd_hash_file(const char* path, char* out_hex33);
int   hd_hash_fd(FILE* fp, char* out_hex33, int64_t* bytes_read);

/* 流式哈希：用于边收边校验的上传路径 */
typedef struct hd_hasher hd_hasher;
hd_hasher* hd_hash_new(void);
void       hd_hash_update(hd_hasher* h, const void* data, size_t n);
void       hd_hash_finish(hd_hasher* h, char* out_hex33);
void       hd_hash_free(hd_hasher* h);

/* ==========================================================================
 * socket 错误
 * ========================================================================== */
int hd_sock_error(void);                    /* 最近一次 socket 错误码 */
int hd_sock_error_is_timeout(int err);      /* 是否为"超时/可重试" */

/* ==========================================================================
 * 线程
 * ========================================================================== */
#ifdef _WIN32
typedef unsigned (__stdcall *hd_thread_fn)(void*);
#else
typedef void* (*hd_thread_fn)(void*);
#endif

int  hd_thread_start(hd_thread* t, hd_thread_fn fn, void* arg);
void hd_thread_join(hd_thread* t);
void hd_thread_dispose(hd_thread* t);      /* 关闭句柄/分离，不再 join */

int  hd_mutex_init(hd_mutex* m);
void hd_mutex_destroy(hd_mutex* m);
void hd_mutex_lock(hd_mutex* m);
void hd_mutex_unlock(hd_mutex* m);
/* 尝试加锁：返回 1=成功，0=已被占用（广播时用它避免被慢客户端阻塞） */
int  hd_mutex_trylock(hd_mutex* m);

/* ==========================================================================
 * 应用层钩子（由 hamsterd.c 实现，供 hd_net 调用）
 * ========================================================================== */
void        hd_app_request_rescan(void);
void        hd_app_request_sync(void);
int         hd_app_uptime_sec(void);
const char* hd_app_version(void);
int         hd_app_peer_count(void);
/* 把发现的设备写入 JSON 数组（含 id/ip/port/name） */
void        hd_app_peers_json(hd_sb* sb);

#endif /* HAMSTER_HD_UTIL_H */
