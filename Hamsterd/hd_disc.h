/*
 * hd_disc.h — 局域网发现：服务端被动应答（PROTOCOL §7）
 * ver.0.0.8
 *
 * 设计要点（与 0.0.7 相反）：
 *   · 服务端**不再广播任何东西**。它只监听一个 UDP 端口，等客户端来探测。
 *   · 只有探测帧里带着 `HMAC(codeword, ...)` 且校验通过，才单播回一条应答。
 *   · 校验失败、版本不符、重放、超速——**一律静默丢弃**（不回任何字节）。
 *     这是安全要求：任何可区分的错误反馈都会把"暗号对不对"变成可离线穷举的信号。
 *
 * 分两层：
 *   1) 纯函数层（build/parse）：不碰 socket，可被 tests/test_disc.c 直接单测。
 *   2) 线程层（hd_disc_thread）：socket + 限速 + 重放窗口 + 主循环。
 */
#ifndef HAMSTER_HD_DISC_H
#define HAMSTER_HD_DISC_H

#include "hd_util.h"

#define HD_DISC_MAGIC_V     1
#define HD_DISC_FRAME_MAX   512         /* 单帧上限，超过直接丢 */
#define HD_DISC_ID_MAX      64          /* 标识串上限（含 '\0'） */
#define HD_DISC_NONCE_HEX   32          /* 16 字节 nonce 的十六进制长度 */
#define HD_DISC_NONCE_MAX   33          /* + '\0' */
#define HD_DISC_MAC_HEX     64          /* HMAC-SHA256 十六进制长度 */
#define HD_DISC_MAC_MAX     65

/* 应答里允许携带的显示名最大长度（已 JSON 转义前） */
#define HD_DISC_NAME_MAX    128

typedef struct {
    int         port;           /* UDP 发现端口；<=0 表示完全禁用 */
    int         respond;        /* 0 = 端口照开但不回应（只记账） */
    const char* codeword;       /* 必须与服务端 codeword 一致；空串 = 禁用 */
    const char* instance_id;    /* 服务端标识，进应答帧 */
    const char* local_name;     /* 服务端显示名 */
    int         tcp_port;       /* 应答里通告的 TCP 端口 */
    const char* version;        /* 应答里的版本号字符串 */
} hd_disc_cfg;

/* --------------------------------------------------------------------------
 * 纯函数层
 * -------------------------------------------------------------------------- */

/* 构造探测帧（客户端侧也会用同一份实现，保证两侧不会写岔）。
 * 返回写入长度，<0 表示参数非法或缓冲不足。 */
int hd_disc_build_probe(const char* codeword, const char* id, const char* nonce_hex,
                        char* out, size_t cap);

/* 校验探测帧。通过返回 0，并填出 id / nonce；任何不符返回 -1。
 * 注意：调用方在返回 -1 时**必须什么都不回**。 */
int hd_disc_parse_probe(const char* codeword, const char* frame, int len,
                        char* id_out, size_t id_cap,
                        char* nonce_out, size_t nonce_cap);

/* 构造应答帧。返回写入长度，<0 表示失败。 */
int hd_disc_build_reply(const char* codeword,
                        const char* probe_id, const char* nonce_hex,
                        const char* self_id, const char* self_name,
                        int tcp_port, const char* version,
                        char* out, size_t cap);

/* 校验应答帧（客户端侧）。通过返回 0 并填出各字段，失败 -1。 */
int hd_disc_parse_reply(const char* codeword, const char* my_id,
                        const char* frame, int len,
                        char* nonce_out, size_t nonce_cap,
                        char* id_out, size_t id_cap,
                        int* port_out,
                        char* name_out, size_t name_cap,
                        char* version_out, size_t version_cap);

/* 标识串是否合法：8–63 字节，仅 [0-9A-Za-z_-]。 */
int hd_disc_valid_id(const char* s);
/* 是否恰好 n 个小写/大写十六进制字符。 */
int hd_disc_is_hex(const char* s, size_t n);

/* 生成一个 nonce 并写成十六进制（需要 CSPRNG）。成功返回 0。 */
int hd_disc_make_nonce(char out[HD_DISC_NONCE_MAX]);

/* --------------------------------------------------------------------------
 * 线程层
 * -------------------------------------------------------------------------- */
/* 复制 cfg 里的字符串并启动发现线程；返回 0 成功，<0 失败。
 * cfg 可以指向栈上的临时对象——函数返回后不再引用它。 */
int hd_disc_start(hd_thread* out, const hd_disc_cfg* cfg);

/* 供 stats/日志用：累计回应了多少次探测（原子读，误差可忽略）。 */
long hd_disc_reply_count(void);

#endif /* HAMSTER_HD_DISC_H */
