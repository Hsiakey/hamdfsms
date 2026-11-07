/*
 * hd_sec.h — 传输加密（PROTOCOL §8）：握手密钥派生 + 记录层
 * ver.0.0.9
 *
 * 职责边界：
 *   · 本文件只做"数学"：派生、封包、拆包。不碰 socket、不碰线程、不分配内存。
 *   · 握手状态机（读写 auth 报文、决定用哪个口令）在 hd_net.c，因为它要和
 *     连接读写、配置、api_keys 打交道。
 *   · 记录层只把字节流切块加密，**不改变上层语义**：明文流内部仍是 0.0.8 的
 *     JSON 行 + payload_bytes + 裸负载（§3），所以 rd_read_line 一行都不用改。
 *
 * 与 JS 实现（Hamster Manager/module/shared/hamster-aead.js）必须逐字节一致，
 * 对齐锚点是 PROTOCOL §8.2 的五组已知答案；tests/test_sec.c 会把它们钉死。
 */
#ifndef HAMSTER_HD_SEC_H
#define HAMSTER_HD_SEC_H

#include <stddef.h>
#include <stdint.h>

#define HD_SEC_SALT_LEN    16          /* salt / nc / ns 都是 16 字节 */
#define HD_SEC_NONCE_LEN   16
#define HD_SEC_KEY_LEN     32          /* master / 记录密钥 */
#define HD_SEC_TAG_LEN     16          /* Poly1305 tag */
#define HD_SEC_HDR_LEN     12          /* len(4) + counter(8) */
#define HD_SEC_MAX_PLAIN   65536u      /* 单条记录明文上限（= HD_CHUNK） */
#define HD_SEC_REC_MAX     (HD_SEC_HDR_LEN + HD_SEC_MAX_PLAIN + HD_SEC_TAG_LEN)
#define HD_SEC_HEX16_LEN   32          /* 16 字节 → 32 hex 字符 */
#define HD_SEC_HEX32_LEN   64          /* 32 字节 → 64 hex 字符 */

#define HD_SEC_DIR_C2S     0x01
#define HD_SEC_DIR_S2C     0x02

/* 一端连接上的加密状态。active=0 表示明文模式（迁移期开关）。 */
typedef struct {
    int      active;
    uint8_t  key_out[HD_SEC_KEY_LEN];   /* 本端发送用的密钥 */
    uint8_t  key_in[HD_SEC_KEY_LEN];    /* 本端接收用的密钥 */
    uint8_t  dir_out;                   /* 发出去的方向字节 */
    uint8_t  dir_in;                    /* 期望收到的方向字节 */
    uint64_t ctr_out;                   /* 已发送记录数（从 0 开始） */
    uint64_t ctr_in;                    /* 期望收到的记录序号 */
} hd_sec;

/* ---- 十六进制（小写，无 0x） ---- */
void hd_sec_hex_encode(const void* in, size_t n, char* out);   /* out 需 2n+1 */
/* 严格解码：长度必须正好 2n，且只接受 0-9a-fA-F；成功返回 0 */
int  hd_sec_hex_decode(const char* hex, size_t n, void* out);

/* 常量时间比较（长度相等才比内容；相等返回 1） */
int  hd_sec_ct_eq(const void* a, const void* b, size_t n);

/* ---- §8.2 派生 ---- */
/* master = HKDF-SHA256(salt = salt, IKM = secret, info = "hamster-auth/v1", L = 32) */
void hd_sec_master(const void* secret, size_t slen,
                   const uint8_t salt[HD_SEC_SALT_LEN], uint8_t master[HD_SEC_KEY_LEN]);

/* proof_C = HMAC(master, "hamster-client-proof/v2\n"+nc+"\n"+ns+"\n"+device_id) */
void hd_sec_proof_c(const uint8_t master[HD_SEC_KEY_LEN],
                    const char* nc_hex, const char* ns_hex, const char* device_id,
                    uint8_t out[HD_SEC_KEY_LEN]);

/* proof_S = HMAC(master, "hamster-server-proof/v2\n"+nc+"\n"+ns) */
void hd_sec_proof_s(const uint8_t master[HD_SEC_KEY_LEN],
                    const char* nc_hex, const char* ns_hex,
                    uint8_t out[HD_SEC_KEY_LEN]);

/*
 * 初始化会话密钥。is_server 决定哪个方向是本端的发送方向。
 * nc/ns 必须是 32 个 hex 字符（原文拼进 info，不是按字节拼）。
 * 返回 0 成功，-1 参数非法。
 */
int hd_sec_init(hd_sec* s, const uint8_t master[HD_SEC_KEY_LEN],
                const uint8_t salt[HD_SEC_SALT_LEN],
                const char* nc_hex, const char* ns_hex, int is_server);

/*
 * 封包：明文 → 一条记录（len|counter|密文|tag）。调用方负责分块到
 * 1..HD_SEC_MAX_PLAIN 字节；out 至少 len + HD_SEC_HDR_LEN + HD_SEC_TAG_LEN。
 * 返回记录总字节数；失败返回 0（调用方必须断开连接）。
 */
size_t hd_sec_seal(hd_sec* s, const void* plain, size_t len, void* out);

/*
 * 拆包：rec 必须正好是一条完整记录（hd_net 负责按 len 字段切出来）。
 * 成功返回明文长度并把明文写进 out（outcap >= HD_SEC_MAX_PLAIN）；
 * 失败返回 -1 —— 长度非法 / counter 不是期望值 / tag 校验失败，
 * 一律当作"这条连接不可信"，调用方直接关闭且不要解释原因。
 */
int hd_sec_open(hd_sec* s, const void* rec, size_t reclen, void* out, size_t outcap);

#endif /* HAMSTER_HD_SEC_H */
