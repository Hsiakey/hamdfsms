/*
 * hd_crypto.h — 最小密码学原语（SHA-256 / HMAC-SHA256 / 十六进制）
 * ver.0.0.8
 *
 * 为什么需要它：
 *   项目的协议里所有"认证"都必须有一个密钥相关的校验值（MAC）。
 *   现有的 xxHash3 是非加密哈希——速度快，但不能当 MAC 用（可被构造碰撞/伪造）。
 *   发现协议的"暗号不对就不回应"、以及后续的 hello 挑战应答、传输加密，
 *   都需要一个可被双方算出、且对攻击者不可伪造的值，因此这里实现标准的 SHA-256 与
 *   HMAC-SHA256（RFC 6234 / RFC 2104 / RFC 4231），并用官方测试向量钉死。
 *
 * 设计约束：
 *   · 零依赖、可重入、不分配内存（调用方给缓冲）
 *   · 只做"算哈希"，不做密钥管理；密钥生命周期由调用方负责
 *   · 所有输出都是小写十六进制字符串，便于塞进 JSON
 */
#ifndef HAMSTER_HD_CRYPTO_H
#define HAMSTER_HD_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define HD_SHA256_LEN   32          /* 原始摘要字节数 */
#define HD_SHA256_HEX   65          /* 十六进制串长度（含 '\0'） */

typedef struct {
    uint32_t h[8];
    uint64_t total;                 /* 已处理的字节数 */
    uint8_t  buf[64];
    size_t   buflen;
} hd_sha256;

void hd_sha256_init(hd_sha256* ctx);
void hd_sha256_update(hd_sha256* ctx, const void* data, size_t len);
void hd_sha256_final(hd_sha256* ctx, uint8_t out[HD_SHA256_LEN]);

/* 一次性接口：digest_out 可为 NULL（只取十六进制串） */
void hd_sha256_once(const void* data, size_t len, uint8_t* digest_out, char* hex_out);

/* HMAC-SHA256；hex_out 需要 HD_SHA256_HEX 字节 */
void hd_hmac_sha256(const void* key, size_t keylen,
                    const void* data, size_t datalen,
                    uint8_t* digest_out, char* hex_out);

/* 便捷封装：把若干段拼起来算 HMAC（避免调用方自己拼 buffer） */
void hd_hmac_sha256v(const void* key, size_t keylen,
                     const void* d1, size_t l1,
                     const void* d2, size_t l2,
                     const void* d3, size_t l3,
                     uint8_t* digest_out, char* hex_out);

/* 字节 → 小写十六进制（out 需要 len*2+1 字节） */
void hd_hex_encode(const uint8_t* in, size_t len, char* out);
/* 十六进制 → 字节；返回解码出的字节数，非法字符返回 -1 */
int  hd_hex_decode(const char* hex, uint8_t* out, size_t out_cap);

#endif /* HAMSTER_HD_CRYPTO_H */
