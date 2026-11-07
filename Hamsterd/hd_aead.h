/*
 * hd_aead.h — ChaCha20-Poly1305 AEAD（RFC 8439）与 HKDF-SHA256（RFC 5869）
 * ver.0.0.8
 *
 * 为什么需要它：
 *   hd_crypto.h 只解决了"算哈希 / 算 MAC"，但两个对端之间的传输还需要
 *   "既保密、又防篡改"：光加密不认证，主动攻击者可以翻转密文比特；
 *   光认证不加密，内容等于裸奔。ChaCha20-Poly1305 是 IETF 标准化的 AEAD
 *   （TLS 1.3 强制套件之一），一次调用同时给出密文与 16 字节 tag，
 *   正好覆盖后续"传输全加密"的需求；它只依赖 32 位整数运算，
 *   在没有 AES-NI 的机器上也不至于拖慢握手与转发。
 *
 *   HKDF 负责从一段共享密钥材料（口令、ECDH 结果等）里"榨"出多个用途
 *   相互独立的子密钥（发送密钥、接收密钥、方向盐……）。RFC 5869 的
 *   extract + expand 两段式是标准做法，这里直接复用已有的
 *   hd_hmac_sha256()，不再重复实现一遍 HMAC。
 *
 * 设计约束：
 *   · 零依赖、不分配内存；密文/明文缓冲由调用方提供
 *   · 认证失败时一个明文字节都不写，调用方可以先验 tag 再信任输出缓冲
 *   · 允许空明文、空 AAD；允许 plain_out == cipher 的原地解密
 *   · 只实现 RFC 8439 的 12 字节 nonce / 32 位块计数器版本，
 *     不做 XChaCha20 之类扩展；nonce 复用是调用方的责任（会毁掉安全性）
 */
#ifndef HAMSTER_HD_AEAD_H
#define HAMSTER_HD_AEAD_H

#include <stddef.h>
#include <stdint.h>

#define HD_AEAD_KEY_LEN     32          /* ChaCha20 密钥字节数 */
#define HD_AEAD_NONCE_LEN   12          /* RFC 8439 AEAD 的 nonce 长度 */
#define HD_AEAD_TAG_LEN     16          /* Poly1305 tag 长度 */

/* RFC 5869 对单次 expand 的上限：255 个 32 字节块 */
#define HD_HKDF_SHA256_MAX_OUT  (255u * 32u)

/* RFC 8439 §2.3 的块函数，输出 64 字节密钥流；counter 是 32 位块计数器。
 * 单独暴露出来是为了让测试能直接钉住 §2.4.2 的官方向量，
 * 也方便将来实现需要原始密钥流的扩展（例如 QUIC 的 header protection）。 */
void hd_chacha20_block(const uint8_t key[HD_AEAD_KEY_LEN], uint32_t counter,
                       const uint8_t nonce[HD_AEAD_NONCE_LEN],
                       uint8_t out[64]);

/* 一次性 Poly1305（RFC 8439 §2.5）；key 为 32 字节：前 16 字节 r，后 16 字节 s。
 * 暴露它同样是为了能对 §2.5.2 向量逐字节验证；AEAD 内部走的是流式路径，
 * 避免把 AAD 与密文拼进一块临时缓冲。 */
void hd_poly1305(const uint8_t key[32], const void* msg, size_t len,
                 uint8_t tag_out[HD_AEAD_TAG_LEN]);

/* RFC 5869 HKDF-SHA256（extract + expand）。
 * salt 可为 NULL/0：HMAC 用全零密钥，与 RFC 的"未提供 salt 就用 HashLen 个 0"
 * 完全等价；info 可为 NULL/0；outlen 上限 HD_HKDF_SHA256_MAX_OUT。
 * outlen 超限时本函数直接不写（返回 void，调用方必须自己先判断）。 */
void hd_hkdf_sha256(const void* salt, size_t saltlen,
                    const void* ikm, size_t ikmlen,
                    const char* info, size_t infolen,
                    uint8_t* out, size_t outlen);

/* 加密并认证：cipher_out 与 plain 可以同指针（原地加密），长度必须一致。
 * 返回 0 成功；参数非法或长度超出计数器上限返回 -1。 */
int hd_chacha20_poly1305_seal(const uint8_t key[HD_AEAD_KEY_LEN],
                              const uint8_t nonce[HD_AEAD_NONCE_LEN],
                              const void* aad, size_t aadlen,
                              const void* plain, size_t plainlen,
                              uint8_t* cipher_out,
                              uint8_t tag_out[HD_AEAD_TAG_LEN]);

/* 先验 tag，通过后才解密；失败返回 -1 且不触碰 plain_out（可以安全地
 * 复用一块可能含敏感数据的缓冲）。plain_out 可与 cipher 同指针。 */
int hd_chacha20_poly1305_open(const uint8_t key[HD_AEAD_KEY_LEN],
                              const uint8_t nonce[HD_AEAD_NONCE_LEN],
                              const void* aad, size_t aadlen,
                              const uint8_t* cipher, size_t cipherlen,
                              const uint8_t tag[HD_AEAD_TAG_LEN],
                              uint8_t* plain_out);

#endif /* HAMSTER_HD_AEAD_H */
