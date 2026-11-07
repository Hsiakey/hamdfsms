/*
 * jsonx — 面向本项目的严格 JSON 子集工具
 *
 * 设计目标（对应审查报告 P2-5）：
 *   - 取代原先的 strstr 手抠：字符串里出现 '}'、'\'、转义引号时不再解析错
 *   - 只做"从对象里按键取值"这一件事，但把这一件事做对：
 *       * 只在深度 1 匹配键，不会误命中嵌套对象里的同名键
 *       * 完整跳过字符串转义、嵌套对象与数组
 *       * 数字按长度受限解析，不做 atoi 式截断
 *   - 绝不写入越界：所有输出函数都保证 NUL 结尾并返回实际长度
 *
 * 不做的事（有意为之）：不构造 DOM、不做 schema 校验、不分配内存。
 */
#ifndef HAMSTER_JSONX_H
#define HAMSTER_JSONX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 整串必须是一个 JSON 对象（允许首尾空白）。1=合法，0=非法。 */
int jx_is_object(const char* s);

/* 顶层是否存在该键 */
int jx_has(const char* obj, const char* key);

/*
 * 取顶层键的原始值片段（对象/数组含括号，字符串不含引号且已反转义）。
 * 返回 1=成功，0=不存在或非法，-1=输出缓冲不足。
 */
int jx_find_raw(const char* obj, const char* key, char* out, size_t n);

/* 取字符串值并反转义。返回 1=成功，0=不存在/类型不符/非法，-1=缓冲不足。 */
int jx_get_str(const char* obj, const char* key, char* out, size_t n);

/* 取整数值。仅接受 JSON 数字（不接受字符串形式的数字）。 */
int jx_get_i64(const char* obj, const char* key, int64_t* out);
int jx_get_int(const char* obj, const char* key, int* out);

/* 取布尔值。仅接受 true/false（不接受 0/1）。 */
int jx_get_bool(const char* obj, const char* key, int* out);

/*
 * JSON 字符串转义（不含首尾引号）。
 * 覆盖 " \ 以及所有 < 0x20 的控制字符（转成 \u00XX）。
 * 返回写入长度（>=0），-1 表示缓冲不足（输出已尽力截断且 NUL 结尾）。
 */
int jx_escape(const char* in, char* out, size_t n);

/* JSON 字符串反转义（输入不含首尾引号）。支持 \uXXXX 与代理对。 */
int jx_unescape(const char* in, char* out, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* HAMSTER_JSONX_H */
