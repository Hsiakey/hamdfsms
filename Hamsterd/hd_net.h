/*
 * hd_net — TCP :9100 协议实现
 *
 * 协议要点（ver.0.0.8）：
 *   - 控制消息：一行一个 JSON 对象，'\n' 结尾，上限 HD_LINE_MAX
 *   - 二进制负载：消息头里带 "payload_bytes": N 与 "framing":"raw"，
 *     紧接 N 字节裸数据；接收方必须精确读取 N 字节后才继续解析下一行。
 *     这取代了旧版"靠 header 里的 size 猜边界"的做法。
 *   - 认证：除 hello / ping / info 外，任何命令都要求连接已通过 hello 认证。
 */
#ifndef HAMSTER_HD_NET_H
#define HAMSTER_HD_NET_H

#include "hd_util.h"

/* 启动监听与接受线程；返回 0=成功 */
int  hd_net_start(const char* bind_addr, int port, int max_clients);
/* 停止：关闭监听、关闭所有连接、join 全部线程 */
void hd_net_stop(void);

int  hd_net_client_count(void);

/* 广播事件。data_json 必须是合法的 JSON 值（通常是对象），不带换行。 */
void hd_net_broadcast(const char* event, const char* data_json);

/* 便捷封装：文件事件 */
void hd_net_file_event(const char* event, const char* abs_path);

#endif /* HAMSTER_HD_NET_H */
