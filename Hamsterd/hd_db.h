/*
 * hd_db — SQLite 索引层：文件表 / 统计 / 查询 / 校验记录 / API 密钥
 *
 * 约定（对应审查报告 P0-6、P1-16）：
 *   - 所有公开函数自己加解锁，内部 *_locked 版本不加锁，禁止嵌套加锁
 *   - 每个 sqlite3 调用都检查返回码，失败必须写日志，不得静默当作成功
 *   - integrity_check 采用"锁内取快照 → 锁外计算哈希 → 锁内写回"，
 *     绝不在持锁期间做 I/O 密集的哈希计算
 */
#ifndef HAMSTER_HD_DB_H
#define HAMSTER_HD_DB_H

#include <stddef.h>
#include <stdint.h>
#include "hd_util.h"

/* 扫描统计 */
typedef struct {
    int visited;    /* 访问到的文件数 */
    int indexed;    /* 新增或更新 */
    int failed;     /* 失败数 */
} hd_scan_stat;

/* 检索条件 */
typedef struct {
    const char* q;          /* 关键词，可为 NULL */
    const char* type;       /* 扩展名过滤，可为 NULL */
    int64_t     size_min;   /* <=0 表示不限 */
    int64_t     size_max;   /* <=0 表示不限 */
    int         limit;      /* 1..HD_SEARCH_MAX */
    int         offset;
    const char* sort;       /* name|size|modified|type，前缀 '-' 表示降序 */
} hd_search_query;

int  hd_db_open(const char* db_path);
void hd_db_close(void);
int  hd_db_checkpoint(void);
const char* hd_db_path(void);
/* 生成一致性快照到 dst_path（sync-database 用）。0=成功。
   内部会先 checkpoint，再用 SQLite backup API 复制一份不可变的副本。 */
int  hd_db_snapshot(const char* dst_path);

/* 单条记录 */
int  hd_db_upsert_file(const char* abs_path, const char* hash);
int  hd_db_delete_file(const char* abs_path);
int  hd_db_delete_dir(const char* abs_dir);
int  hd_db_update_total(void);
/* 取索引中记录的哈希（用于下载响应里的 index_hash，供客户端检测磁盘已变更） */
int  hd_db_file_hash(const char* abs_path, char* out_hex33);

/* 扫描 */
int  hd_db_scan_dir(const char* abs_dir, int depth, hd_scan_stat* st);
int  hd_db_scan_all(const char* abs_root, hd_scan_stat* st);

/* JSON 输出（data 对象内容，不含外层包装） */
int  hd_db_stats_json(char* out, size_t n);
int  hd_db_search_json(const hd_search_query* q, char* out, size_t n);
int  hd_db_verify_json(char* out, size_t n);

/* 完整性校验：返回 1=完成，0=中止（停止标志） */
int  hd_db_integrity_check(int* total, int* ok, int* corrupt, int* missing, int prune_missing);
int  hd_db_record_verify(int total, int ok, int corrupt, int missing, int scan_interval_min);
int  hd_db_bump_scan_count(void);
int  hd_db_set_scan_interval(int minutes);

/* API 密钥 */
int  hd_db_key_add(const char* label, char* out_key, size_t n);
int  hd_db_key_list(char* out, size_t n);
int  hd_db_key_revoke(int key_id);
int  hd_db_key_check(const char* key);

/*
 * §8.2 握手专用：在启用中的 api_keys 里找"能算出一致 proof_C"的那一把。
 * 密钥本身不出库（调用方只拿得到 label），避免为了握手把明文密钥读进内存多处。
 * 返回 1=命中，0=没有命中。
 */
int  hd_db_key_match_proof(const unsigned char salt[16],
                           const char* nc_hex, const char* ns_hex, const char* device_id,
                           const unsigned char proof_c[32],
                           char* out_label, size_t n,
                           unsigned char out_master[32]);

#endif /* HAMSTER_HD_DB_H */
