/* hd_db — SQLite 索引层实现 */

#include "hd_db.h"
#include "hd_sec.h"
#include "jsonx.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "sqlite3.h"

/* ==========================================================================
 * 内部状态
 * ========================================================================== */
static sqlite3*  s_db = NULL;
static hd_mutex  s_lk;
static int       s_lk_ok = 0;
static char      s_db_path[HD_PATH_MAX];

#define DB_LOCK()   do { if (s_lk_ok) hd_mutex_lock(&s_lk); } while (0)
#define DB_UNLOCK() do { if (s_lk_ok) hd_mutex_unlock(&s_lk); } while (0)

const char* hd_db_path(void) { return s_db_path; }

static const char* DDL =
    "CREATE TABLE IF NOT EXISTS file_in ("
    "    xxHash3_128   TEXT,"
    "    file_name     TEXT NOT NULL,"
    "    file_path     TEXT PRIMARY KEY,"
    "    file_type     TEXT NOT NULL DEFAULT '',"
    "    file_sizeBy   INTEGER NOT NULL DEFAULT 0,"
    "    change_dateT  TEXT NOT NULL DEFAULT '',"
    "    file_readme   TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_file_in_hash ON file_in(xxHash3_128);"
    "CREATE INDEX IF NOT EXISTS idx_file_in_name ON file_in(file_name);"
    "CREATE INDEX IF NOT EXISTS idx_file_in_type ON file_in(file_type);"
    "CREATE INDEX IF NOT EXISTS idx_file_in_size ON file_in(file_sizeBy);"
    "CREATE TABLE IF NOT EXISTS file_total ("
    "    id INTEGER PRIMARY KEY CHECK(id=1),"
    "    total_file_num INTEGER NOT NULL DEFAULT 0,"
    "    total_sizeByte INTEGER NOT NULL DEFAULT 0,"
    "    total_type_num INTEGER NOT NULL DEFAULT 0,"
    "    last_update    INTEGER NOT NULL DEFAULT 0"
    ");"
    "INSERT OR IGNORE INTO file_total(id,total_file_num,total_sizeByte,total_type_num,last_update) VALUES(1,0,0,0,0);"
    "CREATE TABLE IF NOT EXISTS api_keys ("
    "    key_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    api_key TEXT UNIQUE NOT NULL,"
    "    label TEXT,"
    "    created TEXT NOT NULL DEFAULT(datetime('now','localtime')),"
    "    enabled INTEGER NOT NULL DEFAULT 1"
    ");"
    "CREATE TABLE IF NOT EXISTS file_verify ("
    "    id INTEGER PRIMARY KEY CHECK(id=1),"
    "    verified_files  INTEGER NOT NULL DEFAULT 0,"
    "    verify_count    INTEGER NOT NULL DEFAULT 0,"
    "    scan_count      INTEGER NOT NULL DEFAULT 0,"
    "    scan_interval   INTEGER NOT NULL DEFAULT 0,"
    "    corrupt_count   INTEGER NOT NULL DEFAULT 0,"
    "    missing_count   INTEGER NOT NULL DEFAULT 0,"
    "    last_verify     TEXT NOT NULL DEFAULT '',"
    "    last_scan       TEXT NOT NULL DEFAULT '',"
    "    last_duration_ms INTEGER NOT NULL DEFAULT 0"
    ");"
    "INSERT OR IGNORE INTO file_verify(id) VALUES(1);"
    "CREATE TABLE IF NOT EXISTS schema_meta (k TEXT PRIMARY KEY, v TEXT);";

/* 返回码检查封装 */
static int db_prepare(const char* sql, sqlite3_stmt** st)
{
    int rc;
    if (!s_db) return -1;
    rc = sqlite3_prepare_v2(s_db, sql, -1, st, NULL);
    if (rc != SQLITE_OK) {
        HD_LOGE("DB", "prepare 失败 rc=%d msg=%s sql=%.120s", rc, sqlite3_errmsg(s_db), sql);
        *st = NULL;
        return -1;
    }
    return 0;
}

/* SQLITE_ROW / SQLITE_DONE 之外都算错误 */
static int db_step_rc(sqlite3_stmt* st, const char* what)
{
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        HD_LOGE("DB", "%s step 失败 rc=%d msg=%s", what, rc, sqlite3_errmsg(s_db));
    }
    return rc;
}

static int db_exec(const char* sql, const char* what)
{
    char* err = NULL;
    int rc;
    if (!s_db) return -1;
    rc = sqlite3_exec(s_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        HD_LOGE("DB", "%s exec 失败 rc=%d msg=%s", what, rc, err ? err : sqlite3_errmsg(s_db));
        if (err) sqlite3_free(err);
        return -1;
    }
    if (err) sqlite3_free(err);
    return 0;
}

/* 迁移：列不存在时补列（SQLite 无 IF NOT EXISTS for column） */
static void ensure_column(const char* table, const char* column, const char* decl)
{
    sqlite3_stmt* st = NULL;
    int found = 0;
    char sql[256];

    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (db_prepare(sql, &st) != 0) return;
    while (db_step_rc(st, "table_info") == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(st, 1);
        if (name && strcmp(name, column) == 0) { found = 1; break; }
    }
    sqlite3_finalize(st);
    if (found) return;

    snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s", table, column, decl);
    if (db_exec(sql, "迁移补列") == 0)
        HD_LOGI("DB", "已补列 %s.%s", table, column);
}

/* ==========================================================================
 * 打开 / 关闭
 * ========================================================================== */
int hd_db_open(const char* db_path)
{
    char* err = NULL;

    if (!db_path) return -1;
    if (!s_lk_ok) {
        if (hd_mutex_init(&s_lk) != 0) return -1;
        s_lk_ok = 1;
    }
    snprintf(s_db_path, sizeof(s_db_path), "%s", db_path);

    if (sqlite3_open(db_path, &s_db) != SQLITE_OK) {
        HD_LOGE("DB", "打开失败: %s (%s)", db_path, s_db ? sqlite3_errmsg(s_db) : "?");
        if (s_db) { sqlite3_close(s_db); s_db = NULL; }
        return -1;
    }

    sqlite3_busy_timeout(s_db, 5000);

    /* WAL 必须真的生效，否则 sync-database 会发出缺数据的库 */
    if (sqlite3_exec(s_db, "PRAGMA journal_mode=WAL", NULL, NULL, &err) != SQLITE_OK) {
        HD_LOGW("DB", "WAL 设置失败: %s", err ? err : "?");
    }
    if (err) { sqlite3_free(err); err = NULL; }
    if (sqlite3_exec(s_db, "PRAGMA synchronous=NORMAL", NULL, NULL, &err) != SQLITE_OK) {
        HD_LOGW("DB", "synchronous 设置失败: %s", err ? err : "?");
    }
    if (err) { sqlite3_free(err); err = NULL; }

    /* DDL 包在事务里，避免中途失败留下半套 schema */
    if (db_exec("BEGIN IMMEDIATE", "DDL BEGIN") != 0) return -1;
    if (db_exec(DDL, "DDL") != 0) {
        db_exec("ROLLBACK", "DDL ROLLBACK");
        sqlite3_close(s_db);
        s_db = NULL;
        return -1;
    }
    if (db_exec("COMMIT", "DDL COMMIT") != 0) { sqlite3_close(s_db); s_db = NULL; return -1; }

    ensure_column("file_verify", "missing_count", "INTEGER NOT NULL DEFAULT 0");
    ensure_column("file_verify", "last_duration_ms", "INTEGER NOT NULL DEFAULT 0");
    ensure_column("file_in", "file_type", "TEXT NOT NULL DEFAULT ''");

    {
        char mode[32];
        sqlite3_stmt* st = NULL;
        mode[0] = '\0';
        if (db_prepare("PRAGMA journal_mode", &st) == 0) {
            if (db_step_rc(st, "journal_mode") == SQLITE_ROW) {
                const char* m = (const char*)sqlite3_column_text(st, 0);
                if (m) snprintf(mode, sizeof(mode), "%s", m);
            }
            sqlite3_finalize(st);
        }
        HD_LOGI("DB", "已打开 %s (journal_mode=%s)", db_path, mode[0] ? mode : "?");
        if (strcmp(mode, "wal") != 0)
            HD_LOGW("DB", "journal_mode 不是 wal，sync-database 前会强制 checkpoint");
    }
    return 0;
}

void hd_db_close(void)
{
    if (s_db) {
        sqlite3_wal_checkpoint_v2(s_db, NULL, SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL);
        sqlite3_close(s_db);
        s_db = NULL;
    }
    if (s_lk_ok) { hd_mutex_destroy(&s_lk); s_lk_ok = 0; }
}

int hd_db_checkpoint(void)
{
    int rc, log_frames = 0, ckpt_frames = 0;
    if (!s_db) return -1;
    DB_LOCK();
    rc = sqlite3_wal_checkpoint_v2(s_db, NULL, SQLITE_CHECKPOINT_TRUNCATE, &log_frames, &ckpt_frames);
    DB_UNLOCK();
    if (rc != SQLITE_OK) {
        HD_LOGW("DB", "checkpoint 失败 rc=%d msg=%s", rc, sqlite3_errmsg(s_db));
        return -1;
    }
    HD_LOGI("DB", "checkpoint 完成 (wal=%d, 已写入主库=%d)", log_frames, ckpt_frames);
    return 0;
}

/*
 * 生成一致性快照（用于 sync-database）
 *
 * 为什么不能"直接把这个库文件流给客户端"：
 *   1) 库处于 WAL 模式，最新记录还在 -wal 里，checkpoint 之前主库是旧的；
 *   2) 即使先 checkpoint，把文件流出去的过程中，别的线程（或另一台客户端同时
 *      同步）还可能再 checkpoint，把页写回主库 —— 于是客户端收到的是**半新半旧**
 *      的库。字节数照样对得上，客户端无从发现，最后是"索引看着正常但查不到刚加的文件"。
 *   SQLite 自己提供了正确做法：backup API 逐页复制一个**已提交**的一致视图。
 *   快照文件在发送期间不会再变，于是"头发里的 hash"就等于"实际发出的字节"。
 *
 * 全程持 DB_LOCK：既保证不和本进程的写线程交错，也顺带把"两个客户端同时同步"
 * 串行化（第二个会等第一个复制完）。DB 通常只有几百 KB，持锁时间以毫秒计。
 */
int hd_db_snapshot(const char* dst_path)
{
    sqlite3* dst = NULL;
    sqlite3_backup* bk;
    int rc = SQLITE_OK;
    int log_frames = 0, ckpt_frames = 0;

    if (!s_db || !dst_path || !dst_path[0]) return -1;

    DB_LOCK();

    /* 先 checkpoint：让 -wal 落回主库，快照才不会漏掉最近的写入 */
    (void)sqlite3_wal_checkpoint_v2(s_db, NULL, SQLITE_CHECKPOINT_TRUNCATE, &log_frames, &ckpt_frames);

    if (sqlite3_open(dst_path, &dst) != SQLITE_OK) {
        HD_LOGE("DB", "快照文件打开失败: %s（%s）", dst_path, dst ? sqlite3_errmsg(dst) : "?");
        if (dst) sqlite3_close(dst);
        DB_UNLOCK();
        return -1;
    }

    bk = sqlite3_backup_init(dst, "main", s_db, "main");
    if (!bk) {
        HD_LOGE("DB", "backup_init 失败: %s", sqlite3_errmsg(dst));
        sqlite3_close(dst);
        DB_UNLOCK();
        return -1;
    }

    do {
        rc = sqlite3_backup_step(bk, 512);
        if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) hd_sleep_ms(2);
    } while (rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED);

    (void)sqlite3_backup_finish(bk);

    if (rc != SQLITE_DONE) {
        HD_LOGE("DB", "快照失败 rc=%d（%s）", rc, sqlite3_errmsg(dst));
        rc = -1;
    } else {
        rc = 0;
    }
    sqlite3_close(dst);
    DB_UNLOCK();

    if (rc == 0) {
        HD_LOGI("DB", "已生成一致性快照: %s (checkpoint wal=%d/写回=%d)", dst_path, log_frames, ckpt_frames);
    }
    return rc;
}

/* ==========================================================================
 * 写操作（*_locked 内部不加锁）
 * ========================================================================== */
static int update_total_locked(void)
{
    /* 单条 UPDATE 内完成聚合，避免多次持锁往返 */
    return db_exec(
        "UPDATE file_total SET "
        "  total_file_num=(SELECT COUNT(*) FROM file_in),"
        "  total_sizeByte=(SELECT COALESCE(SUM(file_sizeBy),0) FROM file_in),"
        "  total_type_num=(SELECT COUNT(DISTINCT file_type) FROM file_in WHERE file_type<>''),"
        "  last_update=strftime('%s','now') "
        "WHERE id=1",
        "update_total");
}

static int upsert_locked(const char* abs_path, const char* hash)
{
    hd_file_info info;
    char name[512];
    char ext[64];
    char stamp[64];
    sqlite3_stmt* st = NULL;
    int rc;

    if (hd_stat64(abs_path, &info) != 0) return -1;

    snprintf(name, sizeof(name), "%s", hd_basename(abs_path));
    hd_ext_lower(name, ext, sizeof(ext));
    hd_iso_local(stamp, sizeof(stamp));

    if (db_prepare(
        "INSERT INTO file_in(xxHash3_128,file_name,file_path,file_type,file_sizeBy,change_dateT,file_readme) "
        "VALUES(@hash,@name,@path,@type,@size,@date,'') "
        "ON CONFLICT(file_path) DO UPDATE SET "
        "  xxHash3_128=@hash, file_name=@name, file_type=@type, "
        "  file_sizeBy=@size, change_dateT=@date",
        &st) != 0) return -1;

    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, "@hash"), hash ? hash : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, "@name"), name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, "@path"), abs_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, "@type"), ext, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, sqlite3_bind_parameter_index(st, "@size"), (sqlite3_int64)info.size);
    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, "@date"), stamp, -1, SQLITE_TRANSIENT);

    rc = db_step_rc(st, "upsert");
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int hd_db_upsert_file(const char* abs_path, const char* hash)
{
    int r;
    if (!s_db || !abs_path) return -1;
    DB_LOCK();
    r = upsert_locked(abs_path, hash);
    if (r == 0) update_total_locked();
    DB_UNLOCK();
    return r;
}

int hd_db_delete_file(const char* abs_path)
{
    sqlite3_stmt* st = NULL;
    int rc;

    if (!s_db || !abs_path) return -1;
    DB_LOCK();
    if (db_prepare("DELETE FROM file_in WHERE file_path=?", &st) != 0) { DB_UNLOCK(); return -1; }
    sqlite3_bind_text(st, 1, abs_path, -1, SQLITE_TRANSIENT);
    rc = db_step_rc(st, "delete_file");
    sqlite3_finalize(st);
    update_total_locked();
    DB_UNLOCK();
    return (rc == SQLITE_DONE) ? 0 : -1;
}

static void escape_like(const char* in, char* out, size_t n)
{
    size_t w = 0;
    size_t i;
    for (i = 0; in && in[i] && w + 3 < n; i++) {
        if (in[i] == '%' || in[i] == '_' || in[i] == '\\') out[w++] = '\\';
        out[w++] = in[i];
    }
    if (n) out[w] = '\0';
}

int hd_db_delete_dir(const char* abs_dir)
{
    char esc[HD_PATH_MAX];
    char pattern[HD_PATH_MAX + 8];
    sqlite3_stmt* st = NULL;
    int rc;

    if (!s_db || !abs_dir) return -1;
    escape_like(abs_dir, esc, sizeof(esc));
    snprintf(pattern, sizeof(pattern), "%s%c%%", esc, HD_PATH_SEP);

    DB_LOCK();
    if (db_prepare("DELETE FROM file_in WHERE file_path LIKE ? ESCAPE '\\'", &st) != 0) { DB_UNLOCK(); return -1; }
    sqlite3_bind_text(st, 1, pattern, -1, SQLITE_TRANSIENT);
    rc = db_step_rc(st, "delete_dir");
    sqlite3_finalize(st);
    update_total_locked();
    DB_UNLOCK();
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int hd_db_update_total(void)
{
    int r;
    if (!s_db) return -1;
    DB_LOCK();
    r = update_total_locked();
    DB_UNLOCK();
    return r;
}

int hd_db_file_hash(const char* abs_path, char* out_hex33)
{
    sqlite3_stmt* st = NULL;
    int found = 0;

    if (!out_hex33) return -1;
    out_hex33[0] = '\0';
    if (!s_db || !abs_path) return -1;

    DB_LOCK();
    if (db_prepare("SELECT COALESCE(xxHash3_128,'') FROM file_in WHERE file_path=?", &st) == 0) {
        sqlite3_bind_text(st, 1, abs_path, -1, SQLITE_TRANSIENT);
        if (db_step_rc(st, "file_hash") == SQLITE_ROW) {
            const char* h = (const char*)sqlite3_column_text(st, 0);
            snprintf(out_hex33, 33, "%s", h ? h : "");
            found = 1;
        }
        sqlite3_finalize(st);
    }
    DB_UNLOCK();
    return found ? 0 : -1;
}

/* ==========================================================================
 * 目录扫描（哈希在锁外计算，只把结果写库）
 * ========================================================================== */
#ifdef _WIN32
    /* windows.h / winsock2.h 由 hd_util.h 统一引入 */
#else
    #include <dirent.h>
    #include <sys/stat.h>
#endif

int hd_db_scan_dir(const char* abs_dir, int depth, hd_scan_stat* st)
{
    if (depth > 64) {
        HD_LOGW("SCAN", "超过最大深度，跳过: %s", abs_dir);
        return -1;
    }

#ifdef _WIN32
    {
        wchar_t wdir[HD_PATH_MAX];
        wchar_t wsearch[HD_PATH_MAX + 4];
        WIN32_FIND_DATAW fd;
        HANDLE h;

        if (MultiByteToWideChar(CP_UTF8, 0, abs_dir, -1, wdir, HD_PATH_MAX) <= 0) return -1;
        _snwprintf(wsearch, HD_PATH_MAX + 4, L"%s\\*", wdir);
        h = FindFirstFileW(wsearch, &fd);
        if (h == INVALID_HANDLE_VALUE) return -1;

        do {
            char name[1024];
            char full[HD_PATH_MAX];
            int conv;

            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            conv = WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, name, sizeof(name), NULL, NULL);
            if (conv <= 0) {
                HD_LOGW("SCAN", "文件名转 UTF-8 失败，跳过（dir=%s）", abs_dir);
                continue;                       /* 修 P1-17：不再用未初始化缓冲 */
            }

            if (hd_is_artifact_name(name)) continue;    /* 跳过中转文件与自身日志/数据库 */

            hd_path_join(full, sizeof(full), abs_dir, name);

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;   /* 不跟随重解析点 */

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                hd_db_scan_dir(full, depth + 1, st);
            } else {
                char hash[33];
                if (st) st->visited++;
                if (hd_hash_file(full, hash) == 0) {
                    if (hd_db_upsert_file(full, hash) == 0) { if (st) st->indexed++; }
                    else if (st) st->failed++;
                } else if (st) st->failed++;
            }
        } while (FindNextFileW(h, &fd));

        FindClose(h);
    }
#else
    {
        DIR* d = opendir(abs_dir);
        struct dirent* e;
        if (!d) return -1;
        while ((e = readdir(d)) != NULL) {
            char full[HD_PATH_MAX];
            hd_file_info info;

            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
            if (hd_is_artifact_name(e->d_name)) continue;
            hd_path_join(full, sizeof(full), abs_dir, e->d_name);
            if (hd_stat64(full, &info) != 0) continue;

            if (info.is_dir) {
                hd_db_scan_dir(full, depth + 1, st);
            } else {
                char hash[33];
                if (st) st->visited++;
                if (hd_hash_file(full, hash) == 0) {
                    if (hd_db_upsert_file(full, hash) == 0) { if (st) st->indexed++; }
                    else if (st) st->failed++;
                } else if (st) st->failed++;
            }
        }
        closedir(d);
    }
#endif
    return 0;
}

int hd_db_scan_all(const char* abs_root, hd_scan_stat* st)
{
    hd_scan_stat local;
    int64_t t0 = hd_now_ms();

    if (st) memset(st, 0, sizeof(*st));
    local.visited = local.indexed = local.failed = 0;

    if (hd_db_scan_dir(abs_root, 0, &local) != 0 && local.visited == 0) {
        HD_LOGE("SCAN", "扫描失败: %s", abs_root);
        if (st) *st = local;
        return -1;
    }

    hd_db_update_total();
    hd_db_bump_scan_count();
    HD_LOGI("SCAN", "完成: 访问=%d 入库=%d 失败=%d 耗时=%lldms",
            local.visited, local.indexed, local.failed, (long long)(hd_now_ms() - t0));
    if (st) *st = local;
    return 0;
}

/* ==========================================================================
 * 统计 / 查询 / 校验状态
 * ========================================================================== */
int hd_db_stats_json(char* out, size_t n)
{
    hd_sb sb;
    sqlite3_stmt* st = NULL;
    int first = 1;

    if (!s_db || !out || n == 0) return -1;
    out[0] = '\0';
    hd_sb_init(&sb, out, n);

    DB_LOCK();
    hd_sb_puts(&sb, "{");

    if (db_prepare("SELECT total_file_num,total_sizeByte,total_type_num,last_update FROM file_total WHERE id=1", &st) == 0) {
        if (db_step_rc(st, "stats_total") == SQLITE_ROW) {
            hd_sb_printf(&sb, "\"total_files\":%lld,\"total_size\":%lld,\"file_type_count\":%d,\"last_update\":%lld",
                         sqlite3_column_int64(st, 0), sqlite3_column_int64(st, 1),
                         sqlite3_column_int(st, 2), sqlite3_column_int64(st, 3));
        } else {
            hd_sb_puts(&sb, "\"total_files\":0,\"total_size\":0,\"file_type_count\":0,\"last_update\":0");
        }
        sqlite3_finalize(st);
        st = NULL;
    } else {
        hd_sb_puts(&sb, "\"total_files\":0,\"total_size\":0,\"file_type_count\":0,\"last_update\":0");
    }

    hd_sb_puts(&sb, ",\"file_types\":[");
    if (db_prepare("SELECT file_type,COUNT(*),COALESCE(SUM(file_sizeBy),0) FROM file_in "
                   "WHERE file_type<>'' GROUP BY file_type ORDER BY COUNT(*) DESC LIMIT 50", &st) == 0) {
        while (db_step_rc(st, "stats_types") == SQLITE_ROW) {
            const char* ext = (const char*)sqlite3_column_text(st, 0);
            if (!first) hd_sb_puts(&sb, ",");
            first = 0;
            hd_sb_puts(&sb, "{\"ext\":");
            if (ext) { hd_sb_puts(&sb, "\""); hd_sb_json(&sb, ext); hd_sb_puts(&sb, "\""); }
            else hd_sb_puts(&sb, "\"\"");
            hd_sb_printf(&sb, ",\"count\":%d,\"size_bytes\":%lld}",
                         sqlite3_column_int(st, 1), sqlite3_column_int64(st, 2));
            if (!hd_sb_ok(&sb)) break;
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    hd_sb_puts(&sb, "]");
    DB_UNLOCK();

    hd_sb_printf(&sb, ",\"monitor_path\":\"");
    hd_sb_json(&sb, g_cfg.monitor_path);
    hd_sb_puts(&sb, "\"}");

    if (!hd_sb_ok(&sb)) { out[n - 1] = '\0'; return -1; }
    return 0;
}

static const char* order_by_clause(const char* sort)
{
    /* 白名单映射，绝不把客户端文本拼进 SQL */
    if (!sort || !sort[0]) return " ORDER BY file_path ASC";
    {
        int desc = (sort[0] == '-') ? 1 : 0;
        const char* key = desc ? sort + 1 : sort;
        const char* col = NULL;

        if (strcmp(key, "name") == 0)          col = "file_name";
        else if (strcmp(key, "size") == 0)     col = "file_sizeBy";
        else if (strcmp(key, "modified") == 0) col = "change_dateT";
        else if (strcmp(key, "type") == 0)     col = "file_type";
        else if (strcmp(key, "path") == 0)     col = "file_path";

        if (!col) return " ORDER BY file_path ASC";
        return desc ? (strcmp(col, "file_name") == 0 ? " ORDER BY file_name DESC" :
                       strcmp(col, "file_sizeBy") == 0 ? " ORDER BY file_sizeBy DESC" :
                       strcmp(col, "change_dateT") == 0 ? " ORDER BY change_dateT DESC" :
                       strcmp(col, "file_type") == 0 ? " ORDER BY file_type DESC" :
                                                        " ORDER BY file_path DESC")
                    : (strcmp(col, "file_name") == 0 ? " ORDER BY file_name ASC" :
                       strcmp(col, "file_sizeBy") == 0 ? " ORDER BY file_sizeBy ASC" :
                       strcmp(col, "change_dateT") == 0 ? " ORDER BY change_dateT ASC" :
                       strcmp(col, "file_type") == 0 ? " ORDER BY file_type ASC" :
                                                        " ORDER BY file_path ASC");
    }
}

int hd_db_search_json(const hd_search_query* q, char* out, size_t n)
{
    hd_sb sb;
    sqlite3_stmt* st = NULL;
    char sql[1024];
    char like[600];
    int limit, offset;
    int64_t total = 0;
    const char* qtext = (q && q->q) ? q->q : "";
    const char* type  = (q && q->type) ? q->type : "";
    int64_t smin = q ? q->size_min : 0;
    int64_t smax = q ? q->size_max : 0;

    if (!s_db || !out || n == 0) return -1;
    out[0] = '\0';

    limit  = (q && q->limit > 0) ? q->limit : 200;
    if (limit > HD_SEARCH_MAX) limit = HD_SEARCH_MAX;
    offset = (q && q->offset > 0) ? q->offset : 0;

    /* 条件构造只用占位符，参数一律绑定 */
    snprintf(sql, sizeof(sql),
             "SELECT xxHash3_128,file_name,file_path,file_type,file_sizeBy,change_dateT FROM file_in WHERE 1=1");
    if (qtext[0])  strncat(sql, " AND (file_name LIKE ? ESCAPE '\\' OR file_path LIKE ? ESCAPE '\\')", sizeof(sql) - strlen(sql) - 1);
    if (type[0])   strncat(sql, " AND file_type=?", sizeof(sql) - strlen(sql) - 1);
    if (smin > 0)  strncat(sql, " AND file_sizeBy>=?", sizeof(sql) - strlen(sql) - 1);
    if (smax > 0)  strncat(sql, " AND file_sizeBy<=?", sizeof(sql) - strlen(sql) - 1);

    {
        /* 计数查询：同样的条件，用于返回 total 以便前端分页 */
        char csql[1024];
        sqlite3_stmt* cst = NULL;
        snprintf(csql, sizeof(csql), "SELECT COUNT(*) FROM file_in WHERE 1=1");
        if (qtext[0])  strncat(csql, " AND (file_name LIKE ? ESCAPE '\\' OR file_path LIKE ? ESCAPE '\\')", sizeof(csql) - strlen(csql) - 1);
        if (type[0])   strncat(csql, " AND file_type=?", sizeof(csql) - strlen(csql) - 1);
        if (smin > 0)  strncat(csql, " AND file_sizeBy>=?", sizeof(csql) - strlen(csql) - 1);
        if (smax > 0)  strncat(csql, " AND file_sizeBy<=?", sizeof(csql) - strlen(csql) - 1);

        DB_LOCK();
        if (db_prepare(csql, &cst) == 0) {
            int idx = 1;
            if (qtext[0]) {
                snprintf(like, sizeof(like), "%%%s%%", qtext);
                sqlite3_bind_text(cst, idx++, like, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(cst, idx++, like, -1, SQLITE_TRANSIENT);
            }
            if (type[0])  sqlite3_bind_text(cst, idx++, type, -1, SQLITE_TRANSIENT);
            if (smin > 0) sqlite3_bind_int64(cst, idx++, smin);
            if (smax > 0) sqlite3_bind_int64(cst, idx++, smax);
            if (db_step_rc(cst, "search_count") == SQLITE_ROW) total = sqlite3_column_int64(cst, 0);
            sqlite3_finalize(cst);
        }
        DB_UNLOCK();
    }

    strncat(sql, order_by_clause(q ? q->sort : NULL), sizeof(sql) - strlen(sql) - 1);
    {
        char tail[64];
        snprintf(tail, sizeof(tail), " LIMIT %d OFFSET %d", limit, offset);
        strncat(sql, tail, sizeof(sql) - strlen(sql) - 1);
    }

    hd_sb_init(&sb, out, n);
    hd_sb_printf(&sb, "{\"total\":%lld,\"limit\":%d,\"offset\":%d,\"files\":[", (long long)total, limit, offset);

    DB_LOCK();
    if (db_prepare(sql, &st) == 0) {
        int idx = 1;
        int first = 1;

        if (qtext[0]) {
            snprintf(like, sizeof(like), "%%%s%%", qtext);
            sqlite3_bind_text(st, idx++, like, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, idx++, like, -1, SQLITE_TRANSIENT);
        }
        if (type[0])  sqlite3_bind_text(st, idx++, type, -1, SQLITE_TRANSIENT);
        if (smin > 0) sqlite3_bind_int64(st, idx++, smin);
        if (smax > 0) sqlite3_bind_int64(st, idx++, smax);

        while (db_step_rc(st, "search") == SQLITE_ROW) {
            const char* hash  = (const char*)sqlite3_column_text(st, 0);
            const char* name  = (const char*)sqlite3_column_text(st, 1);
            const char* path  = (const char*)sqlite3_column_text(st, 2);
            const char* etype = (const char*)sqlite3_column_text(st, 3);
            const char* date  = (const char*)sqlite3_column_text(st, 5);

            if (!first) hd_sb_puts(&sb, ",");
            first = 0;

            hd_sb_puts(&sb, "{\"hash\":\"");
            hd_sb_json(&sb, hash ? hash : "");
            hd_sb_puts(&sb, "\",\"name\":\"");
            hd_sb_json(&sb, name ? name : "");
            hd_sb_puts(&sb, "\",\"path\":\"");
            hd_sb_json(&sb, path ? path : "");
            hd_sb_puts(&sb, "\",\"type\":\"");
            hd_sb_json(&sb, etype ? etype : "");
            hd_sb_printf(&sb, "\",\"size\":%lld,\"modified\":\"",
                         sqlite3_column_int64(st, 4));
            hd_sb_json(&sb, date ? date : "");
            hd_sb_puts(&sb, "\"}");

            if (!hd_sb_ok(&sb)) break;
        }
        sqlite3_finalize(st);
    }
    DB_UNLOCK();

    hd_sb_puts(&sb, "]}");
    if (!hd_sb_ok(&sb)) { out[n - 1] = '\0'; return -1; }
    return 0;
}

int hd_db_verify_json(char* out, size_t n)
{
    hd_sb sb;
    sqlite3_stmt* st = NULL;

    if (!s_db || !out || n == 0) return -1;
    out[0] = '\0';
    hd_sb_init(&sb, out, n);

    DB_LOCK();
    if (db_prepare("SELECT verified_files,verify_count,scan_count,scan_interval,corrupt_count,"
                   "missing_count,last_verify,last_scan,last_duration_ms FROM file_verify WHERE id=1", &st) == 0) {
        if (db_step_rc(st, "verify_json") == SQLITE_ROW) {
            const char* lv = (const char*)sqlite3_column_text(st, 6);
            const char* ls = (const char*)sqlite3_column_text(st, 7);
            hd_sb_puts(&sb, "{\"verified_files\":");
            hd_sb_printf(&sb, "%d,\"verify_count\":%d,\"scan_count\":%d,\"scan_interval\":%d,"
                              "\"corrupt_count\":%d,\"missing_count\":%d,\"last_duration_ms\":%d,",
                         sqlite3_column_int(st, 0), sqlite3_column_int(st, 1),
                         sqlite3_column_int(st, 2), sqlite3_column_int(st, 3),
                         sqlite3_column_int(st, 4), sqlite3_column_int(st, 5),
                         sqlite3_column_int(st, 8));
            hd_sb_puts(&sb, "\"last_verify\":\"");
            hd_sb_json(&sb, lv ? lv : "");
            hd_sb_puts(&sb, "\",\"last_scan\":\"");
            hd_sb_json(&sb, ls ? ls : "");
            hd_sb_puts(&sb, "\"}");
        } else {
            hd_sb_puts(&sb, "{\"verified_files\":0,\"verify_count\":0,\"scan_count\":0,\"scan_interval\":0,"
                            "\"corrupt_count\":0,\"missing_count\":0,\"last_duration_ms\":0,"
                            "\"last_verify\":\"\",\"last_scan\":\"\"}");
        }
        sqlite3_finalize(st);
    } else {
        hd_sb_puts(&sb, "{\"verified_files\":0,\"verify_count\":0,\"scan_count\":0,\"scan_interval\":0,"
                        "\"corrupt_count\":0,\"missing_count\":0,\"last_duration_ms\":0,"
                        "\"last_verify\":\"\",\"last_scan\":\"\"}");
    }
    DB_UNLOCK();

    if (!hd_sb_ok(&sb)) { out[n - 1] = '\0'; return -1; }
    return 0;
}

int hd_db_record_verify(int total, int ok, int corrupt, int missing, int scan_interval_min)
{
    sqlite3_stmt* st = NULL;
    int rc;

    (void)total;
    if (!s_db) return -1;

    DB_LOCK();
    if (db_prepare("UPDATE file_verify SET verified_files=?,verify_count=verify_count+1,"
                   "corrupt_count=?,missing_count=?,scan_interval=?,"
                   "last_verify=datetime('now','localtime'),last_duration_ms=? WHERE id=1", &st) != 0) {
        DB_UNLOCK();
        return -1;
    }
    sqlite3_bind_int(st, 1, ok);
    sqlite3_bind_int(st, 2, corrupt);
    sqlite3_bind_int(st, 3, missing);
    sqlite3_bind_int(st, 4, scan_interval_min);
    sqlite3_bind_int(st, 5, 0);
    rc = db_step_rc(st, "record_verify");
    sqlite3_finalize(st);
    DB_UNLOCK();
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int hd_db_bump_scan_count(void)
{
    if (!s_db) return -1;
    DB_LOCK();
    db_exec("UPDATE file_verify SET scan_count=scan_count+1,last_scan=datetime('now','localtime') WHERE id=1",
            "bump_scan");
    DB_UNLOCK();
    return 0;
}

int hd_db_set_scan_interval(int minutes)
{
    sqlite3_stmt* st = NULL;
    int rc;

    if (!s_db) return -1;
    DB_LOCK();
    if (db_prepare("UPDATE file_verify SET scan_interval=? WHERE id=1", &st) != 0) { DB_UNLOCK(); return -1; }
    sqlite3_bind_int(st, 1, minutes);
    rc = db_step_rc(st, "set_scan_interval");
    sqlite3_finalize(st);
    DB_UNLOCK();
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ==========================================================================
 * 完整性校验：锁内取快照 → 锁外哈希 → 锁内写回
 * ========================================================================== */
typedef struct {
    char** items;
    int    count;
    int    cap;
} strvec;

static int vec_push(strvec* v, const char* s)
{
    if (v->count >= v->cap) {
        int ncap = v->cap ? v->cap * 2 : 256;
        char** ni = (char**)realloc(v->items, (size_t)ncap * sizeof(char*));
        if (!ni) return -1;
        v->items = ni;
        v->cap = ncap;
    }
    v->items[v->count] = strdup(s ? s : "");
    if (!v->items[v->count]) return -1;
    v->count++;
    return 0;
}

static void vec_free(strvec* v)
{
    int i;
    for (i = 0; i < v->count; i++) free(v->items[i]);
    free(v->items);
    v->items = NULL;
    v->count = v->cap = 0;
}

int hd_db_integrity_check(int* total, int* ok, int* corrupt, int* missing, int prune_missing)
{
    strvec paths;
    strvec hashes;
    sqlite3_stmt* st = NULL;
    int i;
    int n_ok = 0, n_corrupt = 0, n_missing = 0;
    int64_t t0 = hd_now_ms();

    memset(&paths, 0, sizeof(paths));
    memset(&hashes, 0, sizeof(hashes));

    if (total) *total = 0;
    if (ok) *ok = 0;
    if (corrupt) *corrupt = 0;
    if (missing) *missing = 0;
    if (!s_db) return 0;

    /* 1) 锁内取快照，随后立即释放锁 */
    DB_LOCK();
    if (db_prepare("SELECT file_path, COALESCE(xxHash3_128,'') FROM file_in", &st) == 0) {
        while (db_step_rc(st, "integrity_snapshot") == SQLITE_ROW) {
            const char* p = (const char*)sqlite3_column_text(st, 0);
            const char* h = (const char*)sqlite3_column_text(st, 1);
            if (!p) continue;
            if (vec_push(&paths, p) != 0) break;
            if (vec_push(&hashes, h) != 0) break;
        }
        sqlite3_finalize(st);
    }
    DB_UNLOCK();

    /* 2) 锁外逐文件校验 */
    for (i = 0; i < paths.count; i++) {
        hd_file_info info;
        char actual[33];

        if (g_stop) break;

        if (hd_stat64(paths.items[i], &info) != 0 || info.is_dir) { n_missing++; continue; }
        if (hashes.items[i][0] == '\0') { n_missing++; continue; }        /* 无哈希视为待校验 */
        if (hd_hash_file(paths.items[i], actual) != 0) { n_missing++; continue; }
        if (strcmp(hashes.items[i], actual) == 0) n_ok++;
        else {
            HD_LOGW("VERIFY", "内容不一致: %s (库=%s 实际=%s)", paths.items[i], hashes.items[i], actual);
            n_corrupt++;
        }
    }

    /* 3) 锁内写回；可选清理已不存在的记录 */
    DB_LOCK();
    if (prune_missing && n_missing > 0) {
        for (i = 0; i < paths.count; i++) {
            hd_file_info info;
            if (hd_stat64(paths.items[i], &info) != 0) {
                sqlite3_stmt* d = NULL;
                if (db_prepare("DELETE FROM file_in WHERE file_path=?", &d) == 0) {
                    sqlite3_bind_text(d, 1, paths.items[i], -1, SQLITE_TRANSIENT);
                    db_step_rc(d, "prune_missing");
                    sqlite3_finalize(d);
                }
            }
        }
        update_total_locked();
    }
    DB_UNLOCK();

    vec_free(&paths);
    vec_free(&hashes);

    HD_LOGI("VERIFY", "完整性校验完成: 总计=%d 正常=%d 内容不一致=%d 缺失=%d 耗时=%lldms",
            n_ok + n_corrupt + n_missing, n_ok, n_corrupt, n_missing,
            (long long)(hd_now_ms() - t0));

    if (total) *total = n_ok + n_corrupt + n_missing;
    if (ok) *ok = n_ok;
    if (corrupt) *corrupt = n_corrupt;
    if (missing) *missing = n_missing;
    return g_stop ? 0 : 1;
}

/* ==========================================================================
 * API 密钥
 * ========================================================================== */
int hd_db_key_add(const char* label, char* out_key, size_t n)
{
    char key[80];
    sqlite3_stmt* st = NULL;
    int rc;

    if (!s_db || !out_key || n < 4) return -1;
    out_key[0] = '\0';

    hd_generate_api_key(key, sizeof(key));

    DB_LOCK();
    if (db_prepare("INSERT INTO api_keys(api_key,label,enabled) VALUES(?,?,1)", &st) != 0) { DB_UNLOCK(); return -1; }
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, label ? label : "", -1, SQLITE_TRANSIENT);
    rc = db_step_rc(st, "key_add");
    sqlite3_finalize(st);
    DB_UNLOCK();

    if (rc != SQLITE_DONE) return -1;
    snprintf(out_key, n, "%s", key);
    HD_LOGI("KEY", "已创建 API 密钥 (label=%s)", label ? label : "");
    return 0;
}

int hd_db_key_list(char* out, size_t n)
{
    hd_sb sb;
    sqlite3_stmt* st = NULL;
    int first = 1;

    if (!s_db || !out || n == 0) return -1;
    out[0] = '\0';
    hd_sb_init(&sb, out, n);
    hd_sb_puts(&sb, "{\"keys\":[");

    DB_LOCK();
    if (db_prepare("SELECT key_id,COALESCE(label,''),created,enabled,api_key FROM api_keys ORDER BY key_id", &st) == 0) {
        while (db_step_rc(st, "key_list") == SQLITE_ROW) {
            const char* label = (const char*)sqlite3_column_text(st, 1);
            const char* created = (const char*)sqlite3_column_text(st, 2);
            const char* key = (const char*)sqlite3_column_text(st, 4);
            char masked[16];

            /* 只返回前缀，完整密钥不再次下发 */
            snprintf(masked, sizeof(masked), "%.6s...", key ? key : "");

            if (!first) hd_sb_puts(&sb, ",");
            first = 0;
            hd_sb_printf(&sb, "{\"id\":%d,\"label\":\"", sqlite3_column_int(st, 0));
            hd_sb_json(&sb, label ? label : "");
            hd_sb_puts(&sb, "\",\"created\":\"");
            hd_sb_json(&sb, created ? created : "");
            hd_sb_printf(&sb, "\",\"enabled\":%d,\"prefix\":\"", sqlite3_column_int(st, 3));
            hd_sb_json(&sb, masked);
            hd_sb_puts(&sb, "\"}");
            if (!hd_sb_ok(&sb)) break;
        }
        sqlite3_finalize(st);
    }
    DB_UNLOCK();

    hd_sb_puts(&sb, "]}");
    if (!hd_sb_ok(&sb)) { out[n - 1] = '\0'; return -1; }
    return 0;
}

int hd_db_key_revoke(int key_id)
{
    sqlite3_stmt* st = NULL;
    int rc;

    if (!s_db) return -1;
    DB_LOCK();
    if (db_prepare("UPDATE api_keys SET enabled=0 WHERE key_id=?", &st) != 0) { DB_UNLOCK(); return -1; }
    sqlite3_bind_int(st, 1, key_id);
    rc = db_step_rc(st, "key_revoke");
    {
        int changed = sqlite3_changes(s_db);
        sqlite3_finalize(st);
        DB_UNLOCK();
        if (rc != SQLITE_DONE) return -1;
        HD_LOGI("KEY", "已吊销密钥 id=%d (影响 %d 行)", key_id, changed);
        return changed > 0 ? 0 : -1;
    }
}

int hd_db_key_check(const char* key)
{
    sqlite3_stmt* st = NULL;
    int ok = 0;

    if (!s_db || !key || !key[0]) return 0;
    DB_LOCK();
    if (db_prepare("SELECT 1 FROM api_keys WHERE api_key=? AND enabled=1", &st) == 0) {
        sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
        if (db_step_rc(st, "key_check") == SQLITE_ROW) ok = 1;
        sqlite3_finalize(st);
    }
    DB_UNLOCK();
    return ok;
}

/*
 * §8.2：握手阶段用 proof_C 反查是哪一把 api_key。
 * 为什么不在 hello 里带 key_id：
 *   自带 ID 等于给攻击者一个枚举维度，而且客户端不该关心"服务端内部怎么存密钥"。
 *   这里对每把启用中的 key 各算一次 HMAC，代价是 O(密钥数)；
 *   密钥表通常只有个位数，且握手只在建连时发生一次。
 */
int hd_db_key_match_proof(const unsigned char salt[16],
                          const char* nc_hex, const char* ns_hex, const char* device_id,
                          const unsigned char proof_c[32],
                          char* out_label, size_t n,
                          unsigned char out_master[32])
{
    sqlite3_stmt* st = NULL;
    unsigned char master[32];
    unsigned char want[32];
    int found = 0;

    if (out_label && n) out_label[0] = '\0';
    if (out_master) memset(out_master, 0, 32);
    if (!s_db || !salt || !nc_hex || !ns_hex || !proof_c) return 0;

    DB_LOCK();
    if (db_prepare("SELECT COALESCE(label,''),api_key FROM api_keys WHERE enabled=1 ORDER BY key_id", &st) == 0) {
        while (db_step_rc(st, "key_proof") == SQLITE_ROW) {
            const char* label = (const char*)sqlite3_column_text(st, 0);
            const char* key   = (const char*)sqlite3_column_text(st, 1);

            if (!key || !key[0]) continue;
            hd_sec_master(key, strlen(key), salt, master);
            hd_sec_proof_c(master, nc_hex, ns_hex, device_id, want);
            if (hd_sec_ct_eq(want, proof_c, 32)) {
                if (out_label && n) snprintf(out_label, n, "%s", label ? label : "");
                if (out_master) memcpy(out_master, master, 32);
                found = 1;
                break;
            }
        }
        sqlite3_finalize(st);
    }
    DB_UNLOCK();
    return found;
}
