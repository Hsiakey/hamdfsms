/*
 * test_log.c — 日志绝不能写爆磁盘（事故回归）
 *
 * 背景：GUI 侧日志没有上限，一个"写日志→触发事件→再写日志"的自激循环把系统盘
 * 写到 15GB+。守护进程侧也有同类隐患：轮转改名失败时会重新以追加方式打开同一个
 * 文件并把计数清零 —— 每 8MB 重试一次、永远轮转不掉。
 *
 * 本测试把两道闸门钉死：
 *   1. 正常轮转：主文件与 .1 都不超过阈值；
 *   2. 轮转被占用（Windows 上 .1 被记事本/杀毒打开时改名会失败）：
 *      必须退化为截断，仍然不能超过阈值。
 */
#include "../Hamsterd/hd_util.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#endif

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; printf("  ok   %s\n", msg); } \
    else { g_fail++; printf("  FAIL %s  (第 %d 行)\n", msg, __LINE__); } \
} while (0)

#define LOG_DIR  "tests/tmp/logtest"
#define LOG_PATH LOG_DIR "/hamsterd.log"
#define LOG_OLD  LOG_PATH ".1"
#define THRESH   4096

static long long fsize(const char* p)
{
    hd_file_info info;
    if (hd_stat64(p, &info) != 0) return -1;
    return info.size;
}

static void spam(int start, int count)
{
    int i;
    char pad[64];
    memset(pad, 'x', sizeof(pad) - 1);
    pad[sizeof(pad) - 1] = '\0';
    for (i = 0; i < count; i++) {
        HD_LOGI("TEST", "line %d %s", start + i, pad);
    }
}

int main(void)
{
    long long sz, sz1;

    printf("=== 日志上限测试（事故回归） ===\n");

    (void)hd_mkdirs(LOG_DIR);
    (void)hd_remove_file(LOG_PATH);
    (void)hd_remove_file(LOG_OLD);

    hd_log_init(LOG_PATH, 0, HD_LOG_DEBUG);
    hd_log_set_rotate_bytes(THRESH);

    /* 1) 正常轮转：写 ~200KB，阈值 4KB */
    spam(0, 2000);
    sz  = fsize(LOG_PATH);
    sz1 = fsize(LOG_OLD);
    printf("     主=%lld 字节，.1=%lld 字节（阈值 %d）\n", sz, sz1, THRESH);
    CHECK(sz > 0 && sz <= THRESH + 512, "主日志文件不超过阈值");
    CHECK(sz1 > 0 && sz1 <= THRESH + 512, "轮转保留的 .1 不超过阈值");

    /* 2) 轮转被占用：把 .1 以独占方式打开，让 MoveFileEx 失败 */
#ifdef _WIN32
    {
        HANDLE hold = CreateFileW(L"tests\\tmp\\logtest\\hamsterd.log.1",
                                  GENERIC_READ, 0 /* 不共享 */, NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hold == INVALID_HANDLE_VALUE) {
            CHECK(0, "无法以独占方式打开 .1（本用例无法执行）");
        } else {
            long long before = fsize(LOG_PATH);
            spam(5000, 2000);                     /* 足以触发多次轮转 */
            sz = fsize(LOG_PATH);
            printf("     轮转受阻后：主=%lld 字节（之前 %lld）\n", sz, before);
            CHECK(sz > 0 && sz <= THRESH + 512, "轮转受阻时必须截断，不能继续增长");
            CHECK(fsize(LOG_PATH) < before + THRESH + 512, "总体没有随写入量线性增长");
            CloseHandle(hold);
        }
    }
#else
    printf("     （非 Windows：rename 语义不同，跳过轮转受阻用例）\n");
#endif

    /* 3) 恢复默认阈值后仍能正常写 */
    hd_log_set_rotate_bytes(0);
    HD_LOGI("TEST", "恢复默认阈值");
    hd_log_shutdown();

    (void)hd_remove_file(LOG_PATH);
    (void)hd_remove_file(LOG_OLD);

    printf("\n=== 通过 %d, 失败 %d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
