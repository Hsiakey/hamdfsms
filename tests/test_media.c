/*
 * test_media.c — 存储介质探测（决定扫描/校验的并发读线程数）
 *
 * 目的只有一个：别在机械盘上开 4 个线程互相抢磁头。判定规则必须可预测：
 *   - 有寻道惩罚 → HDD → 线程数 1
 *   - 无寻道惩罚 → SSD/NVMe；UNC/GetDriveType 判定为网络盘 → NETWORK
 *   - 判不出来 → UNKNOWN + 返回 -1，调用方沿用配置值（绝不猜）
 *
 * 这里验证纯逻辑（映射表、边界输入、UNC 不联网）+ 在本机真实介质上的一致性。
 * 具体判定成什么取决于跑测试的机器，所以只断言"自洽"，不写死期望值。
 */
#include "../Hamsterd/hd_util.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
    #include <direct.h>
    #define TEST_GETCWD _getcwd
#else
    #include <unistd.h>
    #define TEST_GETCWD getcwd
#endif

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; printf("  ok   %s\n", msg); } \
    else { g_fail++; printf("  FAIL %s  (第 %d 行)\n", msg, __LINE__); } \
} while (0)

static void fill(hd_media_info* m, hd_media_kind k)
{
    memset(m, 0, sizeof(*m));
    m->kind = k;
    m->seek_penalty = -1;
    m->bus_type = -1;
    m->drive_type = -1;
}

int main(void)
{
    printf("=== 存储介质探测测试 ===\n");

    printf("== 名称与建议线程数\n");
    {
        hd_media_info m;
        const hd_media_kind kinds[] = {
            HD_MEDIA_UNKNOWN, HD_MEDIA_HDD, HD_MEDIA_SSD,
            HD_MEDIA_NVME, HD_MEDIA_NETWORK, HD_MEDIA_REMOVABLE
        };
        size_t i, j;
        int distinct = 1;

        for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
            const char* n = hd_media_name(kinds[i]);
            if (!n || !n[0]) distinct = 0;
            for (j = 0; j < i; j++) {
                if (strcmp(n, hd_media_name(kinds[j])) == 0) distinct = 0;
            }
        }
        CHECK(distinct, "六种介质的名字都不为空且互不相同");

        fill(&m, HD_MEDIA_HDD);
        CHECK(hd_media_suggest_threads(&m) == 1, "机械盘 -> 1 个读线程（单磁头）");
        fill(&m, HD_MEDIA_SSD);
        CHECK(hd_media_suggest_threads(&m) == 4, "SSD -> 4 个读线程");
        fill(&m, HD_MEDIA_NVME);
        CHECK(hd_media_suggest_threads(&m) == 4, "NVMe -> 4 个读线程（默认值）");
        fill(&m, HD_MEDIA_NETWORK);
        CHECK(hd_media_suggest_threads(&m) == 4, "网络盘 -> 4 个读线程（填满高延迟链路）");
        fill(&m, HD_MEDIA_REMOVABLE);
        CHECK(hd_media_suggest_threads(&m) == 4, "可移动盘 -> 4 个读线程");
        fill(&m, HD_MEDIA_UNKNOWN);
        CHECK(hd_media_suggest_threads(&m) == 4, "未知 -> 保持默认 4");
        CHECK(hd_media_suggest_threads(NULL) == 4, "NULL 也保持默认 4（不崩）");
    }

    printf("== 边界输入不该乱猜\n");
    {
        hd_media_info m;
        CHECK(hd_detect_media(NULL, &m) == -1, "NULL 路径 -> 判不出来");
        CHECK(hd_detect_media("", &m) == -1, "空路径 -> 判不出来");
        CHECK(hd_detect_media("relative/dir", &m) == -1, "相对路径 -> 判不出来");
        CHECK(hd_detect_media("1:\\x", &m) == -1, "非法盘符 -> 判不出来");
        CHECK(hd_detect_media("C:", &m) >= -1, "裸盘符不崩（允许判出或判不出）");
    }

    printf("== UNC 路径直接判网络盘（不发起任何网络请求）\n");
    {
        hd_media_info m;
        int64_t t0 = hd_now_ms();
        int rc = hd_detect_media("\\\\server\\share\\dir", &m);
        int64_t dt = hd_now_ms() - t0;

        CHECK(rc == 0, "UNC 路径判定成功");
        CHECK(m.kind == HD_MEDIA_NETWORK, "UNC 路径 -> 网络盘");
        CHECK(hd_media_suggest_threads(&m) == 4, "UNC -> 4 个读线程");
        CHECK(dt < 200, "UNC 判定没有去连网络（耗时应 <200ms）");
        CHECK(hd_media_name(m.kind)[0] != '\0', "UNC 的类型名可读");
    }

    printf("== 本机真实介质（断言自洽，不写死机器）\n");
    {
        char cwd[1024];
        hd_media_info m;
        int rc;
        int suggest;

        cwd[0] = '\0';
        if (TEST_GETCWD(cwd, sizeof(cwd)) == NULL || cwd[0] == '\0') {
            snprintf(cwd, sizeof(cwd), ".");
        }
        rc = hd_detect_media(cwd, &m);
        printf("  本机: %s -> rc=%d kind=%s seek=%d bus=%d drive_type=%d\n",
               cwd, rc, hd_media_name(m.kind), m.seek_penalty, m.bus_type, m.drive_type);

        if (rc == 0) {
            CHECK(m.kind != HD_MEDIA_UNKNOWN, "判定成功时一定有具体类型");
            suggest = hd_media_suggest_threads(&m);
            CHECK(suggest == 1 || suggest == 4, "建议线程数只可能是 1 或 4");
            CHECK((m.kind == HD_MEDIA_HDD) == (suggest == 1),
                  "只有机械盘才建议 1 个线程");
            CHECK(m.kind != HD_MEDIA_HDD || m.seek_penalty == 1,
                  "判成机械盘必须真的查到寻道惩罚");
        } else {
            CHECK(m.kind == HD_MEDIA_UNKNOWN, "判定失败时必须报未知，不能瞎归类");
            CHECK(m.seek_penalty == -1, "判定失败时字段保持 -1");
        }

        /* 同一路径连查两次必须一致（判定不能抖） */
        {
            hd_media_info m2;
            int rc2 = hd_detect_media(cwd, &m2);
            CHECK(rc2 == rc && m2.kind == m.kind, "同一路径两次判定结果一致");
        }
    }

    printf("\n  通过 %d / 失败 %d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
