/* reprl_win.c - QuickJS 的 Fuzzilli REPRL 通道原语（Windows 实现）
 *
 * 对应 fuzzillai 的 POSIX REPRL 协议，Windows 版通道映射：
 *   控制读 (CRFD=100 等价): GetStdHandle(STD_INPUT_HANDLE)
 *   控制写 (CWFD=101 等价): GetStdHandle(STD_OUTPUT_HANDLE)
 *   脚本通道 (DRFD=102 等价): 匿名共享内存，HANDLE 经环境变量
 *                             REPRL_SCRIPT_HANDLE 继承传入, MapViewOfFile 后直读
 *   覆盖位图: 命名共享内存 (环境变量 SHM_ID, fuzzilli 侧创建),
 *             __sanitizer_cov_trace_pc_guard 置位
 *
 * 本文件只提供通道原语；REPRL 求值循环写在 qjs.c（需访问 static 的
 * eval_buf / js_std_loop）。编译：-DFUZZILLI。
 */
#ifdef _WIN32

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reprl_win.h"

/* 覆盖位图布局（与 fuzzillai libcoverage.h 的 shmem_data 严格一致,
   offsetof(edges) 必须匹配, 否则 fuzzilli 读位图错位） */
#define QJS_SHM_SIZE 0x202000
#define QJS_MAX_FEEDBACK_NEXUS 100000
struct feedback_nexus_data {
    uint32_t vector_address;
    uint32_t ic_state;
};
struct shmem_data {
    uint32_t num_edges;
    uint32_t feedback_nexus_count;
    uint32_t max_feedback_nexus;
    uint32_t turbofan_flags;
    uint64_t turbofan_optimization_bits;
    struct feedback_nexus_data feedback_nexus_data[QJS_MAX_FEEDBACK_NEXUS];
    uint8_t edges[];
};

static HANDLE g_hCtrlIn, g_hCtrlOut;
static char *g_script_map;
static struct shmem_data *g_cov;
static uint32_t *g_cov_start, *g_cov_stop;

/* sancov module ctor 会把 guards 段边界传给 init — 保存下来用于覆盖初始化与重置,
   避免 extern __start_/__stop_ 段符号 (COFF 下链接器不生成)。定义在下方带诊断。 */

int reprl_read_ctrl(void *buf, int n) {
    DWORD r = 0;
    if (!ReadFile(g_hCtrlIn, buf, (DWORD)n, &r, NULL)) return -1;
    return (int)r;
}

int reprl_write_ctrl(const void *buf, int n) {
    DWORD w = 0;
    if (!WriteFile(g_hCtrlOut, buf, (DWORD)n, &w, NULL)) return -1;
    return (int)w;
}

/* sancov runtime 的初始化回调 (module ctor 调用) — 见上方 g_cov_start/g_cov_stop 保存,
   提供此符号避免链接 compiler-rt 的 fuzzer runtime (其 trace_pc_guard 与我们的冲突) */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    g_cov_start = start;
    g_cov_stop = stop;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t index = *guard;
    if (!index) return;
    g_cov->edges[index / 8] |= 1u << (index % 8);
    *guard = 0;
}

void __sanitizer_cov_reset_edgeguards(void) {
    uint32_t n = 0;
    if (!g_cov) return;
    for (uint32_t *x = g_cov_start; x < g_cov_stop && n < g_cov->num_edges; x++)
        *x = ++n;
}

int reprl_handshake(void) {
    g_hCtrlIn = GetStdHandle(STD_INPUT_HANDLE);
    /* 控制写管道: 环境变量 REPRL_CTRL_OUT_HANDLE 传入 (不用 STD_OUTPUT_HANDLE ——
       JS 的 stdout 也走它, 会污染协议通道) */
    const char *v = getenv("REPRL_CTRL_OUT_HANDLE");
    if (!v) {
        fprintf(stderr, "[REPRL] no REPRL_CTRL_OUT_HANDLE env\n");
        return -1;
    }
    g_hCtrlOut = (HANDLE)(uintptr_t)_strtoui64(v, NULL, 10);
    char helo[] = "HELO";
    if (reprl_write_ctrl(helo, 4) != 4 || reprl_read_ctrl(helo, 4) != 4)
        return -1;
    if (memcmp(helo, "HELO", 4) != 0)
        return -1;
    return 0;
}

int reprl_open_script_channel(void) {
    const char *v = getenv("REPRL_SCRIPT_HANDLE");
    if (!v) {
        fprintf(stderr, "[REPRL] no REPRL_SCRIPT_HANDLE env\n");
        return -1;
    }
    HANDLE h = (HANDLE)(uintptr_t)_strtoui64(v, NULL, 10);
    g_script_map = (char *)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!g_script_map) {
        fprintf(stderr, "[REPRL] MapViewOfFile(script) failed: %lu\n", GetLastError());
        return -1;
    }
    return 0;
}

const char *reprl_script_map(void) {
    return g_script_map;
}

int reprl_open_coverage(void) {
    const char *shm_key = getenv("SHM_ID");
    if (!shm_key) {
        fprintf(stderr, "[COV] no SHM_ID, coverage disabled\n");
        return -1;
    }
    /* CreateFileMapping: 不存在则创建, 存在则打开 — 与 POSIX shm_open(O_CREAT) 语义一致。
       必需: fuzzilli 在 runner.initialize(spawn 本进程) 之后才创建 SHM_ID 共享内存,
       用 OpenFileMapping(只打开) 会因时序竞争永远失败。 */
    HANDLE h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                  0, QJS_SHM_SIZE, shm_key);
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[COV] CreateFileMapping(%s) failed: %lu\n", shm_key, GetLastError());
        return -1;
    }
    g_cov = (struct shmem_data *)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!g_cov) {
        fprintf(stderr, "[COV] MapViewOfFile failed: %lu\n", GetLastError());
        return -1;
    }
    /* g_cov_start/g_cov_stop 已由 sancov module ctor 经 init 保存 */
    g_cov->num_edges = (uint32_t)(g_cov_stop - g_cov_start);
    return 0;
}

#endif /* _WIN32 */
