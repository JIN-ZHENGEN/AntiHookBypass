/*
 * 退出探针 v2：只记录，不落盘、不 dlsym。
 *
 * 为什么重做
 * ----------
 * 上一版在退出路径上做了两件危险的事，导致探针自己把进程崩掉：
 *   1) ahb_filelog() -> fopen/fwrite：退出时进程状态正在拆解；
 *   2) dlsym(RTLD_NEXT, ...)：动态链接器锁可能已被持有。
 * tombstone 栈顶就停在 ep__exit+92。于是当时把整组接管撤掉了。
 *
 * 但现在目标变了：实测 hunter 的主进程会**静默退出**，
 * 既不产生 tombstone，也没有 signal —— 那是它自己的自杀路径，
 * 而用户要求把它拦下来。所以要重新接管，只是这次：
 *   - 真函数指针在早初始化阶段就 dlsym 好，退出路径上不再解析；
 *   - 只用 __android_log_print 打 logd（socket，不碰文件系统），
 *     并且连打 4 次，避开 logd 对单条低频日志的丢弃；
 *   - 计数器放在全局，供后续"要不要真的阻止"判断使用。
 */
#ifndef AHB_EXIT_PROBE_H
#define AHB_EXIT_PROBE_H

#include <unwind.h>

typedef void (*exit_fn)(int);
typedef void (*_exit_fn)(int);
typedef int  (*kill_fn)(pid_t, int);
typedef int  (*raise_fn)(int);
typedef void (*abort_fn)(void);
typedef int  (*tgkill_fn)(pid_t, pid_t, int);
typedef void (*exit_group_fn)(int);

static exit_fn       g_real_exit       = NULL;
static _exit_fn      g_real__exit      = NULL;
static kill_fn       g_real_kill       = NULL;
static raise_fn      g_real_raise      = NULL;
static abort_fn      g_real_abort      = NULL;
static tgkill_fn     g_real_tgkill     = NULL;
static exit_group_fn g_real_exit_group = NULL;

/* 各退出入口被调用的次数，供周期日志带出 */
static volatile int g_exit_hits[8];

/*
 * 阻止退出：置 1 时 ep_* 记录完就返回，不再真的退出。
 * 默认 1 —— 用户的要求是别让 hunter 自己死掉。
 * 若发现目标卡在异常状态，改回 0 只观察。
 */
#ifndef AHB_BLOCK_EXIT
#define AHB_BLOCK_EXIT 0
#endif

/*
 * 模块区间表：早初始化时把 /proc/self/maps 的模块名与地址范围缓存下来。
 *
 * 为什么必须缓存而不能在退出时现查：
 *   退出路径上不能 open（进程状态在拆解）、不能 dlsym（链接器锁可能被持）。
 *   而一个裸地址（r0/r1）如果不翻译成"哪个库+偏移"，就完全无法定位。
 *   所以提前把表读进静态数组，退出时只做纯内存的线性查找。
 */
#define EP_MAP_MAX 384
typedef struct { uintptr_t s, e; char name[56]; } ep_map_ent;
static ep_map_ent g_ep_maps[EP_MAP_MAX];
static int g_ep_map_n;

static void ep_cache_maps(void) {
    long fd;
    char *buf;
    size_t cap = 512 * 1024, len = 0;
    char *line;
    g_ep_map_n = 0;
    fd = (long)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return;
    buf = (char *)malloc(cap);
    if (!buf) { syscall(SYS_close, (int)fd); return; }
    for (;;) {
        long k;
        if (len + 65536 > cap) {
            char *nb = (char *)realloc(buf, cap * 2);
            if (!nb) break;
            buf = nb; cap *= 2;
        }
        k = (long)syscall(SYS_read, (int)fd, buf + len, cap - len - 1);
        if (k <= 0) break;
        len += (size_t)k;
    }
    syscall(SYS_close, (int)fd);
    buf[len] = 0;

    line = buf;
    while (line && *line && g_ep_map_n < EP_MAP_MAX) {
        char *nl = strchr(line, '\n');
        /* 行格式: start-end perm offset dev inode  name */
        char *dash = strchr(line, '-');
        if (dash && nl && dash < nl) {
            char *p = nl;
            int fields = 0;
            /* 跳过地址范围与 4 个字段，剩下路径 */
            while (p > line && fields < 6) {
                if (*p == ' ' || *p == '\t') {
                    while (p > line && (*p == ' ' || *p == '\t')) p--;
                    fields++;
                } else p--;
            }
            if (fields >= 5) {
                char *namep = p + 1;
                while (namep < nl && (*namep == ' ' || *namep == '\t')) namep++;
                if (namep < nl && *namep != '[') {
                    uintptr_t a = strtoull(line, NULL, 16);
                    uintptr_t b = strtoull(dash + 1, NULL, 16);
                    size_t nl2 = (size_t)(nl - namep);
                    if (nl2 > sizeof(g_ep_maps[0].name) - 1)
                        nl2 = sizeof(g_ep_maps[0].name) - 1;
                    g_ep_maps[g_ep_map_n].s = a;
                    g_ep_maps[g_ep_map_n].e = b;
                    memcpy(g_ep_maps[g_ep_map_n].name, namep, nl2);
                    g_ep_maps[g_ep_map_n].name[nl2] = 0;
                    g_ep_map_n++;
                }
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
}

/* 把地址翻译成 "模块名+偏移"，查不到返回 ? */
static const char *ep_which(uintptr_t a) {
    static char out[80];
    int i;
    for (i = 0; i < g_ep_map_n; i++) {
        if (a >= g_ep_maps[i].s && a < g_ep_maps[i].e) {
            const char *b = strrchr(g_ep_maps[i].name, '/');
            snprintf(out, sizeof(out), "%s+0x%lx",
                     b ? b + 1 : g_ep_maps[i].name,
                     (unsigned long)(a - g_ep_maps[i].s));
            return out;
        }
    }
    return "?";
}

static void ep_prepare(void) {
    if (!g_real_exit)       g_real_exit       = (exit_fn)dlsym(RTLD_NEXT, "exit");
    if (!g_real__exit)      g_real__exit      = (_exit_fn)dlsym(RTLD_NEXT, "_exit");
    if (!g_real_kill)       g_real_kill       = (kill_fn)dlsym(RTLD_NEXT, "kill");
    if (!g_real_raise)      g_real_raise      = (raise_fn)dlsym(RTLD_NEXT, "raise");
    if (!g_real_abort)      g_real_abort      = (abort_fn)dlsym(RTLD_NEXT, "abort");
    if (!g_real_tgkill)     g_real_tgkill     = (tgkill_fn)dlsym(RTLD_NEXT, "tgkill");
    if (!g_real_exit_group) g_real_exit_group = (exit_group_fn)dlsym(RTLD_NEXT, "exit_group");
    ep_cache_maps();
}

/*
 * 只打 logd，连打 4 次。不用 ahb_filelog —— 那条路会在退出时 fopen。
 * 参数只取寄存器里的返回地址，不做栈回溯。
 */
/*
 * 沿帧指针链取调用者，而不是 __builtin_return_address(0)。
 *
 * 原因：__builtin_return_address(0) 在 -O2 下会把内联后的返回地址
 * 报成 0x...2ee4 这种落在 ---p guard page 上的值，完全没法定位。
 * AArch64 的 x29 链是标准帧链，每层 [x29] 存上一层 x29、[x29+8] 存
 * 返回地址，纯读内存，不依赖 unwind 信息，任何上下文都安全。
 *
 * 只打 2 层：第 0 层是 ep_* 自己的返回点，第 1 层才是真正的调用者。
 */
static void ep_note(const char *what, int code, int idx) {
    uintptr_t fp = (uintptr_t)__builtin_frame_address(0);
    uintptr_t r0 = 0, r1 = 0, r2 = 0;
    if (fp > 0x1000) {
        uintptr_t nx = *(uintptr_t *)fp;
        uintptr_t ra = *(uintptr_t *)(fp + 8);
        r0 = ra;
        if (nx > fp && nx < fp + 0x100000) {
            r1 = *(uintptr_t *)(nx + 8);
            {
                uintptr_t n2 = *(uintptr_t *)nx;
                if (n2 > nx && n2 < nx + 0x100000) r2 = *(uintptr_t *)(n2 + 8);
            }
        }
    }
    if (idx >= 0 && idx < 8) g_exit_hits[idx]++;
    {
        int n;
        for (n = 0; n < 3; n++) {
            __android_log_print(ANDROID_LOG_ERROR, "AHBEXIT",
                "%s code=%d n=%d r0=%lx(%s) r1=%lx(%s)",
                what, code, n,
                (unsigned long)r0, ep_which(r0),
                (unsigned long)r1, ep_which(r1));
        }
    }
}

static void ep_exit(int code) {
    ep_note("exit", code, 0);
#if AHB_BLOCK_EXIT
    return;
#else
    if (g_real_exit) g_real_exit(code);
    syscall(SYS_exit_group, code);
    __builtin_unreachable();
#endif
}

static void ep__exit(int code) {
    ep_note("_exit", code, 1);
#if AHB_BLOCK_EXIT
    return;
#else
    if (g_real__exit) g_real__exit(code);
    syscall(SYS_exit_group, code);
    __builtin_unreachable();
#endif
}

static int ep_kill(pid_t pid, int sig) {
    ep_note("kill", (int)sig, 2);
#if AHB_BLOCK_EXIT
    return 0;
#else
    if (g_real_kill) return g_real_kill(pid, sig);
    return (int)syscall(SYS_kill, pid, sig);
#endif
}

static int ep_raise(int sig) {
    ep_note("raise", (int)sig, 3);
#if AHB_BLOCK_EXIT
    return 0;
#else
    if (g_real_raise) return g_real_raise(sig);
    return 0;
#endif
}

static void ep_abort(void) {
    ep_note("abort", 0, 4);
#if AHB_BLOCK_EXIT
    return;
#else
    if (g_real_abort) g_real_abort();
    __builtin_unreachable();
#endif
}

static int ep_tgkill(pid_t tgid, pid_t tid, int sig) {
    ep_note("tgkill", (int)sig, 5);
#if AHB_BLOCK_EXIT
    return 0;
#else
    if (g_real_tgkill) return g_real_tgkill(tgid, tid, sig);
    return (int)syscall(SYS_tgkill, tgid, tid, sig);
#endif
}

static void ep_exit_group(int code) {
    ep_note("exit_group", code, 6);
#if AHB_BLOCK_EXIT
    return;
#else
    if (g_real_exit_group) g_real_exit_group(code);
    syscall(SYS_exit_group, code);
    __builtin_unreachable();
#endif
}

#endif
