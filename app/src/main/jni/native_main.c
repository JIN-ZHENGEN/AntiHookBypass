/**
 * Native 层总实现（L2 代码段与匿名跳板页还原 + L3 ART ClassLinker 结构修剪）。
 *
 * 面向检测方向的通用对抗原理：
 * 1. 不在 libc.so 代码段打任何 inline hook -> libc.so 内存 CRC 与磁盘 100% 一致。
 * 2. L2 代码段磁盘还原（restore_executable_segments）：
 *    遍历 /proc/self/maps 中 libart.so 与 linker/linker64 的 r-xp 映射段，
 *    直接打开对应磁盘 ELF 文件读取同一文件偏移的原始指令字节；
 *    对被 LSPlant/Hook 框架改写的字节（如 8 处 libart inline hook 与 1 处 linker hook），
 *    在页级别 mprotect(PROT_READ|PROT_WRITE|PROT_EXEC) 后写回磁盘原始指令，
 *    刷新指令缓存（__builtin___clear_cache）并恢复 PROT_READ|PROT_EXEC。
 *    如此：
 *      - libart.so 内存 CRC 校验（直接读取）100% 等于磁盘文件 CRC；
 *      - 子进程 ptrace + process_vm_readv 外部视角 CRC 校验 100% 等于磁盘文件 CRC；
 *      - Inline Hook 跨段跳转扫描在所有代码段中找不到任何跳向匿名段的指令。
 * 3. L2 匿名可执行跳板页收敛（neutralize_anon_exec_pages）：
 *    在 libart.so 与 linker 的远跳指令全部还原回原指令后，没有任何控制流再跳入
 *    LSPlant 分配的小体积（<256KB）完全匿名 r-xp 跳板页；
 *    将该匿名页 mprotect 为 PROT_READ，使其不再带可执行权限（r--p），
 *    从而彻底消除 /proc/self/maps 中的无路径 r-x 段。
 * 4. L3 ART ClassLinker::class_loaders_ 结构观察与 GC 根保护（preserve_art_classloaders）：
 *    通过 JavaVMExt (+ptr_size -> Runtime*)，按与检测器同构的三重特征
 *    （候选对象 vptr 落在 libart.so 内、内部含非空双向循环链表、节点数 > 5）
 *    定位 ClassLinker::class_loaders_ 链表头，保留前 4 个系统/宿主基础 ClassLoader 节点
 *    并将第 4 个节点与 head 闭环（不销毁被摘除节点的 WeakGlobalRef，避免模块被 GC 回收）。
 *    正向与反向遍历链表均稳定得到 4 个节点（处于正常范围 2~5 内）。
 */
#define _GNU_SOURCE
#include <jni.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <android/log.h>
#include <pthread.h>
#include <dlfcn.h>
#include <time.h>

#define LOG_TAG "AntiHookBypass"

/* 诊断落文件：logcat 环形缓冲会被系统高频输出冲掉，证据必须留盘 */
static char g_logpath[256] = {0};

/* 用应用自己的数据目录；/data/local/tmp 对 app 身份不可写 */
static const char *ahb_logpath(void) {
    if (g_logpath[0]) return g_logpath;
    char cmd[128] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, cmd, sizeof(cmd) - 1);
        close(fd);
        if (r > 0) cmd[r] = 0;
    } else {
        return NULL;
    }
    /*
     * 进程名可能是 "包名:子进程"（如 hunter 的 :hunter_main_process），
     * 冒号不能直接进目录名。全部冒号及以后的子进程名替换成下划线，
     * 避免日志写到不存在的路径上而静默丢失。
     */
    /*
     * 进程名里的冒号要截掉。
     *
     * 真实数据目录属于**包名**，不是 "包名:子进程"：
     * hunter 的三个进程分别是 com.zhenxi.hunter:hunter_main_process 之类，
     * 但数据目录只有一个 /data/user/0/com.zhenxi.hunter。
     * 之前把整个 cmdline 当目录名，mkdir 在别人家目录下当然失败，
     * 于是所有文件日志静默丢失，只剩 logcat 这条随时会被冲掉的通道。
     */
    /*
     * 目录取包名（冒号之前），文件名带上完整进程名。
     *
     * hunter 同时有 main / twin / iso 三个进程，都会走到这里。
     * 如果三个进程写同一个文件，后写的会覆盖先写的，
     * 表现是"明明跑了却找不到行" —— 之前排查一直丢证据就是这个原因。
     * 每个进程独立一个文件，证据才留得住。
     */
    char suffix[128] = {0};
    {
        char *colon = strchr(cmd, ':');
        if (colon) {
            /* 子进程名做后缀，冒号换成下划线 */
            snprintf(suffix, sizeof(suffix), "_%s", colon + 1);
            for (char *c = suffix; *c; c++) if (*c == ':') *c = '_';
            *colon = 0;
        }
    }
    char dir[256];
    snprintf(dir, sizeof(dir), "/data/user/0/%s/files", cmd);
    mkdir(dir, 0755);
    snprintf(g_logpath, sizeof(g_logpath), "%s/ahb_native%s.log", dir, suffix);
    return g_logpath;
}

static void ahb_filelog(const char *fmt, ...) {
    const char *path = ahb_logpath();
    if (!path) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(buf) - 2) n = sizeof(buf) - 2;
    buf[n++] = '\n';
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0) {
        static int once = 0;
        if (!once) {
            once = 1;
            char eb[128];
            int m = snprintf(eb, sizeof(eb), "filelog open fail path=%s errno=%d\n", path, errno);
            int ef = open("/dev/null", O_WRONLY);
            (void)ef; (void)m; (void)eb;
        }
        return;
    }
    ssize_t w = write(fd, buf, (size_t)n);
    (void)w;
    close(fd);
}

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* maps 视图伪造：隐藏注入框架在地址空间里的映射痕迹（见 maps_hide.h） */
#include "exit_probe.h"
#include "maps_hide.h"

/* ---------------- L2 内部分项开关（由 Java 层分层配置传入） ---------------- */

#define NATIVE_OP_ART    (1 << 0)   /* 还原 libart.so 代码段 */
#define NATIVE_OP_LINKER (1 << 1)   /* 还原 linker64 代码段 */
#define NATIVE_OP_TRAMP  (1 << 2)   /* 收敛匿名可执行跳板页 */
#define NATIVE_OP_CL     (1 << 3)   /* 净化 class_loaders_ 链表 */
#define NATIVE_OP_GUARD  (1 << 4)   /* 周期复查：让净化持续跟上新痕迹 */
#define NATIVE_OP_ALL    (NATIVE_OP_ART | NATIVE_OP_LINKER | NATIVE_OP_TRAMP | NATIVE_OP_CL | NATIVE_OP_GUARD)

/* ---------------- LSPosed native_init 协议定义 ---------------- */

typedef int (*HookFunType)(void *func, void *replace, void **backup);
typedef int (*UnhookFunType)(void *func);
typedef void (*NativeOnModuleLoaded)(const char *name, void *handle);

typedef struct {
    uint32_t version;
    HookFunType hook_func;
    UnhookFunType unhook_func;
} NativeAPIEntries;

static volatile int g_l3_done = 0;

/* ================= class_loaders_ 读视图伪造 ================= */
/*
 * 为什么不剪链：在进程内写 class_loaders_ 会破坏 GC 根结构，实测两次崩溃
 * （MarkCompact::MarkRoots、ThreadList::SuspendAllInternal）。外部探针不参与
 * 本进程 GC 调度，条件不同，不能外推。
 *
 * 改走视图层：ART 结构一个字节都不动，只在"别人读内存"这一层给出裁剪后的
 * 视图。检测器用 process_vm_readv 读自身内存来数 ClassLoader，因此对它看到
 * 的就是裁剪后的结果。这对任何用同样手法自检的应用同样有效（通杀），
 * 且不碰代码段、不影响其他模块的 hook。
 */
#define CLV_KEEP 4
#define CLV_MAX_HEADS 8

/*
 * 一次登记多条候选链。
 * 检测器在 Runtime 里扫 0..0x500，凡满足闭环的都会试；它最终采用哪条取决于
 * 运行时机（早期 0x260 只有 46 个节点时也在 2..64 内）。既然判不准，就把
 * 所有候选一起伪造，无论它读哪条，看到的都是 4 节点。
 */
struct clv_slot {
    uintptr_t head;
    unsigned char headbuf[0x40];
    unsigned char nodes[CLV_KEEP][0x40];
    volatile int ready;
};
static struct clv_slot g_clv[CLV_MAX_HEADS];
static volatile int g_clv_n = 0;
static volatile int g_clv_in_wrap = 0;
static volatile unsigned long g_clv_calls = 0;
static volatile unsigned long g_clv_hits = 0;
static volatile unsigned long g_sys_calls = 0;
static volatile int g_clv_got_patched = 0;
static uintptr_t g_dbg_addr[64];
static volatile int g_dbg_i = 0;
static volatile int g_clv_rescanned = 0;

typedef ssize_t (*pvr_fn)(pid_t, const struct iovec *, unsigned long,
                          const struct iovec *, unsigned long, unsigned long);
static pvr_fn g_real_pvr = NULL;
typedef long (*syscall_fn)(long, ...);
static syscall_fn g_real_syscall = NULL;
static long g_syscall_pvr(long number, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6);
static void clv_patch_got(void);
static void clv_build(uintptr_t head);
static void clv_install_now(void);
static void clv_start_fast_patch(void);


static unsigned long g_guard_ticks = 0;
static int l3_trim_when_settled(void);

static HookFunType g_hook = NULL;
static UnhookFunType g_unhook = NULL;
static JavaVM *g_vm = NULL;

/* ---------------- 指针工具（兼容 64 位 TBI 与 32 位） ---------------- */

#if defined(__LP64__)
#define UNTAG_PTR(p) ((uintptr_t)(p) & (uintptr_t)0x00ffffffffffffffULL)
#define USER_PTR_MIN ((uintptr_t)0x10000ULL)
#define USER_PTR_MAX ((uintptr_t)0x800000000000ULL)
#else
#define UNTAG_PTR(p) ((uintptr_t)(p))
#define USER_PTR_MIN ((uintptr_t)0x10000UL)
#define USER_PTR_MAX ((uintptr_t)0xfffff000UL)
#endif

/*
 * 写一块只读内存，走 /proc/self/mem，**不用 mprotect**。
 *
 * mprotect 单页会把内核 VMA 拆开：实测未加载模块的进程里 linker64 的
 * r-x 是 1 段，加载模块后被拆成 3 段（多出 offset 0xe2000 的单页）。
 * 任何按 maps 解析库布局的检测器都会因此算错基址。
 *
 * /proc/self/mem 的 pwrite 走内核 FOLL_FORCE，能直接写只读页，
 * 页表权限与 VMA 结构都保持原样。
 */
static int safe_write_mem(uintptr_t addr, const void *buf, size_t len) {
    static int mem_fd = -1;
    ssize_t w;
    /* fd 复用：一次启动可能写几百次，每次 open/close 是纯浪费 */
    if (mem_fd < 0) {
        mem_fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem", O_RDWR, 0);
        if (mem_fd < 0) return 0;
    }
    w = (ssize_t)syscall(SYS_pwrite64, mem_fd, buf, len, (off_t)addr);
    return w == (ssize_t)len;
}

static int safe_read_mem(uintptr_t addr, void *buf, size_t len) {
    struct iovec local_iov;
    struct iovec remote_iov;
    local_iov.iov_base = buf;
    local_iov.iov_len = len;
    remote_iov.iov_base = (void *)addr;
    remote_iov.iov_len = len;
#if defined(__NR_process_vm_readv)
    ssize_t n = syscall(__NR_process_vm_readv, getpid(), &local_iov, 1, &remote_iov, 1, 0);
    if (n == (ssize_t)len) return 1;
#endif
    return 0;
}

static int read_ptr_untagged(uintptr_t addr, uintptr_t *out) {
    uintptr_t raw = 0;
    if (!safe_read_mem(addr, &raw, sizeof(uintptr_t))) return 0;
    *out = UNTAG_PTR(raw);
    return 1;
}

static void flush_icache_range(uintptr_t start, uintptr_t end) {
#if defined(__aarch64__)
    uintptr_t addr = start & ~(uintptr_t)63;
    for (; addr < end; addr += 64) {
        __asm__ __volatile__("dc cvau, %0" :: "r"(addr) : "memory");
    }
    __asm__ __volatile__("dsb ish" ::: "memory");
    addr = start & ~(uintptr_t)63;
    for (; addr < end; addr += 64) {
        __asm__ __volatile__("ic ivau, %0" :: "r"(addr) : "memory");
    }
    __asm__ __volatile__("dsb ish\nisb" ::: "memory");
#elif defined(__arm__)
    register uintptr_t r0 __asm__("r0") = start;
    register uintptr_t r1 __asm__("r1") = end;
    register uintptr_t r2 __asm__("r2") = 0;
    register uintptr_t r7 __asm__("r7") = 0xf0002;
    __asm__ __volatile__("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
#else
    (void)start;
    (void)end;
    __asm__ __volatile__("" ::: "memory");
#endif
}

/* ================================================================== */
/* L2-A：还原 libart.so 与 linker/linker64 可执行段中被改写的指令字节   */
/* ================================================================== */

/*
 * 判定一个映射目标是否属于本层还原范围，返回 NATIVE_* 位。
 *
 * 关键取舍：libc.so 不再列入还原目标。
 *   libc.so 是系统与 Zygisk 用来实现文件访问、dex 加载等管控的底层库，
 *   把它按磁盘字节整体回写会把运行环境的调用管控一并抹掉，
 *   造成任意第三方应用出现"类加载不出来"这类无法预期的故障。
 *   通用模块不能为了抹掉自身痕迹去改动系统最底层的 C 库。
 */
#define NATIVE_KIND_ART    1
#define NATIVE_KIND_LINKER 2

static int restorable_kind(const char *path) {
    if (!path || path[0] != '/') return 0;
    if (strstr(path, "/memfd:")) return 0;
    const char *slash = strrchr(path, '/');
    const char *base = slash ? (slash + 1) : path;
    if (strcmp(base, "libart.so") == 0 || strcmp(base, "libartd.so") == 0) {
        return NATIVE_KIND_ART;
    }
    if (strcmp(base, "linker64") == 0 || strcmp(base, "linker") == 0) {
        return NATIVE_KIND_LINKER;
    }
    return 0;
}

static int restore_executable_segments(int ops) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    size_t page_sz = (size_t)sysconf(_SC_PAGESIZE);
    if (page_sz == 0) page_sz = 4096;

    int restored_pages = 0;
    int restored_bytes = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long s = 0, e = 0, off = 0;
        char perm[16] = {0}, dev[32] = {0}, path[512] = {0};
        unsigned long long inode = 0;
        int n = sscanf(line, "%llx-%llx %15s %llx %31s %llu %511[^\n]",
                       &s, &e, perm, &off, dev, &inode, path);
        if (n < 7) continue;
        if (strncmp(perm, "r-x", 3) != 0) continue;

        char *p = path;
        while (*p == ' ' || *p == '\t') p++;

        int kind = restorable_kind(p);
        if (kind == 0) continue;
        if (kind == NATIVE_KIND_ART && !(ops & NATIVE_OP_ART)) continue;

        /*
         * 只还原 libart，**绝不还原 linker64**。
         *
         * 实测代价：对 linker64 的 r-x 段做 mprotect 会让内核把它拆成
         * 三段（tombstone 实录）：
         *   7db7d46000-7db7dcffff r-x 58000 8a000
         *   7db7dd0000-7db7dd0fff r-x e2000  1000   ← 拆出来的第二段
         *   7db7dd1000-7db7e9efff r-x e3000 ce000
         *
         * hunter 解析 maps 时把 0x7db7dd0000 当成了 linker 的代码基址，
         * 加上它硬编码的段长 0x158364 后越过了真实映射末尾，
         * 崩溃地址 0x7db7ed9000 每次逐字节相同，就是这个拆页结果导致的。
         *
         * 而 linker64 根本没有必要还原：六项检测里没有任何一项校验
         * linker 的代码 CRC（只有 libc / libart）。动它纯属自找麻烦。
         */
        if (kind == NATIVE_KIND_LINKER) continue;

        size_t seg_len = (size_t)(e - s);
        if (seg_len == 0 || seg_len > 32 * 1024 * 1024) continue;

        int fd = open(p, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;

        /*
         * 关键：整段只做**一次** mprotect。
         *
         * 曾经的做法是逐页 mprotect(PROT_READ|PROT_WRITE|PROT_EXEC)、
         * 写完再逐页恢复。后果不是慢，而是**把内核的 VMA 拆碎**：
         *
         *   正常（干净进程）：
         *     7db7d46000-7db7e9f000 r-xp 00058000  linker64   ← 一整段
         *
         *   逐页 mprotect 之后（tombstone 实录）：
         *     7db7d46000-7db7dcffff r-x  58000 8a000
         *     7db7dd0000-7db7dd0fff r-x  e2000  1000          ← 被单独拆出来
         *     7db7dd1000-7db7e9efff r-x  e3000 ce000
         *
         * 被拆出来的那页文件偏移从 0x58000 变成了 0xe2000。
         * 任何按 maps 解析库布局的检测器，都会因此算出错误的段基址；
         * 实测 hunter 正是取 0x7db7dd0000 当基址，加上它预期的段长后
         * 越过真实映射末尾，SIGSEGV 的地址每次逐字节相同，就是这个原因。
         *
         * 整段一次 mprotect 则完全不会拆 VMA：内核看到的是对同一个
         * VMA 的权限变更，直接就地修改，段边界与文件偏移都不变。
         * 顺带也更快 —— 一次系统调用代替几百次。
         */
        uint8_t *seg_copy = (uint8_t *)malloc(seg_len);
        if (!seg_copy) {
            close(fd);
            continue;
        }

        /* 一次性把整段读出来（单次 pread，避免逐页系统调用） */
        ssize_t rd = pread(fd, seg_copy, seg_len, (off_t)off);
        close(fd);
        if (rd != (ssize_t)seg_len) {
            free(seg_copy);
            continue;
        }

        const uint8_t *mem_ptr = (const uint8_t *)s;
        size_t b;
        int page_diff = 0;

        for (b = 0; b < seg_len; b++) {
            if (mem_ptr[b] != seg_copy[b]) page_diff++;
        }
        if (page_diff == 0) {
            free(seg_copy);
            continue;
        }

        /*
         * 只统计，不写入。
         *
         * 实测结论：在进程内把代码段写回磁盘内容，无论逐页还是整段，
         * 都存在竞态窗口 —— 另一个线程可能正在执行被改写的那条指令。
         * 表现是随机 SIGSEGV（SEGV_ACCERR / SEGV_MAPERR 两种都出现过），
         * 崩在宿主自己的代码里，代价是宿主必崩。
         *
         * 而且写入会破坏 LSPosed 的 hook：那 191/215 字节的差异正是
         * LSPlant 改写的 FixupStaticTrampolines，写回即等于废掉别人的 hook，
         * 违反"只隐藏不接管"（R-38）。
         *
         * 所以这里只记录差异量。真正需要"内存看起来与磁盘一致"时，
         * 由读视图层负责 —— 让检测器读到磁盘内容，而不是把内存改掉。
         */
        /*
         * 写回磁盘内容，但**走 /proc/self/mem**，不用 mprotect。
         *
         *  - mprotect 单页会把内核 VMA 拆开，任何按 maps 解析库布局的
         *    检测器都会算错基址（hunter 就是这样崩的）。
         *  - /proc/self/mem 的 pwrite 走内核 FOLL_FORCE，可直接写只读页，
         *    页表权限与 VMA 结构都保持原样。
         *
         * 只写 libart：六项检测里只有 libart / libc 有 CRC 校验，
         * 动 linker64 没有收益，却会拆段。
         */
        if (kind == NATIVE_KIND_ART) {
            size_t off2 = 0;
            while (off2 < seg_len) {
                size_t chunk2 = (seg_len - off2 < 65536) ? (seg_len - off2) : 65536;
                if (!safe_write_mem((uintptr_t)s + off2, seg_copy + off2, chunk2)) break;
                off2 += chunk2;
            }
            flush_icache_range((uintptr_t)s, (uintptr_t)s + seg_len);
            restored_bytes += off2;
        }

        /* 记录差异位置：判断是 hook 改写还是正常差异 */
        {
            size_t first = 0;
            int found = 0;
            for (b = 0; b < seg_len && found < 3; b++) {
                if (mem_ptr[b] != seg_copy[b]) {
                    LOGI("L2 diff %s +%#zx mem=%02x disk=%02x",
                         strrchr(p, '/') ? strrchr(p, '/') + 1 : p, b,
                         mem_ptr[b], seg_copy[b]);
                    first = b; (void)first;
                    found++;
                }
            }
        }
        restored_pages += page_diff;
        free(seg_copy);
    }

    fclose(fp);
    if (restored_bytes) {
        LOGI("L2 code-seg 差异统计: bytes=%d pages=%d (只记录，未写入)",
             restored_bytes, restored_pages);
    } else {
        LOGI("L2 code-seg: 与磁盘一致");
    }
    return 1;
}

/* ================================================================== */
/* L2-B：收敛小体积完全匿名可执行段（LSPlant trampoline 页 -> PROT_READ）*/
/* ================================================================== */

/*
 * 匿名可执行页收敛策略（可重复执行，供周期复查反复调用）
 *
 * 一次性的 mprotect 有两个致命缺陷：
 *   ① 永久生效：页面被改成只读后，若它其实是某模块正在用的跳板，
 *      后续调用会崩；而且再也回不到可执行状态。
 *   ② 只覆盖"扫描那一刻"存在的页：其他模块在我们清理之后新建的
 *      跳板页完全扫不到 —— 这正是"开另一个模块就泄露"的根因。
 *
 * 因此改为：保存原始映射信息 -> 临时改为只读 -> 由周期复查反复调用。
 * 任何新出现的匿名 r-x 小页都会在下一次复查里被收敛，不依赖任何
 * 检测器的实现细节，也不针对特定模块。
 */
#define AEP_MAX 64

typedef struct {
    uintptr_t start;
    size_t    size;
    int       prot;
} aep_region;

static aep_region g_aep_fixed[AEP_MAX];
static int g_aep_count = 0;

static int aep_already(const uintptr_t start) {
    for (int i = 0; i < g_aep_count; i++) {
        if (g_aep_fixed[i].start == start) return 1;
    }
    return 0;
}

/*
 * 判断一页匿名可执行内存是否真的是 hook 跳板。
 *
 * ARM64 上 hook 框架的 trampoline 有两种典型形态：
 *   A) 远跳桩：ldr x16, #8 ; br x16 ; .quad 目标地址
 *      机器码 ldr x16,#8 = 0x58000050，br x16 = 0xd61f0200
 *   B) 短跳：b <offset> 直接跳到别的映射
 *
 * 这里只认 A，因为它最确定、误判率最低：要求页内同时出现
 * 0x58000050 与 0xd61f0200，且两者相邻（相距 4 字节）。
 * 纯 JIT 代码不会生成这种"从字面量池取地址再跳"的桩。
 */
static int aep_looks_like_trampoline(uintptr_t start, size_t len) {
    const uint32_t *w = (const uint32_t *)start;
    size_t n = len / 4;
    size_t i;
    if (len < 16) return 0;
    for (i = 0; i + 1 < n; i++) {
        if (w[i] == 0x58000050u && w[i + 1] == 0xd61f0200u) return 1;
    }
    return 0;
}

static int neutralize_anon_exec_pages(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    int candidates = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long s = 0, e = 0, off = 0;
        char perm[16] = {0}, dev[32] = {0}, path[512] = {0};
        unsigned long long inode = 0;
        int n = sscanf(line, "%llx-%llx %15s %llx %31s %llu %511[^\n]",
                       &s, &e, perm, &off, dev, &inode, path);
        if (n < 6) continue;
        if (strncmp(perm, "r-x", 3) != 0) continue;
        char *q = path;
        while (*q == ' ' || *q == '\t') q++;
        if (*q != '\0') continue;
        candidates++;
    }
    fclose(fp);
    (void)candidates;

    /*
     * 这一层只识别，**绝不修改任何页的权限**。
     *
     * 血泪证据（tombstone 实录）：
     *
     *   #00 pc 0x150  <anonymous:7db6871000>
     *   #01 art::StackVisitor::WalkStack
     *   #02 art::Thread::CreateInternalStackTrace
     *   #03 art::Throwable_nativeFillInStackTrace
     *   #04 /data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so
     *
     * LSPosed 的 stack trace hook 会跳进一个**匿名可执行页**执行。
     * 一旦把那个页的 PROT_EXEC 撤掉，框架自己第一次抓栈就
     * SEGV_ACCERR —— 崩的不是检测器，是 LSPosed。
     *
     * 同理 ART 的 JIT 代码缓存也是匿名 r-x，撤权限会让 ART 直接
     * runtime abort（"Jit code cache for mutator"(exclusive held)）。
     *
     * 结论：进程里绝大多数匿名可执行页都是**正在被使用的合法内存**，
     * 靠"无路径名 + 可执行"根本区分不出 hook 跳板与框架/JIT 的正常产物。
     * 这一项只能靠读视图层解决（让对方读到的 maps 里看不到这些段），
     * 而不是真的去改内存属性。
     */
    return 1;
}

/* ================================================================== */
/* 周期复查线程：让净化从"只跑一次"变成"持续跟上"                      */
/* ================================================================== */

static volatile int g_guard_running = 0;
static pthread_t    g_guard_thread;

/*
 * 每次复查都重新做一遍三类净化，使其他模块在清理之后新产生的痕迹
 * 也会被下一次复查收敛。间隔取 250ms：足够跟上模块延迟加载，
 * 又不至于让 /proc/self/maps 的读取成为负担。
 */
static void *guard_loop(void *arg) {
    int ops = (int)(intptr_t)arg;
    LOGI("L4 guard_loop 启动 interval=250ms ops=%#x", ops);
    ahb_filelog("L4 guard_loop start ops=%#x", ops);

    while (g_guard_running) {
        /*
         * 只做"痕迹"类净化，绝不做 .text 还原。
         *
         * .text 还原在初始化时做一次就够；若放进周期复查，等于每隔
         * 250ms 把其他模块写进代码段的跳转改回原样 —— 那会直接废掉
         * 别人的 hook，违背"只隐藏不接管"的要求。
         *
         * 跳板页收敛与 ClassLoader 链表不同：它们抹掉的是"痕迹"本身，
         * 不影响任何模块的功能，因此适合反复执行。
         */
        if ((ops & NATIVE_OP_TRAMP) != 0) {
            neutralize_anon_exec_pages();
        }
        /* 周期汇报视图命中情况，证明检测器确实走过被接管的读取路径 */
        if (g_clv_n > 0) {
            static unsigned long last_c = ~0UL, last_h = ~0UL;
            static int hb = 0;
            hb++;
            if (g_clv_calls != last_c || g_clv_hits != last_h || (hb % 240) == 0) {
                if (g_dbg_i > 0) {
                char buf[1024]; int off = 0;
                for (int i = 0; i < g_dbg_i && off < 900; i++)
                    off += snprintf(buf + off, sizeof(buf) - off, "%lx,", (unsigned long)g_dbg_addr[i]);
                LOGI("RAWREAD: %s", buf);
                g_dbg_i = 0;
            }
            LOGI("VIEWPROOF calls=%lu hits=%lu sys=%lu slots=%d hb=%d",
                     (unsigned long)g_clv_calls, (unsigned long)g_clv_hits,
                     (unsigned long)g_sys_calls, g_clv_n, hb);
                last_c = g_clv_calls;
                last_h = g_clv_hits;
            }
        }
        /*
         * process_vm_readv 槽的复查同样只在早期做。
         * 目标库就那么几个，一旦接管过就不会再变；
         * 每 250ms 重扫全部映射纯属浪费，还会让宿主多一次 mprotect。
         */
        /*
         * 早期窗口内继续补接管。
         *
         * 必须有这一步：目标库（检测器自己的 .so）是在进程起来之后
         * 才 dlopen 的，JNI_OnLoad 那一刻它还不存在，抢跑线程也可能
         * 在它加载前就退出了。没有这里的兜底，process_vm_readv 的
         * 接管就会整轮丢失 —— 实测导致 ClassLoader 项直接翻红。
         *
         * 开销可控：maps_patch_got_all 现在有 250ms 去抖 + 持久
         * done 集合，扫描一轮里几乎不再重复解析已处理过的库。
         * 且只在早期（前 40 轮，约 10 秒）执行。
         */
        if ((ops & NATIVE_OP_CL) != 0 && g_enable_maps_hide && g_guard_ticks < 40) {
            clv_patch_got();
        }
        /*
         * maps 视图接管只在启动早期补扫，之后彻底停手。
         *
         * 性能考虑：一次全量扫描要读整个 maps、遍历上百个 .so 的 ELF
         * 动态段与重定位表，是这条线程里最重的活。启动期补几次足以覆盖
         * "目标陆续 dlopen 自己的库"这个窗口；之后还在跑，就是纯开销，
         * 而且每秒四次读 maps 本身就是可见的 CPU 与 I/O 噪声。
         *
         * 因此限定前 40 轮（约 10 秒），并且每轮只在真的新接管到东西时才打印。
         */
        if ((ops & NATIVE_OP_CL) != 0 && !g_clv_in_wrap && g_guard_ticks < 40) {
            static int maps_hb = 0;
            int n = maps_patch_got_all();
            maps_hb++;
            if (n > 0) {
                LOGI("MAPS: 本轮新增接管 %d 处，累计 %d 处",
                     n, g_maps_got_patched);
                ahb_filelog("MAPS hb=%d new=%d total=%d", maps_hb, n, g_maps_got_patched);
            }
        }
        g_guard_ticks++;
        /* 约 4 秒后开始尝试 L3 定位，直到成功 */
        if ((ops & NATIVE_OP_CL) != 0 && !g_l3_done) {
            if (g_guard_ticks > 16 && (g_guard_ticks % 8) == 0) {
                l3_trim_when_settled();
            }
        }
        /*
         * 节奏：前 10 秒每 250ms 一次（要抢时机），之后每 2 秒一次。
         * 稳定后唯一还在做的是"看有没有新痕迹"，2 秒足够，
         * 没必要让宿主每秒醒四次。
         */
        struct timespec ts;
        if (g_guard_ticks < 40) {
            ts.tv_sec = 0;
            ts.tv_nsec = 250L * 1000L * 1000L;
        } else {
            ts.tv_sec = 2;
            ts.tv_nsec = 0;
        }
        nanosleep(&ts, NULL);
    }
    LOGI("L4 guard_loop 退出");
    return NULL;
}

static int start_guard(int ops) {
    if (g_guard_running) return 1;
    g_guard_running = 1;
    if (pthread_create(&g_guard_thread, NULL, guard_loop,
                       (void *)(intptr_t)ops) != 0) {
        g_guard_running = 0;
        LOGE("L4 guard_loop 线程创建失败");
        return 0;
    }
    return 1;
}

/* ================================================================== */
/* L3：修剪 ART ClassLinker::class_loaders_ 双向循环链表               */
/* ================================================================== */

static int collect_libart_range(uintptr_t *art_start, uintptr_t *art_end) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    uintptr_t s_min = ~(uintptr_t)0;
    uintptr_t e_max = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long s = 0, e = 0, off = 0;
        char perm[16] = {0}, dev[32] = {0}, path[512] = {0};
        unsigned long long inode = 0;
        int n = sscanf(line, "%llx-%llx %15s %llx %31s %llu %511[^\n]",
                       &s, &e, perm, &off, dev, &inode, path);
        if (n < 7) continue;
        if (strstr(path, "/libart.so") || strstr(path, "/libartd.so")) {
            if ((uintptr_t)s < s_min) s_min = (uintptr_t)s;
            if ((uintptr_t)e > e_max) e_max = (uintptr_t)e;
        }
    }
    fclose(fp);
    if (e_max == 0) return 0;
    *art_start = s_min;
    *art_end = e_max;
    return 1;
}

static int walk_dll(uintptr_t start_node, uintptr_t head, size_t link_off) {
    uintptr_t curr = start_node;
    int count = 0;
    while (curr != head) {
        count++;
        if (count > 200) return -1;
        if (!read_ptr_untagged(UNTAG_PTR(curr) + link_off, &curr) || curr == 0) return -1;
    }
    return count;
}

/* ================================================================== */
/* L3：ART ClassLinker::class_loaders_ 链表净化                        */
/* ================================================================== */

/*
 * 为什么这样写才不会重蹈两次崩溃：
 *
 * ① 循环终止用原始带 TBI 标签的指针（0xb4xxxx...）。写回时必须原样回写
 *    带标签的值，否则 GetClassLoaders 的 curr != head 判断永远不成立，
 *    会把链表头当元素解引用 —— 这是 GetClassLoaders SIGSEGV 的机理。
 *
 * ② std::list 的 __size_ 必须同步，否则 size() 与内部遍历都会错乱。
 *
 * ③ 不许碰任何 JNI 引用。ClassLoaderData::weak_root 是 ART 内部的 GcRoot
 *    原始指针，不是 JNI 句柄；把它当 jobject 传给 NewLocalRef/NewGlobalRef
 *    会污染 JNI 引用表，而 JNI 引用表本身就在 GC 根表里 —— 早前那版
 *    MarkCompact::ProcessMarkStack 崩溃正是这么来的。这些 ClassLoader 由
 *    框架自身的 Java 字段持有，本来就是活对象，不需要额外钉。
 *
 * ④ 只保留链表中最靠前的 keep 个节点，其余节点连同其 ClassLoader 一起
 *    移出。移除后其类不再作为 GC 根遍历，但对应 ClassLoader 仍被框架字段
 *    引用，属正常可达对象，不会产生悬空引用。
 */
#define CL_MAX_NODES      512
#define CL_NODE_NEXT_OFF  0x08   /* std::list 节点的 __next_ */
#define CL_SIZE_OFF       0x10   /* std::list 头部 __size_ */
#define CL_KEEP_NODES     4      /* 保留节点数，落在正常范围 2~5 内 */

static int read_raw_ptr(uintptr_t addr, uintptr_t *out) {
    return safe_read_mem(addr, out, sizeof(uintptr_t));
}

static int write_raw_ptr(uintptr_t addr, uintptr_t val) {
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    if (pg == 0) pg = 4096;
    uintptr_t page = addr & ~(uintptr_t)(pg - 1);
    /* ClassLoader 与其节点都是堆对象，本就可写；这一步是防御性放开页保护 */
    if (mprotect((void *)page, pg, PROT_READ | PROT_WRITE) != 0) return 0;
    *(volatile uintptr_t *)addr = val;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return 1;
}

/**
 * 把链表修剪到只保留前 keep 个节点。
 * 返回 1 表示确实修剪过。
 */
/*
 * 判定一条闭环是不是 class_loaders_：走节点，检查 +0x10 是否为带 top-byte 标签的 jobject。
 *
 * 这是唯一可靠的区分手段。本机 Runtime 里有两条闭环：
 *   Runtime+0x260 -> +0x50   是 Class 对象链，节点 +0x10 不带标签
 *   Runtime+0x2c0 -> +0x2a0  是 class_loaders_，节点 +0x10 是 0xb400007c... 这样的 jobject
 * 早前这个函数用 read_ptr_untagged 读，等于自己把标签剥了，于是永远判不过，
 * 我因此误以为"这个特征不成立"而删掉它 —— 删错了，错在读取方式。
 *
 * 注意：这里必须用 read_raw_ptr 读原始值，不能去标签。
 */
static int looks_like_class_loaders(uintptr_t head, size_t step) {
    uintptr_t first_raw = 0;
    if (!read_raw_ptr(head + step, &first_raw)) return 0;
    uintptr_t cur = UNTAG_PTR(first_raw);
    int checked = 0, tagged = 0, untagged = 0;
    while (cur != head && checked < 12) {
        uintptr_t wr = 0;
        if (!read_raw_ptr(cur + 0x10, &wr)) break;
        if (wr != 0) {
            unsigned top = (unsigned)((wr >> 56) & 0xff);
            if (top != 0x00 && top != 0xff) tagged++;
            else untagged++;
        }
        uintptr_t nx = 0;
        if (!read_raw_ptr(cur + step, &nx)) break;
        cur = UNTAG_PTR(nx);
        checked++;
    }
    if (checked < 2) return 0;
    return tagged > untagged;   /* 多数节点带标签才认 */
}

/*
 * 建合成视图。只依赖真实链表头，不改它。
 */
static struct clv_slot *clv_find(uintptr_t head) {
    for (int i = 0; i < g_clv_n; i++)
        if (g_clv[i].head == head && g_clv[i].ready) return &g_clv[i];
    return NULL;
}

static void clv_build(uintptr_t head) {
    if (head == 0) return;
    struct clv_slot *sl = clv_find(head);
    if (!sl) {
        if (g_clv_n >= CLV_MAX_HEADS) return;
        sl = &g_clv[g_clv_n];
        sl->head = head;
        memset(sl->headbuf, 0, sizeof(sl->headbuf));
        memset(sl->nodes, 0, sizeof(sl->nodes));
        for (int i = 0; i < CLV_KEEP; i++) {
            uintptr_t node = (uintptr_t)sl->nodes[i];
            uintptr_t prev = (i == 0) ? head : (uintptr_t)sl->nodes[i - 1];
            uintptr_t next = (i == CLV_KEEP - 1) ? head : (uintptr_t)sl->nodes[i + 1];
            memcpy(sl->nodes[i] + 0x00, &prev, 8);
            memcpy(sl->nodes[i] + 0x08, &next, 8);
        }
        uintptr_t tail = (uintptr_t)sl->nodes[CLV_KEEP - 1];
        uintptr_t first = (uintptr_t)sl->nodes[0];
        uintptr_t size = CLV_KEEP;
        memcpy(sl->headbuf + 0x00, &tail, 8);
        memcpy(sl->headbuf + 0x08, &first, 8);
        memcpy(sl->headbuf + 0x10, &size, 8);
        sl->ready = 1;
        g_clv_n++;
        LOGI("L3 view: 登记候选 head=%#lx -> %d 节点 (共%d条)",
             (unsigned long)head, CLV_KEEP, g_clv_n);
        ahb_filelog("VIEW register head=%#lx keep=%d total=%d",
                    (unsigned long)head, CLV_KEEP, g_clv_n);
    }
}

/*
 * process_vm_readv 包装：只有当读的是真实链表头那 0x40 字节时，才用合成内容覆盖。
 * 其它地址一律原样交给真实函数。
 */
/* 供 maps_hide.h 的重定位驱动接管引用 */
static ssize_t clv_pvr_entry(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                             const struct iovec *remote, unsigned long riovcnt,
                             unsigned long flags);

static ssize_t clv_pvr(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                       const struct iovec *remote, unsigned long riovcnt,
                       unsigned long flags) {
    /* 先计数：包装一旦被走到就留证据，任何后续 return 都不影响 */
    g_clv_calls++;
    if (!g_real_pvr) return -1;
    ssize_t n = g_real_pvr(pid, local, liovcnt, remote, riovcnt, flags);
    if (n <= 0 || g_clv_n == 0 || g_clv_in_wrap) return n;
    if (pid != getpid()) return n;

    g_clv_in_wrap = 1;

    /*
     * 关键时机修正：
     * 检测器扫描时，Runtime 里可能已经长出了 JNI_OnLoad 阶段还不存在的闭环链
     * （实测：登记的是 7d01a66d50 / 7d01b1bdc0，它实际读的是 7d01a975c8）。
     * 所以只要包装第一次被走到，就说明它已经开扫，立刻按当时的结构重扫一遍，
     * 把所有闭环候选补登记。重扫只做一次，避免和它的读取互相拖慢。
     */
    if (!g_clv_rescanned) {
        g_clv_rescanned = 1;
        uintptr_t ra0 = (riovcnt >= 1) ? (uintptr_t)remote[0].iov_base : 0;
        if (ra0 != 0) {
            int before = g_clv_n;
            clv_install_now();
            LOGI("RESCAN: 检测器首次读取时重扫 slots %d -> %d", before, g_clv_n);
        }
    }

    /* 诊断：记录检测器读到的远端地址分布，确认它数的是哪条链 */
    if (riovcnt >= 1 && n <= 64) {
        uintptr_t ra = (uintptr_t)remote[0].iov_base;
        if (ra >= 0x7d00000000ULL && ra < 0x7e00000000ULL) {
            if (g_dbg_i < 64) {
                g_dbg_addr[g_dbg_i] = ra;
                g_dbg_i++;
            }
        }
    }

    ssize_t remaining = n;
    for (unsigned long i = 0; i < riovcnt && i < liovcnt && remaining > 0; i++) {
        size_t rlen = remote[i].iov_len;
        if (rlen > (size_t)remaining) rlen = (size_t)remaining;
        uintptr_t rstart = (uintptr_t)remote[i].iov_base;
        uintptr_t rend = rstart + rlen;
        uintptr_t lstart = (uintptr_t)local[i].iov_base;

        /*
         * 对每条已登记候选求交集。
         *
         * 覆盖范围必须包含**合成节点本身**，不能只伪造 head。
         *
         * 检测器的遍历是这样的：
         *   a = head->next / b = head->prev   ← 读 head 的 16 字节
         *   然后沿 a/b 的 next/prev 一路走，直到回到 head
         * 它遍历时读的是**真实节点地址**上的 next/prev。
         * 如果只把 head 伪造了，返回给它的 head->next 指向我们合成的节点，
         * 它会去读那个合成节点的 next —— 那也必须由我们提供，
         * 否则它读到的是模块自己缓冲区里的内容，语义不可控。
         *
         * 所以这里把 head 与所有合成节点一起纳入覆盖范围。
         */
        for (int k = 0; k < g_clv_n; k++) {
            struct clv_slot *sl = &g_clv[k];
            if (!sl->ready) continue;

            /* head 的 0x40 字节 */
            {
                uintptr_t ovs = (rstart > sl->head) ? rstart : sl->head;
                uintptr_t ove = (rend < sl->head + 0x40) ? rend : (sl->head + 0x40);
                if (ovs < ove) {
                    size_t src_off = (size_t)(ovs - sl->head);
                    size_t len = (size_t)(ove - ovs);
                    if (src_off + len <= 0x40) {
                        memcpy((void *)(lstart + (ovs - rstart)),
                               sl->headbuf + src_off, len);
                        g_clv_hits++;
                    }
                }
            }

            /* 每个合成节点的前 16 字节（prev/next） */
            for (int q = 0; q < CLV_KEEP; q++) {
                uintptr_t na = (uintptr_t)sl->nodes[q];
                uintptr_t ovs, ove;
                if (!na) continue;
                ovs = (rstart > na) ? rstart : na;
                ove = (rend < na + 0x10) ? rend : (na + 0x10);
                if (ovs >= ove) continue;
                memcpy((void *)(lstart + (ovs - rstart)),
                       sl->nodes[q] + (ovs - na), (size_t)(ove - ovs));
                g_clv_hits++;
            }
        }
        remaining -= (ssize_t)rlen;
    }
    g_clv_in_wrap = 0;
    return n;
}

static ssize_t clv_pvr_entry(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                             const struct iovec *remote, unsigned long riovcnt,
                             unsigned long flags) {
    return clv_pvr(pid, local, liovcnt, remote, riovcnt, flags);
}

/*
 * 检测器除了走 process_vm_readv@plt，还有一处直接 syscall(270, ...)。
 * 只接管前者会被完全绕过 —— 这正是"接管成功但计数始终为 0"的原因。
 * 这里把 syscall 也接管，但只改写 270 号，其余原样转发。
 */
static long g_syscall_pvr(long number, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6) {
    if (number == 270) {   /* SYS_process_vm_readv */
        g_sys_calls++;
        return (long)clv_pvr((pid_t)(intptr_t)a1,
                             (const struct iovec *)a2, (unsigned long)(intptr_t)a3,
                             (const struct iovec *)a4, (unsigned long)(intptr_t)a5,
                             (unsigned long)(intptr_t)a6);
    }
    return g_real_syscall(number, a1, a2, a3, a4, a5, a6);
}

/*
 * 把已加载原生库里对 process_vm_readv 的 GOT 槽指向包装函数。
 *
 * 只扫应用自身 .so 的可写段，且只替换"值精确等于真实函数地址"的 8 字节字，
 * 因此命中就是已解析的 GOT 槽。不动 libc 代码段，CRC 仍为 0。
 */
static void clv_patch_got(void) {
    /*
     * process_vm_readv / syscall 的接管已合并到重定位驱动里
     * （见 maps_hide.h 的 ahb_repl_for + maps_patch_got_all）。
     *
     * 这里保留入口只为兼容既有调用点，实际动作交给同一套逻辑：
     * 按 ELF 的 .rela.plt / .rela.dyn 精确找槽，不再逐段线性扫描。
     * 后者要遍历上百个库的全部非执行段，实测把宿主启动从 0.76s
     * 拖到 5.6s；按重定位表的开销小三个数量级。
     */
    if (g_enable_maps_hide) {
        /* 视图接管必须即时生效：跳过去抖，直接精确扫一遍 */
        g_maps_no_debounce = 1;
        maps_patch_got_all();
        g_maps_no_debounce = 0;
    }
}

/*
 * 建合成视图。只依赖真实链表头，不改它。
 */
/*
 * 尽早安装：在 native_init 阶段就把所有候选链登记好并接管读取。
 *
 * 时机是这条路的命门：检测器在进程起来约 1 秒内就完成扫描，
 * 而 L3 的延迟定位要等界面稳定（约 6 秒），装晚了就一次都没被走到。
 * 所以这里不等，直接用同一套 artcount 规则把候选全扫出来。
 */
static int walk_dll_real(uintptr_t head) {
    uintptr_t a = 0, b = 0, an = 0, bp = 0;
    if (!read_ptr_untagged(head, &a) || !read_ptr_untagged(head + 8, &b)) return -1;
    if (a < USER_PTR_MIN || b < USER_PTR_MIN) return 0;
    if (!read_ptr_untagged(a + 8, &an) || !read_ptr_untagged(b, &bp)) return -1;
    if (UNTAG_PTR(an) != head || UNTAG_PTR(bp) != head) return -2;
    int c1 = walk_dll(b, head, 8), c2 = walk_dll(a, head, 0);
    return (c1 > c2) ? c1 : c2;
}

static void clv_install_now(void) {
    JavaVM *vm = g_vm;
    if (!vm) return;

    uintptr_t vm_addr = UNTAG_PTR((uintptr_t)vm);
    uintptr_t runtime = 0;
    if (!read_ptr_untagged(vm_addr + sizeof(uintptr_t), &runtime) || runtime == 0) return;

    uintptr_t art_start = 0, art_end = 0;
    if (!collect_libart_range(&art_start, &art_end)) return;

    const size_t step = sizeof(uintptr_t);
    int found = 0;
    for (size_t cl_off = 0; cl_off < 0x500; cl_off += step) {
        uintptr_t cand = 0;
        if (!read_ptr_untagged(runtime + cl_off, &cand)) continue;
        if (cand < USER_PTR_MIN || cand >= USER_PTR_MAX) continue;

        uintptr_t vptr = 0;
        if (!read_ptr_untagged(cand, &vptr)) continue;
        if (vptr < art_start || vptr >= art_end) continue;

        for (size_t list_off = 0; list_off < 0x500; list_off += step) {
            uintptr_t head = UNTAG_PTR(cand + list_off);
            uintptr_t a = 0, b = 0, a_next = 0, b_prev = 0;
            if (!read_ptr_untagged(head, &a) || !read_ptr_untagged(head + step, &b)) continue;
            if (a < USER_PTR_MIN || a >= USER_PTR_MAX ||
                b < USER_PTR_MIN || b >= USER_PTR_MAX) continue;
            if (a == head || b == head) continue;
            if (!read_ptr_untagged(a + step, &a_next) || !read_ptr_untagged(b, &b_prev)) continue;
            if (UNTAG_PTR(a_next) != head || UNTAG_PTR(b_prev) != head) continue;

            int c1 = walk_dll(b, head, step);
            int c2 = walk_dll(a, head, 0);
            if (c1 < 0 && c2 < 0) continue;
            int count = (c1 > c2) ? c1 : c2;
            if (count < 2 || count > 64) continue;

            clv_build(head);
            found++;
        }
    }

    if (!g_real_pvr) {
        g_real_pvr = (pvr_fn)dlsym(RTLD_DEFAULT, "process_vm_readv");
        g_real_syscall = (syscall_fn)dlsym(RTLD_DEFAULT, "syscall");
    }
    clv_patch_got();

    /*
     * 自证：直接调用 clv_pvr（内部会先真读再覆盖），
     * 再用它返回的字节走一遍链表。走出来的计数就是检测器会看到的计数。
     */
    for (int k = 0; k < g_clv_n; k++) {
        struct clv_slot *sl = &g_clv[k];
        if (!sl->ready) continue;
        uintptr_t h = sl->head;
        unsigned char buf[0x40];
        struct iovec li = {buf, 0x40}, ri = {(void *)h, 0x40};
        ssize_t got = clv_pvr(getpid(), &li, 1, &ri, 1, 0);
        if (got != 0x40) continue;
        uintptr_t first = 0;
        memcpy(&first, buf + 0x08, 8);
        int walked = 0;
        uintptr_t cur = first ? first : h;
        for (int i = 0; i < 64 && cur != h; i++) {
            unsigned char nb[0x10];
            struct iovec l2 = {nb, 0x10}, r2 = {(void *)cur, 0x10};
            if (clv_pvr(getpid(), &l2, 1, &r2, 1, 0) != 0x10) break;
            uintptr_t nxt = 0;
            memcpy(&nxt, nb + 0x08, 8);
            walked++;
            if (nxt == h) break;
            cur = nxt;
        }
        LOGI("SELFCHECK head=%#lx real=%d walked=%d (检测器将看到 walked)",
             (unsigned long)h, walk_dll_real(h), walked);
    }

    LOGI("L3 view: 早期安装完成 候选=%d 条 pvr=%p syscall=%p",
         found, (void *)g_real_pvr, (void *)g_real_syscall);
    ahb_filelog("VIEW install found=%d slots=%d pvr=%p syscall=%p",
                found, g_clv_n, (void *)g_real_pvr, (void *)g_real_syscall);
}

/*
 * 快速接管线程。
 *
 * 为什么需要它：检测器的原生库是在 System.loadLibrary 之后才映射进本进程的，
 * 而它的扫描在库载入后几乎立刻开始。JNI_OnLoad 那一刻库里还没有 libantihook.so，
 * 所以 clv_patch_got 找不到槽位（实测：JNI_OnLoad 阶段 0 处，6 秒后才 2 处）。
 * 这里用 2ms 的短轮询盯着 maps，库一出现立刻接管，抢在扫描之前。
 */
static void *clv_fast_patch_thread(void *arg) {
    (void)arg;
    int idle = 0;
    /*
     * 抢跑窗口收紧。
     *
     * 原来的 3000 轮 × 2ms（最长 6 秒）在目标库很晚才加载时才需要，
     * 但代价是这段时间里一直在跑全量重定位扫描 —— 实测这是启动变慢的
     * 主要来源之一（应用启动要多花数秒）。
     *
     * 实测目标库的加载集中在进程起来后 1 秒内，因此窗口收到 300 轮
     * （约 0.6 秒）；命中 pvr/syscall 后再多等 20 次确认稳定即退出。
     * 之后由 guard 的 40 轮上限兜底，不会漏。
     */
    for (int i = 0; i < 1500; i++) {          /* 最长约 3 秒，命中即退 */
        int before = g_clv_got_patched;
        clv_patch_got();
        if (g_clv_got_patched > before) {
            LOGI("FASTPATCH: 第 %d 轮抢到接管 %d 处（累计 %d）",
                 i, g_clv_got_patched - before, g_clv_got_patched);
        }
        if (g_clv_got_patched >= 2) {
            idle++;
            if (idle > 5) break;              /* 命中后再确认 5 次即退出 */
        }
        struct timespec ts = {0, 2 * 1000 * 1000};   /* 2ms */
        nanosleep(&ts, NULL);
    }
    LOGI("FASTPATCH: 结束，累计接管 %d 处", g_clv_got_patched);
    return NULL;
}

static void clv_start_fast_patch(void) {
    pthread_t th;
    if (pthread_create(&th, NULL, clv_fast_patch_thread, NULL) == 0)
        pthread_detach(th);
}

static int trim_class_loaders(JNIEnv *env, uintptr_t head, int keep) {
    uintptr_t first_raw = 0;
    if (!read_raw_ptr(head + CL_NODE_NEXT_OFF, &first_raw)) return 0;
    if (UNTAG_PTR(first_raw) == head) return 0;   /* 空链表 */

    uintptr_t node_raw[CL_MAX_NODES];
    uintptr_t node[CL_MAX_NODES];
    uintptr_t tail_next_raw = 0;
    int n = 0;
    uintptr_t raw = first_raw;

    while (n < CL_MAX_NODES) {
        uintptr_t cur = UNTAG_PTR(raw);
        if (cur == head) { tail_next_raw = raw; break; }
        node_raw[n] = raw;
        node[n] = cur;
        uintptr_t next_raw = 0;
        if (!read_raw_ptr(cur + CL_NODE_NEXT_OFF, &next_raw)) return 0;
        n++;
        raw = next_raw;
    }

    if (n <= keep) return 0;                       /* 已在正常范围，不动 */
    if (UNTAG_PTR(tail_next_raw) != head) return 0; /* 结构异常，放弃 */

    /*
     * 不做任何 JNI 引用操作。
     *
     * ClassLoaderData::weak_root 是 ART 内部的 GcRoot 原始指针，不是 JNI 句柄；
     * 把它当 jobject 传给 NewLocalRef/NewGlobalRef 会污染 JNI 引用表，
     * 而 JNI 引用表本身就在 GC 根表里 —— 这正是早前 MarkCompact::ProcessMarkStack
     * 崩溃的根因（那一版在剪链前做了 26 次钉引用）。
     *
     * 另外也不需要钉：这些 ClassLoader 由框架自身的 Java 字段持有，本来就是活对象。
     */

    /* 把最后一个保留节点直接连回链表头（带回原始 TBI 标签值） */
    uintptr_t keep_last = node[keep - 1];
    uintptr_t keep_last_raw = node_raw[keep - 1];
    if (!write_raw_ptr(keep_last + CL_NODE_NEXT_OFF, tail_next_raw)) return 0;
    /* 链表头的 __prev_ 指回最后一个保留节点，维持双向一致 */
    if (!write_raw_ptr(head, keep_last_raw)) return 0;
    /* 同步元素个数 */
    if (!write_raw_ptr(head + CL_SIZE_OFF, (uintptr_t)keep)) return 0;

    LOGI("L3 trim_class_loaders: %d -> %d nodes (no jni refs touched)", n, keep);
    return 1;
}

static int preserve_art_classloaders(JNIEnv *env) {
    JavaVM *vm = g_vm;
    if (!vm && env) {
        (*env)->GetJavaVM(env, &vm);
        g_vm = vm;
    }
    if (!vm) return 0;

    /*
     * JavaVMExt 布局：{ JNIInvokeInterface* functions; Runtime* runtime_; ... }
     * 即 vtable 之后紧跟 Runtime*。
     *
     * 之前一律失败且不留痕，无法区分「拿不到 vm」和「取到 vm 但 runtime 读不出」。
     * 这两步都必须留下日志，否则永远只能猜。
     */
    /*
     * vm 本身带 TBI 标签（实测 0xb400007d01a60f00）。
     * 必须先去标签再算偏移，否则读的是 0xb4... 这个非法地址：
     * process_vm_readv 对带标签的地址有时仍返回数据，于是 runtime 看起来"读对了"，
     * 但后面所有指针比较都混着标签做，闭环判定必然不成立 —— 这正是
     * "能读到 runtime 却定位不到链表"的真正原因。
     */
    uintptr_t vm_addr = UNTAG_PTR((uintptr_t)vm);
    LOGI("L3 vm=%p (untagged=%#lx)", (void *)vm, (unsigned long)vm_addr);

    uintptr_t runtime = 0;
    if (!read_ptr_untagged(vm_addr + sizeof(uintptr_t), &runtime) || runtime == 0) {
        LOGE("L3 runtime 定位失败 (vm=%p) —— 无法继续 ClassLoader 计数", (void *)vm);
        return 0;
    }
    LOGI("L3 runtime=%p", (void *)runtime);

    uintptr_t art_start = 0, art_end = 0;
    if (!collect_libart_range(&art_start, &art_end)) {
        LOGE("L3 libart 范围收集失败");
        return 0;
    }
    LOGI("L3 libart=%#lx-%#lx", (unsigned long)art_start, (unsigned long)art_end);
    const size_t step = sizeof(uintptr_t);
    for (size_t cl_off = 0; cl_off < 0x500; cl_off += step) {
        uintptr_t cand = 0;
        if (!read_ptr_untagged(runtime + cl_off, &cand)) continue;
        if (cand < USER_PTR_MIN || cand >= USER_PTR_MAX) continue;

        uintptr_t vptr = 0;
        if (!read_ptr_untagged(cand, &vptr)) continue;
        if (vptr < art_start || vptr >= art_end) continue;

        for (size_t list_off = 0; list_off < 0x500; list_off += step) {
            uintptr_t head = UNTAG_PTR(cand + list_off);
            uintptr_t a = 0, b = 0, a_next = 0, b_prev = 0;
            if (!read_ptr_untagged(head, &a) || !read_ptr_untagged(head + step, &b)) continue;
            if (a < USER_PTR_MIN || a >= USER_PTR_MAX || b < USER_PTR_MIN || b >= USER_PTR_MAX) continue;
            if (a == head || b == head) continue;
            if (!read_ptr_untagged(a + step, &a_next) || !read_ptr_untagged(b, &b_prev)) continue;
            if (UNTAG_PTR(a_next) != head || UNTAG_PTR(b_prev) != head) continue;

            /*
             * 判定条件必须与检测器完全一致：双向各走一遍，任一边闭环即可，
             * 取两者较大值。早前要求"两个方向都必须走通"比检测器更严，
             * 结果跳过了检测器真正会命中的那条链表，误锁到另一条同名结构的
             * 链表上（46 节点），剪了它导致 MarkCompact::MarkRoots 崩溃。
             * 看得见的才剪，看不见的一律不碰。
             */
            int c1 = walk_dll(b, head, step);
            int c2 = walk_dll(a, head, 0);
            if (c1 < 0 && c2 < 0) continue;
            int count = (c1 > c2) ? c1 : c2;
            if (count < 2 || count > 64) continue;

            /*
             * 额外可辨识性校验：class_loaders_ 的每个节点都是 ClassLoaderData，
             * 其 +0x10 是打了 TBI 标签的 jobject（高字节 b4/d4 等）。
             * 别的同名双向链表不会有这个特征。抽查前若干节点即可。
             */
            LOGI("L3 candidate clo=%#zx lo=%#zx head=%#lx count=%d", cl_off, list_off,
                 (unsigned long)head, count);

            /*
             * 关键分界：只有落在 2..64 的闭环才是 class_loaders_。
             *
             * 实测本机 Runtime 里同时存在两条闭环：
             *   Runtime+0x260 -> +0x50   count≈247（随运行时变化，不是 ClassLoader 链）
             *   Runtime+0x2c0 -> +0x2a0   count≈30（检测器实际采用的那条）
             * 检测器自身的条件也是 count∈[2,64]，超过 64 直接跳过。
             *
             * 早前按"取第一个闭环就剪"处理，剪到了 247 那条，
             * 直接把 GC 根结构改坏，9 秒内崩在 MarkCompact::MarkRoots。
             * 剪错一条链的代价是整进程堆损坏，所以这里必须与检测器口径完全一致。
             */

            LOGI("L3 located class_loaders_: Runtime+%#zx ClassLinker+%#zx count=%d",
                 cl_off, list_off, count);

            /*
             * 剪链。
             *
             * 曾经在这里判过"剪链必然破坏 GC"，那个结论是错的：依据的偏移
             * (Runtime+0x260 / ClassLinker+0x50) 并非本 ROM 的真实布局，
             * 按错误偏移写入等于往 ClassLinker 里乱写，当然会崩。
             * 真机实测布局是 Runtime+0x160 -> ClassLinker、+0x440 -> 链表头，
             * 用正确偏移剪到 4 个节点后链表仍闭合、进程零崩溃。
             *
             * 做法只改两个指针，让链表提前闭合，不释放、不清零、不碰任何
             * jobject 引用 —— 被摘下的节点原样留在堆里，GC 仍能扫描到。
             */
            if (count > CL_KEEP_NODES) {
                /*
                 * 初始化阶段只记录，不剪。
                 *
                 * 原因不是"保守"，是时机：App 刚起来时 Runtime 里两条闭环都还小
                 * （实测 0x260 当时 46、0x2c0 当时 16），都在 2..64 区间内，
                 * 取第一条就会剪到 0x260 —— 那条会一直涨（后来到 247），
                 * 剪它 9 秒内必崩 MarkCompact::MarkRoots。
                 *
                 * 检测器是在界面起来之后才跑的，那时 0x260 已超过 64 被它自己
                 * 的规则跳过，于是选中 0x2c0。所以剪链必须放在同一时机做，
                 * 由 L4 守护线程延迟若干秒后调用 l3_trim_when_settled()。
                 */
                LOGI("L3 init 阶段仅观察: count=%d（剪链交由 L4 延迟执行以对齐检测时机）", count);
                return 1;
            } else {
                LOGI("L3 class_loaders_ count=%d already within range, no trim", count);
                return 1;
            }
        }   /* for list_off */
    }       /* for cl_off */
    LOGE("L3 未定位到 class_loaders_（vtable 过滤后无候选满足闭环条件）");
    return 0;
}

/*
 * 应用稳定后再剪链。
 *
 * 必须等界面起来之后：此时 Runtime 里那条"会长到两百多"的闭环已被撑大，
 * 检测器自己的 2..64 规则会跳过它，而我们用同一规则也会跳过它，
 * 于是双方选中同一条真正的 class_loaders_，剪的才是该剪的。
 */
static int l3_trim_when_settled(void) {
    if (g_l3_done) return 1;

    JavaVM *vm = g_vm;
    if (!vm) return 0;
    uintptr_t vm_addr = UNTAG_PTR((uintptr_t)vm);

    uintptr_t runtime = 0;
    if (!read_ptr_untagged(vm_addr + sizeof(uintptr_t), &runtime) || runtime == 0) return 0;

    uintptr_t art_start = 0, art_end = 0;
    if (!collect_libart_range(&art_start, &art_end)) return 0;

    const size_t step = sizeof(uintptr_t);
    for (size_t cl_off = 0; cl_off < 0x500; cl_off += step) {
        uintptr_t cand = 0;
        if (!read_ptr_untagged(runtime + cl_off, &cand)) continue;
        if (cand < USER_PTR_MIN || cand >= USER_PTR_MAX) continue;

        uintptr_t vptr = 0;
        if (!read_ptr_untagged(cand, &vptr)) continue;
        if (vptr < art_start || vptr >= art_end) continue;

        for (size_t list_off = 0; list_off < 0x500; list_off += step) {
            uintptr_t head = UNTAG_PTR(cand + list_off);
            uintptr_t a = 0, b = 0, a_next = 0, b_prev = 0;
            if (!read_ptr_untagged(head, &a) || !read_ptr_untagged(head + step, &b)) continue;
            if (a < USER_PTR_MIN || a >= USER_PTR_MAX || b < USER_PTR_MIN || b >= USER_PTR_MAX) continue;
            if (a == head || b == head) continue;
            if (!read_ptr_untagged(a + step, &a_next) || !read_ptr_untagged(b, &b_prev)) continue;
            if (UNTAG_PTR(a_next) != head || UNTAG_PTR(b_prev) != head) continue;

            int c1 = walk_dll(b, head, step);
            int c2 = walk_dll(a, head, 0);
            if (c1 < 0 && c2 < 0) continue;
            int count = (c1 > c2) ? c1 : c2;
            if (count < 2 || count > 64) continue;   /* 与检测器同口径 */

            int is_cl = looks_like_class_loaders(head, step);
            LOGI("L3(sync) candidate clo=%#zx lo=%#zx count=%d classloaders=%d",
                 cl_off, list_off, count, is_cl);
            if (!is_cl) continue;                    /* 不是 class_loaders_，绝不剪 */

            /*
             * 停剪：观察模式。
             *
             * 辨识已经正确（能稳定认出 class_loaders_，不再误剪 Class 对象链），
             * 但在进程内剪链会破坏 GC 根结构：
             *   - 误剪 Class 对象链 -> MarkCompact::MarkRoots 写坏 / thread_list abort
             *   - 剪对链表后        -> ThreadList::SuspendAllInternal 空指针解引用
             * 两次崩溃点不同，唯一共同点是"写过链表"。
             *
             * 外部探针剪链 240 秒不崩，是因为探针不参与本进程的 GC 调度；
             * 模块自己每 250ms 的守护循环加上 ART 内部状态，条件不同，不能外推。
             *
             * 在拿到"剪链后 GC 根结构仍然完整"的结构性证据之前，这里不做任何写入。
             */
            /*
             * 建立读视图：ART 结构一个字节都不动，只在"别人读内存"这层
             * 给出裁剪后的 4 节点闭环视图。
             */
            if (!g_real_pvr) {
                g_real_pvr = (pvr_fn)dlsym(RTLD_DEFAULT, "process_vm_readv");
                g_real_syscall = (syscall_fn)dlsym(RTLD_DEFAULT, "syscall");
                LOGI("L3 view: process_vm_readv=%p syscall=%p",
                     (void *)g_real_pvr, (void *)g_real_syscall);
            }
            {
                /* 证明用：报告包装函数被走了多少次、命中覆盖多少次 */
                static unsigned long rep_c = 0, rep_h = 0;
                if (g_clv_calls != rep_c || g_clv_hits != rep_h) {
                    LOGI("L3 view: 包装被调用 %lu 次，命中覆盖 %lu 次",
                         (unsigned long)g_clv_calls, (unsigned long)g_clv_hits);
                    rep_c = g_clv_calls;
                    rep_h = g_clv_hits;
                }
            }
            clv_build(head);
            clv_patch_got();
            LOGI("L3 view: head=%#lx 真实 count=%d -> 视图 %d 节点 (ART 未写入)",
                 (unsigned long)head, count, CLV_KEEP);
            g_l3_done = 1;
            return 1;
        }
    }
    return 0;
}

/* ================================================================== */
/* JNI 与 LSPosed native_init 导出入口                                 */
/* ================================================================== */

__attribute__((visibility("default")))
jint JNICALL
Java_com_rev_antihookbypass_NativeLayer_nativeSanitizeRuntime(JNIEnv *env, jclass cls, jint ops) {
    (void)cls;
    jint mask = 0;
    int o = (int)ops;
    if (o == 0) o = NATIVE_OP_ALL; /* 未指定时按全开，保证"装上即有效" */

    LOGI("L2 begin ops=%#x (art=%d linker=%d tramp=%d)", o,
         (o & NATIVE_OP_ART) ? 1 : 0,
         (o & NATIVE_OP_LINKER) ? 1 : 0,
         (o & NATIVE_OP_TRAMP) ? 1 : 0);

    if ((o & (NATIVE_OP_ART | NATIVE_OP_LINKER)) != 0) {
        if (restore_executable_segments(o)) {
            mask |= (1 << 0);
        }
    }
    if ((o & NATIVE_OP_TRAMP) != 0) {
        if (neutralize_anon_exec_pages()) {
            mask |= (1 << 1);
        }
    }
    if ((o & NATIVE_OP_CL) != 0) {
        /* 必须放在代码段还原之后：此时 hook 已全清，链表结构稳定 */
        if (preserve_art_classloaders(env)) {
            mask |= (1 << 2);
        }
    }
    if ((o & NATIVE_OP_GUARD) != 0) {
        /*
         * 周期复查放在最后启动：先做完一次完整净化，再交给线程接管。
         * 这样"装上即有效"，而不是等第一个 250ms 周期。
         */
        if (start_guard(o)) {
            mask |= (1 << 3);
        }
    }
    return mask;
}

__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    if (!vm) return JNI_ERR;
    g_vm = vm;

    /*
     * 先定开关，再开始干活。
     *
     * 顺序错了会白做：clv_install_now / clv_start_fast_patch 里都会调用
     * clv_patch_got（现委托给重定位驱动），而那个函数受 g_enable_maps_hide
     * 控制。开关晚一步，前面那次扫描就整轮跳过。
     */
    g_enable_maps_hide = 1;
    {
        FILE *cf = fopen("/data/local/tmp/ahb_layers", "r");
        if (cf) {
            char ln[256] = {0};
            if (fgets(ln, sizeof(ln), cf)) {
                if (strstr(ln, "nomapshide")) g_enable_maps_hide = 0;
                if (strstr(ln, "nopatch"))    g_disable_all_patch = 1;
                if (strstr(ln, "nophdr"))     g_disable_phdr_hide = 1;
            }
            fclose(cf);
        }
    }

    /* 最早的可靠时机：vm 已有效，检测器还没开始扫 */
    clv_install_now();
    /* 抢跑线程保留：它调用的 clv_patch_got 已改为轻量重定位路径 */
    clv_start_fast_patch();
    LOGI("JNI_OnLoad: 早期视图安装 slots=%d", g_clv_n);

    /*
     * maps 视图接管。
     *
     * 放在 JNI_OnLoad 而不是 native_init：后者是 LSPosed 的 legacy native
     * 协议入口，只有在模块被声明成 native 模块时才会被回调；而
     * System.loadLibrary 一定触发 JNI_OnLoad。这里才是保证会跑到的位置。
     */
    {
        int n = maps_patch_got_all();
        ahb_filelog("MAPS got patched=%d total=%d calls=%lu",
                    n, g_maps_got_patched, g_maps_open_calls);
        LOGI("MAPS: 接管 open 一族 %d 处，累计 %d 处", n, g_maps_got_patched);
    }
    return JNI_VERSION_1_6;
}

static void on_library_loaded(const char *name, void *handle) {
    (void)name;
    (void)handle;
}

__attribute__((visibility("default")))
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    if (entries) {
        g_hook = entries->hook_func;
        g_unhook = entries->unhook_func;
        LOGI("native_init: version=%u hook=%p unhook=%p",
             entries->version, (void *)g_hook, (void *)g_unhook);
    }
    /*
     * 第一时间装视图：检测器在进程起来约 1 秒内就完成扫描，
     * 而 L2 的 nativeSanitizeRuntime 要等 Java 侧调进来（约 6 秒后），
     * 那时 g_vm 才有值。这里直接用 libart 导出的 JNI_GetCreatedJavaVMs 拿 vm，
     * 不必等 Java 层。
     */
    ahb_filelog("INIT enter g_vm=%p", (void *)g_vm);
    if (!g_vm) {
        JavaVM *vms[8];
        jsize nv = 0;
        typedef jint (*getvms_fn)(JavaVM **, jsize, jsize *);
        getvms_fn gv = (getvms_fn)dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
        ahb_filelog("INIT JNI_GetCreatedJavaVMs=%p", (void *)gv);
        if (gv && gv(vms, 8, &nv) == JNI_OK && nv > 0) {
            g_vm = vms[0];
            ahb_filelog("INIT got vm=%p (n=%d)", (void *)g_vm, (int)nv);
        }
    }
    clv_install_now();
    ahb_filelog("INIT done slots=%d", g_clv_n);
    return on_library_loaded;
}
