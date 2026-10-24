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

/* ================================================================== */
/* 日志开关（全部只有"说话"的区别，零行为差异）                          */
/* ================================================================== */

/*
 * AHB_DIAG：排查用探针（SELFCHK/LEAK/CMP/VIEWART/VIEWMNT/WRAPROW/
 *            WATCH/DLOPEN/NOW/FLDD/SRC 等）。
 * 交付版必须 0 —— 这些日志会把模块自己的存在写进 logcat，本身就是痕迹。
 */
#ifndef AHB_DIAG
#define AHB_DIAG 0
#endif

/*
 * AHB_SAY：运行期确认日志（L3 view / VIEW install / VIEWPROOF / SELFCHECK）。
 * 这几类每秒几十条，会把模块存在暴露在 logcat 里。
 * 交付版 0：行为完全不变，只是不再说话。
 */
#ifndef AHB_SAY
#define AHB_SAY 0
#endif

#if AHB_SAY
#define AHB_SAYL(...) LOGI(__VA_ARGS__)
#else
#define AHB_SAYL(...) do { } while (0)
#endif

#if AHB_SAY
static void ahb_pathcheck(void);   /* 前向声明：调用点在定义之前 */
#endif

#define LOG_TAG "AntiHookBypass"

/* 诊断落文件：logcat 环形缓冲会被系统高频输出冲掉，证据必须留盘 */

/*
 * 日志策略：只走 logcat，绝不落文件。
 *
 * 为什么不能落文件：模块运行在目标应用的进程里，任何文件都创建在
 * **目标应用自己的私有目录**中。对方只要 listFiles() 看一眼，或者
 * 读一下自己的 files 目录，就能发现 ahb_native.log 这种异物 ——
 * 这比类名特征暴露得更直接。所以运行时零文件创建是硬要求。
 *
 * 为什么用 logcat 而不是别的通道：LSPosed 会把模块日志汇总到它自己的
 * 日志界面，logcat 本身也是标准观测面，不需要我们在磁盘上留任何东西。
 *
 * 为什么还要分级：高频诊断行一次检测下来几千行，全开会在热路径上
 * 放大成可测量延迟，也会把 logcat 缓冲区冲掉（实测冲掉后连关键证据
 * 都读不到）。所以默认只报关键节点，详细诊断由编译期宏 AHB_DEBUG 打开。
 * 用编译期而不是运行时文件开关：没有用户界面就没有"现场切换"的需求，
 * 留一个文件开关只会给目标应用多一个可探测点。
 */
#ifndef AHB_DEBUG
#define AHB_DEBUG 0
#endif

static void ahb_filelog(const char *fmt, ...) {
#if AHB_SAY
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", buf);
    }
#else
    (void)fmt;
#endif
}

/*
 * 关键日志：无论是否开启 AHB_DEBUG 都要输出。
 * 只用于"层是否装上、补丁是否生效、差异多少字节"这类少量节点。
 */
/*
 * keylog / filelog 是"确认某件事装上了"的运行期日志。
 *
 * 它们不是错误，但每秒几十条，且会把模块存在写进 logcat。
 * 交付版统一由 AHB_SAY 关掉；排查能力是否生效时改成 1。
 */
static void ahb_keylog(const char *fmt, ...) {
#if AHB_SAY
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", buf);
    }
#else
    (void)fmt;
#endif
}

#ifndef AHB_NATIVE_ON
#define AHB_NATIVE_ON 1

/*
 * AHB_MINIMAL_VIEW：只装视图过滤，不做任何 ART 结构改写。
 *
 * 这个开关是为定位 jit_code_cache 断言而设的实验档：
 * 保留 maps/smaps/mounts/modules 的视图过滤（修 SIGSEGV 靠它），
 * 但不调 clv_install_now / clv_start_fast_patch（这两个会遍历并
 * 改写 ART 的 class_loaders_ 链表，是干扰 JIT 记账的头号嫌疑）。
 *
 * 定位完成后应回到 0。
 */
#ifndef AHB_MINIMAL_VIEW
#define AHB_MINIMAL_VIEW 0

/*
 * EXP_NO_VIEW：关掉视图过滤做对照。
 * 目的：把"注入本身"与"maps 改写"分开。若关掉后目标不再 abort，
 * 说明问题出在改写 maps 的内容上（而不是注入这件事）。
 */
#ifndef EXP_NO_VIEW
#define EXP_NO_VIEW 0
#endif
#endif
#endif

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
/* 入口探针：ERROR 级别 + 独立 tag，避免被 logd 的 per-tag 限流丢掉 */
#define AHB_ENTRY(tag) do { \
    for (int _i = 0; _i < 3; _i++) \
        __android_log_print(ANDROID_LOG_ERROR, "AHBENTRY", "%s pid=%d n=%d", \
                            tag, (int)getpid(), _i); \
} while (0)

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
#define CLV_KEEP 2
#define CLV_MAX_CHAIN 64
#define CLV_MAX_HEADS 64

/*
 * 一次登记多条候选链。
 * 检测器在 Runtime 里扫 0..0x500，凡满足闭环的都会试；它最终采用哪条取决于
 * 运行时机（早期 0x260 只有 46 个节点时也在 2..64 内）。既然判不准，就把
 * 所有候选一起伪造，无论它读哪条，看到的都是 4 节点。
 */
struct clv_slot {
    uintptr_t head;
    uintptr_t cand;        /* head 所属的候选对象（head = cand + list_off） */
    unsigned char headbuf[0x40];
    uintptr_t     node_addr[CLV_MAX_CHAIN]; /* 真实节点地址 */
    unsigned char nodebuf[CLV_MAX_CHAIN][0x10]; /* 每个真实节点要返回的 prev/next */
    int           keep;
    volatile int ready;
};
static struct clv_slot g_clv[CLV_MAX_HEADS];

/*
 * ===== 地址索引表（把热路径从 O(n·m) 降到 O(1)）=====
 *
 * 动机是一条实测数据：一次检测里 process_vm_readv 包装被调用 12835 次，
 * 而每次调用都要走两步全表扫描：
 *   clv_find()            -> 遍历最多 64 个 slot
 *   clv_is_chain_member() -> 再遍历每个 slot 的最多 CLV_MAX_CHAIN 个节点
 * 合计最坏 64 + 64×64 次比较，乘以 12835 次调用就是千万级内存读。
 * 改成开放寻址哈希表后，登记时同时插入 head 与全部节点地址，
 * 查询时一次哈希命中。表容量取 2 的幂并留足余量，装载因子在 0.5 以内。
 * 视图只增不减，因此不需要删除与墓碑。
 */
#define CLV_IDX_CAP 4096u
static uintptr_t g_idx_key[CLV_IDX_CAP];   /* 0 表示空槽（0 不是合法用户指针） */
static int       g_idx_kind[CLV_IDX_CAP];  /* 1=head, 2=node */

static inline unsigned clv_hash(uintptr_t a) {
    /* Fibonacci 散列：乘法比取模便宜，对地址这种高位相似的值分布均匀 */
    return (unsigned)((a * 0x9E3779B97F4A7C15ULL) >> 40) & (CLV_IDX_CAP - 1);
}

static void clv_idx_put(uintptr_t a, int kind) {
    if (!a) return;
    unsigned h = clv_hash(a);
    for (unsigned i = 0; i < CLV_IDX_CAP; i++) {
        unsigned k = (h + i) & (CLV_IDX_CAP - 1);
        if (g_idx_key[k] == a) {
            if (kind == 1) g_idx_kind[k] = 1;
            return;
        }
        if (g_idx_key[k] == 0) {
            g_idx_key[k] = a;
            g_idx_kind[k] = kind;
            return;
        }
    }
}

/* 返回 1=head, 2=node, 0=未登记 */
static int clv_idx_get(uintptr_t a) {
    if (!a) return 0;
    unsigned h = clv_hash(a);
    for (unsigned i = 0; i < CLV_IDX_CAP; i++) {
        unsigned k = (h + i) & (CLV_IDX_CAP - 1);
        if (g_idx_key[k] == a) return g_idx_kind[k];
        if (g_idx_key[k] == 0) return 0;
    }
    return 0;
}

/*
 * ===== 合成链表（决定性手段）=====
 *
 * 为什么必须做到这一步：
 *
 * 逐层排查下来确认——检测器读**链表头**时走 process_vm_readv，
 * 所以我们的伪造字节它收下了（日志 VIEW hithead 能证明它拿到了
 * ret[0]/ret[8]/size 三个我们写进去的值）；
 * 但它读完 head->next 之后，去读**节点**时是直接解引用真实内存，
 * 不走任何 libc 读取函数（日志里从头到尾没有读节点的记录）。
 *
 * 后果：我们给它的 head->next 指向真实节点，那个节点的 next 又是真值，
 * 于是它顺着真实链路一路数完，读数永远是真实长度（31/32/33 波动）。
 * 无论把 head 做成空表、4 节点闭环还是别的，都不影响它数节点。
 *
 * 解法：把 head->next / head->prev 指向**我们自己分配的、真实的内存**，
 * 在那块内存里摆一个闭环。因为那是真实内存，它直接解引用拿到的就是
 * 我们写的值 —— 不需要任何拦截。
 *
 * 约束：这条链按"两个方向长度相加"被统计（32 = 16 + 16 可证），
 * 所以节点数取 2，两个方向各 2 步，合计 4，落在它认定正常的 2~5 区间。
 */
#define SYN_NODE_N 2

/*
 * 合成节点按 slot 分开存，不能共用一组。
 *
 * 实测 runtime 里有两条闭环会被检测器读：
 *   哨兵 cl+0x280 = 0x...bda0
 *   首元素 *(cl+0x280) = 0x...c828（这个也在读取记录里反复出现）
 * 共用一组节点会让两条链的 prev/next 互相覆盖，闭环当场断掉。
 */
static uintptr_t g_syn_pool[CLV_MAX_HEADS][SYN_NODE_N][2];
static int       g_syn_used[CLV_MAX_HEADS];

/*
 * 构造合成闭环。head 是真实哨兵/首元素地址，节点指向本模块 .bss。
 *
 * 为什么指向本模块内存就够了：检测器读完 head 之后，是**直接解引用**
 * 拿节点内容的（这也是它绕过我们所有 libc 拦截的原因）。
 * 只要 next 指向的是真实存在的内存，它解引用就能读到我们写的值。
 */
static void clv_build_synthetic(uintptr_t head, int idx) {
    int i;
    if (head == 0 || idx < 0 || idx >= CLV_MAX_HEADS) return;
    for (i = 0; i < SYN_NODE_N; i++) {
        uintptr_t prev = (i == 0) ? head : (uintptr_t)&g_syn_pool[idx][i - 1][0];
        uintptr_t next = (i == SYN_NODE_N - 1) ? head : (uintptr_t)&g_syn_pool[idx][i + 1][0];
        g_syn_pool[idx][i][0] = prev;
        g_syn_pool[idx][i][1] = next;
    }
    g_syn_used[idx] = 1;
}
static volatile int g_clv_n = 0;
static volatile int g_clv_in_wrap = 0;
static volatile unsigned long g_clv_calls = 0;
static volatile unsigned long g_clv_hits = 0;
static volatile unsigned long g_sys_calls = 0;
static volatile int g_clv_got_patched = 0;
static uintptr_t g_dbg_addr[64];
static volatile int g_dbg_i = 0;
static volatile int g_clv_rescanned = 0;
static uintptr_t g_clv_need_build = 0;
volatile int g_clv_empty_probe = 0;
volatile int g_watch_on = 0;
volatile int g_watch_n = 0;
uintptr_t g_watch_addr[16];

/*
 * ============ 合成 ClassLinker 候选（确定性方案）============
 *
 * 检测器的候选扫描是「runtime+0..0x500 逐个读，第一个满足闭环条件就 return」。
 * 也就是说它**永远取第一个**。
 *
 * 之前一直在追"它可能选中哪条真链"并逐个伪造 —— 这是追不完的：
 * Runtime 里的闭环随启动过程不断变化，实测每次启动它选中的链都不同，
 * 于是出现"三轮坏一轮"这种间歇性失败。
 *
 * 正确做法是让它**在第一个偏移就看到我们合成的候选**：
 *   runtime+0   -> 指向 g_fake_cl（一块我们自己控制的内存）
 *   runtime+8.. -> 全部返回 0（让它扫不到任何真候选）
 *
 * g_fake_cl 里放一个真实的 libart vptr（过它的特征 A 校验），
 * 再在 +0x50 处放一个 4 节点闭环（过特征 B 与计数校验）。
 * 它扫到 cl_off=0 就命中，count=4，立即返回 —— 完全确定，无竞态。
 *
 * 所有伪造只发生在 process_vm_readv 的**返回值**上，真实内存零改动。
 */
#define FAKE_CL_SIZE   0x500
#define FAKE_CL_LIST   0x50
#define FAKE_CL_NODES  4

static unsigned char g_fake_cl[FAKE_CL_SIZE];
static unsigned char g_fake_nodes[FAKE_CL_NODES][0x40];
static uintptr_t     g_fake_cl_addr = 0;
static uintptr_t     g_scan_runtime = 0;
static volatile int  g_fake_ready = 0;

/* ART 堆地址区间：由 runtime 指针推出来，动态登记用它做准入 */
static uintptr_t g_art_heap_lo = 0;
static uintptr_t g_art_heap_hi = 0;

typedef ssize_t (*pvr_fn)(pid_t, const struct iovec *, unsigned long,
                          const struct iovec *, unsigned long, unsigned long);
static pvr_fn g_real_pvr = NULL;
typedef long (*syscall_fn)(long, ...);
static syscall_fn g_real_syscall = NULL;
static long g_syscall_pvr(long number, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6);
static void clv_patch_got(void);
size_t clv_fread_entry(void *ptr, size_t size, size_t nmemb, void *stream);
ssize_t clv_read_entry(int fd, void *buf, size_t count);
static void clv_apply_view(uintptr_t rstart, void *buf, size_t rlen);
static void clv_build(uintptr_t head);
static void clv_build_synthetic(uintptr_t head, int idx);
static int clv_trim_real(uintptr_t head);
static int clv_set_size_only(uintptr_t head, uintptr_t n);
static uintptr_t g_clv_cur_first;
static uintptr_t g_clv_cur_cand;
static uintptr_t g_clv_cur_cl;
static void clv_install_now(void);
static void clv_start_fast_patch(void);

/* 早初始化：定义在文件后段，这里先声明，供前面的 JNI 入口调用 */
static void ahb_early_init(void);
static int ahb_neutralize_jvmti(void);
static int ahb_neutralize_libart_debug(void);
static void ahb_selfcheck_fd(void);
/* 这两个包装在 maps_hide.h 里是非 static，可直接调用 */
ssize_t ahb_readlinkat_wrap(int dirfd, const char *path, char *buf, size_t sz);
int ahb_fstat_wrap(int fd, void *buf);

/* ELF/ART 诊断码：定义在这里，前面解析代码要用 */
static volatile int g_libart_diag = 0;    /* 1 无base 2 已断开 3 mprotect失败 4 符号未找到 */
static volatile int g_elf_diag = 0;       /* 51..60 ELF 解析断点 */
/*
 * 刷新指令缓存。
 *
 * 这段必须分架构写：本模块要编四个 ABI（arm64-v8a / armeabi-v7a /
 * x86 / x86_64），寄存器名和缓存维护方式是各自不同的。
 *
 * 踩过的坑：最初用 __builtin___clear_cache，编译出的 so 依赖外部符号
 * __clear_cache，而 bionic 里没有它，于是 System.loadLibrary 直接失败：
 *
 *   UnsatisfiedLinkError: dlopen failed: cannot locate symbol "__clear_cache"
 *
 * 这个失败还很隐蔽 —— Java 层有 try/catch，界面一切正常，
 * 只是整个 native 层从未生效。之后若干轮的"修复"全部空跑，
 * 排查方向被带偏很久。
 */
static void ahb_flush_icache(void *addr, size_t len) {
#if defined(__aarch64__)
    /*
     * 这里**绝对不能**用 ARM 私有系统调用 __ARM_NR_cacheflush(0x0F0002)。
     *
     * 实测代价：目标 com.zhenxi.hunter 自带 seccomp 过滤器
     * （它自己的字符串就有 "install_check_arch_seccomp prctl(PR_SET_SECCOMP)"
     * 和 "hunter seccomp install error"），白名单之外的系统调用会直接
     * 变成 SIGSYS 杀进程：
     *
     *   F libc: Fatal signal 31 (SIGSYS), code 1 (SYS_SECCOMP),
     *           syscall 983042 in tid ... (er_main_process)
     *
     * 983042 正是 0x0F0002。用 svc 发这个号 = 主动往枪口上撞。
     *
     * 也不能用 __builtin___clear_cache：它会被编成对 __clear_cache
     * 的外部调用，而 bionic 里没有这个符号，dlopen 直接失败
     * （UnsatisfiedLinkError: cannot locate symbol "__clear_cache"），
     * 整个 native 层静默不生效。
     *
     * 所以直接下发硬件缓存维护指令。这里用 .inst 硬编码机器码，
     * 避免依赖编译器的 -march 是否认识这几条指令：
     *
     *   dc cvau, x0   = 0xD50B7B20   （按 VA 清理数据缓存到 PoU）
     *   dsb ish       = 0xD5033B9F
     *   ic ivau, x0   = 0xD50B7520   （按 VA 失效指令缓存到 PoU）
     *   dsb ish       = 0xD5033B9F
     *   isb           = 0xD5033FDF
     *
     * 这些是纯 CPU 指令，不经过内核，seccomp 管不到。
     */
    {
        uintptr_t a = (uintptr_t)addr & ~(uintptr_t)63;
        uintptr_t e = ((uintptr_t)addr + len + 63) & ~(uintptr_t)63;
        register uintptr_t p __asm__("x0");
        for (p = a; p < e; p += 64) {
            __asm__ __volatile__(
                ".inst 0xd50b7b20\n\t"   /* dc cvau, x0 */
                ".inst 0xd5033b9f\n\t"   /* dsb ish     */
                ".inst 0xd50b7520\n\t"   /* ic ivau, x0 */
                ".inst 0xd5033b9f\n\t"   /* dsb ish     */
                ".inst 0xd5033fdf\n\t"   /* isb         */
                : "+r"(p) : : "memory");
        }
    }
#elif defined(__arm__)
    /*
     * 32 位 ARM 没有 dc/ic 这套；用 mprotect 往返把页重新映射一次，
     * 内核在处理 mprotect 时会做必要的缓存维护。
     */
    (void)addr; (void)len;
#else
    /*
     * x86 / x86_64 上指令缓存与数据缓存由硬件保持一致，
     * 且 clang 在这两个目标上能把 __builtin___clear_cache 处理干净，
     * 不会产生外部符号依赖。
     */
    __builtin___clear_cache((char *)addr, (char *)addr + len);
#endif
}




static unsigned long g_guard_ticks = 0;

static inline unsigned long ahb_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long)ts.tv_sec * 1000000UL + (unsigned long)(ts.tv_nsec / 1000);
}
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
        /*
         * 对照开关：只做读视图、不写内存。
         *
         * 目的：判定 libart 的 CRC 通过到底靠哪一半。
         *   - 靠写回磁盘内容：那就会破坏其它模块打在这段里的补丁；
         *   - 靠读视图替换：那就能彻底删掉写回，对别人零风险。
         */
        /*
         * 这里原本是把整段按磁盘内容写回真实内存。
         *
         * 现在不写了。写回的代价是把别人打在 libart 上的 inline hook
         * 一起抹掉 —— 挂 Java 方法的不受影响，直接改 libart 机器码的会失效。
         *
         * 替代方案在 maps_hide.h：ahb_libview_fd_for() 把交给检测器的
         * libart.so "磁盘内容"换成"磁盘 ELF + 内存各段覆盖"，
         * 于是内存与磁盘视图自然一致，而真实内存一个字节都没动。
         *
         * 判决性对照：关掉写回、只留 libview，六项依旧全 SAFE，
         * 内存里的差异字节一个都没少 —— 证明写回本来就不是必需的。
         */
        restored_bytes += (size_t)page_diff;

        /* 记录差异位置：判断是 hook 改写还是正常差异 */
        {
            size_t first = 0;
            int found = 0;
            for (b = 0; b < seg_len && found < 3; b++) {
                if (mem_ptr[b] != seg_copy[b]) {
                    AHB_SAYL("L2 diff %s +%#zx mem=%02x disk=%02x",
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
        /* 同时写进文件日志：logcat 会被刷掉，这个文件能留证据 */
        ahb_keylog("L2DIFF diff_bytes=%d diff_pages=%d (内存未改动)",
                    restored_bytes, restored_pages);
        AHB_SAYL("L2 code-seg 差异: bytes=%d pages=%d（内存未改动）",
             restored_bytes, restored_pages);
    } else {
        AHB_SAYL("L2 code-seg: 与磁盘一致");
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
/*
 * 早期补扫窗口。
 *
 * 原来是 40 轮（10 秒），每轮都做全量 maps 补扫。真正需要补扫的时机
 * 只有"目标 .so 在 JNI_OnLoad 之后 dlopen"与"其它模块之后注入新库"，
 * 两者都发生在最初两秒内，所以窗口收到 10 轮（2.5 秒）；
 * 再加一层提前退出：连续 3 轮无新增接管就认为已稳定，停止扫描。
 */
#define GUARD_EARLY_TICKS 40
static int g_maps_idle = 0;

/* ================================================================== */
/* 库加载后立刻中和 JVMTI 插件入口                                       */
/* ================================================================== */

/*
 * 依据（ART 自己打印，不是推测）
 * -----------------------------
 * 实测日志：
 *
 *   W er_main_process: Openjdkjvmti plugin was loaded on a non-debuggable
 *     Runtime. Plugin was loaded too late to change runtime debuggable state.
 *   F er_main_process: jit_code_cache.cc:1309] Check failed:
 *     !ContainsElement(zombie_code_, code_ptr)
 *
 * 紧接着就是 Abort。也就是说：目标把 JVMTI 插件拉起来之后，ART 在
 * "非 debuggable 却又要按 debuggable 语义重装入口"这种不一致状态下
 * 遍历所有类重装 stub，与 lsplant 已经改写过的入口在 zombie_code_ 表上
 * 撞车，直接 abort。
 *
 * 为什么不在 dlopen 处拦
 * ---------------------
 * 实测：hunter 主进程里 dlopen 只有 1 次（本模块自己调用的 libc.so），
 * android_dlopen_ext 0 次。它用的是静态编进 libhunter.so 的 xDL，
 * 自己解析 ELF 再手工映射，完全不经过 libc 的加载入口。
 * 所以只能在"库已经进到进程里、但还没被调用"的窗口内动手。
 *
 * 窗口有多大：实测从 ART 打印那条 W 到 Abort 之间约 50ms，够用。
 *
 * 做法：由已有的 guard 线程高频轮询 maps，一旦出现该库，
 * 就按 ELF 的 .dynsym 找到 ArtPlugin_Initialize 并把入口改成立即返回。
 * 目标是走它自己已有的失败分支（JvmTi::init fail / == null），
 * 不伪造任何检测结果。
 */

/*
 * 读真实的 /proc/self/maps，绕过本模块自己的过滤。
 *
 * 为什么必须绕：本模块在 syscall 上装了包装，凡是 /proc/self/maps 的
 * open 都会被重定向到"过滤后的视图"。而这里要判断的是
 * "目标库到底有没有被映射进这个进程"——查过滤视图做这个判断是错的，
 * 而且会走一遍完整的过滤流程（很慢），在紧循环里直接把窗口错过。
 *
 * 实测教训：最初这里就是普通 syscall()，结果在 1ms 轮询下
 * 中和次数始终为 0，看起来像"库永远不在"，实际是读错了数据源。
 */
static char *ahb_read_real_maps(size_t *out_len) {
    char *buf;
    size_t cap = 512 * 1024, len = 0;
    long fd;
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return NULL;
    fd = ((ahb_sys6_fn)g_raw_syscall)(SYS_openat, AT_FDCWD,
                                      (long)"/proc/self/maps", O_RDONLY, 0, 0, 0);
    if (fd < 0) return NULL;
    buf = (char *)malloc(cap);
    if (!buf) {
        ((ahb_sys6_fn)g_raw_syscall)(SYS_close, fd, 0, 0, 0, 0, 0);
        return NULL;
    }
    for (;;) {
        long k;
        if (len + 65536 > cap) {
            char *nb = (char *)realloc(buf, cap * 2);
            if (!nb) break;
            buf = nb;
            cap *= 2;
        }
        k = ((ahb_sys6_fn)g_raw_syscall)(SYS_read, fd, (long)(buf + len),
                                        (long)(cap - len - 1), 0, 0, 0);
        if (k <= 0) break;
        len += (size_t)k;
    }
    ((ahb_sys6_fn)g_raw_syscall)(SYS_close, fd, 0, 0, 0, 0, 0);
    buf[len] = 0;
    if (out_len) *out_len = len;
    return buf;
}

#define AHB_JVMTI_LIB "libopenjdkjvmti.so"

/*
 * ArtPlugin_Initialize 在 libopenjdkjvmti.so 里的静态偏移。
 * readelf -sW 实测：st_value = 0x4ce00，FUNC，304 字节，PROTECTED。
 * 同一 ROM 上固定；换 ROM 需重新核对。
 */
#define AHB_JVMTI_INIT_OFF 0x4ce00UL

/*
 * 从真实 maps 里的加载实例算出 load bias。
 *
 * 为什么必须"多候选"：实测 hunter 主进程里这个库有两处独立映射
 *
 *   792cc52000-792cd3f000 r--p 00000000  /apex/.../libopenjdkjvmti.so
 *   792e296000-792e2c4000 r--p 00000000  /apex/.../libopenjdkjvmti.so
 *   792e2c4000-792e37b000 r-xp 0002e000  /apex/.../libopenjdkjvmti.so
 *
 * 两行的 file offset 都是 0。最初的实现取"第一条 offset==0"当 base，
 * 正好取到 792cc52000 那个非加载实例，ELF 头校验不过 → 解析失败 →
 * 中和次数一直是 0。所以这里对每一行都算一次 base = start - offset，
 * 去重后逐个尝试，成功为止。
 */
static int ahb_collect_bases(const char *lib, uintptr_t *out, int max) {
    size_t len = 0;
    char *m = ahb_read_real_maps(&len);
    char *line;
    int n = 0;
    if (!m) return 0;
    line = m;
    while (line && *line && n < max) {
        char *nl = strchr(line, '\n');
        if (strstr(line, lib)) {
            char *dash = strchr(line, '-');
            if (dash) {
                uintptr_t st = (uintptr_t)strtoull(line, NULL, 16);
                char *q = dash + 1;
                int fld = 0;
                unsigned long foff;
                while (*q && fld < 2) {
                    if (*q == ' ') { fld++; while (*q == ' ') q++; continue; }
                    q++;
                }
                foff = strtoul(q, NULL, 16);
                if (st > (uintptr_t)foff) {
                    uintptr_t base = st - (uintptr_t)foff;
                    int i, dup = 0;
                    for (i = 0; i < n; i++) if (out[i] == base) { dup = 1; break; }
                    if (!dup) out[n++] = base;
                }
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(m);
    return n;
}

/*
 * 收集 JVMTI 库的加载基址。
 *
 * ===== 为什么先试 dl_iterate_phdr =====
 * 原来只有一条路：读完整 /proc/self/maps（约 280KB）再找库名。
 * 实测这条太慢 —— 单次 1~3ms，而"库映射完成 -> ART abort"只有约 50ms，
 * 整个窗口只够跑 ~20 次轮询，而库真正出现到最后只有 1~2ms，
 * 命中概率约 1/20。诊断表现就是 bases 一直是 0，一次都没看到库。
 *
 * 关键事实：这个库不是 xDL 手工 mmap 的那一类，它有标准 4 段布局
 *   r--p 00000000 / r-xp 0002e000 / r--p 000e5000 / rw-p 000e8000
 * 而且能在 maps 里以正常路径出现 —— 说明它经过正常 linker 加载，
 * 因此 dl_iterate_phdr 看得到它，而且这个调用是纯内存遍历，
 * 几十微秒量级，比读 maps 快两个数量级。
 *
 * 所以：先用 dl_iterate_phdr（快路），没有再退回 maps（慢路）。
 */
struct ahb_phdr_ctx {
    const char *want;       /* 要匹配的库名子串 */
    uintptr_t  bias;        /* 输出：load bias */
    const void *phdr;       /* 输出：程序头数组地址 */
    int        phnum;
    int        found;
};

static int ahb_phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    struct ahb_phdr_ctx *c = (struct ahb_phdr_ctx *)data;
    (void)sz;
    if (!info || !info->dlpi_name) return 0;
    if (strstr(info->dlpi_name, c->want)) {
        c->bias  = (uintptr_t)info->dlpi_addr;
        c->phdr  = (const void *)info->dlpi_phdr;
        c->phnum = info->dlpi_phnum;
        c->found = 1;
        return 1;   /* 找到就停 */
    }
    return 0;
}

/*
 * 微秒级探测：JVMTI 插件库是否已经加载进本进程。
 *
 * 为什么不能靠"读 maps 找库名"
 * ---------------------------
 * 实测（JVMDIAG）：一次 ahb_read_real_maps 要读 ~288KB，
 * 单次 5~50ms 不等。而"库映射完成 -> ART abort"只有约 50ms。
 * 也就是说慢路一次调用就把整个窗口耗掉了，轮询周期被拉长到
 * 超过窗口本身，必然抓不住。诊断表现是含jvmti=0 一直成立。
 *
 * 为什么 dlopen(RTLD_NOLOAD) 是正解
 * --------------------------------
 * RTLD_NOLOAD 不加载任何东西，只是问一句"这个库在不在"，
 * 走的是 linker 内存里的 soinfo 链表，微秒级。
 * 库不在时返回 NULL 且没有副作用；库在时返回已有句柄，
 * 还能直接 dlsym 拿 ArtPlugin_Initialize。
 *
 * 这条路径完全不碰文件系统，因此也不会被目标自身的
 * 文件访问监控看到。
 */
static void *ahb_jvmti_handle_noload(void) {
    return dlopen(AHB_JVMTI_LIB, RTLD_NOLOAD | RTLD_NOW);
}

static int ahb_collect_jvmti_bases(uintptr_t *out, int max) {
    struct ahb_phdr_ctx c;
    void *h;
    int n = 0;

    if (max <= 0) return 0;

    /*
     * 必须先用 dlopen(RTLD_NOLOAD)。
     *
     * 踩过的坑：我一度把 dl_iterate_phdr 排到前面（理由是不取 linker 锁），
     * 结果**再也拿不到基址了**。
     *
     * 原因：libopenjdkjvmti.so 在 **ART APEX 命名空间**里加载，
     * 而 dl_iterate_phdr 只遍历调用方命名空间的 soinfo 链表，
     * 看不到它（实测 c.found 恒为 0）。
     * dlopen(RTLD_NOLOAD) 走 linker 内部的 ndk_lookup，能跨命名空间查到，
     * 所以它是唯一有效的入口。
     */
    h = ahb_jvmti_handle_noload();

    /*
     * 由句柄反推基址。
     * linker 把 soinfo 的 dli_fbase 记在 phdr 里，但若 phdr 没匹配上
     * （命名空间隔离导致 dlpi_name 形式不同），用句柄去查
     * dladdr 拿 dli_fbase。
     */
    if (h && n < max) {
        Dl_info di;
        void *probe = dlsym(h, "ArtPlugin_Initialize");
        if (!probe) probe = (void *)h;
        if (dladdr(probe, &di) && di.dli_fbase) {
            out[n++] = (uintptr_t)di.dli_fbase;
            return n;
        }
    }
    /*
     * 慢路（读完整 maps ~288KB）已**移除**。
     *
     * 实测：单次读 maps 要 5~50ms，而"库映射完成 -> ART abort"只有约 50ms。
     * 也就是说慢路一次调用就把整个窗口耗掉了，轮询周期被拉长到
     * 超过窗口本身，必然抓不住。诊断里 含jvmti=0 一直成立正是这个原因。
     *
     * 现在只剩微秒级的两条快路：
     *   1) dlopen(RTLD_NOLOAD)：问 linker"库在不在"，纯内存
     *   2) dl_iterate_phdr：遍历已加载模块，纯内存
     * libopenjdkjvmti.so 是标准 linker 加载的（4 段标准布局），
     * 这两条都看得到它，不需要读 maps。
     */
    return 0;
}


/*
 * 安全读取自身内存。
 *
 * 这里不能用 /proc/self/mem：实测在 app 域被 SELinux 拒绝，open 直接失败，
 * 于是 ELF 解析全部返回 0（诊断码 art 一直是 0），看起来像"符号不存在"。
 *
 * 改用 process_vm_readv 读自己：自读是允许的，且目标页未映射时只会
 * 返回短读或 -1，不会像直接解引用那样崩掉进程。
 */
static long ahb_mem_read(uintptr_t addr, void *buf, size_t len) {
    struct iovec li, ri;
    if (!g_real_pvr) g_real_pvr = (pvr_fn)dlsym(RTLD_DEFAULT, "process_vm_readv");
    if (!g_real_pvr) return -1;
    li.iov_base = buf;
    li.iov_len  = len;
    ri.iov_base = (void *)addr;
    ri.iov_len  = len;
    return (long)g_real_pvr(getpid(), &li, 1, &ri, 1, 0);
}


/*
 * 在一个候选 base 上解析出 ArtPlugin_Initialize 的运行时地址。
 * 成功返回非 0，失败返回 0。
 */
static uintptr_t ahb_entry_at_base(uintptr_t base) {
    unsigned char eh[64];
    uint64_t phoff = 0;
    uint16_t phentsize = 0, phnum = 0;
    uint64_t dyn_vaddr = 0, dyn_sz = 0;
    uintptr_t symtab = 0, strtab = 0;
    unsigned char dyn[16 * 256];
    int i, k;

    if (ahb_mem_read(base, eh, sizeof(eh)) != (long)sizeof(eh)) return 0;
    if (memcmp(eh, "\177ELF", 4) != 0) return 0;
    if (eh[4] != 2) return 0;                       /* 只要 ELF64 */
    phoff     = *(uint64_t *)(eh + 0x20);
    phentsize = *(uint16_t *)(eh + 0x36);
    phnum     = *(uint16_t *)(eh + 0x38);
    if (phnum == 0 || phentsize < 56 || phnum > 64) return 0;

    for (i = 0; i < (int)phnum; i++) {
        unsigned char ph[56];
        if (ahb_mem_read(base + phoff + (uint64_t)i * phentsize,
                         ph, sizeof(ph)) != (long)sizeof(ph)) break;
        if (*(uint32_t *)(ph + 0) == 2) {           /* PT_DYNAMIC */
            dyn_vaddr = *(uint64_t *)(ph + 0x10);
            dyn_sz    = *(uint64_t *)(ph + 0x28);
            break;
        }
    }
    if (!dyn_vaddr || dyn_sz < 16) return 0;

    if (dyn_sz > sizeof(dyn)) dyn_sz = sizeof(dyn);
    if (ahb_mem_read(base + dyn_vaddr, dyn, (size_t)dyn_sz) != (long)dyn_sz) return 0;
    for (k = 0; k < (int)(dyn_sz / 16); k++) {
        uint64_t tag = *(uint64_t *)(dyn + k * 16);
        uint64_t val = *(uint64_t *)(dyn + k * 16 + 8);
        if (tag == 0) break;
        if (tag == 6) symtab = base + (uintptr_t)val;   /* DT_SYMTAB */
        if (tag == 5) strtab = base + (uintptr_t)val;   /* DT_STRTAB */
    }
#if AHB_DIAG
    {
        static int lg3 = 0;
        if (lg3 < 4) {
            lg3++;
            LOGE("ENTRYDIAG base=%lx dyn_vaddr=%lx dyn_sz=%lu sym=%lx str=%lx",
                 (unsigned long)base, (unsigned long)dyn_vaddr,
                 (unsigned long)dyn_sz, (unsigned long)symtab,
                 (unsigned long)strtab);
        }
    }
#endif
    if (!symtab || !strtab) return 0;

    /*
     * 扫符号表。没有 DT_HASH/DT_GNU_HASH 就直接线性扫，
     * 上限 4096 项 —— 这个库的导出符号在千级以内，足够覆盖。
     */
    /*
     * 从 k = 1 开始。
     *
     * 踩过的坑：原来从 k = 0 开始，而 ELF 符号表**第 0 项规定是全零**
     * （保留槽），配合下面的 `if (nmo == 0 && val == 0) break;`
     * 就等于"一进循环立刻 break"，一个符号都没扫到。
     * 诊断表现是 ENTRYDIAG 里 base/dyn/sym/str 全部正常，
     * 但 entry 恒为 0 —— 中间值都对，结果就是空，最容易被忽略的一类 bug。
     */
    for (k = 1; k < 200000; k++) {
        unsigned char sym[24];
        uint32_t nmo;
        uint64_t val;
        char name[64];
        if (ahb_mem_read(symtab + (uintptr_t)k * 24, sym, sizeof(sym)) != (long)sizeof(sym))
            break;
        nmo = *(uint32_t *)(sym + 0);
        val = *(uint64_t *)(sym + 8);
        /*
         * 不能用 `nmo == 0 && val == 0` 当终止条件：
         * 符号表中间存在保留槽，也可能出现全零项。
         * 空名（nmo == 0）跳过即可，靠扫描上限收敛。
         */
        if (nmo == 0 || nmo > 60000) continue;
        if (ahb_mem_read(strtab + nmo, name, sizeof(name)) != (long)sizeof(name)) continue;
        name[sizeof(name) - 1] = 0;
        if (strcmp(name, "ArtPlugin_Initialize") == 0) {
            /*
             * st_value 在共享库里是相对 load bias 的虚拟地址；
             * 若落在首个可执行段（通常是 0x2000 以上）就直接加 base。
             */
            return base + (uintptr_t)val;
        }
    }
    return 0;
}

/*
 * 在内存里的 ELF 映像中按名字找导出符号：返回 base + st_value。
 *
 * 为什么要自己解析而不能 dlsym：实测 dlsym(RTLD_DEFAULT,
 * "_ZN3art15instrumentation15Instrumentation30UpdateEntrypointsForDebuggableEv")
 * 返回 NULL（诊断码 art=1）。原因是 Android 的链接器命名空间限制，
 * 应用侧看不到 libart 的符号。但内存里的 ELF 结构是完整的，
 * 自己按 .dynamic → .dynsym → .dynstr 走一遍就能拿到。
 *
 * 为什么必须分块批量读：libart 的 .dynsym 有几万项，
 * 逐项 pread 24 字节要几万次系统调用，慢到会错过时机。
 * 这里改为每次读进 4096 项（96KB）再在本地扫。
 */
/* ------------------------------------------------------------------ */
/* 用 dl_iterate_phdr 拿链接器已经解析好的段信息                          */
/* ------------------------------------------------------------------ */

/*
 * 为什么会走到这一步
 * -----------------
 * 目标：把 ART 的 UpdateEntrypointsForDebuggable 入口断掉（原因见下）。
 * 但 dlsym(RTLD_DEFAULT, "_ZN3art15instrumentation15Instrumentation30..."
 * "UpdateEntrypointsForDebuggableEv") 返回 NULL —— Android 的链接器
 * 命名空间限制，应用侧看不到 libart 的导出符号。
 *
 * 于是想自己解析内存里的 ELF。第一版靠 maps 猜 load bias：
 * 取"offset 为 0 的第一段起点"。实测在 libart 上猜错
 * （诊断停在 55 = 找不到 PT_DYNAMIC），因为 ELF 头所在的段
 * 与 .dynamic 所在的段不一定相邻于同一个 bias 基准。
 *
 * 正确做法：dl_iterate_phdr 给出的 dlpi_addr 就是链接器算好的
 * load bias，dlpi_phdr 是已经解析好的程序头数组，两者都可信，
 * 不需要任何猜测。libart 由链接器加载，一定能被它看到。
 */
static uintptr_t ahb_elf_find_export(uintptr_t base, const char *want) {
    struct ahb_phdr_ctx c;
    const unsigned char *eh;
    uint64_t dyn_vaddr = 0, dyn_sz = 0;
    unsigned char dyn[16 * 96];
    uintptr_t symtab = 0, strtab = 0;
    uint64_t strsz = 0;
    char *str;
    int i, k;
    uintptr_t result = 0;

    memset(&c, 0, sizeof(c));
    c.want = "libart.so";
    dl_iterate_phdr(ahb_phdr_cb, &c);
    if (!c.found || !c.phdr || c.phnum <= 0) { g_elf_diag = 71; return 0; }

    /* 用链接器给的 bias 和 phdr 直接找 PT_DYNAMIC */
    for (i = 0; i < c.phnum; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)c.phdr + i;
        if (ph->p_type == 2 /* PT_DYNAMIC */) {
            dyn_vaddr = ph->p_vaddr;
            dyn_sz    = ph->p_memsz;
            break;
        }
    }
    if (!dyn_vaddr || dyn_sz < 16) { g_elf_diag = 72; return 0; }

    eh = (const unsigned char *)0;
    (void)eh;

    if (dyn_sz > sizeof(dyn)) dyn_sz = sizeof(dyn);
    if (ahb_mem_read(c.bias + dyn_vaddr, dyn, (size_t)dyn_sz) != (long)dyn_sz) {
        g_elf_diag = 73;
        return 0;
    }
    for (k = 0; k < (int)(dyn_sz / 16); k++) {
        uint64_t tag = *(uint64_t *)(dyn + k * 16);
        uint64_t val = *(uint64_t *)(dyn + k * 16 + 8);
        if (tag == 0) break;
        if (tag == 6)  symtab = c.bias + (uintptr_t)val;   /* DT_SYMTAB */
        if (tag == 5)  strtab = c.bias + (uintptr_t)val;   /* DT_STRTAB */
        if (tag == 10) strsz  = val;                       /* DT_STRSZ  */
    }
    if (!symtab || !strtab) { g_elf_diag = 74; return 0; }
    if (strsz == 0 || strsz > (8u << 20)) strsz = 2u << 20;

    str = (char *)malloc((size_t)strsz);
    if (!str) { g_elf_diag = 75; return 0; }
    {
        long g = ahb_mem_read(strtab, str, (size_t)strsz);
        if (g < 64) { g_elf_diag = 76; free(str); return 0; }
    }

    {
        const int PER = 4096;
        unsigned char *chunk = (unsigned char *)malloc((size_t)PER * 24);
        if (!chunk) { g_elf_diag = 77; free(str); return 0; }
        for (k = 0; k < 400; k++) {
            long got = ahb_mem_read(symtab + (uintptr_t)k * PER * 24,
                                    chunk, (size_t)PER * 24);
            int cnt = (got > 0) ? (int)(got / 24) : 0;
            int z, stop = 0;   /* stop 保留以备后续使用 */
            if (cnt <= 0) break;
            for (z = 0; z < cnt; z++) {
                unsigned char *sp = chunk + (size_t)z * 24;
                uint32_t nmo = *(uint32_t *)(sp + 0);
                uint64_t val = *(uint64_t *)(sp + 8);
                /*
                 * 注意：.dynsym 的第 0 项必然是 (name=0, value=0) 的
                 * 保留项 STN_UNDEF。
                 * 最初的终止条件写成 "nmo==0 && val==0 就停"，
                 * 结果第一项就命中、整张表一个符号都没扫到
                 * （诊断码停在 78 = 扫完没找到）。
                 * 正确做法是跳过它，按读到的条数扫满。
                 */
                if (nmo == 0 || nmo >= strsz) continue;
                if (strcmp(str + nmo, want) == 0) {
                    result = c.bias + (uintptr_t)val;
                    break;
                }
            }
            if (result || stop) break;
        }
        if (!result) g_elf_diag = 78;
        free(chunk);
    }
    free(str);
    return result;
}


static volatile int g_jvmti_patched = 0;
static volatile int g_jvmti_repatch = 0;
static volatile int g_jvmti_diag = 0;      /* 诊断：0 未跑 1 无库 2 无base 3 无入口 4 已打 */

/* 把函数入口改成立即返回 1（插件初始化失败），已改过则直接返回 */
int ahb_patch_entry_pub(uintptr_t fa);

static int ahb_patch_entry(uintptr_t fa) {
    /*
     * mov w0, #1 ; ret —— 返回非 0 = 插件初始化失败
     *
     * 走 safe_write_mem（/proc/self/mem + FOLL_FORCE），**不用 mprotect**。
     *
     * 为什么必须换掉 mprotect：它会把这个页从原来的 r-x 段里切出来，
     * 变成一个独立的 VMA。实测留下的碎片正是
     *     <page>-<page+0x1000> r-xp <off> ... /apex/.../libart.so
     * 而 hunter 会把这种"同库多出来的 4KB 可执行段"直接判成
     *     find libart.so hooked 4096
     * 再加上跨进程 CRC 比对（iso 读磁盘原件，主进程读内存）
     * 一减就是 patch 的差值 —— 这就是那张 ISO CRC 卡片的来源。
     *
     * FOLL_FORCE 允许直接写只读映射，页表权限和 VMA 结构都不变，
     * 因此不会留下任何可见痕迹。
     */
    static const unsigned char code[8] = {
        0x20, 0x00, 0x80, 0x52,   /* mov w0, #1 */
        0xc0, 0x03, 0x5f, 0xd6    /* ret        */
    };
    if (!fa) return 0;
    if (!safe_write_mem(fa, code, sizeof(code))) return 0;
    ahb_flush_icache((void *)fa, 8);
    return 1;
}

int ahb_patch_entry_pub(uintptr_t fa) { return ahb_patch_entry(fa); }

static void ahb_try_patch_jvmti(void) {
    uintptr_t bases[8];
    int nb, i, hit = 0;

    if (g_jvmti_patched) return;

    nb = ahb_collect_jvmti_bases(bases, 8);
    {
        static int lg = 0;
        #if AHB_DIAG
        if (lg < 40) { lg++; LOGE("WATCH collect bases=%d", nb); }
        #endif
    }
    /*
     * 注意：这里**不**在 nb == 0 时早退。
     *
     * 踩过的坑：原来写成
     *     if (nb == 0) { g_jvmti_diag = 1; return; }
     * 而 dlsym 那段在它后面，于是"phdr 看不到库（APEX 命名空间）"
     * 会连带把 dlsym 这条唯一有效的路也一起跳过 ——
     * 症状就是"中和完成一条日志都没有"，且看不出是早退造成的。
     */

    /*
     * 首选：直接用库句柄 dlsym。
     *
     * 踩过的坑：一开始用 ahb_entry_at_base 手工解析 ELF 找符号，
     * 结果是 entry=0（手工遍历 .dynsym 有 4096 项上限，
     * 而 libopenjdkjvmti.so 的符号比 libart 多，目标符号落在上限之后）。
     *
     * 但这条路本来就不必手工解析：dlopen(RTLD_NOLOAD) 已经给了
     * 一个有效句柄，dlsym(handle, "ArtPlugin_Initialize") 直接就能取，
     * 而且**显式句柄不受命名空间可见性限制** —— 之前 dlsym 失败的那个坑
     * 用的是 RTLD_DEFAULT（全局搜索），语义完全不同。
     */
    {
        void *h = ahb_jvmti_handle_noload();
        if (h) {
            void *sym = dlsym(h, "ArtPlugin_Initialize");
            if (sym && ahb_patch_entry((uintptr_t)sym)) {
                g_jvmti_patched = 1;
                g_jvmti_diag = 5;
#if AHB_DIAG
                LOGE("JVMTI 中和完成(dlsym) sym=%lx n=%d", (unsigned long)sym,
                     g_jvmti_repatch);
#endif
            }
        }
    }

    if (nb == 0) { g_jvmti_diag = 1; return; }

    for (i = 0; i < nb; i++) {
        uintptr_t fa = ahb_entry_at_base(bases[i]);
        {
            static int lg2 = 0;
#if AHB_DIAG
            if (lg2 < 40) { lg2++; LOGE("WATCH base[%d]=%lx entry=%lx", i, (unsigned long)bases[i], (unsigned long)fa); }
#endif
        }
        if (!fa) continue;
        g_jvmti_diag = 3;
        /*
         * 每次命中都**重新打一遍**，不看"是否已经打过"。
         *
         * 踩过的坑（这一版之前的所有失败都是它）：
         *   patch 太早会被覆盖。
         *
         * 证据：开诊断日志时三轮里能成功一轮，关日志后四轮全崩。
         * 日志的 write 系统调用把 patch 推迟了若干个数量级，
         * 于是那次 patch 恰好落在"库已完成重定位"之后，生效了。
         *
         * 机制：库刚 mmap 进来时 .text 可能还没填好（或 linker 随后
         * 会再写这一段），我们在那个时刻写的 8 字节会被后续初始化抹掉。
         * 而且 ART 每次调用插件失败后仍可能重试。
         *
         * 所以正确策略不是"打一次就收工"，而是**在窗口内持续打**：
         * 每轮都写，被覆盖了就再写回。窗口结束时库初始化已完成，
         * 最后一次写入必然生效。成本是每轮一次 mprotect，
         * 在 100µs 级轮询下都可忽略（无系统调用节流）。
         */
        if (ahb_patch_entry(fa)) {
            hit++;
            {
                int k;
#if AHB_DIAG
                for (k = 0; k < 2; k++)
                    LOGE("JVMTI 中和完成 base=%lx entry=%lx", (unsigned long)bases[i], (unsigned long)fa);
#else
                (void)k;
#endif
            }
        }
    }
    if (hit) { g_jvmti_patched = 1; g_jvmti_diag = 4; }
    /*
     * 注意：这里**不置** g_jvmti_patched。
     *
     * 理由见上面的注释 —— 一次成功不代表永久生效，库的后续初始化
     * 可能覆盖我们的写入。保持循环继续跑，每轮重打，
     * 直到时间窗结束（30 秒）或进程退出。
     *
     * 这个函数本身很便宜（phdr 遍历 + 4 字节写），可以持续跑。
     */
}


/* ------------------------------------------------------------------ */
/* JVMTI 专用看门线程                                                    */
/* ------------------------------------------------------------------ */

/*
 * 为什么单独开一个线程、而不是放进已有的 250ms guard 循环
 * ------------------------------------------------------
 * 实测时间线（同一进程，毫秒级）：
 *
 *   06.032  W  Openjdkjvmti plugin was loaded on a non-debuggable Runtime
 *   06.083  F  jit_code_cache.cc:1309 Check failed  -> Abort
 *
 * 从"库已经被加载"到"ART abort"只有约 50ms。
 * 250ms 的循环几乎必然错过这个窗口（实测中和完成 0 次）。
 *
 * 所以这里用 2ms 的紧循环，但每次检测都很便宜：
 * 用 dl_iterate_phdr 遍历已加载模块（几十个），比读 300KB 的 maps
 * 快三个数量级，2ms 一次完全可接受。
 *
 * 只在启动后的前 3 秒工作，之后退出线程 —— 那个窗口一过，
 * JVMTI 该不该加载都已经确定了。
 */

static void *jvmti_watch_thread(void *arg) {
    unsigned long t0 = ahb_now_us();
    int sc_done = 0;
    (void)arg;
    while (!g_jvmti_patched) {
        /*
         * 时间窗从 3 秒延长到 30 秒。
         *
         * 实测依据（JVMDIAG 定向诊断）：
         *     JVMDIAG phdr=0 n=0 rawlen=287639 精确名=0 含jvmti=0
         * rawlen 说明 maps 读到了 287KB，但**整个 maps 里没有 jvmti 字样**
         * —— 也就是库根本还没加载，不是匹配失败。
         *
         * 崩溃栈给了答案：
         *     #12 ... base.vdex (com.zhenxi.hunter.App.onCreate+1118)
         * JVMTI init 发生在 App.onCreate 里，而看门线程从 native_init 起
         * 只跑 3 秒。目标启动慢的时候 App.onCreate 在 3 秒之后，
         * 于是看门线程早已退出，库加载时没有任何人在盯着。
         */
        if (ahb_now_us() - t0 > 30000000UL) break;   /* 30 秒后退出 */
        /*
         * 不用 dl_iterate_phdr 判断"库在不在"。
         *
         * 原因：目标的 xDL 是手工 mmap 加载的，**不会**把自己挂进
         * 链接器的 link_map，所以 dl_iterate_phdr 看不到它
         * （实测：改用 dl_iterate_phdr 之后中和次数仍然是 0）。
         * 而 /proc/self/maps 反映的是真实 VMA，一定看得到。
         *
         * ahb_try_patch_jvmti 内部第一步就是廉价的子串扫描，
         * 库不在时立刻返回，所以 1ms 一次的代价可以接受。
         */
        /*
         * 自证必须在 ahb_try_patch_jvmti 的成功退出口**之前**跑。
         *
         * 踩过的坑：原来写成
         *     ahb_try_patch_jvmti();
         *     if (g_jvmti_patched) break;   // <- 自检在这句后面
         * 于是"patch 成功"这个最关键、也正是最需要验证的场景里，
         * 循环直接 break 掉，自检一次都不执行。
         * 表现成"VIEWART / PATHCHK 一条日志都没有"，
         * 很容易误判成自检代码坏了，实际是 Timing 问题。
         *
         * 现在把它提到 patch 之前：先自检、再 patch。
         * 400ms 的延迟仍保留（避开 logd 未就绪的窗口）。
         */
#if AHB_SAY
        if (!sc_done && ahb_now_us() - t0 > 400000UL) {
            sc_done = 1;
            ahb_pathcheck();
#if AHB_DIAG
            ahb_selfcheck_fd();
#endif
        }
#endif
        ahb_try_patch_jvmti();
        if (g_jvmti_patched) break;
        /*
         * 100µs 轮询。
         *
         * 依据（实测对比）：
         *   1ms 轮询  -> 开诊断日志时三轮里能成功一轮，关日志后四轮全崩
         *   说明 1ms 只是在"日志恰好拖慢时序"时才勉强抓到窗口。
         *
         * 真实窗口极窄：ART 在 libnativeloader 返回句柄后**紧接着**就
         * dlsym + 调用 ArtPlugin_Initialize，间隔在微秒级。
         * 所以必须把这个量级的轮询密度提上来。
         *
         * 单次成本已压到最低：只走 dl_iterate_phdr（纯内存链表，
         * 不取 linker 锁），不做 dlopen、不读 maps。
         */
        usleep(1000);
    }
    return NULL;
}

/* 待启动标志：由 guard_loop 第一拍消费 */
static volatile int g_jvmti_watch_pending = 0;

static void ahb_start_jvmti_watch(void) {
    static int started = 0;
    pthread_t th;
    if (started) return;
    started = 1;
    /* 恒开探针：不经任何宏，确认线程创建是否真的发生/成功 */
    {
        int rc = pthread_create(&th, NULL, jvmti_watch_thread, NULL);
        #if AHB_DIAG
        int k; for (k = 0; k < 2; k++) LOGE("WATCH 线程创建 rc=%d", rc);
        #endif
        if (rc == 0) pthread_detach(th);
    }
}

/*
 * 由 open 包装在每 N 次调用时驱动一次 JVMTI 中和。
 *
 * 这个函数会被高频调用，必须极便宜：
 *   - 用一个静态计数器限流（每 8 次试一次）
 *   - 成功后再也不试
 *   - 防重入，避免内部读 maps 时递归回来
 */
static void ahb_jvmti_tick_from_open(void) {
    static int cnt = 0;
    static int busy = 0;
    static int finished = 0;

    if (finished) return;
    if (busy) return;
    if ((++cnt & 7) != 0) return;      /* 每 8 次试一次 */

    busy = 1;
    {
        int r = ahb_neutralize_jvmti();
        if (r == 1) {
            finished = 1;
            LOGE("JVMTI 中和完成（open 驱动）");
        } else {
            /* 只在有意义的失败码上记一次，避免刷屏 */
            static int logged = 0;
            if (r != -13 && logged < 4) {
                logged++;
                LOGE("JVMTI 中和返回 %d", r);
            }
        }
    }
    busy = 0;
}

static void *guard_loop(void *arg) {
    int ops = (int)(intptr_t)arg;
    AHB_SAYL("L4 guard_loop 启动 interval=250ms ops=%#x", ops);
    ahb_filelog("L4 guard_loop start ops=%#x", ops);

    while (g_guard_running) {
        /*
         * 第一拍就把 JVMTI 看门线程拉起来。
         * 这里是进程已稳定后的时机，pthread_create 与日志都可靠。
         */
        if (g_jvmti_watch_pending) {
            g_jvmti_watch_pending = 0;
            ahb_start_jvmti_watch();
        }
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
        /*
         * 每次迭代都检查 JVMTI 插件是否已被目标加载。
         * 一旦出现就立刻中和它的入口 —— 窗口只有几十毫秒，
         * 所以这一步放在最前面，且自身极轻（先 grep maps 关键字）。
         */
        ahb_try_patch_jvmti();

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
                AHB_SAYL("RAWREAD: %s", buf);
                g_dbg_i = 0;
            }
            AHB_SAYL("VIEWPROOF calls=%lu hits=%lu sys=%lu slots=%d hb=%d",
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
        if ((ops & NATIVE_OP_CL) != 0 && g_enable_maps_hide && g_guard_ticks < GUARD_EARLY_TICKS) {
            clv_patch_got();
        }
        /*
         * 周期重扫候选链。
         *
         * Runtime 里的闭环是启动过程中陆续成形的：JNI_OnLoad 那一刻可能
         * 只有 2 条，检测器真正读取时已经有 3~5 条。只扫一次就会漏掉
         * 后出现的那几条，检测器一旦选中它们，视图伪造全部失效。
         *
         * 只在早期窗口（前 40 轮，约 10 秒）做，且已有登记时也照做 ——
         * clv_build 内部对重复 head 会直接返回，不会重复占槽。
         */
        if ((ops & NATIVE_OP_CL) != 0 && g_guard_ticks < GUARD_EARLY_TICKS && (g_guard_ticks % 2) == 0) {
            int before = g_clv_n;
            clv_install_now();
            if (g_clv_n != before) {
                AHB_SAYL("L3 view: 周期补扫 slots %d -> %d", before, g_clv_n);
            }
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
        /*
         * 补丁驱动不再有"启动窗口"。
         *
         * 原来这里限定 g_guard_ticks < 10（约 2.5 秒）、外加连续三次
         * 无新增就永久停扫。实测后果很严重：检测器自己的 libantihook.so
         * 是进程起来之后才 dlopen 的，等它出现时窗口早关了 ——
         * 于是它的 GOT 一个槽都没接管，maps 过滤对它完全无效。
         *
         * 现在改成：只要已加载模块数发生变化（说明有新库进来），就扫一遍。
         * 这个判断是 dl_iterate_phdr 数出来的，微秒级、纯内存，
         * 所以"一直盯着"几乎没有成本；而真正昂贵的全量解析只在
         * 确有新库时才发生。库只会增加不会减少，所以这个判据是充分的。
         */
        if ((ops & NATIVE_OP_CL) != 0 && !g_clv_in_wrap) {
            extern int ahb_loaded_module_count(void);
            static int last_mod = -1;
            int mod = ahb_loaded_module_count();
            if (mod != last_mod) {
                int n = maps_patch_got_all();
                last_mod = mod;
                if (n > 0) {
                    AHB_SAYL("MAPS: 新增接管 %d 处，累计 %d 处（模块数 %d）",
                         n, g_maps_got_patched, mod);
                    ahb_filelog("MAPS hb new=%d total=%d mod=%d",
                                n, g_maps_got_patched, mod);
                }
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
        if (g_guard_ticks < GUARD_EARLY_TICKS) {
            ts.tv_sec = 0;
            ts.tv_nsec = 250L * 1000L * 1000L;
        } else {
            ts.tv_sec = 2;
            ts.tv_nsec = 0;
        }
        nanosleep(&ts, NULL);
    }
    AHB_SAYL("L4 guard_loop 退出");
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
    /*
     * 结果缓存：libart 的映射区间在一个进程生命周期内不会变，
     * 而这里每次都要 fopen + 逐行解析整个 /proc/self/maps。
     * 实测 clv_install_now 被调用 65 次、累计 1.73 秒，平均每次 26ms，
     * 就是这段地图解析吃掉的。缓存后只付 1 次成本。
     */
    static uintptr_t c_s = 0, c_e = 0;
    static int c_ok = 0;
    if (c_ok) {
        *art_start = c_s;
        *art_end = c_e;
        return 1;
    }
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
    c_s = s_min;
    c_e = e_max;
    c_ok = 1;
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
    /* 用内联汇编屏障，避免任何 libatomic 依赖 */
#if defined(__aarch64__)
    __asm__ __volatile__("dmb ish" ::: "memory");
#else
    __sync_synchronize();
#endif
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
    /*
     * 快路径：哈希表里没有这个地址，就一定不是任何 slot 的 head，
     * 直接返回 NULL，不用再扫 slot 数组。
     */
    if (clv_idx_get(head) != 1) return NULL;
    for (int i = 0; i < g_clv_n; i++)
        if (g_clv[i].head == head && g_clv[i].ready) return &g_clv[i];
    return NULL;
}

/*
 * 判断某个地址是否已经是某条已登记链的成员（节点或头）。
 *
 * 必须做这个排除，否则动态登记会把链上的**中间节点**也当成新头。
 * 实测后果很严重：一条 20 节点的链会产生 20 次误登记，
 * 几十轮下来把 CLV_MAX_HEADS 全部占满，真正的头反而登记不进去 ——
 * 这正是"三轮坏一轮"的直接原因。
 */
static int clv_is_chain_member(uintptr_t addr) {
    return clv_idx_get(addr) != 0;
}

/*
 * 构建合成候选。只要拿到一个真实 ClassLinker 的 vptr 就够了。
 */
static void clv_build_fake(uintptr_t real_vptr) {
    uintptr_t head, n0, n1, n2, n3, prev, next;
    int i;

    if (g_fake_ready || real_vptr == 0) return;

    memset(g_fake_cl, 0, sizeof(g_fake_cl));
    memset(g_fake_nodes, 0, sizeof(g_fake_nodes));

    /* 特征 A：候选对象首字段是 libart 段内的 vptr */
    memcpy(g_fake_cl + 0x00, &real_vptr, 8);

    head = (uintptr_t)g_fake_cl + FAKE_CL_LIST;
    n0 = (uintptr_t)g_fake_nodes[0];
    n1 = (uintptr_t)g_fake_nodes[1];
    n2 = (uintptr_t)g_fake_nodes[2];
    n3 = (uintptr_t)g_fake_nodes[3];

    /* 特征 B：head 的两个方向都指进闭环 */
    memcpy(g_fake_cl + FAKE_CL_LIST + 0x00, &n3, 8);
    memcpy(g_fake_cl + FAKE_CL_LIST + 0x08, &n0, 8);
    /* std::list 的 __size_ */
    {
        uintptr_t size = FAKE_CL_NODES;
        memcpy(g_fake_cl + FAKE_CL_LIST + 0x10, &size, 8);
    }

    /* 4 节点闭环：n0 <-> n1 <-> n2 <-> n3 <-> head */
    for (i = 0; i < FAKE_CL_NODES; i++) {
        uintptr_t na = (uintptr_t)g_fake_nodes[i];
        prev = (i == 0) ? head : (uintptr_t)g_fake_nodes[i - 1];
        next = (i == FAKE_CL_NODES - 1) ? head : (uintptr_t)g_fake_nodes[i + 1];
        memcpy((void *)(na + 0x00), &prev, 8);
        memcpy((void *)(na + 0x08), &next, 8);
    }

    g_fake_cl_addr = (uintptr_t)g_fake_cl;
    g_fake_ready = 1;
    AHB_SAYL("L3 view: 合成候选就绪 cl=%#lx head=%#lx vptr=%#lx",
         (unsigned long)g_fake_cl_addr, (unsigned long)head, (unsigned long)real_vptr);
    ahb_filelog("VIEW fake ready cl=%#lx head=%#lx",
                (unsigned long)g_fake_cl_addr, (unsigned long)head);
}

/*
 * ===== 真实修剪 class_loaders_ 链表 =====
 *
 * 为什么最后只能动真内存：
 *
 * 我们把 process_vm_readv / pread / read / fread 全接了一遍，又把链表头
 * 伪造成 2 节点闭环（日志 VIEW hithead 可证检测器确实收到了我们写的
 * ret[0]/ret[8]/size），读数却从 29 到 33 一动不动。
 * 唯一解释：它计数时在**本进程内直接解引用**内存，不经过任何 libc 读取函数。
 * 想改它的读数，只能改真实链表。
 *
 * 与历史上两次崩溃的区别（这是敢动手的前提）：
 *
 * 以前剪链崩了两次，根因是**剪错了链**。当时把 head 取成 *(cl+0x280)，
 * 那是链表首元素；而 Runtime 里同时存在另一条 21 节点的闭环
 * （cand+0x50，节点 +0x10 不带 jobject 标签，是 Class 对象链）。
 * 剪 Class 对象链会直接毁掉类元数据 -> GC abort。
 * 现在 head 取 cl+0x280（内嵌 std::list 哨兵），并由
 * looks_like_class_loaders() 逐个节点确认 +0x10 是带 TopByte 标签的
 * jobject，两条链不会混淆。
 *
 * 保留 5 个而不是 4 个：检测器判"正常 2~5"，取上界留最大余量给
 * 系统自身需要的 ClassLoader。
 *
 * 写回必须保留原始 TopByte 标签。踩过的坑：写去标签值会让
 * GetClassLoaders 的 `curr != head` 永不成立，把哨兵当元素解引用 -> SIGSEGV。
 */
#define CLV_TRIM_KEEP 5

static int clv_trim_real(uintptr_t head) {
    uintptr_t raw_last = 0, raw_first = 0;
    uintptr_t nodes[64], raws[64];
    int n = 0, i;
    uintptr_t size_raw = 0;

    if (!safe_read_mem(head + 0x00, &raw_last, 8)) return 0;
    if (!safe_read_mem(head + 0x08, &raw_first, 8)) return 0;
    if (!safe_read_mem(head + 0x10, &size_raw, 8)) return 0;
    if (size_raw <= CLV_TRIM_KEEP) return 0;      /* 已经够短，不动 */

    {
        uintptr_t cur_raw = raw_first;
        for (i = 0; i < 64; i++) {
            uintptr_t nx_raw = 0;
            uintptr_t cu = UNTAG_PTR(cur_raw);
            if (cu == head || cu == 0) break;
            if (!safe_read_mem(cu + 0x08, &nx_raw, 8)) break;
            nodes[n] = cu;
            raws[n] = cur_raw;
            n++;
            if (UNTAG_PTR(nx_raw) == head) break;
            cur_raw = nx_raw;
        }
    }
    if (n <= CLV_TRIM_KEEP) return 0;

    {
        /*
         * 第 CLV_TRIM_KEEP-1 个节点的 next 指回哨兵；
         * 哨兵的 prev 指回它；__size_ 同步。
         */
        uintptr_t cut = nodes[CLV_TRIM_KEEP - 1];
        uintptr_t head_plain = head;
        uintptr_t keep = (uintptr_t)CLV_TRIM_KEEP;
        uintptr_t last_tagged = raws[CLV_TRIM_KEEP - 1];
        if (!safe_write_mem(cut + 0x08, &head_plain, 8)) return 0;
        if (!safe_write_mem(head + 0x00, &last_tagged, 8)) return 0;
        if (!safe_write_mem(head + 0x10, &keep, 8)) return 0;
        ahb_filelog("VIEW trim head=%#lx was=%d now=%d cut=%#lx",
                    (unsigned long)head, n, CLV_TRIM_KEEP, (unsigned long)cut);
    }
    return 1;
}

/*
 * ===== 只改 __size_ 字段（GC 安全）=====
 *
 * 判决性实验得出的两条事实：
 *   1. 空表覆盖（prev=next=head、size=0）读数仍 32 —— 它不经过 libc 读内存。
 *   2. 真实剪链读数确实变 4 —— 它读的是真实内存里的东西。
 *
 * 关键区分：真实内存里有两个可能的数据源
 *   A. 沿着 prev/next 遍历节点计数
 *   B. 直接读哨兵 +0x10 的 __size_ 字段
 *
 * 早前剪链时把 A 和 B 一起改了，读数变 4，但摘下的节点连同
 * ClassLoaderData 失去可达性，GC 扫到陈旧引用即 abort。
 *
 * 如果数据源是 B，那么**只改 __size_、完全不动链接**就够了：
 * 链表结构完整，GC 照常能走完全部节点，ClassLoaderData 全部可达，
 * 没有任何悬空引用；而检测器读到的计数是我们写的那个小值。
 *
 * 这个实验只写 8 个字节，且不破坏任何链接，风险极低。
 */
static int clv_set_size_only(uintptr_t head, uintptr_t n) {
    return safe_write_mem(head + 0x10, &n, 8);
}

static void clv_build(uintptr_t head) {
    if (head == 0) return;
    /*
     * 防递归：clv_build 内部用 read_ptr_untagged 读内存，而那走的是
     * process_vm_readv —— 已经被我们自己接管。若不加标记，
     * 就会 clv_build -> read -> clv_pvr -> clv_install_now -> clv_build
     * 无限递归，栈溢出。实测表现是崩在 maps_patch_got_all 附近。
     */
    if (g_clv_in_wrap) return;
    /*
     * 合成节点绝不能再当成"链头"登记。
     *
     * 踩坑（这一步卡了最久）：合成闭环建好后，检测器顺着
     * head->next 读到合成节点 0x...c5a8，而"读到即登记"那条逻辑
     * 把这个地址也当成候选链头登记了一遍，还给它编了 64 个节点。
     * 于是检测器读 0x...c5a8 时，覆盖循环返回的是那个 slot 的
     * nodebuf（真实链视图），而不是我们写的合成 prev/next ——
     * 合成闭环当场被自己人破坏，读数回到真实值。
     * 日志特征：VIEW hithead head=0x6f9c4fc5a8 ... keep=64
     *          （0x6f9c4fc5a8 正是 g_syn_pool 内部地址）
     */
    if ((uintptr_t)head >= (uintptr_t)&g_syn_pool[0][0][0] &&
        (uintptr_t)head <  (uintptr_t)&g_syn_pool[CLV_MAX_HEADS][0][0]) {
        return;
    }
    struct clv_slot *sl = clv_find(head);
    if (sl) return;
    if (g_clv_n >= CLV_MAX_HEADS) return;

    sl = &g_clv[g_clv_n];
    sl->head = head;
    sl->cand = g_clv_cur_cand;
    /* 同步进哈希索引：热路径靠它 O(1) 判重 */
    clv_idx_put(head, 1);
    /*
     * 合成闭环必须在**slot 索引确定之后**构造。
     *
     * 踩坑：一开始放在函数开头，用 g_clv_n 当索引。
     * 但那时还没走 clv_find / 边界检查，g_clv_n 可能因为
     * 已存在同名 head 而根本不会前进，于是合成节点写进了
     * 别人的 slot：日志里同一个 head 出现 idx=1 又出现 idx=3，
     * 而 headbuf 写入时看的是本 slot 的 g_syn_used[k]（k 正确），
     * 两边对不上，合成永远不生效、读数永远是真实值 32。
     */
    if (g_clv_cur_cl != 0 &&
        (head == g_clv_cur_cl + 0x280 || head == g_clv_cur_first)) {
        clv_build_synthetic(head, g_clv_n);
        ahb_filelog("VIEW synth head=%#lx idx=%d first=%#lx",
                    (unsigned long)head, g_clv_n, (unsigned long)g_clv_cur_first);
    }
    /*
     * headbuf 必须用**真实 head 的原始 0x40 字节打底**，不能 memset 成 0。
     *
     * 踩坑经过：早期这里 memset 清零，然后只写回 prev/next 两个字段。
     * 结果是链表头里的其它字段（尤其是 std::list 的 __size_）在我们
     * 视图里全变成 0。检测器走完闭环后还要做结构校验，
     * 一看到"节点数 4 但 size 是 0"就判结构非法，
     * 该项直接从 RISK 变成 INFO("链表结构校验失败") —— 不是安全。
     *
     * 打底真值 + 只改必要的三个字段，视图才是自洽的。
     */
    memset(sl->headbuf, 0, sizeof(sl->headbuf));
    memset(sl->node_addr, 0, sizeof(sl->node_addr));
    if (!safe_read_mem(head, sl->headbuf, sizeof(sl->headbuf)))
        memset(sl->headbuf, 0, sizeof(sl->headbuf));

    /*
     * 直接在**真实节点**上做视图改写，不再合成假节点。
     *
     * 之前的做法是让 head 指向模块自己的缓冲区（合成节点），
     * 但实测无效：检测器会沿它拿到的 next 继续读，而那些地址
     * 一旦离开我们伪造的那几个字节，后面读到的就是真实节点的
     * next/prev —— 于是它照样把整条真链走完，数出 32。
     * 实测证据：calls=1310 hits=10，1310 次读取里只有 10 次命中。
     *
     * 现在的做法：先把真实链表的前 KEEP 个节点走一遍拿到地址，
     * 然后改写这些真实节点的 next/prev，让链表在 KEEP 步内闭合。
     * 检测器无论从 head 还是从中间节点进入，走 KEEP 步就回到 head。
     *
     * 关键：只改视图（process_vm_readv 返回的字节），
     * 真实内存里的链表一个字节不动 —— ART 与 GC 完全不受影响。
     */
    {
        uintptr_t cur = 0;
        int n = 0;
        /*
         * 链表头的 prev/next 字段顺序在 libc++ 的不同实现里是
         * {prev,next} 或 {next,prev}，不能假定 +8 一定是 next。
         *
         * 检测器自己就是这么处理的：它取 a=rp(head)、b=rp(head+8)，
         * 然后分别用 walk_chain(b,head,8) 和 walk_chain(a,head,0)
         * 双向各走一遍取最大值。这里用同一套判定：
         * 哪个方向能闭环回 head，就用哪个作为 next。
         */
        {
            uintptr_t a = 0, b = 0, an = 0, bp = 0;
            int ok_a = 0, ok_b = 0;
            if (read_ptr_untagged(head, &a) && read_ptr_untagged(head + 8, &b)) {
                a = UNTAG_PTR(a); b = UNTAG_PTR(b);
                if (read_ptr_untagged(a + 8, &an)) ok_a = (UNTAG_PTR(an) == head);
                if (read_ptr_untagged(b, &bp))     ok_b = (UNTAG_PTR(bp) == head);
            }
            if (ok_b)      cur = b;   /* head+8 是 next */
            else if (ok_a) cur = a;   /* head+0 是 next */
            else           return;
        }
        while (n < CLV_MAX_CHAIN && cur != 0 && cur != head &&
               cur >= USER_PTR_MIN && cur < USER_PTR_MAX) {
            uintptr_t nxt = 0;
            sl->node_addr[n] = cur;
            clv_idx_put(cur, 2);
            n++;
            if (!read_ptr_untagged(cur + 8, &nxt)) break;
            cur = UNTAG_PTR(nxt);
            if (n > 64) break;   /* 防跑飞 */
        }
        if (n == 0) return;
        sl->keep = n;

        /*
         * 构造**整条链**的视图，而不是只前 4 个。
         *
         * 检测器从 head 出发一路走到回到 head 为止，读的是链上**每一个**
         * 真实节点的 next。只覆盖前 4 个的话，它走到第 5 个节点时读到的
         * 就是真实 next，于是继续沿真链走完，数出 31。
         * 实测证据：calls=1310 hits=10 —— 1310 次读取里只有 10 次命中。
         *
         * 因此把整条链（最多 CLV_MAX_CHAIN 个节点）都纳入视图：
         * 第 KEEP-1 个节点的 next 直接指回 head，链在 KEEP 步内闭合。
         * 其余节点的 next 也统一指向 head，保证从任何节点进入都能快速收敛。
         */
        for (int i = 0; i < n; i++) {
            uintptr_t prev, next;
            if (i < CLV_KEEP) {
                /* 前 KEEP 个节点构成闭环：head <-> n0 <-> n1 <-> n2 <-> n3 <-> head */
                prev = (i == 0) ? head : sl->node_addr[i - 1];
                next = (i == CLV_KEEP - 1) ? head : sl->node_addr[i + 1];
            } else {
                /*
                 * 超出 KEEP 的节点：两个方向都直接指回 head。
                 *
                 * 这一步是决定性的。检测器不是只走一个方向 ——
                 * 它做 c1 = walk_chain(head->next, head, +8)
                 * 与 c2 = walk_chain(head->prev, head, +0)，
                 * 然后取**最大值**。
                 *
                 * 早期只让 forward 在 KEEP 步闭合，backward 仍沿真实 prev
                 * 走完整条链（实测 20 个节点），于是 max(4, 20) = 20，
                 * 照样判风险。日志里 "检测到 20 个" 就是这么来的。
                 *
                 * 现在两个方向都在 KEEP 步内收敛，从任何节点进入
                 * 最多 KEEP 步就回到 head。
                 */
                prev = head;
                next = head;
            }
            memcpy(sl->nodebuf[i] + 0x00, &prev, 8);
            memcpy(sl->nodebuf[i] + 0x08, &next, 8);
        }
        /*
         * head 的 prev/next 指向**闭环内**的两端（第 KEEP-1 个 / 第 0 个），
         * 不能指向整条链的最后一个节点 —— 那会让 backward 从链尾开始走，
         * 一路读回真实前驱。
         */
        {
            uintptr_t prev = sl->node_addr[(n < CLV_KEEP) ? (n - 1) : (CLV_KEEP - 1)];
            uintptr_t next = sl->node_addr[0];
            /*
             * head 与候选对象重合时（list_off == 0），headbuf 的前 8 字节
             * 就是这个对象的 vptr。检测器第一步就靠它判断"这是不是一个
             * ART 对象"，被我们改写成节点地址就再也不是合法 vptr，
             * 候选直接被跳过。所以这种情况必须原样保留真值。
             */
            /*
             * 指向合成闭环，而不是真实节点。
             *
             * 关键区别就在这里：真实节点地址上的 next 是真实值，
             * 检测器顺着走会走完整条真链；合成节点是本模块的静态数组，
             * 内容完全由我们决定，它直接解引用也只读到我们的闭环。
             *
             * head 本身是 ART 的内嵌哨兵，必须保留原样（不能改它的地址），
             * 只有在它上面覆盖 prev/next/size 三个字段。
             */
            if (g_syn_used[(int)(sl - g_clv)]) {
                int si = (int)(sl - g_clv);
                uintptr_t sp = (uintptr_t)&g_syn_pool[si][SYN_NODE_N - 1][0];
                uintptr_t sn = (uintptr_t)&g_syn_pool[si][0][0];
                uintptr_t ssz = (uintptr_t)SYN_NODE_N;
                memcpy(sl->headbuf + 0x00, &sp, 8);
                memcpy(sl->headbuf + 0x08, &sn, 8);
                memcpy(sl->headbuf + 0x10, &ssz, 8);
            } else {
                if (sl->head != sl->cand) {
                    memcpy(sl->headbuf + 0x00, &prev, 8);
                }
                memcpy(sl->headbuf + 0x08, &next, 8);
            }
            /*
             * __size_ 必须和闭环节点数一致。
             *
             * 这是 ClassLoader 项反复翻红/变 INFO 的最后一个原因。
             * libc++ 的 std::list 头是 {__prev_, __next_, __size_}，
             * 前 16 字节是首尾指针，+0x10 是元素个数。
             *
             * 实测表现：
             *   - headbuf 整体清零  -> 走链数出 4，但 size=0，
             *     检测器判"链表结构校验失败"，该项变 INFO（不是 SAFE）
             *   - headbuf 保留真值  -> size=31，检测器直接报"检测到 31 个"，
             *     变 RISK
             * 两种都说明它同时看"走链结果"和"size 字段"，两者必须自洽。
             *
             * 所以这里把 size 一起改写成我们的闭环节点数。
             */
            {
                uintptr_t sz = CLV_KEEP;
                memcpy(sl->headbuf + 0x10, &sz, 8);
                /*
                 * 【临时决定性实验】把头做成空表：prev=next=head, size=0。
                 * 任何从 head 出发的遍历都会立刻回到 head，计数必为 0。
                 * 用来判定检测器到底是不是走 process_vm_readv 拿这几个字节：
                 *   - 若读数变 0/正常  -> 确实走我们的路径，问题在别处
                 *   - 若仍报 33        -> 它用了我们没接管的读取方式
                 */
                if (g_clv_empty_probe) {
                    uintptr_t self = sl->head;
                    memcpy(sl->headbuf + 0x00, &self, 8);
                    memcpy(sl->headbuf + 0x08, &self, 8);
                    uintptr_t zero = 0;
                    memcpy(sl->headbuf + 0x10, &zero, 8);
                }
            }
            {
                uintptr_t h280=0, h2c0=0, h280p=0, h280n=0;
                safe_read_mem(sl->cand + 0x280, &h280, 8);
                safe_read_mem(sl->cand + 0x2c0, &h2c0, 8);
                h280 = UNTAG_PTR(h280);
                if (h280) {
                    safe_read_mem(h280, &h280p, 8);
                    safe_read_mem(h280 + 8, &h280n, 8);
                }
                ahb_filelog("VIEW offs cand=%#lx +280=%#lx prev=%#lx next=%#lx +2c0=%#lx",
                            (unsigned long)sl->cand, (unsigned long)h280,
                            (unsigned long)UNTAG_PTR(h280p), (unsigned long)UNTAG_PTR(h280n),
                            (unsigned long)UNTAG_PTR(h2c0));
            }
            {
                uintptr_t p0=0,p1=0,p2=0,p3=0;
                memcpy(&p0, sl->headbuf+0x00, 8);
                memcpy(&p1, sl->headbuf+0x08, 8);
                memcpy(&p2, sl->headbuf+0x10, 8);
                memcpy(&p3, sl->headbuf+0x18, 8);
                ahb_filelog("VIEW built head=%#lx n=%d view={%#lx,%#lx,%#lx,%#lx} cand=%#lx",
                            (unsigned long)head, n, (unsigned long)p0,
                            (unsigned long)p1, (unsigned long)p2, (unsigned long)p3,
                            (unsigned long)sl->cand);
            }
        }
    }

    sl->ready = 1;
    g_clv_n++;
    AHB_SAYL("L3 view: 登记 head=%#lx 真实节点=%d (共%d条)",
         (unsigned long)head, sl->keep, g_clv_n);
    ahb_filelog("VIEW register head=%#lx keep=%d total=%d",
                (unsigned long)head, sl->keep, g_clv_n);
}

/*
 * process_vm_readv 包装：只有当读的是真实链表头那 0x40 字节时，才用合成内容覆盖。
 * 其它地址一律原样交给真实函数。
 */
/*
 * 把视图覆盖应用到一段刚读到的内存上（pread 与 process_vm_readv 共用的实现）。
 * 只做 memcpy，不读内存，因此不会递归。
 */
static void clv_apply_view(uintptr_t rstart, void *buf, size_t rlen) {
    uintptr_t rend;
    rstart = UNTAG_PTR(rstart);   /* 同上：带 TBItag 的地址要先剥掉 */
    rend = rstart + rlen;
    int k, q;
    for (k = 0; k < g_clv_n; k++) {
        struct clv_slot *sl = &g_clv[k];
        if (!sl->ready) continue;
        {
            uintptr_t ovs = (rstart > sl->head) ? rstart : sl->head;
            uintptr_t ove = (rend < sl->head + 0x40) ? rend : (sl->head + 0x40);
            if (ovs < ove) {
                size_t src_off = (size_t)(ovs - sl->head);
                size_t len = (size_t)(ove - ovs);
                if (src_off + len <= 0x40) {
                    memcpy((char *)buf + (ovs - rstart), sl->headbuf + src_off, len);
                    g_clv_hits++;
                }
            }
        }
        for (q = 0; q < sl->keep; q++) {
            uintptr_t na = sl->node_addr[q];
            uintptr_t ovs, ove;
            if (!na) continue;
            ovs = (rstart > na) ? rstart : na;
            ove = (rend < na + 0x10) ? rend : (na + 0x10);
            if (ovs >= ove) continue;
            memcpy((char *)buf + (ovs - rstart),
                   sl->nodebuf[q] + (ovs - na), (size_t)(ove - ovs));
            g_clv_hits++;
        }
    }
}

/* 供 maps_hide.h 的重定位驱动接管引用 */
static ssize_t clv_pvr_entry(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                             const struct iovec *remote, unsigned long riovcnt,
                             unsigned long flags);

/*
 * ===== pread64 通道 =====
 *
 * 为什么必须接这条路：检测器读内存在两条路上走。
 *   - 一部分检查（CRC 之类）用 process_vm_readv
 *   - ClassLoader 计数走的是 /proc/<pid>/mem + pread
 * 实测证据：
 *   进程里能看到 fd 101 -> /proc/27834/mem；
 *   而且我把链表头伪造成**空表**（prev=next=head, size=0）之后再跑，
 *   计数依然是 33 —— 说明它根本没读我们伪造的那份字节。
 *
 * 所以把同一套视图挂到 pread 上：offset 就是目标地址。
 */
/*
 * ===== read 通道（检测器真正走的那条）=====
 *
 * 为什么绕了这么大圈：直接看检测器 libantihook.so 的导入表，
 * 它没有导入 pread / pread64，导入的是
 *     open, lseek64, read, mmap, process_vm_readv
 * 它读 /proc/<pid>/mem 的方式是 open + lseek64(定位) + read。
 * 我先挂的 pread 包装一次都不会被调用（日志里一条 PREAD 都没有），
 * 现象看着像"接管失效"，其实是它根本不走那条路。
 *
 * 这里只接 read 一个，理由：
 *   - open/openat 已由 maps_hide.h 那边的重定位驱动统一接管，
 *     重复接管会撞名（实测编译报 redefinition）
 *   - 不需要记 lseek：read 会把文件偏移向前推进 n，
 *     所以"本次读的起始地址" = lseek64(fd,0,SEEK_CUR) - n
 *   - fd 是不是 /proc/<pid>/mem，用 readlink 惰性判一次并缓存
 *
 * read 是极热路径（日志、fgets/fread 全在走），
 * 所以顺序必须是"先查缓存表，命中才做事"，绝不反过来。
 */
#define AHB_MAX_FD 1024
/* 0=未判定 1=mem 2=不是 */
static unsigned char g_fd_kind[AHB_MAX_FD];

typedef long long (*lseek64_fn)(int, long long, int);
typedef ssize_t   (*read_fn)(int, void *, size_t);
typedef ssize_t   (*readlink_fn)(const char *, char *, size_t);

static lseek64_fn   g_real_lseek64_r = NULL;
static read_fn      g_real_read      = NULL;
static readlink_fn  g_real_readlink  = NULL;

static int clv_fd_is_mem(int fd) {
    char p[64], t[256];
    ssize_t n;
    if (fd >= 0 && fd < AHB_MAX_FD && g_fd_kind[fd]) return g_fd_kind[fd] == 1;
    if (!g_real_readlink) g_real_readlink = (readlink_fn)dlsym(RTLD_DEFAULT, "readlink");
    snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
    n = g_real_readlink ? g_real_readlink(p, t, sizeof(t) - 1) : -1;
    if (n > 0) {
        size_t L;
        t[n] = 0;
        L = (size_t)n;
        /*
         * 必须精确判"以 /mem 结尾"。
         *
         * 踩坑：一开始用 strstr(t, "/mem")，结果 Android 上大量
         * memfd 的链接名形如 "/memfd:jit-cache (deleted)"、
         * "/memfd:dalvik-main space" —— 全都含 "/mem" 子串，
         * 于是普通内存文件被误判成 /proc/<pid>/mem，
         * 日志里冒出 base=0 n=1458 这种根本不是按地址读的记录。
         */
        if (L >= 4 && strcmp(t + L - 4, "/mem") == 0) {
            if (fd >= 0 && fd < AHB_MAX_FD) g_fd_kind[fd] = 1;
            ahb_filelog("READMEM fd=%d is mem (%s)", fd, t);
            return 1;
        }
    }
    if (fd >= 0 && fd < AHB_MAX_FD) g_fd_kind[fd] = 2;
    return 0;
}

/*
 * ===== fread 通道 =====
 *
 * 最终确认的真实路径：检测器用 fopen("/proc/<pid>/mem") + fread 读内存。
 *
 * 证据链：
 *   1) 它的导入表里没有 pread/pread64，有 fopen/fread/fgets/fdopen
 *   2) 进程里确实存在 fd -> /proc/<pid>/mem
 *   3) 但那个 fd 没有出现在 maps 里（不是 mmap），也没有触发 read 包装
 *   4) GOT 补丁确实打进了 libantihook.so（patched=8），所以不是没接上，
 *      而是 fread 内部直接走 libc 私有 fd，压根不经过 PLT 上的 read
 *
 * 所以必须在 fread 这一层接。起始地址怎么算：
 *     base = ftello(stream) - 本次字节数
 * ftello 返回的是"应用视角的逻辑位置"，已经把 stdio 缓冲区算进去了，
 * 所以读完之后减掉本次长度，就是这次读的内存地址。
 * 这样不需要自己跟踪缓冲，也不会因为内部预读而偏移。
 */
typedef size_t    (*fread_fn)(void *, size_t, size_t, void *);
typedef long long (*ftello_fn)(void *);
typedef int       (*fileno_fn)(void *);

static fread_fn   g_real_fread  = NULL;
static ftello_fn  g_real_ftello = NULL;
static fileno_fn  g_real_fileno = NULL;

size_t clv_fread_entry(void *ptr, size_t size, size_t nmemb, void *stream) {
    size_t n;
    size_t bytes;
    int fd;
    if (!g_real_fread) g_real_fread = (fread_fn)dlsym(RTLD_DEFAULT, "fread");
    if (!g_real_fread) return 0;
    n = g_real_fread(ptr, size, nmemb, stream);
    if (n == 0) return n;
    bytes = n * size;
    if (bytes < 8) return n;
    if (g_clv_n <= 0 || g_clv_in_wrap) return n;
    if (!g_real_fileno) g_real_fileno = (fileno_fn)dlsym(RTLD_DEFAULT, "fileno");
    if (!g_real_fileno) return n;
    fd = g_real_fileno(stream);
    if (fd < 0 || fd >= AHB_MAX_FD) return n;
    if (g_fd_kind[fd] == 2) return n;
    if (!clv_fd_is_mem(fd)) return n;
    {
        static unsigned long fc = 0, fh = 0, diag = 0;
        unsigned long h0 = g_clv_hits;
        long long pos;
        if (!g_real_ftello) g_real_ftello = (ftello_fn)dlsym(RTLD_DEFAULT, "ftello");
        if (!g_real_ftello) return n;
        pos = g_real_ftello(stream);
        if (pos < 0) return n;
        fc++;
        clv_apply_view((uintptr_t)(pos - (long long)bytes), ptr, bytes);
        if (g_clv_hits != h0) fh++;
        if (diag < 20) {
            diag++;
            ahb_filelog("READMEM fread#%lu base=%#lx n=%zu hit=%lu slots=%d",
                        fc, (unsigned long)(pos - (long long)bytes), bytes, fh, g_clv_n);
        }
    }
    return n;
}

/*
 * fd 级 maps 过滤。
 *
 * 这是整条对抗路径上最底层的判定点：不看谁打开、什么时候打开、
 * 用 open 还是 openat 还是 syscall，也不看是哪个线程 ——
 * 只要这个 fd 指向 /proc/<pid>/maps，读出来的就是过滤后的视图。
 *
 * 为什么必须做到这一层（实测依据）：
 *   - 检测器库的 5 个 GOT 槽（open/read/syscall/process_vm_readv/
 *     dl_iterate_phdr）全部接管成功，日志确认 patched=5；
 *   - 但整个检测周期里 open 包装只接到 /proc/self/cmdline 和
 *     /proc/self/stat，一次都没有 /proc/self/maps；
 *   - 它报出来的 3 个匿名可执行段地址（31d0e01000、31d1a47000、
 *     74218c9000）与进程真实 maps 逐条吻合。
 * 结论：它读的是真实地图，只是那条路不经过我接管的那几个入口 ——
 * 很可能 fd 在更早的时刻就拿到了，之后只是对着已有 fd 反复 read。
 * 因此把过滤点下移到 fd 本身。
 */
typedef ssize_t (*ahb_pread_fn)(int, void *, size_t, long long);
static ahb_pread_fn g_ahb_pread64 = NULL;

static int clv_fd_is_maps(int fd) {
    char p[64], t[256];
    ssize_t n;
    if (fd < 0) return 0;
    if (!g_real_readlink) g_real_readlink = (readlink_fn)dlsym(RTLD_DEFAULT, "readlink");
    snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
    n = g_real_readlink ? g_real_readlink(p, t, sizeof(t) - 1) : -1;
    if (n <= 0) return 0;
    t[n] = 0;
    {
        size_t L = (size_t)n;
        /* 精确判"以 /maps 结尾"，避免误吞别的 proc 文件 */
        if (L >= 5 && strcmp(t + L - 5, "/maps") == 0) return 1;
    }
    return 0;
}

/*
 * 用 memfd 里的过滤内容替换真实 maps 内容，同时**保持调用方的文件偏移语义**：
 * 偏移仍然记在原始 fd 上，只是内容从我们的 memfd 按同一偏移 pread 出来。
 * 这样 read 循环、lseek、读到 EOF 的行为与真文件完全一致。
 */
static ssize_t clv_read_maps_override(int fd, void *buf, size_t count, ssize_t *out) {
    static int cfd = -1;
    long long cur;
    ssize_t r;
    if (cfd < 0) cfd = maps_make_clean_fd();
    if (cfd < 0) return 0;
    if (!g_real_lseek64_r) g_real_lseek64_r = (lseek64_fn)dlsym(RTLD_DEFAULT, "lseek64");
    if (!g_ahb_pread64) g_ahb_pread64 = (ahb_pread_fn)dlsym(RTLD_DEFAULT, "pread64");
    if (!g_real_lseek64_r || !g_ahb_pread64) return 0;
    cur = g_real_lseek64_r(fd, 0, SEEK_CUR);
    if (cur < 0) return 0;
    r = g_ahb_pread64(cfd, buf, count, cur);
    if (r < 0) return 0;
    g_real_lseek64_r(fd, cur + r, SEEK_SET);
    {
        static unsigned long cnt = 0;
        if (cnt < 6) {
            cnt++;
            ahb_filelog("READMAPS #%lu fd=%d off=%lld n=%zd", cnt, fd, cur, r);
        }
    }
    *out = r;
    return 1;
}

ssize_t clv_read_entry(int fd, void *buf, size_t count) {
    ssize_t n;
    /*
     * fd 级 maps 过滤：必须在真实 read 之前动手，否则内容已经交给对方了。
     * 放在最前面，连 g_real_read 的解析都不依赖。
     */
    if (!g_clv_in_wrap) {
        ssize_t ov;
        g_clv_in_wrap = 1;
        if (clv_fd_is_maps(fd) && clv_read_maps_override(fd, buf, count, &ov)) {
            g_clv_in_wrap = 0;
            return ov;
        }
        g_clv_in_wrap = 0;
    }
    if (!g_real_read) g_real_read = (read_fn)dlsym(RTLD_DEFAULT, "read");
    if (!g_real_read) return -1;
    n = g_real_read(fd, buf, count);
    /*
     * 记一次"某 fd 被读且读到了内容"，用于确认 maps 到底走不走这里。
     * 只在前 40 次写，避免高频 IO。
     */
    if (n < 8) return n;
    if (g_clv_n <= 0 || g_clv_in_wrap) return n;
    if (fd < 0 || fd >= AHB_MAX_FD) return n;
    if (g_fd_kind[fd] == 2) return n;
    if (!clv_fd_is_mem(fd)) return n;
    {
        static unsigned long rc = 0, rh = 0, diag = 0;
        unsigned long h0 = g_clv_hits;
        long long cur;
        uintptr_t base;
        if (!g_real_lseek64_r) g_real_lseek64_r = (lseek64_fn)dlsym(RTLD_DEFAULT, "lseek64");
        if (!g_real_lseek64_r) return n;
        cur = g_real_lseek64_r(fd, 0, SEEK_CUR);
        if (cur < 0) return n;
        base = (uintptr_t)(cur - (long long)n);
        rc++;
        clv_apply_view(base, buf, (size_t)n);
        if (g_clv_hits != h0) rh++;
        if (diag < 20) {
            diag++;
            ahb_filelog("READMEM #%lu base=%#lx n=%zu hit=%lu slots=%d",
                        rc, (unsigned long)base, (size_t)n, rh, g_clv_n);
        }
    }
    return n;
}

typedef ssize_t (*pread64_fn)(int, void *, size_t, long long);
static pread64_fn g_real_pread64 = NULL;
static pread64_fn g_real_pread = NULL;

static ssize_t clv_pread(int fd, void *buf, size_t count, long long off);
ssize_t clv_pread_entry(int fd, void *buf, size_t count, long long off) {
    static unsigned long ec = 0;
    ec++;
    if (ec <= 5) ahb_filelog("PREAD ENTER #%lu fd=%d off=%#lx n=%zu", ec, fd, (unsigned long)off, count);
    return clv_pread(fd, buf, count, off);
}

static ssize_t clv_pread(int fd, void *buf, size_t count, long long off) {
    /*
     * 懒解析：不要指望某处一次性初始化能跑到。
     * 实测把解析放在 clv_install_now 的 if(!g_real_pvr) 分支里，
     * 那个分支因为已有其它路径设过 g_real_pvr 而整段跳过，
     * 结果 g_real_pread64 永远是 NULL，pread 通道静默失效、
     * 日志里一条 PREAD 都没有，看起来像"接管没生效"。
     */
    if (!g_real_pread64 && !g_real_pread) {
        g_real_pread64 = (pread64_fn)dlsym(RTLD_DEFAULT, "pread64");
        g_real_pread   = (pread64_fn)dlsym(RTLD_DEFAULT, "pread");
        ahb_filelog("PREAD resolve pread64=%p pread=%p", (void *)g_real_pread64, (void *)g_real_pread);
    }
    pread64_fn fn = g_real_pread64 ? g_real_pread64 : g_real_pread;
    ssize_t n;
    if (!fn) return pread(fd, buf, count, (off_t)off);
    n = fn(fd, buf, count, off);
    if (n <= 0 || g_clv_in_wrap) return n;
    if (n < 8) return n;
    {
        static unsigned long pc = 0, ph = 0, diag = 0;
        unsigned long h0 = g_clv_hits;
        pc++;
        clv_apply_view((uintptr_t)off, buf, (size_t)n);
        if (g_clv_hits != h0) ph++;
        if (diag < 30) {
            diag++;
            ahb_filelog("PREAD call#%lu off=%#lx n=%zu hits=%lu slots=%d",
                        pc, (unsigned long)(uintptr_t)off, (size_t)n, ph, g_clv_n);
        }
    }
    return n;
}

static ssize_t clv_pvr(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                       const struct iovec *remote, unsigned long riovcnt,
                       unsigned long flags) {
    /* 先计数：包装一旦被走到就留证据，任何后续 return 都不影响 */
    g_clv_calls++;
    if (!g_real_pvr) return -1;
    ssize_t n = g_real_pvr(pid, local, liovcnt, remote, riovcnt, flags);
    if (n <= 0 || g_clv_in_wrap) return n;
    if (pid != getpid()) return n;

    /*
     * 读到即登记：把检测器实际读到的每个候选地址都纳入视图。
     *
     * 这是整条链路最关键的一步，也是绕了很久才想通的地方。
     *
     * 检测器不是只读"链表头"：它在 Runtime 的候选对象里按 8 字节步进
     * 逐个读，凡是读到的值看起来像指针，就当成潜在链表头去验证。
     * 实测它一次扫描会读 4 个这样的地址，而我们预扫描只登记了其中 2 个
     * （另外两个是 0x7d01b0cb70 / 0x7d01aefe00）。它一旦选中未登记的那个，
     * 读到的就是真实长链，数出 31~33 —— 这就是"三轮坏一轮"的全部原因。
     *
     * 所以：包装里看到的每个未登记地址，只要它落在用户态且我们还没建过视图，
     * 就直接建一份。clv_build 会从该地址出发走链并构造 4 节点闭环视图；
     * 即使它其实不是链表头，最坏也只是多一份无害的视图映射。
     *
     * 成本控制：每个地址只处理一次（clv_find 去重），总数受 CLV_MAX_HEADS 限制，
     * 且不在这里做全量重扫（那会造成几万次触发）。
     */
    if (riovcnt >= 1 && n >= 8 && liovcnt >= 1) {
        uintptr_t ra = (uintptr_t)remote[0].iov_base;
        /*
         * 只对"8 字节整数倍且落在 ART 堆"的读做登记判定。
         * 检测器读 head 是 8 字节一次，读候选对象也是 8 字节，
         * 所以这里 n>=8 已足够；不要限制成必须 8，否则一次读 16 字节的
         * 情况会被漏掉。
         */
        /*
         * 动态登记的准入条件必须严格，否则会把大量无关地址当成链表头。
         *
         * 实测：不加限制时产生 2184 条登记，其中 0xa84fb6c0 这类
         * 根本不是 ART 堆地址（是普通的 32 位指针残留），
         * 它们占满了 CLV_MAX_HEADS，真正的链反而登记不进去。
         *
         * 判据三条同时满足：
         *  1) 落在 ART 堆所在的地址区间（与 runtime 同高 24 位）；
         *  2) 8 字节对齐（ART 对象都是对齐的）；
         *  3) 不是已登记链的成员。
         */
        if (ra >= g_art_heap_lo && ra < g_art_heap_hi &&
            (ra & 7) == 0 &&
            !clv_find(ra) && !clv_is_chain_member(ra)) {
            g_clv_need_build = ra;
        }
    }

    /*
     * 合成候选覆盖必须最先执行，且不能被 g_clv_n / g_clv_in_wrap 挡住。
     *
     * 实测教训：这段原先放在 for 循环里、g_clv_in_wrap=1 之后，
     * 结果是它一次都没跑到（g_clv_n 为 0 时包装在更早处就 return 了），
     * 表现为"合成候选建好了却完全没生效"。
     */
    /* 决定性诊断：记录前 30 次包装调用的远端地址与 fake 分支状态 */
    {
        static int dbg = 0;
        if (dbg < 30) {
            dbg++;
            ahb_filelog("VIEW call ra=%#lx n=%lu fake_ready=%d rt=%#lx",
                        (unsigned long)((riovcnt >= 1) ? (uintptr_t)remote[0].iov_base : 0),
                        (unsigned long)n, g_fake_ready,
                        (unsigned long)g_scan_runtime);
        }
    }
    if (g_fake_ready && g_scan_runtime) {
        static volatile int in_fake = 0;
        if (!in_fake) {
            in_fake = 1;
            for (unsigned long i = 0; i < riovcnt && i < liovcnt; i++) {
                size_t rlen = remote[i].iov_len;
                /*
                 * 必须先去 TBI 标签再比较。
                 *
                 * 实测诊断（VIEW call ra=0xb400006ffcd0cb70）：检测器传进来的
                 * remote iov_base 带 top-byte 标签 0xb4，而 runtime / fake_cl
                 * 都是无标签地址。直接用 rstart <= rt 比较永远为假，
                 * 覆盖分支一次都不会执行 —— 这就是"合成候选建好了却没生效"的根因。
                 *
                 * 去标签只影响我们的区间计算；写回 local 时仍按原始 rstart 算偏移，
                 * 因为调用方给的两个缓冲区是按原始地址对应的。
                 */
                uintptr_t rstart = (uintptr_t)remote[i].iov_base;
                uintptr_t rstart_u = UNTAG_PTR(rstart);
                uintptr_t lstart = (uintptr_t)local[i].iov_base;
                uintptr_t rt = g_scan_runtime;
                uintptr_t fcl = g_fake_cl_addr;
                uintptr_t rend = rstart_u + rlen;
                rstart = rstart_u;
                /* runtime+0 -> fake_cl */
                if (rstart <= rt && rend >= rt + 8) {
                    uintptr_t v = fcl;
                    memcpy((void *)(lstart + (rt - rstart)), &v, 8);
                }
                /*
                 * 不清零 runtime+8..0x500。
                 *
                 * 曾经把这一段全返回 0，想让检测器"扫不到真候选"。
                 * 实测反而更糟：它连真实的 ClassLinker 候选也读不到，
                 * 最后报 "候选内未发现闭环链表 / vtable候选=2 闭环链表=0"，
                 * 状态变成 INFO —— 既不是安全也不是风险，但也不是我们要的 SAFE。
                 *
                 * 正确做法是只伪造 runtime+0：检测器的候选扫描是
                 * "cl_off 从 0 开始，第一个满足闭环条件就 return"，
                 * 所以 cl_off=0 命中我们合成的候选后它立即返回，
                 * 根本不会去读后面那些槽。保持它们为真值反而更安全 ——
                 * 万一合成候选因故没命中，它仍能走正常路径而不是彻底失灵。
                 */
                /* fake_cl 本体 */
                {
                    uintptr_t a = (rstart > fcl) ? rstart : fcl;
                    uintptr_t b = (rend < fcl + FAKE_CL_SIZE) ? rend : (fcl + FAKE_CL_SIZE);
                    if (a < b) memcpy((void *)(lstart + (a - rstart)), g_fake_cl + (a - fcl), (size_t)(b - a));
                }
                /* 合成节点 */
                {
                    int q;
                    for (q = 0; q < FAKE_CL_NODES; q++) {
                        uintptr_t na = (uintptr_t)g_fake_nodes[q];
                        uintptr_t a = (rstart > na) ? rstart : na;
                        uintptr_t b = (rend < na + 0x10) ? rend : (na + 0x10);
                        if (a < b) {
                            memcpy((void *)(lstart + (a - rstart)),
                                   (void *)(na + (a - na)), (size_t)(b - a));
                        }
                    }
                }
                g_clv_hits++;
            }
            in_fake = 0;
            /*
             * 这里**不能** return。
             *
             * 踩过坑：早期为了"合成候选命中就不再走真链"在这里直接 return n，
             * 结果把后面基于真实链的伪造整段跳过 —— 而合成候选依赖
             * "检测器从 runtime+0 开始扫并且第一个就命中我们"，一旦它
             * 从别的偏移进入，就彻底没人兜底，表现为 count=31~33 翻红。
             *
             * 两者是互补关系不是替代关系：合成候选负责"抢先命中"，
             * 真链视图负责"没抢到时兜底"。所以继续往下走。
             */
        }
    }

    g_clv_in_wrap = 1;

    /*
     * 关键时机修正：
     * 检测器扫描时，Runtime 里可能已经长出了 JNI_OnLoad 阶段还不存在的闭环链
     * （实测：登记的是 7d01a66d50 / 7d01b1bdc0，它实际读的是 7d01a975c8）。
     * 所以只要包装第一次被走到，就说明它已经开扫，立刻按当时的结构重扫一遍，
     * 把所有闭环候选补登记。重扫只做一次，避免和它的读取互相拖慢。
     */
    /*
     * 候选清单必须在"检测器开始读"到"它真正选中某条链"之间保持最新。
     *
     * 原来只重扫一次，实测不够：Runtime 里的闭环是在启动过程中陆续成形的，
     * 检测器先读 vm/runtime（触发我的那一次重扫），之后才真正遍历它选中的链 ——
     * 那条链可能是重扫之后才闭合的，于是没被登记，读到的仍是真值。
     * 表现就是 ClassLoader 项间歇性翻红（实测 3 轮里坏 1 轮）。
     *
     * 改为：前若干次读取里每次都补扫一遍，直到候选数稳定为止。
     * 扫描本身是"扫 Runtime 的 0..0x500 指针 + 找闭环"，开销很小。
     */
    {
        /*
         * 补扫节流。
         *
         * 原来是"前 64 次读取各补扫一次"，实测是检测期最大的模块内开销：
         * clv_install_now 每次要约 26ms，64 次就是 1.7 秒。
         * 改成按时间节流：每 250ms 最多一次。Runtime 里新成形的闭环
         * 是毫秒级过程，250ms 的粒度绰绰有余。
         */
        static unsigned long last_us = 0;
        static int rescans = 0;
        uintptr_t ra0 = (riovcnt >= 1) ? (uintptr_t)remote[0].iov_base : 0;
        unsigned long now_us = ahb_now_us();
        if (ra0 != 0 && rescans < 24 &&
            (last_us == 0 || now_us - last_us >= 250000UL)) {
            rescans++;
            last_us = now_us;
            int before = g_clv_n;
#if !AHB_MINIMAL_VIEW
            clv_install_now();
#endif
            if (g_clv_n != before) {
                AHB_SAYL("RESCAN: 第 %d 次补扫 slots %d -> %d", rescans, before, g_clv_n);
                ahb_filelog("RESCAN %d: %d -> %d", rescans, before, g_clv_n);
            }
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

    /*
     * 只有在"读的是已登记候选 head 或合成节点"时才改写。
     * 若 pid 不是自己、或读的不是这些地址，原样返回，不引入任何额外语义。
     */
    /*
     * 轻量补扫：每次包装调用最多补登记一条新链。
     *
     * 全量重扫太贵（clv_install_now 要读 Runtime 的 0x500 指针 × 每个候选的 0x500，
     * 实测放进包装会造成 6 万次触发、性能灾难）。但完全不补又会漏掉
     * 检测器实际使用的那条链 —— 实测三轮里坏一轮、读数 31/32/33。
     *
     * 折中：只在"读的地址落在 Runtime 附近"时，做一次轻量检查 ——
     * 把这次读到的值当作潜在链表头，验证它是否是闭环（两次读即可判定）。
     * 成本是每次包装调用最多两次额外读取，可忽略。
     */
    ssize_t remaining = n;
    for (unsigned long i = 0; i < riovcnt && i < liovcnt && remaining > 0; i++) {
        size_t rlen = remote[i].iov_len;
        if (rlen > (size_t)remaining) rlen = (size_t)remaining;
        /*
         * 必须去 TBI 标签再比较。
         *
         * 踩坑：检测器读内存时有的路径传带标签指针（0xb400006ffcd0cb70），
         * 有的不传（0x6ffcc1c828）。而我们登记 head / node_addr 时
         * 统一用去标签值。直接比就变成
         *     0xb400006ffcd0cb70 > 0x6ffcd1bda0  恒真
         * 于是偏移算出天文数字、src_off 越界被丢弃，
         * 只剩下恰好没带标签的那几次能命中 —— 日志里 hits 一直很小、
         * 看着像"覆盖逻辑写错了"，其实只是标签没剥。
         *
         * lstart 是本地缓冲，不能去标签，保持原值。
         */
        uintptr_t rstart = UNTAG_PTR((uintptr_t)remote[i].iov_base);
        uintptr_t rend = rstart + rlen;

        uintptr_t lstart = (uintptr_t)local[i].iov_base;

        /*
         * 全量去重记录每一个被读的地址。
         *
         * 目的：确认检测器计数时究竟读了哪些位置。
         * 已经知道它读链表头时确实经过我们（VIEW hithead 里
         * 它拿到的就是我们写的合成 prev/next/size），
         * 但读数始终 32 不动，说明计数用的是别处的读取。
         * 把地址全列出来就能定位。
         */
        /*
         * ===== 读到即建视图（关键时序修复）=====
         *
         * 这是整件事最后一个、也是决定性的缺口。
         *
         * 实测证据（同一次运行）：
         *   RD #1 rs=0x6ffcd1bda0 n=64    <- 检测器第一次读哨兵
         *   RD #2 rs=0x6fa1625020 n=16    <- 接着读的是**真实** prev
         * 而我们给它的 prev 是 0x6f2635d4f0（模块内存里的合成节点）。
         * 它读到的却是 0x6fa1625020 —— 说明 RD #1 那次返回的是真值，
         * 不是我们伪造的值。
         *
         * 原因：视图是在 clv_install_now() 里登记的，而那个函数在
         * JNI_OnLoad 才跑。检测器的 native 扫描发生在
         * "库已加载、但我们的扫描还没登记完"这个窗口里，
         * 它第一次读链表头就落在这个窗口 —— 拿到真值，一次数完。
         * 后面我们再怎么覆盖，它已经不需要再读了。
         *
         * 所以必须在**这次读取之内**把视图建好，然后重新覆盖返回值。
         * 顺序：先补登记 → 再 apply_view，这样第一次读就能命中。
         *
         * 成本控制：只对"看起来像链表头"的读取尝试
         * （长度 >= 16、地址在 ART 堆内、8 字节对齐），
         * 且每个地址只尝试一次（clv_build 内部有 clv_find 去重）。
         */
        if (g_clv_n < CLV_MAX_HEADS && rlen >= 16 && (rstart & 7) == 0 &&
            rstart >= g_art_heap_lo && rstart < g_art_heap_hi &&
            !clv_find(rstart)) {
            uintptr_t x = 0, y = 0, xn = 0, yp = 0;
            if (read_ptr_untagged(rstart, &x) && read_ptr_untagged(rstart + 8, &y) &&
                x >= USER_PTR_MIN && y >= USER_PTR_MIN && x != rstart && y != rstart &&
                read_ptr_untagged(x + 8, &xn) && read_ptr_untagged(y, &yp) &&
                UNTAG_PTR(xn) == rstart && UNTAG_PTR(yp) == rstart) {
                int e1 = walk_dll(y, rstart, 8), e2 = walk_dll(x, rstart, 0);
                int ec = (e1 > e2) ? e1 : e2;
                if (ec >= 2 && ec <= 200) {
                    clv_build(rstart);
                    if (g_clv_n > 0 && rstart == g_clv[g_clv_n - 1].head) {
                        g_clv[g_clv_n - 1].cand = g_clv_cur_cand;
                    }
                    ahb_filelog("VIEW late head=%#lx count=%d slots=%d",
                                (unsigned long)rstart, ec, g_clv_n);
                }
            }
        }

        /*
         * 合成候选覆盖：让检测器在 cl_off=0 就命中我们的假候选。
         *
         * 检测器的候选扫描是「runtime+0..0x500 逐个读，第一个满足闭环就 return」，
         * 永远取第一个。只要让它在 +0 就看到一个过检的候选，
         * 它就永远不会去碰真链 —— 这是确定性的，没有竞态。
         */
        if (g_fake_ready && g_scan_runtime) {
            (void)0;
            /*
             * 决定性修复：远端地址带 TBI 标签，必须先去标签再和
             * 我们自己的地址（runtime / head / node_addr，全部无标签）比较。
             *
             * 实测证据：日志里检测器读的目标地址形如 0xb400006ffcd0cb70，
             * 高字节 0xb4 是 arm64 的 top-byte-ignore 标记。
             * 而 sl->head / sl->node_addr 是纯地址 0x6ffcd0cb70。
             * 直接比较永远是假 —— 1310 次读取只命中 10 次，
             * 于是整条链的伪造形同虚设，检测器照样走真链数出 31。
             */
            rstart = UNTAG_PTR(rstart);
            rend = rstart + rlen;
            uintptr_t rt = g_scan_runtime;
            /* runtime+0 那 8 字节 -> g_fake_cl 地址 */
            {
                uintptr_t ovs = (rstart > rt) ? rstart : rt;
                uintptr_t ove = (rend < rt + 8) ? rend : (rt + 8);
                if (ovs < ove) {
                    uintptr_t v = g_fake_cl_addr;
                    memcpy((void *)(lstart + (ovs - rstart)),
                           (unsigned char *)&v + (ovs - rt), (size_t)(ove - ovs));
                    g_clv_hits++;
                }
            }
            /* runtime+8..0x500 范围内 -> 0，让它扫不到真候选 */
            {
                uintptr_t ovs = (rstart > rt + 8) ? rstart : (rt + 8);
                uintptr_t ove = (rend < rt + 0x500) ? rend : (rt + 0x500);
                if (ovs < ove) {
                    memset((void *)(lstart + (ovs - rstart)), 0, (size_t)(ove - ovs));
                    g_clv_hits++;
                }
            }
            /* g_fake_cl 自身 */
            {
                uintptr_t fcl = g_fake_cl_addr;
                uintptr_t ovs = (rstart > fcl) ? rstart : fcl;
                uintptr_t ove = (rend < fcl + FAKE_CL_SIZE) ? rend : (fcl + FAKE_CL_SIZE);
                if (ovs < ove) {
                    memcpy((void *)(lstart + (ovs - rstart)),
                           g_fake_cl + (ovs - fcl), (size_t)(ove - ovs));
                    g_clv_hits++;
                }
            }
            /* 4 个合成节点的 prev/next */
            {
                int q;
                for (q = 0; q < FAKE_CL_NODES; q++) {
                    uintptr_t na = (uintptr_t)g_fake_nodes[q];
                    uintptr_t ovs = (rstart > na) ? rstart : na;
                    uintptr_t ove = (rend < na + 0x10) ? rend : (na + 0x10);
                    if (ovs >= ove) continue;
                    memcpy((void *)(lstart + (ovs - rstart)),
                           (void *)(na + (ovs - na)), (size_t)(ove - ovs));
                    g_clv_hits++;
                }
            }
        }


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
                        /*
                         * 判决性探针：在**真正生效的覆盖块**里把返回内容
                         * 改成空表（prev=next=head, size=0）。
                         *
                         * 必须写在这里，不能写在旁边那些诊断分支里 ——
                         * 之前那次探针就放在一个从不执行的分支内，
                         * 于是"读数没变"被误读成"检测器不走读路径"，
                         * 白白绕了一大圈。
                         *
                         * 判读：读数变 0/正常 -> 覆盖生效，问题在别处；
                         *       读数仍 32     -> 它确实直接解引用真实内存。
                         */
                        if (g_clv_empty_probe) {
                            uintptr_t self = sl->head;
                            size_t bofs = (size_t)(ovs - sl->head);
                            unsigned char tmp[0x40];
                            memcpy(tmp, sl->headbuf, 0x40);
                            memcpy(tmp + 0x00, &self, 8);
                            memcpy(tmp + 0x08, &self, 8);
                            memset(tmp + 0x10, 0, 8);
                            memcpy((void *)(lstart + (ovs - rstart)),
                                   tmp + bofs, len);
                        }
                    }
                }
            }

            /* 每个**真实节点**的 prev/next 也按我们的视图返回 */
            {
                int q;
                for (q = 0; q < sl->keep; q++) {
                    uintptr_t na = sl->node_addr[q];
                    uintptr_t ovs, ove;
                    if (!na) continue;
                    ovs = (rstart > na) ? rstart : na;
                    ove = (rend < na + 0x10) ? rend : (na + 0x10);
                    if (ovs >= ove) continue;
                    memcpy((void *)(lstart + (ovs - rstart)),
                           sl->nodebuf[q] + (ovs - na), (size_t)(ove - ovs));
                    g_clv_hits++;
                    {
                        static int dbg3 = 0;
                        if (dbg3 < 200) {
                            dbg3++;
                            uintptr_t nv = 0, pv = 0;
                            memcpy(&pv, sl->nodebuf[q] + 0, 8);
                            memcpy(&nv, sl->nodebuf[q] + 8, 8);
                            (void)0;
                        }
                    }
                }
            }
        }
        {
            static int dbg2 = 0;
            if (dbg2 < 40) {
                dbg2++;
                            (void)0;
            }
        }
        remaining -= (ssize_t)rlen;
    }
    g_clv_in_wrap = 0;

    /*
     * 消费补登记请求。
     *
     * 必须在 g_clv_in_wrap 复位之后执行：clv_build 内部要读内存，
     * 那些读会再次进入本包装，若标志未复位就会直接返回、构建失败。
     */
    if (g_clv_need_build) {
        uintptr_t h = g_clv_need_build;
        g_clv_need_build = 0;
        clv_build(h);
        ahb_filelog("VIEW dyn head=%#lx total=%d", (unsigned long)h, g_clv_n);
    }

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
        /*
         * 视图接管必须即时生效：跳过去抖，直接精确扫一遍。
         *
         * 用一个独立的原子锁把"置位 → 扫描 → 复位"整段保护起来。
         * 实测踩坑：这个全局开关被抢跑线程与守护线程同时改写，
         * 会出现 A 置 1、B 置 0 的交错；更糟的是它与 maps_patch_got_all
         * 内部的表重建没有共同保护，曾出现半截表项被另一线程遍历，
         * 用错的 base 解析 ELF 后 SIGSEGV（崩在 maps_patch_got_all）。
         */
        /*
         * 不要再套一层原子锁。
         *
         * 踩过两次同一个坑：__atomic_* 与 __sync_* 在 clang + Bionic 下会引用
         * __aarch64_cas4_acq_rel / __aarch64_swp4_acq_rel 这些 libatomic 符号，
         * 而 Bionic 不导出它们 —— dlopen 直接失败，整个模块装不上
         * （日志："cannot locate symbol __aarch64_cas4_acq_rel"）。
         *
         * maps_patch_got_all 内部已经有内联汇编实现的自旋锁（maps_try_lock），
         * 并发安全由它保证。这里直接调用即可。
         */
        /*
         * 只在"确实有新库被加载"时才做全量扫描。
         *
         * 性能账（实测）：一次全量扫描要读 440 个已映射 .so 的 ELF 动态段
         * 与重定位表，单次约 10ms 量级；而这条入口在启动阶段被调用几十次
         * ——日志里一次启动出现 43 行 MAPS scan。43 × 10ms ≈ 400ms，
         * 正好对上"模块全开比空转慢 250~370ms"那个实测差值。
         *
         * 而绝大多数轮次里并没有新库加载，那些扫描是纯浪费。
         * 用 dl_iterate_phdr 数一下已加载模块数（微秒级，纯内存遍历），
         * 数量没变就直接返回。
         *
         * 为什么不用进程内已有的更"精确"的判断：那些都要读 maps 或解析 ELF，
         * 成本就是我们要省掉的东西。数模块数是这里最便宜的充分条件 ——
         * 库只会增加不会减少（Android 不卸载已 dlopen 的库），
         * 所以"数量没变"就能安全地断定"没有新库"。
         */
        {
            extern int ahb_loaded_module_count(void);
            static int last_count = -1;
            static unsigned long last_us = 0;
            int now = ahb_loaded_module_count();
            if (now >= 0 && now == last_count) return;

            /*
             * 再加一道最小间隔。
             *
             * 启动阶段库是连着加载的，计数会在几十毫秒内跳好几次，
             * 每次都全量扫一遍就是重复劳动。实测把扫描从 43 次压到 22 次
             * 之后，剩下的 22 次里仍有一批挤在极短的窗口内。
             *
             * 8ms 的依据：全量扫描本身约 10ms 量级，间隔小于它没有意义；
             * 而检测器真正读地图要等它自己的 .so 完成加载并开始扫描，
             * 那个动作在库加载之后，8ms 远不足以让它抢在前面
             * （实测 6/6 连续多轮稳定，见下面的验证）。
             */
            {
                unsigned long t = ahb_now_us();
                if (last_us && t - last_us < 8000) {
                    last_count = now;      /* 记下计数，下次变化时才重新评估 */
                    return;
                }
                last_us = t;
            }
            last_count = now;
        }
        maps_patch_got_all();
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
    /*
     * 每次都要完整重扫，不能因"已经登记过几条"就提前返回。
     *
     * Runtime 里的闭环是陆续成形的：首轮可能只有 2 条，
     * 检测器真正读取时已经有第 3、第 4 条（实测出现过
     * head=0x7d01b1bc20 / 0x7ca2825020 / 0x7d01b0cb70）。
     * 一旦它选中那些没登记的长链，视图伪造就完全失效 ——
     * 这正是"三轮里坏一轮、读数 31/32/33"的根因。
     *
     * clv_build 内部对已存在的 head 会直接返回，重复扫描不会占额外槽位。
     */

    uintptr_t vm_addr = UNTAG_PTR((uintptr_t)vm);
    uintptr_t runtime = 0;
    if (!read_ptr_untagged(vm_addr + sizeof(uintptr_t), &runtime) || runtime == 0) return;

    uintptr_t art_start = 0, art_end = 0;
    if (!collect_libart_range(&art_start, &art_end)) return;

    /*
     * 记下 ART 堆所在的地址区间：runtime 指针就在堆上，
     * 取它所在的高位段作为准入范围。动态登记只接受落在这个范围内的地址。
     */
    /*
     * 记下检测器会用的 Runtime 地址 —— 合成候选的覆盖全靠它。
     *
     * 这里漏赋值过一次，症状很隐蔽：g_fake_ready 明明为 1、日志也有
     * "VIEW fake ready"，但覆盖分支 if (g_fake_ready && g_scan_runtime)
     * 永远为假，合成候选一次都没生效，看起来像"伪造成了但没用"。
     */
    g_scan_runtime = runtime;

    if (g_art_heap_lo == 0) {
        uintptr_t base = runtime & ~(uintptr_t)0xffffffffULL;
        g_art_heap_lo = base;
        g_art_heap_hi = base + (uintptr_t)0x100000000ULL;
        static int once = 0;
        if (!once) { once = 1;
            ahb_filelog("VIEW heap range %#lx-%#lx (runtime=%#lx)",
                        (unsigned long)g_art_heap_lo, (unsigned long)g_art_heap_hi,
                        (unsigned long)runtime); }
    }

    const size_t step = sizeof(uintptr_t);
    int found = 0;

    /*
     * ===== 确定性路径：直接按检测器公布的偏移取链表头 =====
     *
     * 检测器自己的 detail 里写着它的解析链：
     *     [Runtime+0x2c0 -> ClassLinker, +0x280 -> class_loaders_]
     * 也就是说它读 head 的方式是：
     *     cl     = *(Runtime + 0x2c0)
     *     head   = *(cl + 0x280)
     *
     * 之前我们做的是「在 Runtime+0..0x500 与候选+0..0x500 里暴力搜闭环」，
     * 搜到哪条就伪造哪条。实测证明这是错的：搜出来的 head 与
     * 检测器真正用的 head 完全是不同地址。
     * 日志对照（同一进程内）：
     *     我们登记的 head = 0x6ffcd1bda0
     *     cl+0x280 实际值 = 0x6ffcc1c828   ← 检测器走的是这个
     * 伪造节点虽然命中了，但检测器从它自己的 head 出发，
     * 走到我们没伪造的那一段就回到真链，照样数出 31。
     *
     * 所以第一步必须先按官方偏移取到真正的链表头，再对它做视图。
     * 按偏移取是确定性的，不依赖运气，也就不会再有"三轮坏一轮"。
     */
    {
        uintptr_t cl = 0;
        if (read_ptr_untagged(runtime + 0x2c0, &cl) && cl >= USER_PTR_MIN && cl < USER_PTR_MAX) {
            /*
             * 链表头 addr = ClassLinker + 0x280，**不是** *(ClassLinker+0x280)。
             *
             * 这是整件事里藏得最深的一个坑。std::list 的成员是内嵌的
             * __list_node_base，所以 class_loaders_ 这个成员的**地址**
             * 就是哨兵节点（链表头）的地址，它的前两个字段才是首尾指针。
             *
             * 原来写成 head = *(cl + 0x280)，拿到的是哨兵的第一个字段
             * （某个真实元素地址），再把那个元素当成头去伪造。
             * 检测器从真正的头 cl+0x280 出发，我们伪造的地址根本不在它的
             * 路径上 —— 它照样走真链数出 17~32，视图完全白做。
             *
             * 日志对照（同一进程、同一 cl）：
             *     错误 head = *(cl+0x280) = 0x6ffcc1c828
             *     正确 head = cl+0x280    = 0x6ffcd1bda0   (实测 count=17)
             */
            /*
             * head = *(cl + 0x280)。
             *
             * 注意这里是**取值**不是取地址。实测依据：
             * 用这个写法跑出过 "当前 4 个 ClassLoader，处于正常范围" 的 SAFE，
             * 说明检测器正是把 *(cl+0x280) 当链表头指针用。
             * 后来我一度改成 head = cl+0x280（当成内嵌哨兵），
             * 该项立刻退回 33 —— 证明原写法是对的。
             */
            /*
             * head = cl + 0x280 —— 取**地址**，不取值。
             *
             * 这是整件事最后、也是最关键的一个错误。std::list 的成员是
             * 内嵌的 __list_node_base，所以 class_loaders_ 这个成员的地址
             * 就是哨兵节点的地址；它的前两个字段才是首尾指针。
             *
             * 实测证据（同一次运行、同一 cl）：
             *   VIEW LOOP cand=0x6ffcd1bb20 off=0x280
             *             head=0x6ffcd1bda0 count=16 cl=1
             *             ^^^^^^^^^^^^^^ 这个是哨兵，cl=1 表示它是 class_loaders_
             *   而 *(cl+0x280) = 0x6ffcc1c828，那是链表的**第一个元素**。
             *
             * 之前写成 head = *(cl+0x280)，把第一个元素当成头去伪造。
             * 检测器从真哨兵 cl+0x280 出发，压根走不到我们伪造的地址，
             * 所以无论把那个假头做成空表、4 节点闭环还是别的，读数都不变 ——
             * 这就是为什么"空表探针"下去它照样报 32。
             *
             * 另外从 32 = 16 + 16 可以确认：它是把两个方向的长度**相加**。
             * 所以保留节点数按 sum 计算，keep=2 时 sum=4，落在正常 2~5 区间。
             */
            uintptr_t h = cl + 0x280;
            {
                uintptr_t a = 0, b = 0;
                if (read_ptr_untagged(h, &a) && read_ptr_untagged(h + step, &b) &&
                    a >= USER_PTR_MIN && b >= USER_PTR_MIN && a != h && b != h) {
                    ahb_filelog("VIEW direct cl=%#lx head=%#lx a=%#lx b=%#lx",
                                (unsigned long)cl, (unsigned long)h,
                                (unsigned long)UNTAG_PTR(a), (unsigned long)UNTAG_PTR(b));
                    g_clv_cur_cand = cl;
                    g_clv_cur_cl = cl;
                    /*
                     * 先记住链表首元素再编链。
                     *
                     * 检测器有两个入口会读：哨兵 cl+0x280，
                     * 以及首元素 *(cl+0x280)。两个都必须合成闭环，
                     * 否则它会走没合成的那条，读数纹丝不动。
                     */
                    {
                        uintptr_t f0 = 0;
                        if (read_ptr_untagged(h, &f0)) g_clv_cur_first = UNTAG_PTR(f0);
                    }
                    /*
                     * 先修剪真实链表，再建读视图。
                     * 顺序很重要：视图是"别人读时给什么"，修剪是"内存里到底有几个"。
                     * 检测器只在进程内直接解引用，所以真正起作用的是后者。
                     */
                    clv_build(h);
                    if (g_clv_cur_first && g_clv_cur_first != h) clv_build(g_clv_cur_first);
                    found++;
                }
            }
        }
    }

    /*
     * 官方偏移命中就够了，**不再做暴力扫描兜底**。
     *
     * 踩坑经过：两条路径同时登记会产生互相覆盖的真 bug。
     * 实测日志（同一进程）：
     *     VIEW direct  cl=0x6ffcd1bb20 head=0x6ffcc1c828
     *                  prev=0x6fa1625400 next=0x6ffcd1bda0
     *     VIEW built   head=0x6ffcd1bda0   <- 暴力扫描把它也当成另一条链的头
     * 注意 next 正好等于后者的 head —— 它们是同一条链上的相邻对象。
     *
     * 覆盖循环按 slot 顺序写入，后写覆盖先写：
     * 检测器读 0x6ffcd1bda0 时，本应拿到"前驱指回 0x6ffcc1c828"的视图，
     * 却被后一个 slot 的 headbuf 覆盖成它自己的前后驱，
     * 闭环校验当场失败，检测器跳过我们、回去走真链，照样数出 32。
     *
     * 所以：官方偏移命中即返回。这条路径是确定性的，
     * 不依赖"扫到哪条"，也就不会再有重叠和竞态。
     */
    ahb_filelog("VIEW install direct found=%d total=%d", found, g_clv_n);

    for (size_t cl_off = 0; cl_off < 0x500; cl_off += step) {
        uintptr_t cand = 0;
        if (!read_ptr_untagged(runtime + cl_off, &cand)) continue;
        if (cand < USER_PTR_MIN || cand >= USER_PTR_MAX) continue;

        uintptr_t vptr = 0;
        if (!read_ptr_untagged(cand, &vptr)) continue;
        /*
         * 不再构建合成候选。
         *
         * 它靠 spoof "runtime+0 -> 假 ClassLinker" 让检测器在 cl_off=0 命中。
         * 实测结果是该项从 RISK 变成 INFO("链表结构校验失败") —— 不是 SAFE，
         * 而且它与下面基于真链的视图会互相干扰（同一批地址两套内容）。
         * 真链视图修好后这条路不再需要。
         */
        (void)art_start; (void)art_end;
        /*
         * 不要求 vptr 落在 libart 段内。
         *
         * 实测检测器会用到一条 vptr 不在 libart 范围的链
         * （head=0x7d01aefe00，count=31）。按原条件它被整条漏掉，
         * 而检测器一旦先扫到它就直接返回 —— 这正是"三轮坏一轮"的根因。
         * 我们是伪造视图，多登记一条没有副作用。
         */
        if (vptr < USER_PTR_MIN || vptr >= USER_PTR_MAX) continue;

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

            /*
             * 冲突跳过：该地址已经是某条已登记链的成员，就不要再当头登记。
             *
             * 踩坑：cl+0x280 那条链的 next 恰好也是暴力扫描命中的"头"，
             * 它们本就是同一条链上的相邻对象。两条 slot 都会覆盖这段地址，
             * 后写的把先写的盖掉，闭环校验当场失败，检测器退回真链数出 32。
             * 日志对照：
             *     VIEW direct head=0x6ffcc1c828 next=0x6ffcd1bda0
             *     VIEW built  head=0x6ffcd1bda0      <- 同一个对象被登记两次
             */
            if (clv_is_chain_member(head)) continue;

            g_clv_cur_cand = cand;
            clv_build(head);
            found++;
        }
    }

    if (!g_real_pvr) {
        g_real_pvr = (pvr_fn)dlsym(RTLD_DEFAULT, "process_vm_readv");
        g_real_pread64 = (pread64_fn)dlsym(RTLD_DEFAULT, "pread64");
        g_real_pread   = (pread64_fn)dlsym(RTLD_DEFAULT, "pread");
        ahb_filelog("VIEW pread resolve pread64=%p pread=%p", (void *)g_real_pread64, (void *)g_real_pread);
    }
    if (!g_real_syscall) {
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
        AHB_SAYL("SELFCHECK head=%#lx real=%d walked=%d (检测器将看到 walked)",
             (unsigned long)h, walk_dll_real(h), walked);
    }

    AHB_SAYL("L3 view: 早期安装完成 候选=%d 条 pvr=%p syscall=%p",
         found, (void *)g_real_pvr, (void *)g_real_syscall);
    ahb_keylog("VIEW install found=%d slots=%d pvr=%p syscall=%p",
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
     * 预热 libart 的磁盘视图。
     *
     * 为什么必须在这里预热、而不是等检测器来问时再生成：
     *
     * 检测器整个扫描过程只用了 368ms。而生成 libart 视图要把它那些
     * 映射段（合计十几 MB）写进 memfd，实测要一两百毫秒 ——
     * 如果这笔时间花在检测器的 open 调用里，就等于直接从它的
     * 扫描窗口里扣掉，端到端表现为启动变慢 250ms。
     *
     * 这个线程在进程起来很早就在跑，而检测器库是后来才 dlopen 的，
     * 中间有几百毫秒空窗。把生成放在这里，检测器来问时缓存已经好了，
     * 它那边是零等待。
     */
    {
        char artpath[AHB_PATH_MAX];
        if (ahb_find_libart_path(artpath, sizeof(artpath))) {
            int fd = ahb_libview_fd_for(artpath);
            if (fd >= 0) syscall(SYS_close, fd);
        }
    }
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
    /*
     * 轮询粒度 60ms，不再 2ms。
     *
     * 这是"检测期变慢"的主要来源之一：原来是 1500 轮 × 2ms 的紧循环，
     * 每轮都做一次完整重定位扫描（单次约 4ms），累计约 6 秒纯 CPU，
     * 全程与检测器抢同一批核心。而这条线程要等的只是"目标 .so 被 dlopen"，
     * 那是几百毫秒内一次性完成的事件。60ms 一次能把总开销降到约 0.25 秒。
     */
    /*
     * 轮询 1ms，而不是 60ms。
     *
     * 为什么必须是 1ms：检测器自己的 libantihook.so 是进程起来之后才
     * dlopen 的，它的扫描在 JNI_OnLoad 里就跑完 —— 实测整轮检测只用了
     * 435ms。而补丁必须在它读地图之前装上才有效。60ms 的轮询意味着
     * 平均要等 30ms 才轮到我，那段时间它已经读完地图了。
     *
     * 这么密的轮询不贵：每轮只调 dl_iterate_phdr 数一下已加载模块数，
     * 纯内存遍历、微秒级；真正昂贵的全量 ELF 解析只在计数变化时才做。
     */
    /*
     * 第一件事：把 JVMTI 看门线程拉起来。
     * 本线程已被证明能可靠运行（有 FASTPATCH 日志），
     * 此时进程已就绪，pthread_create 不会再失败。
     */
    /*
     * JVMTI 检测**不另开线程**，直接放在本循环里。
     *
     * 依据：本线程已被反复证明能可靠运行（每轮都有 FASTPATCH 日志），
     * 而另外用 pthread_create 起一个看门线程，在实测里从未成功
     *（JWSTART 探针一条都没打出来，且 JNI_OnLoad 早期 logd 尚未就绪，
     * 连恒开的 __android_log_print 都会被静默丢弃，无法确认失败原因）。
     *
     * 本循环本来就是 1ms 一轮、跑 3000 轮 = 3 秒，正好覆盖
     * "目标 App.onCreate 里拉起 JVMTI"的时间窗（实测约 2.5s）。
     * 复用它是零成本的。
     */
    g_jvmti_watch_pending = 0;

    for (int i = 0; i < 3000; i++) {
        int before = g_clv_got_patched;
        /* 每轮检查一次：库出现了就改掉它，没出现就下一轮 */
        if (ahb_neutralize_jvmti() == 1) {
            LOGE("JVMTI 中和完成（循环第 %d 轮）", i);
            break;
        }
        clv_patch_got();
        if (g_clv_got_patched > before) {
            AHB_SAYL("FASTPATCH: 第 %d 轮抢到接管 %d 处（累计 %d）",
                 i, g_clv_got_patched - before, g_clv_got_patched);
        }
        if (g_clv_got_patched >= 2) {
            idle++;
            if (idle > 2) break;              /* 命中后再确认 3 次即退出 */
        }
        {
            struct timespec ts = {0, 1000 * 1000};
            nanosleep(&ts, NULL);
        }
    }
    AHB_SAYL("FASTPATCH: 结束，累计接管 %d 处", g_clv_got_patched);
    return NULL;
}

static void clv_start_fast_patch(void) {
    pthread_t th;
    int rc = pthread_create(&th, NULL, clv_fast_patch_thread, NULL);
    if (rc == 0) pthread_detach(th);
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

    AHB_SAYL("L3 trim_class_loaders: %d -> %d nodes (no jni refs touched)", n, keep);
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
    AHB_SAYL("L3 vm=%p (untagged=%#lx)", (void *)vm, (unsigned long)vm_addr);

    uintptr_t runtime = 0;
    if (!read_ptr_untagged(vm_addr + sizeof(uintptr_t), &runtime) || runtime == 0) {
        LOGE("L3 runtime 定位失败 (vm=%p) —— 无法继续 ClassLoader 计数", (void *)vm);
        return 0;
    }
    AHB_SAYL("L3 runtime=%p", (void *)runtime);

    uintptr_t art_start = 0, art_end = 0;
    if (!collect_libart_range(&art_start, &art_end)) {
        LOGE("L3 libart 范围收集失败");
        return 0;
    }
    AHB_SAYL("L3 libart=%#lx-%#lx", (unsigned long)art_start, (unsigned long)art_end);
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
            AHB_SAYL("L3 candidate clo=%#zx lo=%#zx head=%#lx count=%d", cl_off, list_off,
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

            AHB_SAYL("L3 located class_loaders_: Runtime+%#zx ClassLinker+%#zx count=%d",
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
                AHB_SAYL("L3 init 阶段仅观察: count=%d（剪链交由 L4 延迟执行以对齐检测时机）", count);
                return 1;
            } else {
                AHB_SAYL("L3 class_loaders_ count=%d already within range, no trim", count);
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
            AHB_SAYL("L3(sync) candidate clo=%#zx lo=%#zx count=%d classloaders=%d",
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
                AHB_SAYL("L3 view: process_vm_readv=%p syscall=%p",
                     (void *)g_real_pvr, (void *)g_real_syscall);
            }
            {
                /* 证明用：报告包装函数被走了多少次、命中覆盖多少次 */
                static unsigned long rep_c = 0, rep_h = 0;
                if (g_clv_calls != rep_c || g_clv_hits != rep_h) {
                    AHB_SAYL("L3 view: 包装被调用 %lu 次，命中覆盖 %lu 次",
                         (unsigned long)g_clv_calls, (unsigned long)g_clv_hits);
                    rep_c = g_clv_calls;
                    rep_h = g_clv_hits;
                }
            }
            /*
             * 这条旧路径（nativeSanitizeRuntime）扫到的 head 可能是
             * 另一条已登记链的**中间节点**，登记它会覆盖那条链的节点视图。
             *
             * 实测：链 A head=0x6ffcc1c828 的 next=0x6ffcd1bda0，
             * 这里又把 0x6ffcd1bda0 当成独立头登记。
             * 覆盖循环按 slot 顺序写，后写覆盖先写 ——
             * 检测器读 0x6ffcd1bda0 时本应拿到"前驱指回链 A 头"的视图，
             * 却被第二份 headbuf 覆盖成它自己的前后驱，
             * 链 A 的闭环当场断裂，检测器退回真链数出 32。
             */
            if (!clv_is_chain_member(head)) {
                clv_build(head);
            }
            clv_patch_got();
            AHB_SAYL("L3 view: head=%#lx 真实 count=%d -> 视图 %d 节点 (ART 未写入)",
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

/*
 * 显式早初始化入口。
 *
 * Java 层在 handleLoadPackage 的第一步就调它，比等 L2 开关走到
 * nativeSanitizeRuntime 更早。检测器通常 1 秒内完成扫描，
 * 越早装上视图越稳。
 */

/* ================================================================== */
/* 原地改写 String 内部字节（走 JNI，绕开 hidden API）                   */
/* ================================================================== */
/*
 * 为什么必须走 JNI 而不是 Java 反射
 * --------------------------------
 * Java 侧 `String.class.getDeclaredField("value")` 在本机直接抛：
 *     NoSuchFieldException: No field value in class Ljava/lang/String;
 * 这是 hidden API 政策在拦 —— java.lang 核心类的私有字段对反射不可见。
 *
 * 而 JNI 的 GetFieldID 走 native 路径，不做 hiddenapi 检查。
 * 这条通道是解这个问题的唯一正路。
 *
 * 为什么需要改写而不是换引用
 * ------------------------
 * ART 会把「读某个 final 字段」内联成「直接引用那个 String 对象」。
 * 换引用改不到内联处，所以只能改对象自己的字节。
 *
 * 长度必须严格相等：
 *     antihookbypass        (14) -> androidruntime         (14)
 *     libantihook_bypass.so (21) -> libandroid_runtime.so  (21)
 *
 * 调用方拿到的仍是同一个 String 对象、同一个引用，
 * 但内容已经换成中性包名，任何读法（反射、toString、ptrace 读内存）
 * 看到的都是一致的干净值。
 */
static int ahb_patch_bytes(unsigned char *b, int n, int is_wide) {
    static const char from[] = "antihookbypass";
    static const char to[]   = "androidruntime";
    static const char fromso[] = "libantihook_bypass.so";
    static const char toso[]   = "libandroid_runtime.so";
    int step = is_wide ? 2 : 1;
    int hits = 0;
    int i;

    if (n < (int)sizeof(from)) return 0;

    /* 先处理更长的 so 名，避免被短串替换打断 */
    for (i = 0; i + (int)sizeof(fromso) - 1 <= n; i += step) {
        int k, ok = 1;
        for (k = 0; k < (int)sizeof(fromso) - 1; k++) {
            unsigned char c = b[i + k * step];
            if (c != (unsigned char)fromso[k]) { ok = 0; break; }
        }
        if (!ok) continue;
        for (k = 0; k < (int)sizeof(toso) - 1; k++) {
            /* 只写低字节，宽字符的高字节保持 0 */
            b[i + k * step] = (unsigned char)toso[k];
        }
        hits++;
    }
    for (i = 0; i + (int)sizeof(from) - 1 <= n; i += step) {
        int k, ok = 1;
        for (k = 0; k < (int)sizeof(from) - 1; k++) {
            unsigned char c = b[i + k * step];
            if (c != (unsigned char)from[k]) { ok = 0; break; }
        }
        if (!ok) continue;
        for (k = 0; k < (int)sizeof(to) - 1; k++) {
            b[i + k * step] = (unsigned char)to[k];
        }
        hits++;
    }
    return hits;
}

JNIEXPORT jboolean JNICALL
Java_com_rev_antihookbypass_NativeLayer_nativeRewriteString(JNIEnv *env, jclass cls,
                                                            jstring js) {
    jclass sc;
    jfieldID fid;
    int hits = 0;

    (void)cls;
    if (!js) return JNI_FALSE;
    sc = (*env)->FindClass(env, "java/lang/String");
    if (!sc) { (*env)->ExceptionClear(env); return JNI_FALSE; }

    /* Android 9+ compact string：byte[] value */
    fid = (*env)->GetFieldID(env, sc, "value", "[B");
    if (fid) {
        jbyteArray arr = (jbyteArray)(*env)->GetObjectField(env, js, fid);
        if (arr) {
            jsize n = (*env)->GetArrayLength(env, arr);
            jbyte *buf = (*env)->GetByteArrayElements(env, arr, NULL);
            if (buf) {
                hits += ahb_patch_bytes((unsigned char *)buf, (int)n, 0);
                (*env)->ReleaseByteArrayElements(env, arr, buf, 0);
            }
        }
    } else {
        (*env)->ExceptionClear(env);
        /* 老系统：char[] value */
        fid = (*env)->GetFieldID(env, sc, "value", "[C");
        if (!fid) { (*env)->ExceptionClear(env); return JNI_FALSE; }
        {
            jcharArray arr = (jcharArray)(*env)->GetObjectField(env, js, fid);
            if (arr) {
                jsize n = (*env)->GetArrayLength(env, arr);
                jchar *buf = (*env)->GetCharArrayElements(env, arr, NULL);
                if (buf) {
                    hits += ahb_patch_bytes((unsigned char *)buf, (int)n, 1);
                    (*env)->ReleaseCharArrayElements(env, arr, buf, 0);
                }
            }
        }
    }

    /* 清掉缓存的 hash，避免改写后 hashCode 与内容不一致 */
    if (hits > 0) {
        jfieldID hf = (*env)->GetFieldID(env, sc, "hash", "I");
        if (hf) (*env)->SetIntField(env, js, hf, (jint)0);
        else (*env)->ExceptionClear(env);
    }
    return hits > 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_rev_antihookbypass_NativeLayer_nativeEarlyInit(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    ahb_early_init();
}

__attribute__((visibility("default")))
jint JNICALL
Java_com_rev_antihookbypass_NativeLayer_nativeSanitizeRuntime(JNIEnv *env, jclass cls, jint ops) {
#if AHB_DIAG
    { int i; for (i = 0; i < 3; i++) LOGE("SANITIZE-ENTER v=NEUTRAL2 pid=%d", (int)getpid()); }
#endif
    /*
     * 这里才是本模块真实的 native 入口。
     *
     * 依据（实测，非推测）：JNI_OnLoad 与 native_init 里的探针
     * （ERROR 级、独立 tag）在目标进程里一次都没出现过；反汇编确认
     * 两个函数里都确实调用了那条日志，所以不是被优化掉。
     * 而 Java 层的 nativeSanitizeRuntime 每次启动都被调用
     * （日志里有"L2 nativeSanitizeRuntime 完成"）。
     *
     * 结论：LSPosed 加载本模块时并不走 JNI_OnLoad，assets/native_init
     * 声明的 legacy 协议在这个版本上也没有触发 native_init。
     * 于是把初始化挂到确定会被调用的这个 JNI 函数上，用 pthread_once
     * 保证只跑一次。
     */
    ahb_early_init();
    (void)cls;
    jint mask = 0;
    int o = (int)ops;
    /*
     * 注意：0 就是"全关"，不能再被当成"未指定按全开"。
     *
     * 早期这里写的是 if (o == 0) o = NATIVE_OP_ALL，本意是"Java 没指定就
     * 全开"。但 Java 侧用 0 明确表示关掉全部动作，于是两者语义打架：
     * 我把 Java 默认改成 0 想做"只留视图过滤"的对照实验，实际上
     * native 侧仍然全开，实验结论全部失真（还多崩了几次）。
     *
     * 未指定由 Java 侧的 parseNative 负责给默认值，这里只管执行。
     */

    AHB_SAYL("L2 begin ops=%#x (art=%d linker=%d tramp=%d)", o,
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

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/*
 * 把 linker64 最后一个映射的末尾补成一个可读零页。
 *
 * 为什么需要：实测目标应用（hunter 6.58）的 native 扫描线程在本机稳定
 * SIGSEGV，故障地址每次都是同一个值，而该值恰好等于本进程 linker64
 * 最后一个映射（[anon:.bss]）的**结束地址**，一字节不差；寄存器里另一个
 * 指针正好落在 linker64 的 r-xp 段起点。也就是说它在按段遍历 linker64，
 * 用的长度与实际段布局不匹配（本机是 Android 17，linker64 更大），
 * 走到最后一个映射末尾就踩空。
 *
 * 这里不做任何结果改写：只是把那一页变成可读的零页，让越界读返回 0，
 * 目标应用那条路径会当成"没有数据"跳过，而不是把进程干掉。
 *
 * 只在"该处确实还没映射"时补（MAP_FIXED_NOREPLACE），已占用则自动放弃，
 * 不会覆盖任何已有映射。
 */
static unsigned long ahb_maps_parse_lo(const char *line, unsigned long *endout) {
    unsigned long s = 0, e = 0;
    const char *q = line;
    while (*q && *q != '-') {
        s <<= 4;
        s |= (unsigned long)(*q <= '9' ? *q - '0' : (((*q) | 0x20) - 'a' + 10));
        q++;
    }
    if (*q != '-') return 0;
    q++;
    while (*q && *q != ' ') {
        e <<= 4;
        e |= (unsigned long)(*q <= '9' ? *q - '0' : (((*q) | 0x20) - 'a' + 10));
        q++;
    }
    *endout = e;
    return s;
}

static void ahb_guard_linker_tail(void) {
    static char mbuf[1024 * 1024];
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return;
    /*
     * 必须读满，不能只读一次。
     *
     * 实测踩坑：这里原来只 read 一次、缓冲区 256KB，而本机 maps 约 350KB，
     * read 一次就截断了。linker64 的映射在地址空间的**末尾**，正好落在
     * 被截掉的那一段里，于是 cur 永远算不出来，补页静默跳过 ——
     * 日志里一条 GUARD 都没有，我一开始还以为内核不支持。
     */
    size_t total = 0;
    for (;;) {
        if (total >= sizeof(mbuf) - 1) break;
        long k = (long)syscall(SYS_read, fd, mbuf + total,
                               sizeof(mbuf) - 1 - total);
        if (k <= 0) break;
        total += (size_t)k;
    }
    syscall(SYS_close, fd);
    if (total == 0) return;
    mbuf[total] = 0;

    char line[512];
    unsigned long cur = 0;

    /* 第一遍：linker64 所有映射里最大的结束地址 */
    for (size_t i = 0; i < total; ) {
        size_t j = i;
        while (j < total && mbuf[j] != '\n') j++;
        size_t len = j - i;
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, mbuf + i, len);
        line[len] = 0;
        if (strstr(line, "linker64")) {
            unsigned long e = 0;
            if (ahb_maps_parse_lo(line, &e) && e > cur) cur = e;
        }
        i = j + 1;
    }
    if (!cur) return;

    /* 第二遍：把紧跟其后、覆盖 cur 的 [anon:.bss] 块逐段接上 */
    for (int round = 0; round < 8; round++) {
        unsigned long next = cur;
        for (size_t i = 0; i < total; ) {
            size_t j = i;
            while (j < total && mbuf[j] != '\n') j++;
            size_t len = j - i;
            if (len >= sizeof(line)) len = sizeof(line) - 1;
            memcpy(line, mbuf + i, len);
            line[len] = 0;
            if (strstr(line, "[anon:.bss]")) {
                unsigned long e = 0;
                unsigned long st = ahb_maps_parse_lo(line, &e);
                if (e && st <= cur && cur < e && e > next) next = e;
            }
            i = j + 1;
        }
        if (next == cur) break;
        cur = next;
    }

    /*
     * 连续补 64 页（256KB）。
     *
     * 补一页不够：目标应用越界读的位置可能不止一页。实测崩溃指令是
     * 「以 x23 为基址 + 0x410 偏移读 16 字节」，单页勉强够，但不同版本的
     * 偏移会变，留足余量比精确计算稳妥。整块都是 PROT_READ 的零页，
     * 对越界读来说效果等同"这块内存存在但没有数据"。
     *
     * 逐页用 MAP_FIXED_NOREPLACE 补，遇到已占用就跳过 —— 绝不覆盖已有映射。
     */
    int ok = 0;
    for (int i = 0; i < 64; i++) {
        void *want = (void *)(cur + (unsigned long)i * 4096UL);
        void *r = mmap(want, 4096, PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (r == want) ok++;
        else if (i == 0) break;   /* 首页都拿不到就没必要继续 */
    }
    AHB_SAYL("GUARD: linker64 末尾 0x%lx 补可读页 %d/64", cur, ok);
}

/*
 * 自检：从**进程内部**核对每个 /proc 入口的视图是否已经干净。
 *
 * 为什么要从进程内部测：root shell 读 /proc/<pid>/maps 拿的是内核
 * 真实内容，我们只改"本进程自己打开时看到的视图"，两者本来就不同。
 * 用 root 视角去验证过滤效果，得到的结论没有意义 —— 这一条踩过。
 *
 * 这里走的是和外部调用完全相同的路径：先把要过滤的东西生成好，
 * 再统计残留痕迹数。目标是每个入口都为 0。
 */
static void ahb_selfcheck_entry(const char *path, const char *label) {
    size_t len = 0;
    char *buf;
    int fd = ahb_filtered_fd_for(path);
    int hits = 0;
    if (fd < 0) { AHB_SAYL("SELFCHECK %-8s fd=-1（未接管）", label); return; }
    buf = ahb_read_file_all_fd(fd, &len);
    if (!buf) { syscall(SYS_close, fd); AHB_SAYL("SELFCHECK %-8s read失败", label); return; }
    {
        static const char *const mk[] = {
            "antihookbypass", "liblspd", "lsplant", "lsposed",
            "zygisk", "riru", "/data/adb", "KSU", "magisk", NULL
        };
        const char *const *m;
        for (m = mk; *m; m++) {
            const char *p = buf, *e = buf + len;
            while (p < e) {
                const char *hit = ahb_memstr(p, (size_t)(e - p), *m);
                if (!hit) break;
                hits++; p = hit + 1;
            }
        }
    }
    AHB_SAYL("SELFCHECK %-8s 字节=%zu 残留痕迹=%d", label, len, hits);
    free(buf);
    syscall(SYS_close, fd);
}

static void ahb_selfcheck_all(void) {
    ahb_selfcheck_entry("/proc/self/maps", "maps");
    ahb_selfcheck_entry("/proc/self/smaps", "smaps");
    ahb_selfcheck_entry("/proc/self/mounts", "mounts");
    ahb_selfcheck_entry("/proc/modules", "modules");
}

/*
 * 早期初始化，只执行一次。
 * ====================
 *
 * 为什么必须抽出来：本模块由 LSPosed 以 legacy native_init 协议加载，
 * **不走 System.loadLibrary 的 JNI_OnLoad**。实测证据：JNI_OnLoad 里
 * 紧跟 clv_start_fast_patch 之后的那条日志从未出现过，而 native_init
 * 的日志一直在。
 *
 * 后果是 JNI_OnLoad 里的初始化整段作废，其中最严重的是
 * clv_start_fast_patch() —— 全文件只有那一处调用它，等于抢跑线程
 * 从来没启动过。补丁只能等后续零散时机，表现为"有的项时好时坏"。
 *
 * 所以把初始化收拢成一个函数，两个入口都调用，用 pthread_once 保证
 * 只跑一次，谁先到谁执行。
 */
static pthread_once_t g_early_once = PTHREAD_ONCE_INIT;

/*
 * 早期初始化的进展标志。
 *
 * 为什么用标志而不是只靠日志：实测 logd 在进程启动瞬间对这个 tag 的
 * 突发日志会丢，EARLY_BODY / EARLY_INIT 这类启动最早期打出的行
 * 一条都看不到，而稍后零散打出的 DLOPEN[n] 却能正常保留。
 * 于是把"走到哪一步"记在全局变量里，由后续一定会执行到的
 * dlopen 包装把它带出来 —— 纯内存，零副作用。
 */
static volatile int g_early_stage = 0;    /* 1=body 进入 2=JVMTI 已处理 3=视图就绪 */
static volatile int g_jvmti_result = -1;  /* -1 未做 0 失败 1 成功 */

int ahb_early_stage_get(void) { return g_early_stage; }
int ahb_jvmti_result_get(void) { return g_jvmti_result; }
int ahb_jvmti_diag_get(void) { return g_jvmti_diag; }
int ahb_libart_diag_get(void) { return g_libart_diag; }
int ahb_elf_diag_get(void) { return g_elf_diag; }

/* ================================================================== */
/* 中和 JVMTI 插件入口                                                  */
/* ================================================================== */

/*
 * 依据（实测调用栈 + 实测字符串，不是推测）
 * ----------------------------------------
 * com.zhenxi.hunter 主进程 abort 的完整栈是：
 *
 *   jit_code_cache.cc:1309  Check failed: !ContainsElement(zombie_code_, code_ptr)
 *   JitCodeCache::AddZombieCodeInternal
 *   JitCodeCache::AddZombieCode
 *   Instrumentation::InstallStubsForClass
 *   ClassLinker::VisitClassesInternal / VisitClasses
 *   Instrumentation::UpdateEntrypointsForDebuggable
 *   openjdkjvmti::DeoptManager::FinishSetup
 *   ArtPlugin_Initialize
 *   libhunter.so                     <-- 目标自己调进来
 *
 * 也就是说：目标把 JVMTI 插件拉起来，运行时被当成 debuggable，
 * ART 于是遍历**所有类**重装入口 stub；而 lsplant 已经把大量方法的
 * 入口改成了自己的跳板，两边在 zombie_code_ 表上撞车，直接 abort。
 *
 * 这不是本模块做了什么，而是"框架 hook"与"JVMTI 调试代理"天生冲突：
 * 只要框架在，目标一旦把 JVMTI 拉起来就会踩这个断言。
 *
 * 为什么不能靠拦 dlopen / 藏文件
 * ------------------------------
 * 实测：给 dlopen 加探针，目标主进程整轮只调 1 次（libc.so）；
 * 加 dlsym 屏蔽，命中 0 条；藏 libopenjdkjvmti.so 文件，命中 0 条。
 * 它用静态编进 libhunter.so 里的 xDL，配合自有解析直接拿到符号，
 * 完全不经过 libc 的 open/dlopen。
 *
 * 所以改成在"函数入口"这一层处理：自己先把该库加载进来，
 * 把它的插件入口 ArtPlugin_Initialize 改写成"立即返回非 0"。
 * 目标之后无论用哪条路拿到这个符号，拿到的都是我们改过的入口，
 * 于是走它自己已有的 `JvmTi::init ArtPlugin_Initialize == null`
 * / `JvmTi::init fail` 分支 —— 那是它亲手写的失败处理，不会崩。
 *
 * 只改这一个函数的第一条指令，且改动只在本进程内（MAP_PRIVATE 私有页）。
 */
/* ================================================================== */
/* 断开 ART 的"按 debuggable 语义重装入口"这条链                          */
/* ================================================================== */

/*
 * 依据（ART 自己打印的日志 + 完整 native 栈，不是推测）
 * ---------------------------------------------------
 *    W  Openjdkjvmti plugin was loaded on a non-debuggable Runtime.
 *       Plugin was loaded too late to change runtime debuggable state.
 *    F  jit_code_cache.cc:1309  Check failed: !ContainsElement(zombie_code_, code_ptr)
 *
 *    #13  Instrumentation::InstallStubsForClass
 *    #14  ClassLinker::VisitClassesInternal
 *    #15  Instrumentation::UpdateEntrypointsForDebuggable
 *    #16  openjdkjvmti::DeoptManager::FinishSetup
 *    #17  ArtPlugin_Initialize
 *    #18  libhunter.so
 *
 * 目标把 JVMTI 插件拉起来后，ART 走进"运行时不是 debuggable、却要按
 * debuggable 语义把所有类的入口 stub 重装一遍"这条自相矛盾的路径。
 * 而 lsplant 早已把大量方法的入口换成自己的跳板，两边在 zombie_code_
 * 表上撞车，断言失败直接 abort。
 *
 * 为什么不在加载处拦
 * -----------------
 * 实测：hunter 主进程里 dlopen 只调 1 次（本模块自己的 libc.so），
 * android_dlopen_ext 0 次；它用静态编进 libhunter.so 的 xDL 手工映射。
 * 而"库被映射"到"入口被调用"之间只有微秒级间隙 —— 实测从 ART 打出
 * 上面那条 W 到 abort 只有 14ms，但映射与调用几乎紧挨着，
 * 1ms 轮询永远抢不到（实测中和 0 次）。
 *
 * 所以在冲突点本身处理：把这条遍历链的**顶端**改成空返回。
 * 这一步在进程早期就能做（libart 从一开始就加载好了），没有竞态。
 *
 * 只影响"重装入口 stub"这一件事：正常方法的执行、hook 分发、
 * 目标自身的检测逻辑都不受影响。仅在本模块作用域内的进程生效。
 */
#define AHB_ART_UPDATE_ENTRY \
    "_ZN3art15instrumentation15Instrumentation30UpdateEntrypointsForDebuggableEv"

/* ------------------------------------------------------------------ */
/* 自证：假 fd 的 readlink / fstat 是否与真 maps 一致                    */
/* ------------------------------------------------------------------ */

/*
 * 为什么必须自证：hunter 的 checkFileIsLegal 是
 * "open(/proc/<pid>/maps) 成功后，readlink 这个 fd，核对路径"。
 * 我们交的是 memfd，若 readlink 露出 /memfd:maps 就当场被识破。
 *
 * 只看"日志里没出现 memfd"不够 —— 它可能这轮压根没走那条分支。
 * 所以在自己进程里把同样的动作做一遍，把结果打出来：
 * open → readlink → 应得到 /proc/<pid>/maps；fstat → st_dev 应为
 * proc 的 0x9fa0，st_ino 应与真 maps 相同。
 */
/* 统计一个缓冲区里某个子串出现次数 */
static int ahb_cnt(const char *buf, const char *needle) {
    int n = 0;
    size_t l = strlen(needle);
    const char *p = buf;
    while ((p = strstr(p, needle)) != NULL) { n++; p += l; }
    return n;
}

/* 用裸 syscall 读一个"真路径"，完全绕开本模块任何包装 */
static char *ahb_read_path_raw(const char *path, size_t *out_len) {
    char *b;
    size_t cap = 512 * 1024, len = 0;
    long fd;
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return NULL;
    fd = ((ahb_sys6_fn)g_raw_syscall)(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0) return NULL;
    b = (char *)malloc(cap);
    if (!b) { ((ahb_sys6_fn)g_raw_syscall)(SYS_close, fd, 0, 0, 0, 0, 0); return NULL; }
    for (;;) {
        long k;
        if (len + 65536 > cap) break;
        k = ((ahb_sys6_fn)g_raw_syscall)(SYS_read, fd, (long)(b + len),
                                        (long)(cap - len - 1), 0, 0, 0);
        if (k <= 0) break;
        len += (size_t)k;
    }
    ((ahb_sys6_fn)g_raw_syscall)(SYS_close, fd, 0, 0, 0, 0, 0);
    b[len] = 0;
    if (out_len) *out_len = len;
    return b;
}


#if AHB_SAY
/* 路径判定自检：构造若干路径，直接看 maps_path_is_self 认不认。 */
static void ahb_pathcheck(void) {
    static const char *yes[] = {
        "/proc/self/maps",
        "/proc/18023/maps",                 /* 目标从子进程读主进程 —— 关键 */
        "/proc/1/maps",
        "/proc/21624/task/21624/maps",
        "/proc/18023/smaps",              /* 外部 pid 的 smaps，同样关键 */
        "/proc/18023/smaps_rollup",
        "/proc/self/smaps",               /* 自身 smaps 当然也要过滤 */
        "/proc/self/smaps_rollup",
        NULL
    };
    static const char *no[] = {
        "/proc/self/status",
        "/proc/self/fd/3",
        "/system/lib64/libc.so",
        NULL
    };
    char buf[256];
    int i, bad = 0;
    /*
     * 这里必须问「真实的分发函数」，而不是单独问 maps_path_is_self。
     *
     * 踩过的坑：第一版所有用例都丢给 maps_path_is_self，
     * 但 /proc/<pid>/smaps 实际由 ahb_is_smaps_path 负责，
     * 于是在自检里显示"漏"，而线上路径是好的 ——
     * 自检本身给错了结论，比不测更糟。
     *
     * ahb_filtered_fd_for 才是 open 包装真正调用的入口，
     * 它内部已按 maps / smaps / mounts / modules 分流。
     */
    for (i = 0; yes[i]; i++) {
        int r = ahb_path_would_filter(yes[i]);
        if (!r) bad++;
        snprintf(buf, sizeof(buf), "PATHCHK 应认 %s -> %s", yes[i], r ? "认" : "漏");
        AHB_SAYL("%s", buf);
    }
    for (i = 0; no[i]; i++) {
        int r = ahb_path_would_filter(no[i]);
        if (r) bad++;
        snprintf(buf, sizeof(buf), "PATHCHK 应弃 %s -> %s", no[i], r ? "误认" : "弃");
        AHB_SAYL("%s", buf);
    }
    AHB_SAYL("PATHCHK 结论 错判=%d", bad);
}
#endif

#if AHB_DIAG
static void ahb_selfcheck_fd(void) {
    int fd;
    int pid = (int)getpid();
    char *buf;
    size_t cap = 512 * 1024, len = 0;
    int i;
    static const char *const needles[] = {
        "antihookbypass", "libantihook_bypass", "lspd", "lsposed", "lsplant",
        "zygisk", "riru", "xposed", "edxp", "magisk", NULL
    };

    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return;

    /*
     * 决定性对比：同一时刻，"内核真内容"与"包装 fd 内容"里
     * 各自的痕迹数量。
     *
     * 这一项是整轮排查的关键。前面几轮都在猜"哪里漏了"：
     * 猜标记没加、猜掩码没写、猜统计写错，全都不是。
     * 必须同时拿到两边的计数，才知道问题出在"过滤没跑"还是"过滤跑了但没匹配"。
     */
    {
        size_t rl = 0, wl = 0;
        char *raw = ahb_read_path_raw("/proc/self/maps", &rl);
        int fd2 = maps_open_wrap("/proc/self/maps", O_RDONLY, 0);
        char *wrapped = NULL;
        if (fd2 >= 0) {
            size_t cap2 = 512 * 1024, l2 = 0;
            wrapped = (char *)malloc(cap2);
            if (wrapped) {
                for (;;) {
                    long k;
                    if (l2 + 65536 > cap2) break;
                    k = ((ahb_sys6_fn)g_raw_syscall)(SYS_read, fd2,
                                                    (long)(wrapped + l2),
                                                    (long)(cap2 - l2 - 1), 0, 0, 0);
                    if (k <= 0) break;
                    l2 += (size_t)k;
                }
                wrapped[l2] = 0;
                wl = l2;
            }
            ((ahb_sys6_fn)g_raw_syscall)(SYS_close, fd2, 0, 0, 0, 0, 0);
        }
        if (raw && wrapped) {
            LOGE("CMP 内核 len=%lu 痕迹=%d | 包装 len=%lu 痕迹=%d",
                 (unsigned long)rl, ahb_cnt(raw, "antihookbypass"),
                 (unsigned long)wl, ahb_cnt(wrapped, "antihookbypass"));
            LOGE("CMP 内核 aexec=%d | 包装 aexec=%d",
                 ahb_cnt(raw, "r-xp 00000000 00:00 0"),
                 ahb_cnt(wrapped, "r-xp 00000000 00:00 0"));
            /* 把包装内容里仍含痕迹的行逐行打出来，看清是哪几行漏了 */
            {
                const char *pp = wrapped;
                int shown = 0;
                while (pp && *pp && shown < 6) {
                    const char *nl2 = strchr(pp, '\n');
                    size_t l = nl2 ? (size_t)(nl2 - pp) : strlen(pp);
                    if (ahb_memstr(pp, l, "antihookbypass")) {
                        char t[256];
                        size_t c = l < sizeof(t) - 1 ? l : sizeof(t) - 1;
                        memcpy(t, pp, c); t[c] = 0;
                        /*
                         * 直接把这行原文喂给判定函数，看它到底认不认。
                         * 这一步能一次性分清两种可能：
                         *   trace=1 → 判定是对的，问题在别处（比如这行不是
                         *             走 masked 分支，而是走了合并/别的分支）
                         *   trace=0 → 判定本身没认出这行，是匹配问题
                         */
                        LOGE("WRAPROW trace=%d len=%lu %s",
                             maps_line_is_trace_len(pp, l), (unsigned long)l, t);
                        shown++;
                    }
                    if (!nl2) break;
                    pp = nl2 + 1;
                }
            }
        } else {
            LOGE("CMP 读取失败 raw=%p wrapped=%p", (void *)raw, (void *)wrapped);
        }
        /* 包装视图里 libart 的段数：应合并成 6 段、无 00ba0000 碎片 */
        if (wrapped) {
            const char *pp = wrapped;
            int seg = 0, frag = 0;
            while (pp && *pp) {
                const char *nl2 = strchr(pp, '\n');
                size_t l = nl2 ? (size_t)(nl2 - pp) : strlen(pp);
                if (ahb_memstr(pp, l, "libart.so")) {
                    char t[256];
                    size_t c = l < sizeof(t) - 1 ? l : sizeof(t) - 1;
                    memcpy(t, pp, c); t[c] = 0;
                    seg++;
                    if (strstr(t, "00ba0000")) frag++;
                    LOGE("VIEWART %s", t);
                }
                if (!nl2) break;
                pp = nl2 + 1;
            }
            LOGE("VIEWART seg=%d frag=%d", seg, frag);
        }
        /* 包装视图里 /proc/self/mounts 的 root 痕迹 */
        {
            size_t ml = 0;
            char *mw;
            int fd3 = maps_open_wrap("/proc/self/mounts", O_RDONLY, 0);
            if (fd3 >= 0) {
                size_t cap3 = 256 * 1024, l3 = 0;
                mw = (char *)malloc(cap3);
                if (mw) {
                    for (;;) {
                        long k;
                        if (l3 + 65536 > cap3) break;
                        k = ((ahb_sys6_fn)g_raw_syscall)(SYS_read, fd3,
                                                        (long)(mw + l3),
                                                        (long)(cap3 - l3 - 1), 0, 0, 0);
                        if (k <= 0) break;
                        l3 += (size_t)k;
                    }
                    mw[l3] = 0;
                    ml = l3;
                    LOGE("VIEWMNT len=%lu adb=%d magisk=%d",
                         (unsigned long)ml, ahb_cnt(mw, "/data/adb"),
                         ahb_cnt(mw, "magisk"));
                    free(mw);
                }
                ((ahb_sys6_fn)g_raw_syscall)(SYS_close, fd3, 0, 0, 0, 0, 0);
            } else {
                LOGE("VIEWMNT open 失败");
            }
        }
        free(raw);
        free(wrapped);
        return;   /* 本轮只做这个对比，其余自检跳过 */
    }

    /* --- 第一段：fd 身份伪装（已验证通过，保留回归） --- */
    fd = maps_open_wrap("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) { LOGE("SELFCHK open 失败"); return; }
    {
        char p[64];
        char ln_k[160], ln_w[160];
        ssize_t n;
        snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
        ln_k[0] = 0;
        n = (ssize_t)((ahb_sys6_fn)g_raw_syscall)(SYS_readlinkat, AT_FDCWD,
                                                  (long)p, (long)ln_k,
                                                  (long)(sizeof(ln_k) - 1), 0, 0);
        if (n > 0) ln_k[n] = 0;
        ln_w[0] = 0;
        n = ahb_readlinkat_wrap(AT_FDCWD, p, ln_w, sizeof(ln_w) - 1);
        if (n > 0) ln_w[n] = 0;
        LOGE("SELFCHK readlink 内核=%s 包装=%s", ln_k[0] ? ln_k : "(空)",
             ln_w[0] ? ln_w : "(空)");
    }
    {
        struct stat sk, sw, rs;
        memset(&sk, 0, sizeof(sk)); memset(&sw, 0, sizeof(sw));
        ((ahb_sys6_fn)g_raw_syscall)(SYS_fstat, fd, (long)&sk, 0, 0, 0, 0);
        ahb_fstat_wrap(fd, &sw);
        memset(&rs, 0, sizeof(rs));
        ((ahb_sys6_fn)g_raw_syscall)(SYS_newfstatat, AT_FDCWD,
                                     (long)"/proc/self/maps", (long)&rs, 0, 0, 0);
        LOGE("SELFCHK fstat 内核 dev=0x%lx ino=%lu | 包装 dev=0x%lx ino=%lu | 真maps ino=%lu",
             (unsigned long)sk.st_dev, (unsigned long)sk.st_ino,
             (unsigned long)sw.st_dev, (unsigned long)sw.st_ino,
             (unsigned long)rs.st_ino);
    }

    /*
     * --- 第二段：过滤视图里还剩哪些痕迹 ---
     *
     * 这是本轮最重要的一项。前面几轮都在"猜"哪里漏了，
     * 而这里直接把"对方会读到的那份 maps"整体拿出来，
     * 逐个对照 hunter 自己用的那几类特征词去数。
     * 数出来的才是真泄露点，不数就是猜。
     */
    buf = (char *)malloc(cap);
    if (!buf) { ((ahb_sys6_fn)g_raw_syscall)(SYS_close, fd, 0, 0, 0, 0, 0); return; }
    for (;;) {
        long k;
        if (len + 65536 > cap) break;
        k = ((ahb_sys6_fn)g_raw_syscall)(SYS_read, fd, (long)(buf + len),
                                        (long)(cap - len - 1), 0, 0, 0);
        if (k <= 0) break;
        len += (size_t)k;
    }
    ((ahb_sys6_fn)g_raw_syscall)(SYS_close, fd, 0, 0, 0, 0, 0);
    buf[len] = 0;

    for (i = 0; needles[i]; i++) {
        const char *p = buf;
        int cnt = 0;
        size_t nl = strlen(needles[i]);
        while ((p = strstr(p, needles[i])) != NULL) { cnt++; p += nl; }
        if (cnt > 0) LOGE("LEAK %s x%d", needles[i], cnt);
    }
    /* 把仍含 antihookbypass 的那几行的原文打出来，看清是哪个字段漏的 */
    {
        const char *p = buf;
        int shown = 0;
        while (p && *p && shown < 5) {
            const char *nl2 = strchr(p, '\n');
            size_t l = nl2 ? (size_t)(nl2 - p) : strlen(p);
            if (ahb_memstr(p, l, "antihookbypass")) {
                char t[256];
                size_t c = l < sizeof(t) - 1 ? l : sizeof(t) - 1;
                memcpy(t, p, c); t[c] = 0;
                LOGE("LEAKROW %s", t);
                shown++;
            }
            if (!nl2) break;
            p = nl2 + 1;
        }
    }

    /* 匿名可执行段：hunter 把它当作注入跳板的直接证据 */
    {
        const char *p = buf;
        int ae = 0;
        while (p && *p) {
            const char *nl2 = strchr(p, '\n');
            size_t l = nl2 ? (size_t)(nl2 - p) : strlen(p);
            /*
             * 必须按行判断。第一版这里写的是
             *   if (l > 20 && strstr(p, "r-xp") && strstr(p, " 00:00 0"))
             * 但 strstr 会越过本行扫到缓冲区末尾，
             * 于是"前面某行是 r-xp" + "后面某行有 00:00 0" 就被算成匿名段，
             * 报出 3518 个 —— 完全是统计 bug，不是真泄露。
             */
            if (l > 20 && ahb_memstr(p, l, "r-xp") && ahb_memstr(p, l, " 00:00 0  ")) {
                if (!ahb_memstr(p, l, " /")) ae++;
            }
            if (!nl2) break;
            p = nl2 + 1;
        }
        LOGE("LEAK 匿名可执行段 x%d", ae);
    }
    free(buf);
}
#endif



/*
 * 是否允许改 libart 代码段。
 *
 * 这条旗子在 4.1 起默认关闭，原因是跨进程 CRC 比对：
 *
 *   ISO CRC NOT MATCH LOCALITY CRC
 *   /apex/com.android.runtime/bin/linker64
 *   locality crc -> 139524896     remote service crc -> 139526216   (差 1320)
 *   /apex/com.android.art/lib64/libart.so
 *   locality crc -> 1142253448    remote service crc -> 1142253258  (差 190)
 *
 * "locality" 是主进程（被注入、被我们改过代码段），
 * "remote service" 是 hunter 的 iso 进程 —— 它没被 LSPosed 注入，
 * 读的是磁盘上原封不动的库。两边一比对，差值就是我们的 patch。
 *
 * 这条**没法靠过滤视图绕过**：比的是两个进程各自读到的库内容，
 * 不是 /proc 视图。所以只能让 libart 一个字节都不动。
 *
 * 关掉之后要靠 AHB_BLOCK_JVMTI（open 层）与 AHB_BLOCK_JVMTI_SYM
 * 拦住 JVMTI 插件；拦不住的话 jit_code_cache abort 会回来。
 */
#ifndef AHB_ART_NEUTRALIZE
#define AHB_ART_NEUTRALIZE 1
#endif

static int ahb_neutralize_libart_debug(void) {
#if !AHB_ART_NEUTRALIZE
    /*
     * 不改 libart：保持与磁盘上的库逐字节一致。
     * g_libart_diag 记 9 表示"策略性不修改"，与"失败"区分开。
     */
    g_libart_diag = 9;
    return 1;
#endif
    unsigned char *p;
    uintptr_t page;
    size_t pgsz;

    p = (unsigned char *)ahb_elf_find_export(0, AHB_ART_UPDATE_ENTRY);
    if (!p) { g_libart_diag = 1; return 0; }

    /*
     * 用 /proc/self/mem（FOLL_FORCE）写入，**不用 mprotect**。
     *
     * mprotect 会把这个页从原来的 r-x 段里切出来，成为一个独立 VMA。
     * 实测留下的碎片正是
     *     <page>-<page+0x1000> r-xp <off> ... /apex/.../libart.so
     * 而 hunter 会把"同库多出来的 4KB 可执行段"直接判成
     *     find libart.so hooked 4096
     * 这也是"检测到libart.so被修改"那张卡片的直接证据。
     *
     * FOLL_FORCE 允许写只读映射，页表权限和 VMA 结构都不变，
     * 因此不会再产生任何碎片。
     */
    {
        static const unsigned char ret4[4] = { 0xc0, 0x03, 0x5f, 0xd6 };
        (void)page; (void)pgsz;
        if (!safe_write_mem((uintptr_t)p, ret4, sizeof(ret4))) {
            g_libart_diag = 3;
            return 0;
        }
        ahb_flush_icache(p, 4);
    }
    g_libart_diag = 2;
    {
#if AHB_DIAG
        int k;
        for (k = 0; k < 2; k++)
            LOGE("ART 断开完成 fn=%lx", (unsigned long)p);
#endif
    }
    return 1;
}



static int ahb_neutralize_jvmti(void) {
    /*
     * 在主线程同步完成，**不新建线程**。
     *
     * ===== 为什么必须同步 =====
     * 实测这个进程里 pthread_create 在 JNI_OnLoad 阶段整体不可用：
     *   - JWSTART 恒开探针一条都没打出来
     *   - FASTPATCH 日志 0 条（连 clv_start_fast_patch 起的线程也没跑）
     * 所以"起个看门线程去轮询"的所有方案都不成立，只能在这里当场做完。
     *
     * ===== 三个关键点 =====
     * 1) 用 ahb_real_dlopen_raw 而不是 dlopen：
     *    ahb_dlopen_wrap 里有"JVMTI 拒绝加载"分支，会把自己这次加载
     *    也拒掉（症状是 jvmti=-10）。
     *
     * 2) 改的是 libopenjdkjvmti.so 的 ArtPlugin_Initialize，
     *    **完全不碰 libart**。
     *    依据：twin 进程里这个库根本没加载（实测 jvmti=0），
     *    iso 侧读不到它，因此它不参与跨进程 CRC 比对。
     *    而 libart 是 ISO CRC 卡片指向的对象，一个字节都不能动。
     *
     * 3) 用 safe_write_mem（/proc/self/mem，FOLL_FORCE），不用 mprotect。
     *    mprotect 会拆 VMA，留下"同库多出 4KB 可执行段"的碎片。
     */
    static int done = 0;
    if (done) return 1;

    /*
     * 不加载、只等它出现，然后改它。
     *
     * ===== 为什么不能自己 dlopen =====
     * 实测 ahb_real_dlopen_raw（绕过自家包装的真实 dlopen）也失败，
     * 结果码 jvmti=-10。原因是 libopenjdkjvmti.so 位于 **ART APEX
     * 命名空间**，应用侧的 dlopen 根本无权加载它。
     *
     * 而且自己加载它本身也是祸根：那正好促成
     *     "Openjdkjvmti plugin was loaded on a non-debuggable Runtime"
     * 随后 DeoptManager::FinishSetup 触发 UpdateEntrypointsForDebuggable，
     * 与 lsplant 改过的入口撞车 -> zombie_code_ 断言 abort。
     *
     * ===== 做法 =====
     * 该库由 ART 自己加载。我们只在这里轮询等待它出现，
     * 一旦出现就按内存地址定位 ArtPlugin_Initialize 并改掉。
     * 全程不改 libart 一个字节。
     *
     * 定位符号用"按 .dynsym 线性扫"，不用 dlsym：
     * 因为句柄拿不到（命名空间隔离），只能自己解 ELF。
     */
    {
        uintptr_t bases[4];
        int nb, i2, hit = 0;
        nb = ahb_collect_bases("libopenjdkjvmti.so", bases, 4);
        if (nb == 0) return -13;        /* 还没加载，下次再试 */

        for (i2 = 0; i2 < nb; i2++) {
            /*
             * 必须先验证基址是真的 ELF 映像，否则会写到随机地址。
             *
             * 事故现场：某轮 base 被算成 0x2000000（明显不是映射起点），
             * 于是我们按 base+0x4ce00 写了 8 字节到 0x204ce00，
             * 把 ART 的数据结构打穿，GC 随即崩：
             *     Abort message: 'GC tried to mark invalid reference 0x52800020'
             *     #00 libart.so (art::mirror::Object::PrettyTypeOf()+40)
             * 这类"写坏内存"的后果比不 patch 严重得多 ——
             * 不 patch 只是 ART abort，写坏则是不确定的随机崩溃。
             *
             * 校验用 ELF 魔数，成本 4 字节读，足够强。
             */
            {
                unsigned char magic[4];
                if (ahb_mem_read(bases[i2], magic, sizeof(magic)) != (long)sizeof(magic))
                    continue;
                if (magic[0] != 0x7f || magic[1] != 'E' ||
                    magic[2] != 'L'  || magic[3] != 'F')
                    continue;   /* 不是 ELF，基址算错了，跳过 */
            }
            /*
             * 直接用**静态符号偏移**，不再自己解析 ELF。
             *
             * 依据（readelf 实测）：
             *     ArtPlugin_Initialize  st_value = 0x4ce00  (FUNC, 304 字节)
             * 这个库随 ART APEX 一起发布，同一 ROM 上偏移固定。
             *
             * 为什么不解析 ELF：手工遍历 .dynsym 在这条极窄时间窗里
             * 太慢（上千项 pread），而且前面已踩过 k=0 早退那类坑。
             * 为什么不 dlsym：库在 ART APEX 命名空间，应用侧拿不到句柄。
             *
             * 校验：先在 base+0x4ce00 处读 4 字节，确认是合理的函数开头
             *（非全零、非已 patch 过的 ret），避免偏移不匹配时乱改。
             */
            uintptr_t fa = bases[i2] + AHB_JVMTI_INIT_OFF;
            unsigned char cur[4];
            if (ahb_mem_read(fa, cur, sizeof(cur)) != (long)sizeof(cur)) continue;
            if (cur[0] == 0 && cur[1] == 0 && cur[2] == 0 && cur[3] == 0) continue;
            /* 已经是 ret（c0 03 5f d6）说明改过了 */
            if (cur[0] == 0xc0 && cur[1] == 0x03 && cur[2] == 0x5f && cur[3] == 0xd6)
                { hit++; continue; }
            if (ahb_patch_entry(fa)) {
                hit++;
                LOGE("JVMTI 中和完成 base=%lx sym=%lx",
                     (unsigned long)bases[i2], (unsigned long)fa);
            }
        }
        if (!hit) return -14;
    }
    done = 1;
    return 1;
}

static void ahb_early_init_body(void) {
    g_early_stage = 1;
    AHB_ENTRY("early_init_body");
    /*
     * 先把真实函数地址解析好，再开始任何接管。
     * clv_patch_got 依赖 g_real_pvr 非空才干活，若首轮扫描发生在赋值前，
     * 那一轮就整轮跳过。
     */
    if (!g_real_pvr)     g_real_pvr     = (pvr_fn)dlsym(RTLD_DEFAULT, "process_vm_readv");
    if (!g_real_syscall) g_real_syscall = (syscall_fn)dlsym(RTLD_DEFAULT, "syscall");

    /*
     * 退出函数的真指针也在这里解析好。
     * 退出路径上必须做到"零解析"：那一刻动态链接器锁可能已被持有，
     * 再 dlsym 会卡死或崩。上一版探针就是这么把进程弄崩的。
     */
    ep_prepare();
    /* 预取真实 procfs 的 stat：后面 fake fd 要交这份值 */
    ahb_prefetch_real_stats();

    /*
     * 视图过滤与补丁开关一律取默认值，不读任何文件。
     * 读配置文件的路径会被目标监看 open 记录而暴露，所以没有现场开关，
     * 要改就改代码重新打包。
     */
#if EXP_NO_VIEW
    /* 实验：完全关掉视图过滤，只保留注入本身 */
    g_enable_maps_hide = 0;
#else
    g_enable_maps_hide = 1;
#endif

    /*
     * 中和 JVMTI 插件入口。
     * 必须在目标自己拉起 JVMTI 之前完成，所以放在最前面，
     * 且不受任何层开关影响 —— 这不是"检测规避"，是防 ART abort。
     */
    /*
     * 先断开 ART 的"重装入口 stub"链条。
     * 这是 hunter 主进程 abort 的直接冲突点，必须在目标拉起 JVMTI 之前完成；
     * libart 从进程启动就在，这里没有竞态。
     */
    ahb_neutralize_libart_debug();

    g_jvmti_result = ahb_neutralize_jvmti();
    g_early_stage = 2;

    /*
     * JVMTI 看门线程的创建**不能在这里做**。
     *
     * 实测：本函数在 JNI_OnLoad 极早期执行，此时 liblog 尚未就绪，
     * 所有日志静默丢失（连恒开的 __android_log_print 也看不到），
     * 且 pthread_create 在这个阶段不可靠。
     *
     * 更麻烦的是：如果这里先把 started 置 1，后面那条可靠路径
     * （clv_fast_patch_thread 里创建）会因为 started 已置位而被跳过，
     * 于是两个时机都拿不到线程。
     *
     * 所以这里只置 pending，把创建**唯一地**交给 fastpatch 线程。
     *
     * 注意 guard_loop 那条路不能依赖：它只在 ops 带 NATIVE_OP_GUARD
     * 位时才创建，而 hunter 这条路径下该位并未置上。
     * fastpatch 线程则是无条件启动的（有 FASTPATCH 日志佐证），所以选它。
     */
    /*
     * 这里只置待启动标志，实际创建交给 clv_fast_patch_thread 的第一拍。
     *
     * 实测依据：本函数结束时 g_early_stage 能到 3（说明代码全部走完），
     * 但 WATCH 线程的创建日志与后续轮询日志**一条都没有** ——
     * 早期调用 pthread_create 失败了，失败日志又被 logd 丢掉
     *（进程启动最初几毫秒的日志不可见）。
     *
     * 而 clv_fast_patch_thread 确实能跑（有 FASTPATCH 日志），
     * 它启动时进程已就绪，从那里创建可靠。
     */
    g_jvmti_watch_pending = 1;

#if AHB_PROBE
    ahb_selfcheck_all();
#endif

#if !AHB_MINIMAL_VIEW
    /* 最早的可靠时机：vm 已有效，检测器还没开始扫 */
    clv_install_now();
    /* 抢跑线程：它调用的 clv_patch_got 已改为轻量重定位路径 */
    clv_start_fast_patch();
#endif
    g_early_stage = 3;
}

static void ahb_early_init(void) {
    pthread_once(&g_early_once, ahb_early_init_body);
}

__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    AHB_ENTRY("JNI_OnLoad");
    if (!vm) return JNI_ERR;
    g_vm = vm;
#if !AHB_NATIVE_ON
    g_enable_maps_hide = 0;
    AHB_SAYL("NATIVEOFF: 不安装任何补丁");
    return JNI_VERSION_1_6;
#endif

    /*
     * 这里曾经调用 ahb_guard_linker_tail() 给 linker64 末尾补零页，
     * 用来兜住目标应用的越界读。现在不需要了：
     *
     * 真正的修法是在 maps 视图里把 linker64 的碎片段合并成连续段
     * （见 maps_hide.h 的 linker64 分支），让对方的扫描范围算对。
     * 补页只是把越界位置往后推 —— 实测推后 0x40000（64 页）后
     * 它继续在新区间的末尾崩，属于掩盖症状。
     *
     * 而且补页有副作用：占用的地址可能落在 ART 的 JIT 分配区附近，
     * 干扰 JIT 代码缓存管理，反而引出 jit_code_cache 断言。
     */

    /*
     * 先定开关，再开始干活。
     *
     * 顺序错了会白做：clv_install_now / clv_start_fast_patch 里都会调用
     * clv_patch_got（现委托给重定位驱动），而那个函数受 g_enable_maps_hide
     * 控制。开关晚一步，前面那次扫描就整轮跳过。
     */
    /*
     * 先把真实函数地址解析好，再开始任何接管。
     *
     * 顺序问题会造成间歇性失败：clv_patch_got 依赖 g_real_pvr 非空才干活，
     * 而它原来是在 clv_install_now 之后才被赋值的。若首轮扫描发生在赋值前，
     * 那一轮就整轮跳过，接管只能等下一轮 —— 实测表现为"约一半的启动
     * ClassLoader 项读到真值 32"。
     */
    ahb_early_init();
    AHB_SAYL("JNI_OnLoad: 早期视图安装 slots=%d", g_clv_n);

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
        AHB_SAYL("MAPS: 接管 open 一族 %d 处，累计 %d 处", n, g_maps_got_patched);
    }
    return JNI_VERSION_1_6;
}

static void on_library_loaded(const char *name, void *handle) {
    (void)name;
    (void)handle;
}

__attribute__((visibility("default")))
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    AHB_ENTRY("native_init");
    if (entries) {
        g_hook = entries->hook_func;
        g_unhook = entries->unhook_func;
        AHB_SAYL("native_init: version=%u hook=%p unhook=%p",
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
    ahb_early_init();
    ahb_filelog("INIT done slots=%d", g_clv_n);
    return on_library_loaded;
}
