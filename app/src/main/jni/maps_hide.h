/*
 * maps 视图伪造：隐藏注入框架在进程地址空间留下的映射痕迹
 * ============================================================
 *
 * 机制说明
 * --------
 * 任何 Zygisk / Xposed 系注入，要能把代码送进目标进程，就必须把
 * 框架自己的库映射进这个进程。这是注入机制的物理结果，不是某个
 * 检测器的特征。所以这里匹配的是"注入框架自身的文件名/路径"，
 * 属于机制级特征：换一个检测器、换一代检测手法，它读到的仍然是
 * 同一份被污染过的映射表。新增一种注入框架，只需往表里加一行。
 *
 * 只过滤**视图**，绝不 unmap。那些映射是框架正在使用的真实内存，
 * 动它会直接把 LSPosed 自己以及其它被注入的模块弄死（R-38）。
 *
 * 为什么用 memfd 而不是拦截 read()
 * --------------------------------
 * read 的粒度完全由调用方决定：可能按字节读、按行读、甚至 mmap 整个
 * 文件。给一个内容已经干净的真实 fd，对方怎么读都对，而且不需要
 * 意识到自己在被处理。拦截 read 则要处理任意切分，反而脆弱。
 */

#ifndef AHB_MAPS_HIDE_H
#define AHB_MAPS_HIDE_H

#include <link.h>
#include <signal.h>

#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif

/* 用户态指针范围。头文件被更早包含，不能依赖 native_main.c 里的同名宏。 */
#ifndef AHB_USER_PTR_MIN
#if defined(__LP64__)
#define AHB_USER_PTR_MIN ((uintptr_t)0x10000ULL)
#define AHB_USER_PTR_MAX ((uintptr_t)0x800000000000ULL)
#else
#define AHB_USER_PTR_MIN ((uintptr_t)0x10000UL)
#define AHB_USER_PTR_MAX ((uintptr_t)0xfffff000UL)
#endif
#endif

/* ---------------- 痕迹特征表 ---------------- */

/*
 * 匹配对象是 maps 里的整行文本，因此用子串即可。
 * 这些路径/文件名来自注入框架本身，与被保护的应用无关。
 */
static const char *const g_trace_markers[] = {
    /*
     * 通用判据：**任何** /data/adb 下的路径都是 root 模块。
     *
     * 这一条替代了下面一长串"已知框架黑名单"的作用。
     * 黑名单的根本问题是它永远滞后：没被列进去的模块照样一眼被看穿。
     * 实测本机就装着 hma_oss_zygisk / inline_hook_spoof / oh_my_keymint
     * 三个模块，它们都不在黑名单里。
     *
     * 而正常应用进程不该有任何 /data/adb 的映射 —— 那是 root 的目录，
     * 能出现在 app 的 maps 里只有一种解释：模块注入。
     * 所以这一条既是通用的，也不会有误伤。
     */
    "/data/adb",
    /* 以下保留：它们是不在 /data/adb 下的框架痕迹 */
    "/data/adb/modules/zygisk_lsposed",
    "/data/adb/modules/zygisk_lspatch",
    "/data/adb/modules/zygisk_sui",
    "/data/adb/modules/zygisk-shamiko",
    "libzygisk_lsposed",
    "libzygisk.so",
    "/zygisk/arm64-v8a.so",
    "/zygisk/armeabi-v7a.so",
    "/zygisk/x86.so",
    "/zygisk/x86_64.so",
    "libriru_",
    "liblspd.so",
    "libxposed_art.so",
    "libedxp.so",
    "libsandhook.so",
    "liblsplant.so",
    "libwhale.so",
    "libpine.so",
    "libyahfa.so",
    "riru_edxposed",
    "riru_lsposed",
    "edxp.prop",
    "/data/misc/riru",
    "libantihook_bypass.so",
    /*
     * 本模块自己的包路径。
     *
     * 必须单列：模块的 so 是用 System.loadLibrary 从模块 APK 里加载的，
     * 映射行的路径是 /data/app/~~xxx==/com.rev.antihookbypass-xxx==/base.apk，
     * 这条路径里**不含** "libantihook_bypass.so"，所以只列 so 名根本匹配不到。
     *
     * 实测：在 com.zhenxi.hunter 主进程的真实 maps 里，
     * 它自己的 base.apk 被映射 3 次，全部可见。
     * 也就是说目标只要看一眼 maps 就能直接认出"装了 AntiHookBypass 模块"，
     * 随后走它的 JVMTI 反制路径把运行时切成 debuggable，
     * 与 lsplant 已改写的入口撞车，ART 的 zombie_code_ 断言失败并 abort。
     */
    "com.rev.antihookbypass",
    "antihookbypass",
    "/data/adb/ap/",
    NULL
};

/*
 * 判断一行 maps 是否应该在视图里被隐藏。
 *
 * 两类：
 *  1) 路径命中注入框架特征表；
 *  2) **匿名可执行段**（无路径名且权限含 x）。
 *
 * 第二类是通用判据，不是某个检测器的特征：
 * 任何"内存里有可执行页却不属于任何文件"的状态，本身就是
 * 代码注入/跳板的物理证据。ART 的 JIT 缓存也落在这类里，
 * 但那是运行时正常产物——所以**只能隐藏视图，绝不能改权限**。
 * 实测给 JIT 页撤执行权限会让 ART 当场 abort
 * （"Jit code cache for mutator"(exclusive held)）。
 */
int maps_line_is_trace_len(const char *line, size_t len);

/*
 * 有界子串搜索。
 *
 * 这是整个模块里最严重的一处性能缺陷，值得写清楚它的成因：
 *
 * strstr(hay, needle) 会在 hay 里一直找到 '\0' 为止。而这里 hay 是
 * 指向"整个 maps 缓冲区中当前行开头"的指针 —— 缓冲区是一整块、
 * 只在最末尾有一个 '\0'。于是对第 i 行调用 strstr，它会从第 i 行
 * 一路扫到缓冲区末尾才肯罢休。
 *
 * 量级：缓冲区约 317KB、3000 行、25 个 marker，
 *      累计扫描量 ≈ 25 × Σ(剩余字节) ≈ 25 × 3000 × 158KB ≈ 12 GB。
 * 实测代价：单次 maps 过滤要 5.6~5.9 秒，而空转同样的循环只要 3ms。
 * 这个时间全程压在检测器刚开始检测的那几秒上，是"检测明显变慢"的主因。
 *
 * 旁证：日志里每 250 行的耗时是递减的（830ms → 145ms）——
 * 因为越靠后的行，剩余缓冲区越短。这正是"扫到缓冲区末尾"的指纹。
 *
 * 修法：按行长度做上界，命中即返回，绝不越过本行。
 */
static const char *ahb_memstr(const char *hay, size_t haylen, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0 || haylen < nl) return NULL;
    const char *end = hay + haylen - nl;
    const char c0 = needle[0];
    for (const char *p = hay; p <= end; p++) {
        /* 先比首字节再走完整比较：maps 里绝大多数位置首字节就不同 */
        if (*p != c0) continue;
        if (memcmp(p, needle, nl) == 0) return p;
    }
    return NULL;
}

int maps_line_is_trace_len(const char *line, size_t len) {
    const char *const *m;
    for (m = g_trace_markers; *m; m++) {
        if (ahb_memstr(line, len, *m)) return 1;
    }

    /*
     * 通用判据：非 ART 的 memfd 映射。
     *
     * 依据（全机实测，不是猜）：把本机所有进程的 memfd 名字统计一遍，
     * 只有下面四种是系统/运行时正常产物：
     *
     *     /memfd:jit-cache          228 处   ART JIT 代码缓存
     *     /memfd:jit-zygote-cache   114 处   ART zygote JIT 缓存
     *     /memfd:perfetto_shmem       2 处   perfetto 跟踪缓冲
     *     /memfd:bitmap               1 处   图形
     *
     * 除此之外的 memfd 名字（实测见到 /memfd:payload 8 处、
     * /memfd:upx 2 处）都属于"把代码装进匿名文件再映射"的注入手法。
     * Zygisk 类框架加载模块也用这条路，因此这条对"别的模块"同样有效。
     *
     * 白名单而不是黑名单：注入了什么名字事先无法知道（可以随机），
     * 但系统正常用的那几个名字是固定的。
     */
    {
        const char *mp = ahb_memstr(line, len, "/memfd:");
        if (mp) {
            size_t rest = (size_t)((line + len) - mp);
            if (!ahb_memstr(mp, rest, "/memfd:jit-cache") &&
                !ahb_memstr(mp, rest, "/memfd:jit-zygote-cache") &&
                !ahb_memstr(mp, rest, "/memfd:perfetto_shmem") &&
                !ahb_memstr(mp, rest, "/memfd:bitmap")) {
                return 1;
            }
        }
    }

    /*
     * 匿名可执行段：形如 "7f..-7f.. r-xp 00000000 00:00 0"（行尾没有路径）。
     *
     * 这里不能用 sscanf 的 "抑制赋值不计入返回值" 来判空。
     * 实测踩坑：原写法
     *     n = sscanf(line, "%llx-%llx %15s %*s %*s %*s %7s", ...);
     *     if (n == 3 && ...) return 1;
     * 想靠 "n == 3 表示没有路径字段" 判匿名段，但在 Bionic 上
     * 带 %*s 的调用返回 6 而不是 3 —— 匿名可执行段一条都没被丢掉。
     * 后果很直接：过滤后的 maps 里仍留着
     *     "30f938f000-30f9537000 r-xp 00000000 00:00 0"
     * 检测器的 native_anon_exec 项照样数出 3 个匿名可执行段判 RISK，
     * 而其它项全绿 —— 表现成"过滤明明跑了却没生效"。
     *
     * 改成自己走 token：跳过起止地址、权限、偏移、dev、inode 五个字段，
     * 若已到行尾则这一行没有路径，就是匿名段。
     */
    {
        /*
         * 手工取前三个字段，不用 sscanf。
         *
         * 这个函数对 maps 的每一行都要跑一次（实测约 3000 行），
         * 而 Bionic 的 sscanf 要走完整的格式串解析与可变参数处理，
         * 单次几十微秒；乘上 3000 行就是几百毫秒的纯开销，
         * 全部落在检测器刚开始检测、最不该被拖慢的那几秒里。
         *
         * 这里只需要"跳过前两个十六进制数 + 取第三个字段"，
         * 用指针走一遍即可，代价是每行几个字节的比较。
         */
        const char *pp = line;
        const char *pend = line + len;
        const char *perm_p = NULL;
        int tok = 0;
        while (pp < pend && *pp && tok < 3) {
            while (pp < pend && *pp == ' ') pp++;
            if (pp >= pend || !*pp) break;
            tok++;
            if (tok == 3) { perm_p = pp; break; }
            while (pp < pend && *pp && *pp != ' ') pp++;
        }
        if (perm_p && perm_p[0] == 'r' && perm_p[1] == '-' && perm_p[2] == 'x') {
            const char *p = line;
            int tokens = 0;
            while (tokens < 5 && *p) {
                while (*p == ' ') p++;
                if (!*p) break;
                while (*p && *p != ' ' && *p != '\n') p++;
                tokens++;
            }
            while (*p == ' ') p++;
            if (*p == '\0' || *p == '\n') return 1;
        }
    }
    return 0;
}

/* 无长度版本：内部按 strnlen 取本行长度，仅供没有行边界的调用点使用 */
static int maps_line_is_trace(const char *line) {
    return maps_line_is_trace_len(line, strlen(line));
}

/* ---------------- 状态 ---------------- */

static unsigned long g_maps_open_calls = 0;

/* 各通道调用次数与累计耗时：用于把"检测变慢"精确归因到某个包装 */
static volatile unsigned long g_c_open = 0,  g_t_open = 0;
/* 每个被接管入口的调用计数：用来定位"到底是哪条通道被高频穿过" */
static volatile unsigned long g_c_openat = 0, g_c_open2 = 0, g_c_open64 = 0;
static volatile unsigned long g_c_openat2 = 0, g_c_open642 = 0;
static volatile unsigned long g_c_fopen = 0, g_c_popen = 0, g_c_opendir = 0;
static volatile unsigned long g_c_sys = 0, g_c_dlphdr = 0;
static volatile unsigned long g_c_self = 0,  g_t_self = 0;
static volatile unsigned long g_c_read = 0,  g_t_read2 = 0;
static volatile unsigned long g_c_fread = 0;
static unsigned long g_maps_filtered   = 0;
/*
 * 不再需要"防递归"全局标志。
 *
 * 早期用一个全局 int 标记"正在过滤中"，多线程并发读 maps 时，
 * 线程 A 置位后线程 B 看到置位就直接走真实 fopen，
 * 拿到的是**未过滤**的原始 maps —— 于是又看到被拆碎的 linker 段，
 * 崩溃依旧。实测 303 次 fopen(/proc/self/maps) 里只有 1 次真正过了过滤。
 *
 * maps_read_all 全部使用裸 syscall（openat/read/close），
 * 不经过任何被接管的 libc 包装，天然不会递归，这个标志本就是多余的。
 */
static int g_maps_got_patched = 0;
static unsigned long g_mapshdr_calls = 0;
static int g_disable_phdr_hide = 0;   /* 对照实验开关 */
static int g_disable_all_patch = 0;
   /* 对照实验：完全不接管任何槽 */
/*
 * 默认关闭。
 *
 * 这套 GOT 接管是为了隐藏注入痕迹，属于新增能力；它一旦在
 * JNI_OnLoad 里对所有应用无条件执行，就会影响原本已经通过的场景。
 * 实测代价是 antihook.detect 直接崩在 maps_patch_got_all。
 * 因此默认不启用，由配置显式打开，未验证前不改变任何既有行为。
 */
static int g_enable_maps_hide = 0;

/* ---------------- 路径判定 ---------------- */

/*
 * 认三种写法：/proc/self/maps、/proc/<本pid>/maps、以及 task 视角。
 * 检测器常用显式 pid 那种，因为它认为"自己算出来的 pid 更可信"。
 */
/*
 * 探针：记录目标进程实际打开过哪些 /proc 路径。
 *
 * 用途是测量，不是拦截。我们目前只伪造了 /proc/self/maps 一份视图，
 * 而真实的反检测要求"所有视角互相一致"：maps 说没有某段，
 * 那么 map_files、smaps、fd 目录也必须一致，否则两边一对照就露。
 *
 * 所以第一步必须知道它到底开了哪些路径，而不是凭猜测去伪造一堆。
 * 只记路径、去重、限 64 条，不做任何行为改变。
 * 定位完成后由 AHB_PROBE 宏整体关掉。
 */
#ifndef AHB_PROBE
/*
 * 诊断自检开关。默认关。
 *
 * 打开时会在早初始化阶段连续 open /proc/self/{maps,smaps,mounts} 与
 * /proc/modules 各一次并全量扫一遍——那几条路径本身也要走我们的
 * 过滤函数。在目标进程的加载早期做这些额外动作，会把"初始化窗口"
 * 拉长，且曾经引出过 clv_build 里的越界读。
 * 定位完就关掉，生产不留。
 */
#define AHB_PROBE 0
#endif

static void ahb_probe_path(const char *path) {
#if AHB_PROBE
    if (!path) return;
    if (path[0] != '/' || memcmp(path, "/proc/", 6) != 0) return;
    static unsigned long long seen[64];
    static int nseen = 0;
    unsigned long long h = 1469598103934665603ULL;
    for (const char *p = path; *p; p++) {
        h ^= (unsigned long long)(unsigned char)*p;
        h *= 1099511628211ULL;
    }
    for (int i = 0; i < nseen; i++) if (seen[i] == h) return;
    if (nseen >= 64) return;
    seen[nseen++] = h;
    LOGI("PROBE proc-open %s", path);
#endif
}

/* ------------------------------------------------------------------ */
/* 让 JVMTI / JDWP 的库文件在这个进程里"不存在"                         */
/* ------------------------------------------------------------------ */

/*
 * 为什么不是在 dlopen 上拦
 * -----------------------
 * 实测：在 hunter 主进程里给 dlopen 加探针，整轮只记录到 1 次调用
 * （libc.so）。也就是目标根本没走 dlopen 去拉 JVMTI 库 ——
 * 它用的是静态编进 libhunter.so 里的 **xDL**，自己走 linker 内部结构。
 * 所以拦 dlopen / dlsym 都没命中（实测屏蔽日志 0 条）。
 *
 * 但 xDL 无论怎么绕，最终都必须 open 那个 .so 文件才能 mmap。
 * 因此在路径层让它"不存在"，是这条链上绕不过去的一环。
 *
 * 这条与隐藏 maps 是同一类手段：让它拿不到那件东西，而不是改它的结论。
 * 目标自己带 xdl_open ERROR 的失败分支，拿不到就正常跳过 JVMTI 初始化，
 * 于是不会走 UpdateEntrypointsForDebuggable，也就不会踩
 * jit_code_cache 的 zombie_code_ 断言（该断言的完整栈见 dlopen 拦截处注释）。
 */
#ifndef AHB_HIDE_JVMTI_FILE
#define AHB_HIDE_JVMTI_FILE 1
#endif

static int ahb_is_hidden_file(const char *path) {
    if (!path) return 0;
#if AHB_HIDE_JVMTI_FILE
    /*
     * 只藏 JVMTI/JDWP 这一类"调试代理"库。
     * 不做宽泛匹配：误藏普通库会直接让目标功能缺失。
     */
    if (strstr(path, "libopenjdkjvmti.so")) return 1;
    if (strstr(path, "libjdwp.so")) return 1;
    if (strstr(path, "libdt_jdwp.so")) return 1;
#endif
    return 0;
}

/* 早期初始化进展，定义在 native_main.c，供诊断日志带出 */
int ahb_early_stage_get(void);
int ahb_jvmti_result_get(void);
int ahb_jvmti_diag_get(void);
int ahb_libart_diag_get(void);
int ahb_elf_diag_get(void);

static int maps_path_is_self(const char *path) {
    char want[64];
    if (!path) return 0;
    if (!strstr(path, "/maps")) return 0;
    if (strcmp(path, "/proc/self/maps") == 0) return 1;
    snprintf(want, sizeof(want), "/proc/%d/maps", (int)getpid());
    if (strcmp(path, want) == 0) return 1;
    /*
     * 父进程的地图也要认。
     *
     * 依据：libantihook.so 的导入表里有 fork / pipe / getppid / waitpid —— 
     * 它会 fork 一个子进程，由子进程去读
     *     /proc/<父pid>/maps
     * 做"外部视角"检查。子进程继承了我们补过的 GOT，但原来这里只认
     * getpid()，在子进程里父 pid 不等于自己，于是那条路**完全没被过滤**，
     * 子进程看到的是真实地图，里面还有 LSPlant 的匿名跳板段。
     *
     * 这正好解释了"该项时好时坏"：取决于那次读是在父进程里做的，
     * 还是在 fork 出来的子进程里做的。
     */
    snprintf(want, sizeof(want), "/proc/%d/maps", (int)getppid());
    if (strcmp(path, want) == 0) return 1;
    snprintf(want, sizeof(want), "/proc/%d/task/%d/maps", (int)getpid(), (int)getpid());
    if (strcmp(path, want) == 0) return 1;

    /*
     * 任意 pid 的 maps 也要认。
     *
     * 依据（真实检测输出里抓到的原文）：
     *      find libart.so hooked 4096
     *      /proc/18023/maps
     *      checkFileIsLegal path validation failed
     *
     * 18023 是它自己主进程的 pid —— 它从另一个进程（twin / iso）
     * 读 **指定 pid** 的 maps，而不是 /proc/self/maps。
     * 原来这里只认 self / 本pid / 父pid，这类带"别人 pid"的路径
     * 一条都匹配不上，于是那条读法完全没被过滤。
     *
     * 判定放宽到"任何 /proc/<数字>/maps"，因为：
     *   - 我们的补丁只装在注入了本模块的进程里，
     *     别的进程根本不会走到这段代码
     *   - 在这些进程里，任何"带具体 pid 的 maps 读"都只可能是
     *     目标自己在做外部视角检查，没有正常业务用途
     *
     * 同时认 task 形式 /proc/<pid>/task/<tid>/maps。
     */
    {
        const char *p2 = path;
        long pid = 0;
        int got = 0;
        if (strncmp(p2, "/proc/", 6) != 0) return 0;
        p2 += 6;
        while (*p2 >= '0' && *p2 <= '9') {
            pid = pid * 10 + (*p2 - '0');
            got = 1;
            p2++;
        }
        if (!got) return 0;
        (void)pid;
        /* /proc/<num>/maps */
        if (strcmp(p2, "/maps") == 0) return 1;
        /* /proc/<num>/task/<tid>/maps */
        if (strncmp(p2, "/task/", 6) == 0) {
            const char *p3 = p2 + 6;
            int got2 = 0;
            while (*p3 >= '0' && *p3 <= '9') { got2 = 1; p3++; }
            if (got2 && strcmp(p3, "/maps") == 0) return 1;
        }
    }
    return 0;
}

/* ---------------- 生成干净视图 ---------------- */

/*
 * 每次调用独立分配缓冲区。
 *
 * 早期版本用了两个共享 static 缓冲，没有加锁。目标进程是多线程的
 * （hunter 有 RxCachedThreadS 等线程池），两个线程同时读 maps 就会
 * 互相覆盖，输出半截内容。对解析方来说，半截 maps 意味着它算出的
 * 段范围与真实地址空间对不上 —— 表现就是校验时越界读取未映射内存，
 * SIGSEGV @ 段末尾。
 *
 * maps 读取不频繁（实测百次量级），每次 malloc 完全可接受，
 * 换来的是无可争议的线程安全。
 */
#define AHB_PATH_MAX    320
#define MAPS_INIT_CAP (256 * 1024)
#define MAPS_MAX_CAP  (16 * 1024 * 1024)


/* 读全部内容；返回长度，调用方负责 free */
/*
 * 读 maps 的内容获取必须走**真实** syscall 函数指针，不能写 syscall(...)。
 *
 * 因为 syscall 号 openat 也会被我们接管（检测器就用
 * libc::syscall(SYS_openat, "/proc/self/maps") 直接读，绕过 fopen）。
 * 若这里用 syscall(SYS_openat,...)，就会递归回自己的包装。
 */
typedef long (*raw_syscall_fn)(long, ...);
static raw_syscall_fn g_raw_syscall = NULL;

static void maps_ensure_raw_syscall(void) {
    if (!g_raw_syscall) g_raw_syscall = (raw_syscall_fn)dlsym(RTLD_NEXT, "syscall");
}

static long maps_raw_sys(long n, long a1, long a2, long a3) {
    maps_ensure_raw_syscall();
    if (g_raw_syscall) return g_raw_syscall(n, a1, a2, a3);
    return -1;
}

static int maps_read_all(char **out_buf, size_t *out_cap) {
    size_t cap = MAPS_INIT_CAP;
    char *buf = (char *)malloc(cap);
    size_t total = 0;

    if (!buf) return -1;
    for (;;) {
        long n;
        long fd;
        if (total + 1 >= cap) {
            if (cap >= MAPS_MAX_CAP) break;     /* 真到上限就停 */
            size_t ncap = cap * 2;
            char *nb = (char *)realloc(buf, ncap);
            if (!nb) { free(buf); return -1; }
            buf = nb;
            cap = ncap;
        }
        /* 每次重开：/proc 文件的 read 语义在不同内核上不完全一致 */
        fd = maps_raw_sys(SYS_openat, AT_FDCWD, (long)"/proc/self/maps", O_RDONLY);
        if (fd < 0) { free(buf); return -1; }
        total = 0;
        for (;;) {
            if (total + 1 >= cap) break;
            n = maps_raw_sys(SYS_read, fd, (long)(buf + total), (long)(cap - total - 1));
            if (n <= 0) break;
            total += (size_t)n;
        }
        maps_raw_sys(SYS_close, fd, 0, 0);
        if (total + 1 < cap) break;             /* 没读满 = 读完了 */
    }
    buf[total] = 0;
    *out_buf = buf;
    *out_cap = cap;
    return (int)total;
}

/*
 * 生成过滤后的 maps 视图。
 *
 * 两条硬要求：
 *  1. 只删整行（含换行），其余字节原样不动。任何"重排/截断/改写"
 *     都会让解析方算出的段范围与真实地址空间不一致。
 *  2. 每次调用独立缓冲，天然线程安全。
 */
/*
 * 过滤结果缓存。
 *
 * hunter 在启动阶段反复读 /proc/self/maps（实测 300+ 次）。
 * 每次都重新读一遍内核 maps、逐行判断、写 memfd，代价很高：
 * 实测 CPU 占用从 0 涨到约 100%（3 秒 300 tick）。
 *
 * 但 maps 在很短的时间内几乎不变，所以这里做一层缓存：
 * 用 maps 的"总字节数 + 首尾各 64 字节"做指纹，指纹相同就复用
 * 上一次生成好的 memfd（dup 一份给调用方）。
 *
 * 指纹失效时重新生成，保证内容始终反映当时的真实映射。
 */
#define MAPS_TTL_MS 120
static char    *g_maps_ttl_buf  = NULL;
static size_t   g_maps_ttl_len  = 0;

/*
 * TTL 缓存已整体移除。
 *
 * 事故经过：
 *   g_maps_ttl_buf 是裸全局指针，hunter 多线程并发读 maps 时
 *   两个线程可能同时 free 它（double free），或一个在读一个已 free
 *   （use-after-free），堆元数据被破坏，之后任意 free 就崩：
 *       signal 11 in je_free -> arena_run_dalloc
 *       #03 ... base.apk (maps_make_clean_fd_ex+2960)
 *   特点是偶发：三轮一中。
 *
 * 两次加锁尝试都失败了，且失败得更彻底（每轮必崩、jit 断言回来）：
 *   一版把 maps_memfd_of 放进锁内 -> 它内部 register fd 可能再触发
 *   maps 读取 -> 递归申请非递归锁 -> 看门线程卡死 -> ART 断开没执行。
 *   改到锁外仍不行，说明这把锁在这条高频路径上本身就是不可接受的代价
 *   （目标启动期读 300+ 次 maps，看门线程必须持续跑才能压住 JVMTI）。
 *
 * 最终选择：**不要缓存**。
 * 每次读都重新过滤一遍。代价是每次多一次 malloc + 3000 行扫描，
 * 但换来的是零共享状态、零锁、零竞态 —— 这条路径上任何阻塞
 * 都会让 JVMTI 断开超时，那个代价远大于几百微秒的过滤。
 */
static time_t   g_maps_ttl_sec  = 0;
static long     g_maps_ttl_nsec = 0;
static unsigned long g_maps_ttl_hits = 0;

/* 用一段内容造一个全新的 memfd，调用方独占其偏移 */
/* ================================================================== */
/* fd 身份伪装：让伪造的 memfd 在 stat 里看起来就是真的 procfs 文件      */
/* ================================================================== */

/*
 * 为什么必须做这一步（有据，不是推测）
 * ------------------------------------
 * 目标应用 libhunter.so 里存在这些字符串：
 *
 *   start checkFileIsLegal fstat64 uid ->
 *   maps inode ->  :        orig inode ->  :   inode mismatching ->
 *   Found inconsistent inode :
 *   readlink find root file
 *
 * 它的做法是：open("/proc/self/maps") 拿到 fd，先用 fstat64 取 fd 的
 * inode，再读内容取每一行的 inode 字段，两边对不上就判定"被 hook"。
 *
 * 而我们交出去的是 memfd：内容和真实 maps 一致（路径名已改写），
 * 但 fd 这个对象本身是 tmpfs 上的匿名文件，st_dev/st_ino/st_size
 * 与 procfs 完全不同 —— 一比对必然不一致。于是它判定篡改并自我终止。
 *
 * 修法不是改比对结果，而是让 memfd 在元数据上与它冒充的那个 procfs
 * 文件完全一致：提前 fstat 一份真实 /proc 文件缓存起来，凡是被问到
 * 我们自己的 memfd，就交这份真实值。
 */

/* 本地 syscall 原型：文件后段才定义 syscall6_fn，这里前方已要用到 */
typedef long (*ahb_sys6_fn)(long, long, long, long, long, long, long);

/* 不同 bionic 版本对 fstatat 的系统调用名不一致，统一一个别名 */
#ifndef SYS_newfstatat
#ifdef SYS_fstatat64
#define SYS_newfstatat SYS_fstatat64
#elif defined(__NR_newfstatat)
#define SYS_newfstatat __NR_newfstatat
#else
#define SYS_newfstatat 79   /* arm64/aarch64 通用编号 */
#endif
#endif

#define AHB_FAKE_FD_MAX 32
static int g_fake_fd[AHB_FAKE_FD_MAX];
static int g_fake_fd_kind[AHB_FAKE_FD_MAX];   /* 0=maps 1=smaps 2=mounts 3=modules */
static int g_fake_fd_n;
static struct stat g_real_stat[4];
static int g_real_stat_ok[4];

static void ahb_fake_fd_register(int fd, int kind) {
    int i;
    if (fd < 0 || kind < 0 || kind > 3) return;
    for (i = 0; i < g_fake_fd_n; i++) {
        if (g_fake_fd[i] == fd) { g_fake_fd_kind[i] = kind; return; }
    }
    if (g_fake_fd_n >= AHB_FAKE_FD_MAX) {
        /* 满了就覆盖最旧的一格，避免无限增长 */
        g_fake_fd[0] = fd; g_fake_fd_kind[0] = kind;
        return;
    }
    g_fake_fd[g_fake_fd_n] = fd;
    g_fake_fd_kind[g_fake_fd_n] = kind;
    g_fake_fd_n++;
}

static void ahb_fake_fd_unregister(int fd) {
    int i;
    for (i = 0; i < g_fake_fd_n; i++) {
        if (g_fake_fd[i] == fd) {
            g_fake_fd[i] = g_fake_fd[g_fake_fd_n - 1];
            g_fake_fd_kind[i] = g_fake_fd_kind[g_fake_fd_n - 1];
            g_fake_fd_n--;
            return;
        }
    }
}

static int ahb_fake_fd_kind_of(int fd) {
    int i;
    for (i = 0; i < g_fake_fd_n; i++)
        if (g_fake_fd[i] == fd) return g_fake_fd_kind[i];
    return -1;
}

/*
 * 预取真实 /proc 文件的 stat。
 * 用 openat 直接拿 fd 再 fstat，避免被自己的 open 包装绕回来。
 */
static void ahb_prefetch_real_stats(void) {
    static const char *const paths[4] = {
        "/proc/self/maps", "/proc/self/smaps",
        "/proc/self/mounts", "/proc/self/modules"
    };
    int k;
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return;
    for (k = 0; k < 4; k++) {
        long fd;
        if (g_real_stat_ok[k]) continue;
        fd = ((ahb_sys6_fn)g_raw_syscall)(SYS_openat, AT_FDCWD,
                                          (long)paths[k], O_RDONLY, 0, 0, 0);
        if (fd < 0) continue;
        {
            struct stat st;
            long r = ((ahb_sys6_fn)g_raw_syscall)(SYS_fstat, fd,
                                                  (long)&st, 0, 0, 0, 0);
            if (r == 0) {
                g_real_stat[k] = st;
                g_real_stat_ok[k] = 1;
            }
        }
        ((ahb_sys6_fn)g_raw_syscall)(SYS_close, fd, 0, 0, 0, 0, 0);
    }
}

/*
 * 把 fd 的 stat 换成本模块伪装值；返回 1 表示已替换。
 * 不改调用者的其它行为，只在确实是我们自己的 fd 时才动手。
 */
static int ahb_fd_fake_stat(int fd, void *buf) {
    int kind = ahb_fake_fd_kind_of(fd);
    if (kind < 0 || !buf || !g_real_stat_ok[kind]) return 0;
    *(struct stat *)buf = g_real_stat[kind];
    return 1;
}

/* readlink 伪装：/proc/self/fd/N 应指向真实 maps 路径 */
/*
 * 让 readlink 对"我们伪造的 fd"返回真实 procfs 路径。
 *
 * 依据（hunter 6.58 自己打印的判定过程，不是推测）
 * ----------------------------------------------
 *   find libart.so hooked 4096
 *   /proc/18023/maps
 *   checkFileIsLegal path validation failed
 *   /proc/18023/maps
 *   /memfd:maps (deleted)
 *
 * 它先 open("/proc/<pid>/maps")，再 readlink 这个 fd 的真实路径来核对
 * "你给我的到底是不是 maps"。而我们用 memfd 造的假文件，路径天然是
 * /memfd:maps (deleted)，一眼就被识破。
 *
 * 这里修掉了原实现的两个漏洞：
 *
 * 1) 原实现只认 "/proc/self/fd/" 和 "/proc/thread-self/fd/"。
 *    但目标用的是带 pid 的 "/proc/18023/fd/N"（它在别的进程里查主进程），
 *    这条路径根本匹配不上，直接漏过去。
 *
 * 2) 原实现返回路径时用的是 getpid()。
 *    即便 pid 形式被识别，返回的也是"我这个进程的 maps"，
 *    与对方请求的 pid 不一致，同样过不了校验。
 *    正确做法是照抄请求里的 pid。
 */
static int ahb_fd_fake_readlink(const char *path, char *buf, size_t sz) {
    int fd, kind;
    const char *p;
    const char *fdp;
    int pid = 0;
    char tmp[96];
    int n;

    if (!path || !buf || sz == 0) return -1;

    /* 统一解析成 "<pid> + fd 数字" 两个值 */
    p = strstr(path, "/proc/");
    if (!p) return -1;
    p += 6;

    if (strncmp(p, "self/", 5) == 0) {
        pid = (int)getpid();
        fdp = p + 5;
    } else if (strncmp(p, "thread-self/", 12) == 0) {
        pid = (int)getpid();
        fdp = p + 12;
    } else if (p[0] >= '0' && p[0] <= '9') {
        char *endp = NULL;
        long v = strtol(p, &endp, 10);
        if (!endp || v <= 0 || v > 0x7fffffffL) return -1;
        pid = (int)v;
        if (*endp != '/') return -1;
        fdp = endp + 1;
    } else {
        return -1;
    }

    /*
     * 支持两种形态：
     *     <pid>/fd/N
     *     <pid>/task/<tid>/fd/N        <- 实测目标用的是这种
     */
    if (strncmp(fdp, "task/", 5) == 0) {
        const char *slash = strchr(fdp + 5, '/');
        if (!slash) return -1;
        fdp = slash + 1;
    }
    if (strncmp(fdp, "fd/", 3) != 0) return -1;
    fd = atoi(fdp + 3);

    kind = ahb_fake_fd_kind_of(fd);
    if (kind < 0) return -1;

    {
        static const char *const nm[4] = { "maps", "smaps", "mounts", "modules" };
        /*
         * 必须**原样保留 task 段**，不能只回 /proc/<pid>/<name>。
         *
         * 实测教训：目标请求的是
         *     /proc/24708/task/25061/maps
         * 而我们只回
         *     /proc/24708/maps
         * 两者一比对就不一致，它直接报
         *     "检测到APK存在沙箱内部(readlink异常)"
         * 也就是说：readlink 伪装的重点不是"内容对不对"，
         * 而是"是否与对方请求的那条路径逐字一致"。
         *
         * 所以这里把请求里的 "task/<tid>/" 原样抄过去。
         */
        const char *taskp = strstr(fdp, "task/");
        if (taskp) {
            /* fdp 形如 "fd/N" 或 "task/<tid>/fd/N"，后者要提取 "<tid>" */
            const char *slash = strchr(taskp + 5, '/');
            if (slash) {
                int tid_len = (int)(slash - (taskp + 5));
                if (tid_len > 0 && tid_len < 24) {
                    n = snprintf(tmp, sizeof(tmp), "/proc/%d/task/%.*s/%s",
                                 pid, tid_len, taskp + 5, nm[kind]);
                    goto built;
                }
            }
        }
        n = snprintf(tmp, sizeof(tmp), "/proc/%d/%s", pid, nm[kind]);
    }
built:
    if (n <= 0 || (size_t)n >= sz) return -1;
    memcpy(buf, tmp, (size_t)n + 1);
    return n;
}


static int maps_memfd_of(const char *buf, size_t len) {
    int fd = (int)syscall(SYS_memfd_create, "maps", 0);
    size_t off = 0;
    if (fd < 0) return -1;
    while (off < len) {
        long k = syscall(SYS_write, fd, buf + off, len - off);
        if (k <= 0) { syscall(SYS_close, fd); return -1; }
        off += (size_t)k;
    }
    syscall(SYS_lseek, fd, 0, SEEK_SET);
    ahb_fake_fd_register(fd, 0);
    return fd;
}

/*
 * 指纹必须覆盖**整块**内容，不能只取首尾。
 *
 * 踩过的坑：最初只哈希首尾各 64 字节 + 长度，结果中间段的增删
 * （比如匿名可执行页出现/消失）检测不到，缓存命中后返回了过期内容，
 * 检测器的匿名段项因此又变回 RISK。
 *
 * 整块 FNV-1a 是 300KB 的线性扫描，比逐行 sscanf 快一个数量级，
 * 用来替代"每次重新解析"完全划算。
 */
static uint64_t maps_sig_of(const char *buf, size_t len) {
    uint64_t h = 1469598103934665603ULL;
    size_t i;
    for (i = 0; i < len; i++) {
        h ^= (unsigned char)buf[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/*
 * 单行 maps 记录。
 *
 * 为什么要自己分词，而不是 sscanf("%llx-%llx %7s %llx %15s %llu %319[^\n]")：
 *
 *   sscanf 格式串里的**空格会匹配并吞掉任意数量的空白，包括换行符**。
 *   而 maps 里"没有路径"的行（匿名段、memfd 段等）在 inode 后面
 *   紧跟的是换行 —— 于是那个空格会吃掉 \n，%[^\n] 接着把**下一整行**
 *   读成 path。
 *
 *   后果不是"解析失败"，而是解析成功但内容错位：本行被当成
 *   "路径 = 下一行全文"，原样写回输出，两行就粘成了一行。
 *   实测过滤产物里有 246 行这种粘连，
 *   形如 "30f938e000-30f938f000 rw-p 0 00:00 0 30f938f000-30f9537000 r-xp ..."。
 *
 *   任何按行解析的读方遇到这种行都会算出错误的段范围。hunter 就是
 *   拿它去 strcpy 进一个 5 字节字段，被 FORTIFY 拦住后 abort。
 *
 * 所以这里手工按空格切，**永远不跨过 \n**，且在极端行长下照样安全。
 */
struct maps_ent {
    unsigned long long start;
    unsigned long long end;
    unsigned long long off;
    unsigned long long inode;
    char perm[8];
    char dev[16];
    char path[AHB_PATH_MAX];
    /* 原始字节指针与长度：输出时可以逐字复制，不做任何重排 */
    const char *raw;
    size_t raw_len;
};

/* 在 [p,end) 内取一个空格分隔的 token，返回下一个 token 的起点；没有则返回 NULL */
static const char *maps_tok(const char *p, const char *end, char *out, size_t outsz) {
    size_t n = 0;
    while (p < end && *p == ' ') p++;
    if (p >= end || *p == '\n') { if (outsz) out[0] = 0; return NULL; }
    while (p < end && *p != ' ' && *p != '\n') {
        if (n + 1 < outsz) out[n++] = *p;
        p++;
    }
    if (outsz) out[n] = 0;
    return p;
}

static int maps_parse_line(const char *line, size_t len, struct maps_ent *e) {
    const char *end = line + len;
    const char *p;
    char addr[64] = {0}, off[32] = {0}, ino[32] = {0};

    memset(e, 0, sizeof(*e));
    e->raw = line;
    e->raw_len = len;

    /* 字段顺序：addr perm offset dev inode [path]，路径可缺省 */
    p = maps_tok(line, end, addr, sizeof(addr));
    if (!p) return 0;
    p = maps_tok(p, end, e->perm, sizeof(e->perm));
    if (!p) return 0;
    p = maps_tok(p, end, off, sizeof(off));
    if (!p) return 0;
    p = maps_tok(p, end, e->dev, sizeof(e->dev));
    if (!p) return 0;
    p = maps_tok(p, end, ino, sizeof(ino));
    if (!p) return 0;
    /* 到行尾就置空串，绝不会跨过 \n 去吞下一行 */
    (void)maps_tok(p, end, e->path, sizeof(e->path));

    {
        char *dash = strchr(addr, '-');
        if (!dash) return 0;
        *dash = 0;
        e->start = strtoull(addr, NULL, 16);
        e->end   = strtoull(dash + 1, NULL, 16);
    }
    e->off   = strtoull(off, NULL, 16);
    e->inode = strtoull(ino, NULL, 10);
    return 1;
}

/*
 * 输出一行。
 *
 * 用记录的原始字节打底，只替换其中的起始/结束地址（合并段时要做），
 * 其余空格、对齐、路径原样保留 —— 保证字段个数与分隔形式与内核一致。
 */
/*
 * 保行改写：把一行里的路径字段换掉，其余字节（地址、权限、偏移、设备、
 * inode、分隔空格）逐字保留。
 *
 * 为什么必须保行：目标应用按行解析 maps 并累加偏移，行数一变它就算错，
 * 后面按索引取的地址会整体越界。删行看起来"更干净"，实际是把对方的
 * 解析器搞崩。行数、地址布局、字段个数三者必须与真实视图完全一致。
 *
 * 替换目标选 /system/framework/ 下的真实存在的名字，长度不必相等，
 * 但必须是"这行原本就该长这样"的形态：
 *   - 设备文件（/dev/...）→ /dev/ashmem
 *   - 其余 → /system/framework/framework.jar
 * 这样它在形态上完全正常，不会因为"路径诡异"被单独挑出来。
 */
static size_t maps_emit_masked_line(char *out, size_t w, size_t cap,
                                    const char *line, size_t len, int seq) {
    (void)seq;
    if (w + len + 2 > cap) return w;

    /* 找路径字段起点：第 6 个字段（path 可含空格） */
    size_t i = 0;
    int fields = 0;
    size_t path_at = len;
    size_t dev_at = 0, dev_end = 0;
    size_t ino_at = 0, ino_end = 0;
    while (i < len) {
        if (line[i] == ' ' || line[i] == '\t') { i++; continue; }
        fields++;
        size_t fstart = i;
        while (i < len && line[i] != ' ' && line[i] != '\t') i++;
        if (fields == 4) { dev_at = fstart; dev_end = i; }
        if (fields == 5) { ino_at = fstart; ino_end = i; }
        /*
         * 字段次序：addr(1) perm(2) offset(3) dev(4) inode(5) path(6)。
         *
         * 这里必须是 fields == 5 —— 第 5 个字段（inode）读完之后，
         * 紧接着才是路径。
         *
         * 曾经写成 fields == 6，那是差一错误，而且表现得极其隐蔽：
         * 循环在 fields==6 时已经把"路径"这个字段整段吃掉了，
         * 于是 path_at 落在行尾（== len），走下面"没有路径字段"的分支，
         * 把整行原样抄进输出 —— 路径一个字节都没换。
         *
         * 后果：过滤看起来在跑（总长度确实变了，因为别的行有合并），
         * 但痕迹行全部原样保留。实测在 hunter 主进程里
         * 包装视图仍含 3 行 com.rev.antihookbypass 就是这么来的。
         */
        if (fields == 5) {
            while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
            path_at = i;
            break;
        }
    }

    if (path_at >= len) {
        /* 没有路径字段（理论上不会走到，匿名段另有分支） */
        memcpy(out + w, line, len);
        w += len;
        if (w < cap) out[w++] = '\n';
        return w;
    }

    /*
     * 决定替换路径，并**同时换掉 dev 与 inode**。
     *
     * ===== 为什么必须一起换（实测教训）=====
     * 只换路径、留下原来的 "00:00 0"，目标会拿新路径去 stat，
     * 然后把 stat 到的 dev/inode/size 与行内值对比，一旦不符就报：
     *     (inode不匹配)inode mismatching ->
     *     /system/framework/framework.jar 21619546 8356463
     * 也就是说"路径合理但身份字段造假"比"路径可疑"更容易被抓，
     * 因为它把两处信息交叉验证了一次。
     *
     * 所以这里取被替换文件的**真实** dev/inode（stat 一次后缓存），
     * 让整行自洽：路径、dev、inode 三者互相印证。
     */
    const char *rep;
    if (path_at + 4 <= len && memcmp(line + path_at, "/dev", 4) == 0) {
        rep = "/dev/ashmem";
    } else if (path_at + 4 <= len && memcmp(line + path_at, "/mem", 4) == 0) {
        rep = "/memfd:jit-cache (deleted)";
    } else {
        rep = "/system/framework/framework.jar";
    }

    /* 先原样抄到 dev 字段起点 */
    size_t copy_to = (dev_at > 0 && dev_at < path_at) ? dev_at : path_at;
    memcpy(out + w, line, copy_to);
    w += copy_to;

    if (copy_to == dev_at) {
        /*
         * 取被替换路径的真实身份。
         * stat 结果缓存：这条路径固定，没必要每次重取。
         */
        static int    cached = 0;
        static char   dev_s[16];
        static char   ino_s[24];
        static size_t dev_l = 0, ino_l = 0;
        if (!cached) {
            struct stat st;
            cached = 1;
            if (stat(rep, &st) == 0) {
                unsigned maj = (unsigned)((st.st_dev >> 8) & 0xfff);
                unsigned min = (unsigned)((st.st_dev & 0xff) |
                                          ((st.st_dev >> 12) & 0xfff00));
                dev_l = (size_t)snprintf(dev_s, sizeof(dev_s), "%02x:%02x",
                                         maj, min);
                ino_l = (size_t)snprintf(ino_s, sizeof(ino_s), "%llu",
                                         (unsigned long long)st.st_ino);
            }
        }
        if (dev_l && ino_l) {
            if (w + dev_l + (ino_end - ino_at) + 2 > cap) return w;
            memcpy(out + w, dev_s, dev_l);       w += dev_l;
            /* dev 与 inode 之间的空白沿用原样 */
            memcpy(out + w, line + dev_end, ino_at - dev_end);
            w += ino_at - dev_end;
            memcpy(out + w, ino_s, ino_l);       w += ino_l;
            /* inode 到路径之间的空白沿用原样 */
            memcpy(out + w, line + ino_end, path_at - ino_end);
            w += path_at - ino_end;
        } else {
            /* stat 失败：保持原字段，只换路径（至少不比原来差） */
            memcpy(out + w, line + dev_at, path_at - dev_at);
            w += path_at - dev_at;
        }
    }

    size_t rl = strlen(rep);
    if (w + rl + 2 > cap) return w;
    memcpy(out + w, rep, rl);
    w += rl;

    out[w++] = '\n';
    return w;
}

/*
 * 匿名可执行段的保行改写：给它一个 JIT 代码缓存的名字。
 *
 * 真实安卓进程里本来就有大量 [anon:dalvik-jit-code-cache] 之类的可执行段，
 * 所以这个名字在这个位置完全合理。关键仍然是**行数不变**。
 */
/*
 * 匿名可执行段：**从视图里整行剔除**，不输出、不改写。
 *
 * ===== 五次试错的完整账，一次比一次接近真相 =====
 *
 * 1) [anon:dalvik-jit-code-cache]
 *    hunter 按 "[anon:" 前缀判 "Found suspicious anonymous memory"。
 *
 * 2) 伪装成 boot.oat + stat 出来的 dev/inode
 *    路径 60 字节 -> FORTIFY 溢出崩溃。
 *
 * 3) 行尾追加 "/system/framework/framework.jar"
 *    hunter stat 这个路径拿到 size=21619546，与行里 dev/inode=00:00/0
 *    打架 -> 判 "libart.so 被修改"。
 *
 * 4) 原样输出
 *    detect 的 native_anon_exec 立刻从 SAFE 掉到 RISK（它数"无路径的 r-x"）。
 *
 * 5) [anon_shmem:dalvik-jit-cache]（带自洽的 dev=00:01 与 inode）
 *    又崩了，还是 FORTIFY：'prevented 8-byte write into 5-byte buffer'。
 *    这次连名字本身都危险 —— hunter 会把方括号里的名字按 '-' 切开再拷，
 *    "dalvik" 是 7 字符 + 终止符 = 8 字节，写进 5 字节缓冲。
 *    也就是说：**在名字里放任何结构化片段都可能触发它的小缓冲区**。
 *
 * ===== 现在这版：不写名字，整行不输出 =====
 *
 * 依据：这类段对双方都只是"证据"，不是功能依赖。
 *   - hunter 找不到可执行匿名段，就没有 "suspicious anonymous memory" 可报
 *   - detect 的 native_anon_exec 数到 0 个，判 SAFE
 *   - 我们给不出名字，就不会触发它任何一段按名解析的代码路径
 *
 * 行数变化不影响其它段：真实进程里这些段本来就是独立 VMA，
 * 与相邻有路径的段不共享区间，删掉不会留下空洞地址。
 */
static size_t maps_emit_anon_exec_masked(char *out, size_t w, size_t cap,
                                         const char *line, size_t len, int seq) {
    (void)out; (void)w; (void)cap; (void)line; (void)len; (void)seq;
    return w;   /* 直接不输出这一行 */
}

static size_t maps_emit_line(char *out, size_t w, size_t cap, const struct maps_ent *e) {
    char head[80];
    int hn = 0;
    size_t i = 0;

    /*
     * 手工把 start/end 写成十六进制，不用 snprintf。
     *
     * 与 is_trace 的 sscanf 同理：这段对每一行都跑，
     * 而 Bionic 的 snprintf 单次开销在几十微秒量级，
     * 3000 行累加成百毫秒，正好压在检测期上。
     * 十六进制格式化本身只是移位与查表，没有理由借道 printf 系列。
     */
    {
        static const char hexd[] = "0123456789abcdef";
        unsigned long long v[2];
        v[0] = (unsigned long long)e->start;
        v[1] = (unsigned long long)e->end;
        for (int k = 0; k < 2; k++) {
            char tmp[17];
            int t = 0;
            unsigned long long x = v[k];
            if (x == 0) { tmp[t++] = '0'; }
            else {
                while (x && t < 16) { tmp[t++] = hexd[x & 0xf]; x >>= 4; }
            }
            while (t > 0) head[hn++] = tmp[--t];
            if (k == 0) head[hn++] = '-';
        }
        head[hn] = 0;
    }
    if (hn <= 0) return w;

    /* 原行里第一个空格之前的地址字段长度即需要替换的范围 */
    while (i < e->raw_len && e->raw[i] != ' ' && e->raw[i] != '\n') i++;
    if (w + (size_t)hn + (e->raw_len - i) + 2 > cap) return w;
    memcpy(out + w, head, (size_t)hn);
    w += (size_t)hn;
    if (i < e->raw_len) {
        memcpy(out + w, e->raw + i, e->raw_len - i);
        w += e->raw_len - i;
    }
    out[w++] = '\n';
    return w;
}

static int maps_make_clean_fd_ex(int is_smaps);
static int maps_make_clean_fd(void) { return maps_make_clean_fd_ex(0); }

static int maps_make_clean_fd_ex(int is_smaps) {
    char *raw = NULL, *out = NULL;
    size_t cap = 0, w = 0;
    int n, dropped = 0;
    char *line;
    long fd;


    /*
     * 时间窗口缓存，这是性能的关键。
     *
     * 实测问题：hunter 启动阶段会读 300+ 次 /proc/self/maps。
     * 早期实现每次都要「完整读 300KB → 完整哈希 300KB → 逐行解析」，
     * 累计上百 MB 的内存扫描与同等量级的 IO 解析，
     * 直接表现就是应用启动变慢、检测过程被拉长。
     *
     * 正确的做法不是把解析做得更快，而是**根本不重复做**：
     * maps 的内容在几十毫秒内不会变，而检测器连读几百次是同一个瞬间。
     * 因此这里做一个短时间窗口（默认 120ms）：窗口内直接复用上一次的
     * 结果 fd，不读内核、不哈希、不解析。
     *
     * 窗口之外一定重新生成，保证内容不会长期过期。
     */
    {
        struct timespec now;
        /* TTL 缓存已移除：这里原本会在 120ms 窗口内复用上次结果 */
    }

    n = maps_read_all(&raw, &cap);
    if (n <= 0) {
        static int once = 0;
        if (!once) { once = 1; ahb_filelog("MAPS read_all failed n=%d", n); }
        return -1;
    }

    out = (char *)malloc(cap);
    if (!out) { free(raw); return -1; }

    /*
     * 逐行处理，同时把"同一文件被拆碎的连续可执行段"合并回一行。
     *
     * 背景（实测数据）：
     *   未经 LSPosed 注入的进程： linker64 的 r-x 是 1 段
     *   被 LSPosed 注入的进程：   linker64 的 r-x 被拆成 3 段
     *     7db7d46000-7db7dd0000 r-xp 00058000
     *     7db7dd0000-7db7dd1000 r-xp 000e2000
     *     7db7dd1000-7db7e9f000 r-xp 000e3000
     *
     * 这是注入框架改页保护时内核拆 VMA 的结果，和被保护应用无关。
     * 但任何按 maps 解析库布局的检测器都会因此算错段基址：
     * hunter 就取到了被拆出来的那页当基址，加上它硬编码的段长后
     * 越过真实映射末尾，SIGSEGV 的地址每次逐字节相同。
     *
     * 这里在**视图**上把同文件、地址相邻、权限相同的可执行段合并成一行，
     * 让解析方看到的布局与"未注入进程"一致。真实映射一个字节都没动。
     */
    {
        /*
         * 逐行处理，并把"同一文件被拆碎的连续可执行段"在视图上合并回一行。
         *
         * 必须保持原行的字段格式：解析方是按 "%llx-%llx %s %llx %s %llu %s"
         * 这种固定格式来读的。早期版本用 snprintf 重组时把连字符两侧的空格
         * 与分隔符写错（变成 "地址-地址-r-xp"），导致解析方拿不到正确字段，
         * 段长度算错、越界读取，直接 SIGSEGV。
         *
         * 因此这里只做一件事：把相邻同文件的可执行段的**结束地址**往后延，
         * 其余字段原样保留并原样输出。
         */
        unsigned long long prev_e = 0;
        char prev_perm[8] = {0}, prev_path[AHB_PATH_MAX] = {0};
        struct maps_ent prev;
        int have_prev = 0;
        memset(&prev, 0, sizeof(prev));

        line = raw;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            size_t len = nl ? (size_t)(nl - line + 1) : strlen(line);

            /*
             * 命中痕迹的行：不删除，只改写路径。
             *
             * 这里曾经是 dropped++ 然后 continue —— 整行删掉。
             * 那是错的，而且错得很隐蔽：
             *
             * 实测目标应用（hunter 6.58）按行解析 /proc/self/maps 并累加偏移，
             * 它拿到的行数一旦与我们视图不一致，后面所有按索引取的地址就整体
             * 错位。崩出来的故障地址每次都是本进程 linker64 最后一个映射的
             * 结束地址（如 0x7422f30000，与该 [anon:.bss] 的末端一字节不差），
             * 而每次触发时的长度都不同（0xeb / 0x10f / 0xb8）—— 正是"按行
             * 累加后越过末尾"的指纹。
             *
             * 所以规则改成：**行数、地址、字段个数全部保持不变**，
             * 只把路径那一段换成一个中性的、格式合法的系统路径。
             * 检测器仍然看到同样多的行、同样的地址布局，不会错位。
             */
            if (maps_line_is_trace_len(line, nl ? (size_t)(nl - line) : strlen(line))) {
                dropped++;
                w = maps_emit_masked_line(out, w, cap, line,
                                          nl ? (size_t)(nl - line) : strlen(line),
                                          dropped);
                if (!nl) break;
                line = nl + 1;
                continue;
            }

            {
                struct maps_ent ce;
                if (maps_parse_line(line, nl ? (size_t)(nl - line) : strlen(line), &ce)) {
                    /*
                     * 显式丢弃匿名可执行段。
                     *
                     * 检测器把"无路径的 r-x 段"当作注入跳板来数。
                     * 判定必须只看本行：权限是 r-x 且路径为空。
                     */
                    if (ce.perm[0] == 'r' && ce.perm[1] == '-' &&
                        ce.perm[2] == 'x' && ce.path[0] == '\0') {
                        /*
                         * 匿名可执行段：同样不删行，只给它一个看起来正常的
                         * 名字（JIT 代码缓存本来就会以这种形式出现在真实进程里）。
                         */
                        dropped++;
                        w = maps_emit_anon_exec_masked(out, w, cap, line,
                                                       nl ? (size_t)(nl - line) : strlen(line),
                                                       dropped);
                        if (!nl) break;
                        line = nl + 1;
                        continue;
                    }

                    /*
                     * linker64 的相邻可执行碎片段：合并。
                     *
                     * 为什么这里必须合并：实测本机 linker64 被拆成了
                     * 0x7422d9d000 / 0x7422e27000 / 0x7422e28000 等多个
                     * 4KB~大段的 r-xp 碎片 —— 这是 lsplant 装 inline hook
                     * 时改页权限留下的 VMA 分裂，属于系统级注入的必然结果，
                     * 我们改不了。
                     *
                     * 目标应用（hunter 6.58）会扫 linker64 找这类碎片，
                     * 它按段起点加固定窗口算读取地址，碎片一多就算过头，
                     * 读到最后一个映射的末尾之外 → SIGSEGV。
                     * 实测：故障地址每次恰好等于最后一段的结束地址。
                     *
                     * 合并成连续段后，它看到的 linker64 与未注入时一致，
                     * 不会算出越界地址。
                     */
                    /*
                     * 同文件、地址相邻、权限相同的可执行段：合并成一行。
                     *
                     * 这里原本只匹配 "linker64"，那是按第一个遇到的样本
                     * （hunter 崩溃在 linker64 越界）窄化出来的。
                     * 实测同样的问题也出现在 libart.so 上：
                     *
                     *   7a8e44e000-7a8e44f000 r-xp 00ba0000 .../libart.so
                     *   7a8e44f000-7a8e736000 r-xp 00ba1000 .../libart.so
                     *
                     * 那个 4KB 的碎片是我们自己造成的 —— 为了让
                     * UpdateEntrypointsForDebuggable 的入口可写，
                     * 对该页做过 mprotect，内核因此把 VMA 拆开了。
                     * hunter 6.58 会把它当成"libart.so 被 hook"的直接证据：
                     *
                     *   find libart.so hooked 4096
                     *   exec address start-> 0x7a8e44e000
                     *   exec address end->   0x7a8e44f000
                     *
                     * 判据改成通用形式：同路径 + 权限相同 + 首尾相接。
                     * 这对任何被注入框架拆碎过的库都成立，不针对某个检测器。
                     */
                    if (!is_smaps && have_prev && ce.path[0] &&
                        strcmp(prev_path, ce.path) == 0 &&
                        strncmp(ce.perm, "r-x", 3) == 0 &&
                        strncmp(prev_perm, "r-x", 3) == 0 &&
                        ce.start == prev_e) {
                        prev_e = ce.end;   /* 只延长结束地址，不新增行 */
                        if (!nl) break;
                        line = nl + 1;
                        continue;
                    }

                    if (have_prev) {
                        prev.end = prev_e;      /* 合并过的结束地址要同步 */
                        w = maps_emit_line(out, w, cap, &prev);
                    }

                    prev = ce;
                    prev_e = ce.end;
                    strncpy(prev_perm, ce.perm, sizeof(prev_perm) - 1);
                    strncpy(prev_path, ce.path, sizeof(prev_path) - 1);
                    have_prev = 1;
                } else {
                    /* 解析失败就原样输出，绝不做任何加工 */
                    if (w + len < cap) { memcpy(out + w, line, len); w += len; }
                    have_prev = 0;
                }
            }
            if (!nl) break;
            line = nl + 1;
        }
        if (have_prev) {
            prev.end = prev_e;
            w = maps_emit_line(out, w, cap, &prev);
        }
    }
    g_maps_filtered++;
    (void)dropped;

    /*
     * 这里原来有一段诊断 dump：把过滤后的 maps 内容写到目标 App 自己的
     * files/maps_filtered，用来核对过滤结果长什么样。
     *
     * 整段删除，不再保留任何形式的文件写入。
     * 理由：它写在目标应用的私有目录里，对方 listFiles() 就能发现；
     * 而且诊断用途完全可以用 logcat 的计数行替代，不需要落盘。
     */

    fd = syscall(SYS_memfd_create, "maps", 0);
    if (fd < 0) {
        static int once = 0;
        if (!once) { once = 1; ahb_filelog("MAPS memfd failed errno=%d", errno); }
        free(raw); free(out); return -1;
    }
    {
        size_t off = 0;
        while (off < w) {
            long k = syscall(SYS_write, (int)fd, out + off, w - off);
            if (k <= 0) {
                syscall(SYS_close, (int)fd);
                free(raw); free(out);
                return -1;
            }
            off += (size_t)k;
        }
    }
    syscall(SYS_lseek, (int)fd, 0, SEEK_SET);

    /* 记录时间戳 + 保存内容副本供窗口内复用 */
    /* TTL 缓存已移除：不再保存任何跨调用的缓冲副本 */

    free(raw);
    free(out);
    return (int)fd;
}

/* ---------------- libc 真实地址 ---------------- */

typedef int  (*open_fn)(const char *, int, ...);
typedef int  (*openat_fn)(int, const char *, int, ...);
typedef void *(*fopen_fn)(const char *, const char *);
typedef struct __dirstream *(*opendir_fn)(const char *);
typedef void *(*popen_fn)(const char *, const char *);

/*
 * clang 对"flags 是编译期常量"的 open 会改调 __open_2 / __openat_2
 * （省掉可变参数处理）。检测器读 /proc/self/maps 这类路径全是常量 flags，
 * 所以它极可能根本不走 open@plt，而是走 __open_2@plt。
 * 只接管 open/openat 会漏掉整条真实路径——这是上一版过滤已触发但仍失败的原因。
 */
static open_fn   g_real_open      = NULL;
static openat_fn g_real_openat    = NULL;
static fopen_fn  g_real_fopen     = NULL;
/* maps 快照：由 maps_read_all 走真实 syscall 读入，供补丁扫描逐行解析 */
static char   *g_maps_snap      = NULL;
static size_t  g_maps_snap_len  = 0;
static open_fn   g_real_open64    = NULL;
static open_fn   g_real_open_2    = NULL;
static openat_fn g_real_openat_2  = NULL;
static open_fn   g_real_open64_2  = NULL;
static opendir_fn g_real_opendir  = NULL;
static popen_fn  g_real_popen     = NULL;

/* ================= dl_iterate_phdr 视图过滤 ================= */

/*
 * 这是 maps 过滤的盲区，也是上一版"过滤生效但仍被识破"的真正原因。
 *
 * dl_iterate_phdr 不读 /proc/self/maps，而是直接遍历 linker 内部的
 * link_map 链表。任何读过 Rick 的注入检测都会优先用它，因为它更快、
 * 更权威，而且天然不受 /proc 层伪造的影响。
 *
 * 处理方式：包一层回调。框架相关的库直接 return 0 跳过，
 * 不交给对方的回调——对方永远不知道那个库存在过。
 */
typedef int (*dl_phdr_cb)(struct dl_phdr_info *, size_t, void *);
typedef int (*dl_iterate_fn)(dl_phdr_cb, void *);

static dl_iterate_fn g_real_dl_iterate = NULL;

/*
/*
 * 回调上下文通过 data 参数传递，不使用任何共享或线程局部变量。
 *
 * 这里连踩两坑：
 *
 * 1) 用全局变量存 cb/data：dl_iterate_phdr 会被多线程并发调用
 *    （hunter 就在 RxCachedThreadS 线程池里并行调用），两个线程互相覆盖后，
 *    A 的遍历途中调到的是 B 的回调，目标于是拿到属于别人的 dl_phdr_info，
 *    据此算出的库基址整体偏移，再按错误基址读内存就踩到未映射空洞。
 *
 * 2) 改用 __thread 隔离：Android 交叉编译把它展开成 emutls 调用，
 *    产物依赖 __emutls_get_address，Bionic 上 dlopen 直接失败
 *    （cannot locate symbol __emutls_get_address），模块整个装不上。
 *
 * 正解是不需要共享状态：dl_iterate_phdr 会把 data 原样回传给回调，
 * 上下文放在调用方栈上即可，天然线程安全且无运行时依赖。
 */
typedef struct {
    dl_phdr_cb cb;
    void      *user_data;
} maps_phdr_ctx;

static int maps_phdr_trampoline(struct dl_phdr_info *info, size_t sz, void *data) {
    maps_phdr_ctx *ctx = (maps_phdr_ctx *)data;
    if (info && info->dlpi_name && info->dlpi_name[0]) {
        if (maps_line_is_trace(info->dlpi_name)) return 0;
    }
    if (!ctx || !ctx->cb) return 0;
    return ctx->cb(info, sz, ctx->user_data);
}

static int maps_dl_iterate_wrap(dl_phdr_cb cb, void *data) {
    g_c_dlphdr++;
    maps_phdr_ctx ctx;
    if (!g_real_dl_iterate) {
        g_real_dl_iterate = (dl_iterate_fn)dlsym(RTLD_NEXT, "dl_iterate_phdr");
        if (!g_real_dl_iterate) return -1;
    }
    ctx.cb = cb;
    ctx.user_data = data;
    g_mapshdr_calls++;
    return g_real_dl_iterate(maps_phdr_trampoline, &ctx);
}


static void maps_resolve_reals(void) {
    if (!g_real_open)      g_real_open      = (open_fn)dlsym(RTLD_NEXT, "open");
    if (!g_real_openat)    g_real_openat    = (openat_fn)dlsym(RTLD_NEXT, "openat");
    if (!g_real_fopen)     g_real_fopen     = (fopen_fn)dlsym(RTLD_NEXT, "fopen");
    if (!g_real_open64)    g_real_open64    = (open_fn)dlsym(RTLD_NEXT, "open64");
    if (!g_real_open_2)    g_real_open_2    = (open_fn)dlsym(RTLD_NEXT, "__open_2");
    if (!g_real_openat_2)  g_real_openat_2  = (openat_fn)dlsym(RTLD_NEXT, "__openat_2");
    if (!g_real_open64_2)  g_real_open64_2  = (open_fn)dlsym(RTLD_NEXT, "__open64_2");
    if (!g_real_opendir)   g_real_opendir   = (opendir_fn)dlsym(RTLD_NEXT, "opendir");
    if (!g_real_popen)     g_real_popen     = (popen_fn)dlsym(RTLD_NEXT, "popen");
    if (!g_real_exit)      g_real_exit      = (exit_fn)dlsym(RTLD_NEXT, "exit");
    if (!g_real__exit)     g_real__exit     = (_exit_fn)dlsym(RTLD_NEXT, "_exit");
    if (!g_real_kill)      g_real_kill      = (kill_fn)dlsym(RTLD_NEXT, "kill");
    if (!g_real_raise)     g_real_raise     = (raise_fn)dlsym(RTLD_NEXT, "raise");
    if (!g_real_abort)     g_real_abort     = (abort_fn)dlsym(RTLD_NEXT, "abort");
    if (!g_real_tgkill)    g_real_tgkill    = (tgkill_fn)dlsym(RTLD_NEXT, "tgkill");
    if (!g_real_exit_group) g_real_exit_group = (exit_group_fn)dlsym(RTLD_NEXT, "exit_group");
}

/* ---------------- 包装函数 ---------------- */

/* 前向声明：包装函数里要用到，定义在后面 */
static int  maps_patch_got_all(void);

/* 定义放这里，避免"只有声明没有定义"被链接成未定义符号 */
static void maps_lazy_rescan(void) {
    static int calls_seen = 0;
    static int last_at = 0;
    calls_seen++;
    /* 频率大幅下调：真正需要补扫的窗口只有启动那一下 */
    if (last_at == 0 || calls_seen - last_at >= 2000) {
        last_at = calls_seen;
        if (calls_seen <= 2 || (calls_seen % 2000) == 0) {
            maps_patch_got_all();
        }
    }
}

/* 前置声明：GOT 补丁表要引用，实体在文件末尾 */
void *ahb_dlopen_wrap(const char *name, int flags);

/* 真实 dlopen，绕开本文件的包装。自用。 */
void *ahb_real_dlopen_raw(const char *name);
void *ahb_android_dlopen_ext_wrap(const char *name, int flags, const void *extinfo);

int ahb_libview_fd_for(const char *path);
static int ahb_is_libview_target(const char *path);

/* ================= 其它 /proc 入口的过滤 ================= */

/*
 * 为什么必须把过滤面从一个入口扩到多个
 * ------------------------------------
 * 之前只伪造了 /proc/self/maps 一份视图，其余入口全部原样透传。
 * 这在反检测上是致命的：单独看 maps 是干净的，可只要换成 smaps、
 * 或者去看 /proc/mounts，同一个事实立刻露出来。对方不需要多聪明，
 * 两个入口一对就够。
 *
 * 实测依据（在本机 hunter 6.58 进程里统计）：
 *   maps  命中 antihookbypass/liblspd/lsplant/lsposed 共 6 行
 *   smaps 同样 6 行 —— 因为 smaps 路径里不含 "/maps" 子串，
 *         原有的路径判定根本没覆盖到它
 *
 * 所以这里按"同一事实在每个入口都一致"来补：
 *   - smaps      : 与 maps 同样的路径改写（但不做段合并，见下）
 *   - mounts 系  : 丢掉携带 root/模块目录的行
 *   - modules    : 丢掉携带可疑模块名的行
 *
 * smaps 为什么不能做段合并：
 *   smaps 每个映射下面跟着一串明细行（Size/KernelPageSize/Rss...）。
 *   段合并依赖"相邻两行是映射行"，而明细行会打断这个判断；
 *   强行合并还会把明细行的归属搞错。宁可 smaps 保持未合并，
 *   也不能输出结构错乱的内容——错乱本身就比泄漏更容易被识别。
 */

/*
 * smaps / smaps_rollup 判定。
 *
 * 必须支持任意 pid，理由与 maps 完全相同：
 * 目标是从子进程读「主进程」的 /proc/<pid>/smaps，
 * 只认 self / 本pid / 父pid 会整条漏掉。
 *
 * smaps 比 maps 更敏感 —— 它带 Pss/Swap 等逐段统计，
 * 漏掉一处就能被拿去做内存指纹。
 */
static int ahb_is_smaps_path(const char *path) {
    char want[64];
    const char *p2;
    int got = 0;

    if (!path) return 0;
    if (strcmp(path, "/proc/self/smaps") == 0 ||
        strcmp(path, "/proc/self/smaps_rollup") == 0) return 1;
    snprintf(want, sizeof(want), "/proc/%d/smaps", (int)getpid());
    if (strcmp(path, want) == 0) return 1;
    snprintf(want, sizeof(want), "/proc/%d/smaps", (int)getppid());
    if (strcmp(path, want) == 0) return 1;

    /* 任意 pid：/proc/<num>/smaps 或 /proc/<num>/smaps_rollup */
    if (strncmp(path, "/proc/", 6) != 0) return 0;
    p2 = path + 6;
    while (*p2 >= '0' && *p2 <= '9') { got = 1; p2++; }
    if (!got) return 0;
    if (strcmp(p2, "/smaps") == 0 || strcmp(p2, "/smaps_rollup") == 0) return 1;
    return 0;
}

static int ahb_is_mounts_path(const char *path) {
    if (!path) return 0;
    if (!strcmp(path, "/proc/mounts") ||
        !strcmp(path, "/proc/self/mounts") ||
        !strcmp(path, "/proc/mountinfo") ||
        !strcmp(path, "/proc/self/mountinfo") ||
        !strcmp(path, "/proc/mountstats") ||
        !strcmp(path, "/proc/self/mountstats")) return 1;

    /*
     * 带 pid 的形式：/proc/<pid>/mounts 等。
     *
     * 必须单列。实测 hunter 是在**子进程里**读主进程的
     * /proc/<pid>/mounts 来判断 root 的，路径里带的是对方的 pid，
     * 上面那批精确比较一条都匹配不上，于是整条过滤被绕过，
     * 它直接读到：
     *
     *   /dev/block/dm-39 /data/adb/modules/murongruyan/... f2fs rw,...
     *
     * 然后判定 "Check Find Root In Mounts" 命中。
     */
    if (strncmp(path, "/proc/", 6) == 0) {
        const char *p = path + 6;
        const char *end = p;
        while (*end >= '0' && *end <= '9') end++;
        if (end > p && *end == '/') {
            const char *rest = end + 1;
            if (!strcmp(rest, "mounts") || !strcmp(rest, "mountinfo") ||
                !strcmp(rest, "mountstats")) return 1;
        }
    }
    return 0;
}

static int ahb_is_modules_path(const char *path) {
    return path && !strcmp(path, "/proc/modules");
}

/* 整文件读入（走真实 syscall，避免递归回自己的包装） */
static char *ahb_read_file_all(const char *path, size_t *out_len) {
    size_t cap = 256 * 1024, len = 0;
    char *buf;
    long fd = (long)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return NULL;
    buf = (char *)malloc(cap);
    if (!buf) { syscall(SYS_close, (int)fd); return NULL; }
    for (;;) {
        long k;
        if (len + 65536 > cap) {
            char *nb;
            if (cap >= 16u * 1024u * 1024u) break;
            cap *= 2;
            nb = (char *)realloc(buf, cap);
            if (!nb) { free(buf); syscall(SYS_close, (int)fd); return NULL; }
            buf = nb;
        }
        k = (long)syscall(SYS_read, (int)fd, buf + len, cap - len - 1);
        if (k <= 0) break;
        len += (size_t)k;
    }
    syscall(SYS_close, (int)fd);
    buf[len] = 0;
    *out_len = len;
    return buf;
}

/* 从已打开的 fd 读全文（自检用；读前 seek 到 0） */
static char *ahb_read_file_all_fd(int fd, size_t *out_len) {
    size_t cap = 256 * 1024, len = 0;
    char *buf;
    if (fd < 0) return NULL;
    syscall(SYS_lseek, fd, 0, SEEK_SET);
    buf = (char *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        long k;
        if (len + 65536 > cap) {
            char *nb;
            if (cap >= 16u * 1024u * 1024u) break;
            cap *= 2;
            nb = (char *)realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        k = (long)syscall(SYS_read, fd, buf + len, cap - len - 1);
        if (k <= 0) break;
        len += (size_t)k;
    }
    buf[len] = 0;
    *out_len = len;
    return buf;
}

static int ahb_memfd_from_buf(const char *buf, size_t len) {
    size_t off = 0;
    int fd = (int)syscall(SYS_memfd_create, "ahb", 0);
    if (fd < 0) return -1;
    while (off < len) {
        long k = syscall(SYS_write, (int)fd, buf + off, len - off);
        if (k <= 0) { syscall(SYS_close, fd); return -1; }
        off += (size_t)k;
    }
    syscall(SYS_lseek, (int)fd, 0, SEEK_SET);
    return fd;
}

/*
 * 一行里是否带着"这个设备不干净"的证据。
 *
 * mounts 与 modules 用不同的词表：mounts 关注被挂进来的模块目录与
 * 伪装成文件系统的 root 实现；modules 关注内核模块名。
 *
 * 判定用有界搜索（ahb_memstr），不用 strstr：这些缓冲区没有逐行
 * 加 '\0'，strstr 会越过本行一直扫到缓冲区末尾，行数一多就非常慢。
 */
static int ahb_mount_line_bad(const char *line, size_t len) {
    static const char *const mk[] = {
        "/data/adb", "KSU", "kernelsu", "KernelSU",
        "magisk", "Magisk", "apatch", "APatch",
        "zygisk", "Zygisk", "riru", "Riru", NULL
    };
    const char *const *m;
    for (m = mk; *m; m++) if (ahb_memstr(line, len, *m)) return 1;
    return 0;
}

static int ahb_module_line_bad(const char *line, size_t len) {
    static const char *const mk[] = {
        "kernelsu", "ksu_", "KSU", "magisk", "apatch",
        "zygisk", "frida", "dobby", NULL
    };
    const char *const *m;
    for (m = mk; *m; m++) if (ahb_memstr(line, len, *m)) return 1;
    return 0;
}

/* 逐行过滤：丢掉可疑整行，其余原样保留 */
static int ahb_make_text_filtered_fd(const char *path, int mounts_mode) {
    size_t len = 0, w = 0;
    char *raw, *out, *p;
    int fd;
    raw = ahb_read_file_all(path, &len);
    if (!raw) return -1;
    out = (char *)malloc(len + 2);
    if (!out) { free(raw); return -1; }
    p = raw;
    while (p && *p) {
        char *nl = strchr(p, '\n');
        size_t L = nl ? (size_t)(nl - p + 1) : strlen(p);
        size_t body = nl ? (size_t)(nl - p) : strlen(p);
        int bad = mounts_mode ? ahb_mount_line_bad(p, body)
                              : ahb_module_line_bad(p, body);
        if (!bad) { memcpy(out + w, p, L); w += L; }
        if (!nl) break;
        p = nl + 1;
    }
    fd = ahb_memfd_from_buf(out, w);
    free(raw);
    free(out);
    return fd;
}

/*
 * 统一入口：给一个路径，返回"应该交给对方的 fd"，没有则 -1。
 * 所有 open/openat/fopen 包装都只调这一个函数，避免各入口漏配。
 */
static int ahb_proc_filter_wanted(const char *path) {
    return maps_path_is_self(path) || ahb_is_smaps_path(path) ||
           ahb_is_mounts_path(path) || ahb_is_modules_path(path);
}

/*
 * 这个路径会不会被过滤（只看分流判定，不真的生成 fd）。
 * 自检专用，避免为了"测一下"去分配一整份 memfd。
 */
static int ahb_path_would_filter(const char *path) {
    if (!path) return 0;
    if (ahb_is_smaps_path(path)) return 1;
    if (maps_path_is_self(path)) return 1;
    if (ahb_is_mounts_path(path)) return 1;
    if (ahb_is_modules_path(path)) return 1;
    return 0;
}

static int ahb_filtered_fd_for(const char *path) {
    if (!path) return -1;
    if (ahb_is_smaps_path(path)) return maps_make_clean_fd_ex(1);
    if (maps_path_is_self(path)) return maps_make_clean_fd_ex(0);
    if (ahb_is_mounts_path(path)) return ahb_make_text_filtered_fd(path, 1);
    if (ahb_is_modules_path(path)) return ahb_make_text_filtered_fd(path, 0);
    return -1;
}

static void ahb_jvmti_tick_from_open(void);

static int maps_open_wrap(const char *path, int flags, mode_t mode) {
    struct timespec _ts0, _ts1;
    clock_gettime(CLOCK_MONOTONIC, &_ts0);
    g_c_open++;
    maps_resolve_reals();
    ahb_probe_path(path);
    /*
     * 用 open 这条高频主线程路径驱动 JVMTI 中和。
     *
     * 为什么不用专门线程：实测本进程里 pthread_create 在 JNI_OnLoad
     * 阶段整体不可用（JWSTART 恒开探针 0 条、FASTPATCH 日志 0 条），
     * 所有"起线程轮询"的方案都不成立。
     * 而 open 包装在主线程同步执行、启动期被调几百次，
     * 是天然且可靠的挂载点。
     */
    ahb_jvmti_tick_from_open();
    /*
     * JVMTI 插件：在 open 层直接拒绝。
     *
     * 为什么必须在 open 层：hunter 的 xDL 是自己 open + mmap 手工加载，
     * 全程不经过 dlopen / android_dlopen_ext（实测 android_dlopen_ext
     * 调用 0 次），所以打在 dlopen 上的拦截一次都命中不到。
     *
     * 它有 "xdl_open ERROR" 的优雅失败分支，拿不到句柄不会崩。
     *
     * 这条替代了原来「改 libart 代码段」的做法 —— 那个做法会被跨进程
     * CRC 比对抓出来（见 AHB_ART_NEUTRALIZE 的注释）。
     */
#if AHB_BLOCK_JVMTI
    if (ahb_is_jvmti_path(path)) {
#if AHB_SAY
        AHB_SAYL("JVMTI 拒绝 open: %s", path);
#endif
        errno = ENOENT;
        return -1;
    }
#endif
    if (ahb_is_hidden_file(path)) {
        LOGE("隐藏文件: %s", path);
        maps_ensure_raw_syscall();
        errno = ENOENT;
        return -1;
    }
    g_maps_open_calls++;
    maps_lazy_rescan();
    /* 诊断：记录实际经过的路径，确认目标用什么姿势读 maps */
    {
        /* 凡是带 /maps 的路径一律记录：这是判断"它到底怎么读地图"的唯一依据 */
        static int dbg_left = 200;
        if (dbg_left > 0 && path && strstr(path, "/maps")) {
            dbg_left--;
        }
    }
    if (ahb_is_libview_target(path)) {
        int lv = ahb_libview_fd_for(path);
        if (lv >= 0) return lv;
    }
    {
        struct timespec _s0, _s1;
        int fd;
        clock_gettime(CLOCK_MONOTONIC, &_s0);
        fd = ahb_filtered_fd_for(path);
        clock_gettime(CLOCK_MONOTONIC, &_s1);
        if (fd >= 0) {
            if (ahb_proc_filter_wanted(path)) {
                g_c_self++;
                g_t_self += (unsigned long)((_s1.tv_sec - _s0.tv_sec) * 1000000L
                                            + (_s1.tv_nsec - _s0.tv_nsec) / 1000L);
            }
            clock_gettime(CLOCK_MONOTONIC, &_ts1);
            g_t_open += (unsigned long)((_ts1.tv_sec - _ts0.tv_sec) * 1000000L
                                        + (_ts1.tv_nsec - _ts0.tv_nsec) / 1000L);
            return fd;
        }
    }
    if (g_real_open) {
        int r = g_real_open(path, flags, mode);
        clock_gettime(CLOCK_MONOTONIC, &_ts1);
        g_t_open += (unsigned long)((_ts1.tv_sec - _ts0.tv_sec) * 1000000L
                                    + (_ts1.tv_nsec - _ts0.tv_nsec) / 1000L);
        return r;
    }
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

static int maps_openat_wrap(int dirfd, const char *path, int flags, mode_t mode) {
    g_c_openat++;
    maps_resolve_reals();
    if (ahb_is_hidden_file(path)) {
        LOGE("隐藏文件: %s", path);
        maps_ensure_raw_syscall();
        errno = ENOENT;
        return -1;
    }

    ahb_probe_path(path);
    g_maps_open_calls++;
    {
        int fd = ahb_filtered_fd_for(path);
        if (fd >= 0) return fd;
    }
    if (g_real_openat) return g_real_openat(dirfd, path, flags, mode);
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

static void *maps_fopen_wrap(const char *path, const char *mode) {
    g_c_fopen++;
    maps_resolve_reals();
    ahb_probe_path(path);
    g_maps_open_calls++;
    maps_lazy_rescan();
    {
        static int dbg_left = 20;
        if (dbg_left > 0 && path && strstr(path, "/proc/")) {
            dbg_left--;
            ahb_filelog("FOPEN %s", path);
        }
    }
    {
        int fd = ahb_filtered_fd_for(path);
        if (fd >= 0) {
            FILE *f = fdopen(fd, "r");
            if (f) return (void *)f;
            syscall(SYS_close, fd);
        }
    }
    if (g_real_fopen) return (void *)g_real_fopen(path, mode);
    return NULL;
}

/* __open_2：flags 为常量的 open，clang 的默认落点 */
static int maps_open_2_wrap(const char *path, int flags) {
    g_c_open2++;
    maps_resolve_reals();
    g_maps_open_calls++;
    if (ahb_proc_filter_wanted(path)) {
        int fd = ahb_filtered_fd_for(path);
        if (fd >= 0) return fd;
        }
    if (g_real_open_2) return g_real_open_2(path, flags);
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, 0);
}

static int maps_open64_wrap(const char *path, int flags, mode_t mode) {
    g_c_open64++;
    maps_resolve_reals();
    g_maps_open_calls++;
    if (ahb_proc_filter_wanted(path)) {
        int fd = ahb_filtered_fd_for(path);
        if (fd >= 0) return fd;
        }
    if (g_real_open64) return g_real_open64(path, flags, mode);
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

static int maps_openat_2_wrap(int dirfd, const char *path, int flags) {
    g_c_openat2++;
    maps_resolve_reals();
    g_maps_open_calls++;
    if (ahb_proc_filter_wanted(path)) {
        int fd = ahb_filtered_fd_for(path);
        if (fd >= 0) return fd;
        }
    if (g_real_openat_2) return g_real_openat_2(dirfd, path, flags);
    return (int)syscall(SYS_openat, dirfd, path, flags, 0);
}

static int maps_open64_2_wrap(const char *path, int flags) {
    g_c_open642++;
    maps_resolve_reals();
    g_maps_open_calls++;
    if (ahb_proc_filter_wanted(path)) {
        int fd = ahb_filtered_fd_for(path);
        if (fd >= 0) return fd;
        }
    if (g_real_open64_2) return g_real_open64_2(path, flags);
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, 0);
}

/* opendir("/proc/self") 本身不含 maps，但目录项会暴露；只拦 maps 路径 */
static struct __dirstream *maps_opendir_wrap(const char *path) {
    g_c_opendir++;
    maps_resolve_reals();
    if (g_real_opendir) return g_real_opendir(path);
    return NULL;
}

/*
 * popen：检测器常写 "cat /proc/self/maps | grep libart.so"。
 * 这条路径不经过我们接管的任何 fd 函数，必须单独处理：
 * 命中 maps 时改用已过滤的临时文件。
 */
static void *maps_popen_wrap(const char *cmd, const char *mode) {
    g_c_popen++;
    maps_resolve_reals();
    if (cmd && strstr(cmd, "/proc/self/maps")) {
        g_maps_open_calls++;
        int fd = ahb_filtered_fd_for("/proc/self/maps");
        if (fd >= 0) {
            /*
             * 让 cat 直接读 /proc/self/fd/<n>，不再往磁盘落临时文件。
             *
             * 原因：模块跑在目标应用的进程里，任何落盘文件都写在它自己的
             * 私有目录或 /data/local/tmp 下，对方扫一眼就能发现。
             * 而"把内容先写文件、再 cat 这个文件"这条旧路径，
             * 无论写在哪儿都会留下痕迹。
             *
             * 现在这个 fd 本身就是内存里的 memfd（maps_make_clean_fd 返回的），
             * cat 通过 /proc/self/fd 读它即可 —— 全程不碰磁盘。
             */
            {
                char nc[96];
                snprintf(nc, sizeof(nc), "cat /proc/self/fd/%d", fd);
                if (g_real_popen) return g_real_popen(nc, mode);
            }
        }
    }
    if (g_real_popen) return g_real_popen(cmd, mode);
    return NULL;
}



/* ---------------- GOT 接管 ---------------- */

/*
 * 为什么必须改调用点：libc 先于本模块加载，动态符号解析早已指向
 * libc 的实现。在本 so 里定义同名函数对别人的调用点毫无影响。
 *
 * 与 process_vm_readv 的接管共用同一策略：
 * 只认"值精确等于 libc 真实地址"的 8 字节字（命中即已解析的 GOT）；
 * 保护位不参与过滤 —— full RELRO 的 GOT 是 r--p，按 rw 过滤会整个漏掉。
 */
/* ================= 按重定位表接管（主路径） ================= */

/*
 * 为什么不再用"槽里的值 == dlsym 得到的地址"来匹配：
 *
 *  - __open_2 / __openat_2 / __open64_2 是 libc 的内部符号，
 *    dlsym(RTLD_NEXT, ...) 根本取不到，返回 NULL；
 *    于是这些分支永远不成立，目标的 GOT 一个槽都打不中。
 *  - 同一符号在 libc 里可能有多个实现互相转发，地址并不唯一。
 *  - 懒绑定库的槽里放的是自己的 PLT 桩，不是 libc 地址。
 *
 * 实测：libhunter.so 明明进入了扫描列表（r-xp / r--p / rw-p 三段都有），
 * 却连一行 "MAPS patch" 都没有 —— 就是上面第一条。
 *
 * 正确做法：读 ELF 自己的 .rela.plt / .rela.dyn，按**符号名**找槽，
 * 命中就无条件写入。这样与"槽里现在是什么值"完全无关。
 */

#define AHB_MAX_SO      768
#define AHB_MAX_SEG     8192

#define R_AARCH64_JUMP_SLOT  1026
#define R_AARCH64_GLOB_DAT   1025

typedef struct {
    char      path[AHB_PATH_MAX];
    uintptr_t base;
    int       tried;
    int       miss_count;
    int       has_target;   /* 该库的重定位表里是否存在我们要接管的符号 */
} ahb_so_ent;

typedef struct {
    uintptr_t start;
    uintptr_t end;
    char      perm[8];
} ahb_seg_ent;

static ahb_so_ent  g_so_tab[AHB_MAX_SO];
static int         g_so_n = 0;

/* 已接管过的库路径（跨轮持久） */
#define AHB_DONE_MAX 512
static char g_done_paths[AHB_DONE_MAX][AHB_PATH_MAX];
static int  g_done_n = 0;

static int ahb_already_done(const char *path) {
    int i;
    for (i = 0; i < g_done_n; i++) {
        if (strcmp(g_done_paths[i], path) == 0) return 1;
    }
    return 0;
}

static void ahb_mark_done(const char *path) {
    if (g_done_n >= AHB_DONE_MAX) return;
    strncpy(g_done_paths[g_done_n], path, AHB_PATH_MAX - 1);
    g_done_paths[g_done_n][AHB_PATH_MAX - 1] = 0;
    g_done_n++;
}
static ahb_seg_ent g_seg_tab[AHB_MAX_SEG];
static int         g_seg_n = 0;

static void ahb_seg_reset(void) { g_seg_n = 0; }

static void ahb_seg_add(uintptr_t s, uintptr_t e, const char *perm) {
    if (g_seg_n >= AHB_MAX_SEG) return;
    g_seg_tab[g_seg_n].start = s;
    g_seg_tab[g_seg_n].end = e;
    strncpy(g_seg_tab[g_seg_n].perm, perm, sizeof(g_seg_tab[0].perm) - 1);
    g_seg_tab[g_seg_n].perm[sizeof(g_seg_tab[0].perm) - 1] = 0;
    g_seg_n++;
}

/* 查某地址所在段的原始保护位；查不到按只读处理（GOT 常见形态） */
static void ahb_seg_perm_of(uintptr_t addr, int *out_prot) {
    int i;
    for (i = 0; i < g_seg_n; i++) {
        if (addr >= g_seg_tab[i].start && addr < g_seg_tab[i].end) {
            int prot = 0;
            const char *p = g_seg_tab[i].perm;
            if (p[0] == 'r') prot |= PROT_READ;
            if (p[1] == 'w') prot |= PROT_WRITE;
            if (p[2] == 'x') prot |= PROT_EXEC;
            *out_prot = prot;
            return;
        }
    }
    *out_prot = PROT_READ;
}

/*
 * 地址合法性校验。
 *
 * 任何一次解引用之前都必须过这一关。原因：
 *  - ELF 的 DT_* d_ptr 在有些库里是已重定位的绝对地址，有些仍是文件内偏移；
 *  - 库可能已被删除（maps 里带 " (deleted)"），段表对不上；
 *  - e_phoff / r_offset 来自不可信数据，损坏时会算出任意地址。
 * 直接把 0x3f38 这种值当指针用，就是一次 SIGSEGV。
 */
static int ahb_addr_mapped(uintptr_t a, size_t len) {
    int i;
    if (a < AHB_USER_PTR_MIN || a >= AHB_USER_PTR_MAX) return 0;
    for (i = 0; i < g_seg_n; i++) {
        if (a >= g_seg_tab[i].start && a + len <= g_seg_tab[i].end) return 1;
    }
    return 0;
}

/* ================================================================== */
/* 进程内安全读：地址失效时返回 0，绝不崩溃                             */
/* ================================================================== */

/*
 * 为什么必须有这一层（tombstone 实录）：
 *
 *   signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x742068a000
 *   #00 pc 0x5ee0  (maps_patch_got_all+1384)
 *   #01 pc 0x8784  (clv_fast_patch_thread+120)
 *
 * 崩溃点那条指令是 ldr w8,[x9]，紧跟着 cmp w8, #0x464c457f ——
 * 0x464c457f 就是 "\x7fELF"。也就是说它在读 ELF 魔数。
 *
 * 而读之前明明调过 ahb_addr_mapped() 并且通过了。问题就在这里：
 * 那个判断查的是**上一次扫描 maps 留下的段表快照**，而快照会过期。
 * 从"查到还在"到"真的去读"之间，那个库完全可能被卸载或重新映射
 * （目标应用启动阶段高频 dlopen/dlclose 自己的库）。
 * 快照说在、实际已不在，于是直接解引用就崩在宿主进程里。
 *
 * 解决思路不是"多查几次"，而是**不要直接解引用**：
 * 用 process_vm_readv 让内核替我们读。地址无效时它返回 EFAULT，
 * 我们拿到一个失败返回值，安静跳过这个库。永远不会 SIGSEGV。
 *
 * 注意必须用真实的 syscall 指针，不能走 libc 的 syscall/process_vm_readv
 * —— 那两个已经被本模块自己接管，会绕回来。
 */
static int ahb_safe_read(void *dst, uintptr_t src, size_t len);

/*
 * 读一个以 NUL 结尾的字符串，逐字节读、遇到读失败立即停。
 *
 * 为什么不能一次读一大块：符号名紧挨着 strtab 末尾时，一次读 255 字节
 * 会跨出已映射范围，process_vm_readv 整段失败 —— 于是每一个符号都被判为
 * "读不到"直接跳过。表现就是 patched=0：ELF 头读得到、重定位表读得到，
 * 偏偏一个符号名都认不出来。
 */
static int ahb_safe_read_str(char *dst, uintptr_t src, size_t cap) {
    size_t i;
    if (!dst || cap < 2) return 0;
    for (i = 0; i + 1 < cap; i++) {
        if (!ahb_safe_read(dst + i, src + i, 1)) {
            dst[i] = 0;
            return i > 0;          /* 已经读到内容就算成功 */
        }
        if (dst[i] == 0) return 1;
    }
    dst[cap - 1] = 0;
    return 1;
}

static int ahb_safe_read(void *dst, uintptr_t src, size_t len) {
    struct iovec li, ri;
    long r;
    if (!dst || !len) return 0;
    if (src < AHB_USER_PTR_MIN || src >= AHB_USER_PTR_MAX) return 0;
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return 0;
    li.iov_base = dst;
    li.iov_len  = len;
    ri.iov_base = (void *)src;
    ri.iov_len  = len;
    r = g_raw_syscall(__NR_process_vm_readv, (long)getpid(),
                      (long)&li, 1, (long)&ri, 1, 0);
    return r == (long)len;
}

static void ahb_so_note(const char *path, uintptr_t seg_start, uintptr_t file_off) {
    uintptr_t b;
    int i;
    if (file_off > seg_start) return;
    b = seg_start - file_off;
    for (i = 0; i < g_so_n; i++) {
        if (strcmp(g_so_tab[i].path, path) == 0) {
            if (b < g_so_tab[i].base) g_so_tab[i].base = b;
            return;
        }
    }
    if (g_so_n >= AHB_MAX_SO) return;
    strncpy(g_so_tab[g_so_n].path, path, AHB_PATH_MAX - 1);
    g_so_tab[g_so_n].path[AHB_PATH_MAX - 1] = 0;
    g_so_tab[g_so_n].base  = b;
    g_so_tab[g_so_n].tried = 0;
    g_so_tab[g_so_n].miss_count = 0;
    g_so_tab[g_so_n].has_target = 0;
    g_so_n++;
}

/* 是否为 libc：只允许接管 process_vm_readv，其余一律不碰 */
static int ahb_is_libc(const char *path) {
    return strstr(path, "/libc.so") != NULL;
}

/*
 * 只接管应用侧的库（/data/ 下）。
 *
 * 血的教训：给 /vendor/lib64/libllvm-glnext.so 打上 open/read/syscall 的
 * GOT 补丁之后，Vulkan 初始化直接 abort：
 *     signal 6 (SIGABRT)
 *     #01 libllvm-glnext.so
 *     #06 vulkan.adreno.so (qglinternal::vkCreateInstance)
 * 系统库对这几个函数的调用有自己的假设（返回值、errno、调用约定），
 * 被我们替换成包装后再返回，图形驱动就崩了。
 *
 * 而且从目的上说也不需要：要隐藏的是"有东西注入进了这个进程"，
 * 读地图的是应用侧的检测库和注入框架，它们全在 /data/ 下。
 * 系统库自己读 maps 与我们无关。
 *
 * 这条边界同时解决三件事：不破坏系统组件、扫描量小、加载快。
 */
static int ahb_so_is_app_side(const char *path) {
    return path && strncmp(path, "/data/", 6) == 0;
}

static int ahb_so_skip(const char *path) {
    /*
     * 绝不动 libc/libart/linker：那会破坏系统调用层与 ART 自身。
     *
     * 也绝不动**本模块自己**：模块的日志函数用 open 写文件，
     * 一旦自己的 open 槽也被改到包装上，就变成
     * ahb_filelog -> open -> maps_open_wrap -> ahb_filelog 无限递归，
     * 表现是日志写不出来、进程卡死或栈溢出。
     */
    /*
     * 系统库不再整库跳过 —— 但也不是全都装。
     *
     * 取舍：进表之后，是靠符号名逐个决定装不装（见上面 dlopen 那段）。
     * 纯转发的 dlopen/android_dlopen_ext 系统库也要装，否则收不到
     * "新库加载"通知；会改写内容的 open/read/syscall 只装应用侧。
     */
    if (!ahb_so_is_app_side(path) &&
        !strstr(path, "/libnativeloader") &&
        !strstr(path, "/libc.so") &&
        !strstr(path, "/linker")) return 1;
    /* libc 允许进入（只接管 process_vm_readv，见上面的白名单） */
    return strstr(path, "/libart.so") ||
           strstr(path, "/linker") || strstr(path, "/libbase.so") ||
           strstr(path, "/libc++.so") || strstr(path, "/libm.so") ||
           strstr(path, "libantihook_bypass");
}

/*
 * 写一个槽：走 /proc/self/mem，**不用 mprotect**。
 *
 * 为什么这一点是决定性的：
 *
 *  mprotect 单页会把内核的 VMA 拆开。实测对比（同一台机器）：
 *    未加载模块的进程： linker64 的 r-x 是 **1 段**
 *    加载模块的进程：   linker64 的 r-x 被拆成 **3 段**
 *      7db7d46000-7db7dd0000 r-xp 00058000
 *      7db7dd0000-7db7dd1000 r-xp 000e2000   ← 被单独拆出来
 *      7db7dd1000-7db7e9f000 r-xp 000e3000
 *
 *  hunter 解析 maps 时把被拆出来的那页当成代码段基址，
 *  加上它硬编码的段长后越过真实映射末尾，
 *  崩溃地址 0x7db7ed9000 每次逐字节相同，就是这个拆页结果导致的。
 *
 * /proc/self/mem 的写入走内核 FOLL_FORCE，可以直接写只读页，
 *  页表权限与 VMA 结构都保持原样。因此不会再拆 VMA，
 *  检测器读到的 maps 与未加载模块时完全一致。
 */
static int ahb_write_slot(uintptr_t slot, uintptr_t value) {
    static int mem_fd = -1;
    ssize_t w;
    if (!ahb_addr_mapped(slot, sizeof(uintptr_t))) return 0;

    /*
     * /proc/self/mem 的 fd 复用。
     *
     * 早期每个槽都 open/close 一次，一次启动要接管上千个槽，
     * 等于上千次 open + close —— 这是启动变慢的主要来源之一。
     * fd 可以长期持有，pwrite 每次带自己的偏移，互不影响。
     */
    if (mem_fd < 0) {
        mem_fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem", O_RDWR, 0);
        if (mem_fd < 0) return 0;
    }
    w = (ssize_t)syscall(SYS_pwrite64, mem_fd, &value, sizeof(value), (off_t)slot);
    return w == (ssize_t)sizeof(value);
}

/*
 * syscall 包装：检测器会用 libc::syscall(SYS_openat, "/proc/self/maps")
 * 直接读，绕过 fopen/open 的所有包装。这条路径必须单独处理。
 *
 * 只改写 openat/open 且路径确实是本进程 maps 的那一次；
 * 其余原样转发，不做任何多余判断，避免影响其它系统调用。
 */
typedef long (*syscall6_fn)(long, long, long, long, long, long, long);

static long maps_syscall_wrap(long number, long a1, long a2, long a3,
                              long a4, long a5, long a6) {
    g_c_sys++;
    maps_ensure_raw_syscall();
    #ifdef SYS_open
    if (number == SYS_openat || number == SYS_open) {
#else
    if (number == SYS_openat) {
#endif
#ifdef SYS_open
        const char *path = (number == SYS_openat) ? (const char *)a2 : (const char *)a1;
#else
        const char *path = (const char *)a2;
#endif
        /*
         * xDL 用原始系统调用打开库文件，绕过 open/openat 的 GOT 补丁。
         * 所以在 syscall 这一层也拦一次 JVMTI/JDWP 的库文件。
         */
        if (path && ahb_is_hidden_file(path)) {
            errno = ENOENT;
            return -1;
        }
        if (path && maps_path_is_self(path)) {
            int fd = ahb_filtered_fd_for(path);
            if (fd >= 0) return (long)fd;
        }
    }
    if (g_raw_syscall)
        return ((ahb_sys6_fn)g_raw_syscall)(number, a1, a2, a3, a4, a5, a6);
    return -1;
}

/* process_vm_readv 的包装体在 native_main.c 里，这里只做转发声明 */
static ssize_t clv_pvr_entry(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                             const struct iovec *remote, unsigned long riovcnt,
                             unsigned long flags);

/* ---- stat 家族包装 ---- */
int ahb_fstat_wrap(int fd, void *buf) {
    if (ahb_fd_fake_stat(fd, buf)) return 0;
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return -1;
    return (int)((ahb_sys6_fn)g_raw_syscall)(SYS_fstat, fd, (long)buf, 0, 0, 0, 0);
}
static int ahb_fstat64_wrap(int fd, void *buf) { return ahb_fstat_wrap(fd, buf); }
static int ahb___fstat64_wrap(int fd, void *buf) { return ahb_fstat_wrap(fd, buf); }

static int ahb_newfstatat_wrap(int dirfd, const char *path, void *buf, int flags) {
    /*
     * 目标是"打开过的 fd"，路径形式只可能是 /proc/self/fd/N。
     * 命中时按 fd 伪装，否则原样转发。
     */
    if (path && buf) {
        const char *p = strstr(path, "/fd/");
        if (p) {
            int fd = atoi(p + 4);
            if (ahb_fd_fake_stat(fd, buf)) return 0;
        }
    }
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return -1;
    return (int)((ahb_sys6_fn)g_raw_syscall)(SYS_newfstatat, dirfd,
                                             (long)path, (long)buf, flags, 0, 0);
}
static int ahb_fstatat_wrap(int dirfd, const char *path, void *buf, int flags) {
    return ahb_newfstatat_wrap(dirfd, path, buf, flags);
}
static int ahb_fstatat64_wrap(int dirfd, const char *path, void *buf, int flags) {
    return ahb_newfstatat_wrap(dirfd, path, buf, flags);
}
static int ahb___fstatat64_wrap(int dirfd, const char *path, void *buf, int flags) {
    return ahb_newfstatat_wrap(dirfd, path, buf, flags);
}

static int ahb_stat_common(const char *path, void *buf, int allow_follow) {
    if (path && buf) {
        const char *p = strstr(path, "/fd/");
        if (p) {
            int fd = atoi(p + 4);
            if (ahb_fd_fake_stat(fd, buf)) return 0;
        }
    }
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return -1;
    return (int)((ahb_sys6_fn)g_raw_syscall)(
        allow_follow ? SYS_newfstatat : SYS_newfstatat,
        AT_FDCWD, (long)path, (long)buf, allow_follow ? 0 : AT_SYMLINK_NOFOLLOW, 0, 0);
}
static int ahb_stat_wrap(const char *path, void *buf)  { return ahb_stat_common(path, buf, 1); }
static int ahb_stat64_wrap(const char *path, void *buf){ return ahb_stat_common(path, buf, 1); }
static int ahb___stat64_wrap(const char *path, void *buf){ return ahb_stat_common(path, buf, 1); }
static int ahb_lstat_wrap(const char *path, void *buf) { return ahb_stat_common(path, buf, 0); }
static int ahb_lstat64_wrap(const char *path, void *buf){ return ahb_stat_common(path, buf, 0); }

/* ---- statfs 家族：把文件系统类型改回 procfs ---- */
#ifndef AHB_PROC_SUPER_MAGIC
#define AHB_PROC_SUPER_MAGIC 0x9fa0L
#endif

/*
 * struct statfs 的第一个字段在 bionic 上是 f_type（long）。
 * 只需要改这一项：inode 一致性靠 fstat，而"这个 fd 属于哪种文件系统"
 * 靠 statfs。memfd 报的是 tmpfs 魔数，与 procfs 不符，同样会被识破。
 */
static int ahb_fstatfs_wrap(int fd, void *buf) {
    int kind = ahb_fake_fd_kind_of(fd);
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return -1;
    {
        int r = (int)((ahb_sys6_fn)g_raw_syscall)(SYS_fstatfs, fd, (long)buf, 0, 0, 0, 0);
        if (r == 0 && kind >= 0 && buf) *(long *)buf = AHB_PROC_SUPER_MAGIC;
        return r;
    }
}
static int ahb_fstatfs64_wrap(int fd, void *buf) { return ahb_fstatfs_wrap(fd, buf); }

static int ahb_statfs_common(const char *path, void *buf) {
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return -1;
    {
        int r = (int)((ahb_sys6_fn)g_raw_syscall)(SYS_statfs, (long)path, (long)buf, 0, 0, 0, 0);
        if (r == 0 && buf && path && strstr(path, "/proc/"))
            *(long *)buf = AHB_PROC_SUPER_MAGIC;
        return r;
    }
}
static int ahb_statfs_wrap(const char *path, void *buf)   { return ahb_statfs_common(path, buf); }
static int ahb_statfs64_wrap(const char *path, void *buf) { return ahb_statfs_common(path, buf); }

/* ---- readlink：/proc/self/fd/N 要指向真实 proc 文件 ---- */
static ssize_t ahb_readlink_wrap(const char *path, char *buf, size_t sz) {
    int r = ahb_fd_fake_readlink(path, buf, sz);
    if (r >= 0) return (ssize_t)r;
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return -1;
    return (ssize_t)((ahb_sys6_fn)g_raw_syscall)(SYS_readlinkat, AT_FDCWD,
                                                 (long)path, (long)buf, (long)sz, 0, 0);
}
ssize_t ahb_readlinkat_wrap(int dirfd, const char *path, char *buf, size_t sz) {
    int r = ahb_fd_fake_readlink(path, buf, sz);
    if (r >= 0) return (ssize_t)r;
    maps_ensure_raw_syscall();
    if (!g_raw_syscall) return -1;
    return (ssize_t)((ahb_sys6_fn)g_raw_syscall)(SYS_readlinkat, dirfd,
                                                 (long)path, (long)buf, (long)sz, 0, 0);
}

/* 前置声明：实现在文件后段 */
static void *ahb_dlsym_wrap(void *handle, const char *symbol);
static void *ahb_xdl_sym_wrap(void *handle, const char *symbol, void *size);

/* 名字 -> 替换函数；返回 0 表示不接管这个符号 */
static uintptr_t ahb_repl_for(const char *name) {
    if (!name) return 0;
    if (strcmp(name, "open") == 0)            return (uintptr_t)maps_open_wrap;
    if (strcmp(name, "openat") == 0)          return (uintptr_t)maps_openat_wrap;
    if (strcmp(name, "open64") == 0)          return (uintptr_t)maps_open64_wrap;
    if (strcmp(name, "fopen") == 0)           return (uintptr_t)maps_fopen_wrap;
    if (strcmp(name, "fopen64") == 0)         return (uintptr_t)maps_fopen_wrap;
    if (strcmp(name, "__open_2") == 0)        return (uintptr_t)maps_open_2_wrap;
    if (strcmp(name, "__openat_2") == 0)      return (uintptr_t)maps_openat_2_wrap;
    if (strcmp(name, "__open64_2") == 0)      return (uintptr_t)maps_open64_2_wrap;
    if (strcmp(name, "popen") == 0)           return (uintptr_t)maps_popen_wrap;
    if (!g_disable_phdr_hide && strcmp(name, "dl_iterate_phdr") == 0)
                                              return (uintptr_t)maps_dl_iterate_wrap;
    /*
     * 退出探针（exit/_exit/kill/raise/abort/tgkill/exit_group）不再接管。
     *
     * 它们是早期为了回答"到底哪一步检查把它杀了"临时接的调试设施，
     * 对隐藏痕迹没有任何作用 —— 检测器不会因为 exit 被改过就放行。
     *
     * 反而是实际事故来源：hunter 的 hunter_server_twin 进程退出时走到
     * ep__exit，tombstone 栈顶正是 ep__exit+92 的 SIGSEGV。退出路径上
     * 进程状态已在拆解，这时再 open/write 写日志、再进 dlsym 解析符号
     * 都很危险。
     *
     * 只为记日志、却能在宿主退出时崩掉的东西，收益为负。全部撤掉。
     */
    /*
     * 退出入口重新接管（只记录 + 阻止，见 exit_probe.h 的说明）。
     * 上一版因为"在退出路径上 fopen/dlsym"把进程崩了而整组撤掉；
     * 现在改成零解析、零落盘，可以安全接管。
     */
    if (strcmp(name, "exit") == 0)            return (uintptr_t)ep_exit;
    if (strcmp(name, "_exit") == 0)           return (uintptr_t)ep__exit;
    if (strcmp(name, "kill") == 0)            return (uintptr_t)ep_kill;
    if (strcmp(name, "raise") == 0)           return (uintptr_t)ep_raise;
    if (strcmp(name, "abort") == 0)           return (uintptr_t)ep_abort;
    if (strcmp(name, "tgkill") == 0)          return (uintptr_t)ep_tgkill;
    if (strcmp(name, "exit_group") == 0)      return (uintptr_t)ep_exit_group;
    if (strcmp(name, "syscall") == 0)         return (uintptr_t)maps_syscall_wrap;
    /*
     * fd 元数据伪装（对据可查：目标 so 里有 checkFileIsLegal / fstat64 /
     * "Found inconsistent inode" / readlink 这些字符串）。
     * 不伪装的话，交出去的 memfd 在 inode 与文件系统类型上与 procfs 不符，
     * 对方一比对就判定篡改。
     */
    if (strcmp(name, "fstat") == 0)           return (uintptr_t)ahb_fstat_wrap;
    if (strcmp(name, "fstat64") == 0)         return (uintptr_t)ahb_fstat64_wrap;
    if (strcmp(name, "__fstat64") == 0)       return (uintptr_t)ahb___fstat64_wrap;
    if (strcmp(name, "fstatat") == 0)         return (uintptr_t)ahb_fstatat_wrap;
    if (strcmp(name, "fstatat64") == 0)       return (uintptr_t)ahb_fstatat64_wrap;
    if (strcmp(name, "__fstatat64") == 0)     return (uintptr_t)ahb___fstatat64_wrap;
    if (strcmp(name, "stat") == 0)            return (uintptr_t)ahb_stat_wrap;
    if (strcmp(name, "stat64") == 0)          return (uintptr_t)ahb_stat64_wrap;
    if (strcmp(name, "__stat64") == 0)        return (uintptr_t)ahb___stat64_wrap;
    if (strcmp(name, "lstat") == 0)           return (uintptr_t)ahb_lstat_wrap;
    if (strcmp(name, "lstat64") == 0)         return (uintptr_t)ahb_lstat64_wrap;
    if (strcmp(name, "statfs") == 0)          return (uintptr_t)ahb_statfs_wrap;
    if (strcmp(name, "statfs64") == 0)        return (uintptr_t)ahb_statfs64_wrap;
    if (strcmp(name, "fstatfs") == 0)         return (uintptr_t)ahb_fstatfs_wrap;
    if (strcmp(name, "fstatfs64") == 0)       return (uintptr_t)ahb_fstatfs64_wrap;
    if (strcmp(name, "readlink") == 0)        return (uintptr_t)ahb_readlink_wrap;
    if (strcmp(name, "readlinkat") == 0)      return (uintptr_t)ahb_readlinkat_wrap;
    /*
     * dlopen 一族：这是"新库映射完成、JNI_OnLoad 还没执行"的唯一确定时刻。
     *
     * 实测依据（同一轮日志的时间戳，单位 ns）：
     *   SCAN_BEGIN  79031620197453   ← 检测器开始扫
     *   补丁落地    79031792118391   ← 我的轮询线程才轮到（晚 172ms）
     *   SCAN_END    79031988219016   ← 整轮 368ms 结束
     * 也就是说：靠后台轮询永远赶不上，必须在它开始扫之前就把 GOT 装好。
     * 而 JNI_OnLoad 是 ART 在 dlopen 返回之后才调的，所以只要在 dlopen
     * 返回的那一瞬间补一遍，就必然早于它自己的扫描。
     *
     * 这个点与"哪个库"无关，任何新加载的库都会经过它，所以是通用的。
     */
    if (strcmp(name, "dlsym") == 0)           return (uintptr_t)ahb_dlsym_wrap;
    if (strcmp(name, "xdl_sym") == 0)         return (uintptr_t)ahb_xdl_sym_wrap;
    if (strcmp(name, "dlopen") == 0)          return (uintptr_t)ahb_dlopen_wrap;
    if (strcmp(name, "android_dlopen_ext") == 0)
                                              return (uintptr_t)ahb_android_dlopen_ext_wrap;
    /*
     * 把 process_vm_readv 也纳入重定位驱动接管。
     *
     * 这样就不需要再"逐段线性扫描每个 .so 的字节找值"——
     * 那种做法要遍历上百个库的全部非执行段（几十到上百 MB 内存），
     * 实测让宿主启动从 0.76s 拖到 5.6s。
     * 按重定位表只需读每个库的若干条 Rela，量级差三到四个数量级。
     */
    /*
     * 检测器读 /proc/<pid>/mem 的真实路径是 open + lseek64 + read
     * （其 libantihook.so 的导入表里没有 pread/pread64）。
     * 所以这三个都要接管，pread 留着当兜底。
     */
    {
        extern ssize_t clv_read_entry(int fd, void *buf, size_t count);
        extern ssize_t clv_pread_entry(int fd, void *buf, size_t count, long long off);
        extern size_t  clv_fread_entry(void *ptr, size_t size, size_t nmemb, void *stream);
        if (strcmp(name, "fread") == 0)   return (uintptr_t)clv_fread_entry;
        if (strcmp(name, "read") == 0)    return (uintptr_t)clv_read_entry;
        if (strcmp(name, "pread64") == 0) return (uintptr_t)clv_pread_entry;
        if (strcmp(name, "pread") == 0)   return (uintptr_t)clv_pread_entry;
    }
    if (strcmp(name, "process_vm_readv") == 0) return (uintptr_t)clv_pvr_entry;
    return 0;
}

/* 对单个 .so 按重定位表接管 */
static int ahb_patch_one_so(ahb_so_ent *so) {
    ElfW(Ehdr) eh_buf, *eh;
    ElfW(Phdr) ph_buf[64], *ph;
    ElfW(Dyn)  dyn_buf[2 * 64], *dyn = NULL;
    const ElfW(Sym)  *symtab = NULL;
    const char       *strtab = NULL;
    const ElfW(Rela) *jmprel = NULL, *rela = NULL;
    size_t pltrelsz = 0, relasz = 0, relaent = sizeof(ElfW(Rela));
    size_t i;
    int patched = 0;
    uintptr_t dyn_addr = 0;

    {
        /* 诊断：统计各提前返回原因，只记前三次扫描 */
        static int n = 0;
        if (n < 200) {
            n++;
        }
    }
    if (so->tried) return 0;
    so->tried = 1;
    if (ahb_already_done(so->path)) return 0;
    if (!so->base) return 0;
    if (so->base & 0xfff) return 0;

    /*
     * ELF 头一律经 ahb_safe_read 读，绝不直接解引用。
     *
     * 崩溃就是这么来的：ahb_addr_mapped() 依据的是上次扫描 maps 的快照，
     * 而从"快照说还在"到"真正去读"之间，那个库可能已经被卸载。
     * 快照一过期，下面的 memcmp(e_ident, ELFMAG) 就崩在宿主进程里，
     * 崩溃地址每次就是那个已失效的基址，栈顶正是 memcmp 的那条 ldr。
     */
    if (!ahb_safe_read(&eh_buf, so->base, sizeof(eh_buf))) {
        static int dbg = 0;
        if (dbg < 3) {
            dbg++;
        }
        return 0;
    }
    eh = &eh_buf;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return 0;
    if (eh->e_machine != EM_AARCH64 && eh->e_machine != EM_X86_64) return 0;
    if (eh->e_phentsize != sizeof(ElfW(Phdr))) { ahb_filelog("F phentsize %s", so->path); return 0; }
    if (eh->e_phnum == 0 || eh->e_phnum > 64) { ahb_filelog("F phnum %s", so->path); return 0; }

    if (!ahb_safe_read(ph_buf, so->base + eh->e_phoff,
                       (size_t)eh->e_phnum * sizeof(ElfW(Phdr)))) { ahb_filelog("F phread %s", so->path); return 0; }
    ph = ph_buf;
    for (i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn_addr = so->base + ph[i].p_vaddr;
            /*
             * 必须读满整个缓冲，不能只读 2 个条目。
             *
             * 踩过的坑：缓冲区开了 128 个条目，却只读进 2 个，
             * 后面却一直遍历到 512 个 —— 读到第 3 个开始全是未初始化的
             * 栈垃圾，d_tag 是随机值，DT_SYMTAB / DT_STRTAB 永远匹配不上，
             * 于是每个库都卡在 symtab/strtab 为空，一个都没补上。
             */
            if (!ahb_safe_read(dyn_buf, dyn_addr, sizeof(dyn_buf))) {
                return 0;
            }
            dyn = dyn_buf;
            break;
        }
    }
    if (!dyn) return 0;

    /*
     * 动态段与重定位表同理：先把整块读进本地缓冲，再遍历。
     * 直接遍历 dyn[i] / r[k] 等于用快照地址反复解引用，
     * 每个元素都是一次崩溃机会。
     */
    for (i = 0; i < sizeof(dyn_buf) / sizeof(dyn_buf[0]) && dyn[i].d_tag != DT_NULL; i++) {
        uintptr_t raw = (uintptr_t)dyn[i].d_un.d_ptr;
        switch (dyn[i].d_tag) {
        case DT_PLTRELSZ: pltrelsz = (size_t)raw; break;
        case DT_RELASZ:   relasz   = (size_t)raw; break;
        case DT_RELAENT:  relaent  = (size_t)raw; break;
        case DT_SYMTAB:
        case DT_STRTAB:
        case DT_JMPREL:
        case DT_RELA: {
            uintptr_t v = 0;
            if (!raw) break;
            /*
             * 这里的 d_ptr 有两种可能：已重定位的绝对地址，或未重定位的
             * 相对偏移。用"落没落在某个映射段里"来分辨是错的 —— 一个小的
             * 相对偏移完全可能正好落在别的段范围内，于是被当成绝对地址，
             * 后面按它读符号表全部失败。
             *
             * 实测后果：每个库都卡在 symtab/strtab 为空这一步，
             * so_n=430 一个都没补上，maps 过滤形同虚设。
             *
             * 改用"能不能真读到"来分辨：先按 ELF 语义试 base+raw（未重定位
             * 的绝大多数是这种），读不通再试 raw 原值。
             */
            {
                static const char probe[8] = {0};
                (void)probe;
                if (ahb_safe_read(&v, so->base + raw, sizeof(uintptr_t))) {
                    v = so->base + raw;
                } else if (ahb_safe_read(&v, raw, sizeof(uintptr_t))) {
                    v = raw;
                } else {
                    break;
                }
            }
            if (dyn[i].d_tag == DT_SYMTAB)      symtab = (const ElfW(Sym) *)v;
            else if (dyn[i].d_tag == DT_STRTAB) strtab = (const char *)v;
            else if (dyn[i].d_tag == DT_JMPREL) jmprel = (const ElfW(Rela) *)v;
            else                                rela   = (const ElfW(Rela) *)v;
            break;
        }
        default: break;
        }
    }
    if (!symtab || !strtab) return 0;
    if (relaent == 0) relaent = sizeof(ElfW(Rela));

    {
        int pass;
        for (pass = 0; pass < 2; pass++) {
            const ElfW(Rela) *r = (pass == 0) ? jmprel : rela;
            size_t bytes = (pass == 0) ? pltrelsz : relasz;
            size_t n, k;
            if (!r || bytes == 0) continue;
            if (bytes > 4 * 1024 * 1024) continue;      /* 上限，防跑飞 */
            n = bytes / relaent;
            for (k = 0; k < n; k++) {
                uint32_t sym, type;
                const char *nm;
                uintptr_t repl, slot;
                ElfW(Rela) re;
                ElfW(Sym)  sy;
                char nmbuf[256];

                if (!ahb_safe_read(&re, (uintptr_t)&r[k], sizeof(re))) continue;
                sym  = (uint32_t)(re.r_info >> 32);
                type = (uint32_t)(re.r_info & 0xffffffffu);
                if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT) continue;
                if (!ahb_safe_read(&sy, (uintptr_t)&symtab[sym], sizeof(sy))) continue;
                if (sy.st_name >= 0x10000) continue;
                if (!ahb_safe_read_str(nmbuf, (uintptr_t)(strtab + sy.st_name),
                                       sizeof(nmbuf))) continue;
                nm = nmbuf;
                repl = ahb_repl_for(nm);
                if (!repl) continue;
                /*
                 * libc 只接管 process_vm_readv 一个符号。
                 *
                 * 原因：process_vm_readv 是检测器读链表的唯一通道，
                 * 但它的 GOT 在 libantihook.so 里 —— 而那个库是进程起来
                 * 之后才 dlopen 的，接管必然晚于检测器第一次读取。
                 * 实测这就是 ClassLoader 项间歇性翻红的根因（约一半轮次
                 * 读到真值 31，另一半读到伪造值 4）。
                 *
                 * libc 的槽在进程启动时就已解析完毕，接管它等于
                 * "进程内所有 process_vm_readv 调用都经过我们"，
                 * 不再依赖目标库的加载时机。
                 *
                 * 绝不能顺带接管 libc 的 open/fopen —— 那会让模块自己的
                 * 日志写入递归回包装函数。
                 */
                /*
                 * dlopen / android_dlopen_ext 是"纯转发"监听点：
                 * 我们只是等它返回后补一次 GOT，返回值和 errno 原样透传，
                 * 不改变任何语义，因此可以安全地装在系统库里。
                 *
                 * 而 open/read/syscall 这些会改写返回内容，装在系统库里
                 * 会破坏图形驱动等组件（实测 Vulkan abort），所以只装应用侧。
                 *
                 * 这个区分是必要的：加载检测器库的动作正是系统库做的
                 * （libnativeloader / System.loadLibrary 那条路），
                 * 如果只在应用侧装 dlopen，就永远收不到那个通知，
                 * 补丁只能靠轮询，实测晚了 138ms —— 那时检测早已跑完。
                 */
                if (strcmp(nm, "dlopen") == 0 || strcmp(nm, "android_dlopen_ext") == 0) {
                    /* 允许：纯转发，不改语义 */
                }
                else if (!ahb_so_is_app_side(so->path)) {
                    /* 系统库只装 dlopen 监听，其余一律不碰 */
                    continue;
                }
                else if (ahb_is_libc(so->path) && strcmp(nm, "process_vm_readv") != 0) {
                    continue;
                }
                so->has_target = 1;
                if (strstr(so->path, "/libc.so")) {
                    ahb_filelog("MAPS libc-target %s slot=%p", nm, (void *)(so->base + r[k].r_offset));
                }
                slot = so->base + (uintptr_t)re.r_offset;
                {
                    uintptr_t probe = 0;
                    if (!ahb_safe_read(&probe, slot, sizeof(probe))) continue;
                }
                if (!ahb_write_slot(slot, repl)) continue;
                patched++;
                g_maps_got_patched++;
                /* 记录接管的符号名：排查"pvr 到底接没接上"必须看到这一行 */
                if (strcmp(nm, "process_vm_readv") == 0 || strcmp(nm, "syscall") == 0 ||
                    strstr(so->path, "libantihook.so") != NULL) {
                    ahb_filelog("MAPS key %s slot=%p path=%s", nm, (void *)slot, so->path);
                }
                /*
                 * 不再逐槽写日志。
                 *
                 * 实测一次启动会接管数百到上千个槽，逐槽写文件意味着
                 * 同样的次数 open/write/close —— 光这一步就能把
                 * 应用启动拖慢几百毫秒。改成按库汇总一行，信息量足够排查，
                 * IO 从上千次降到几十次。
                 */
            }
        }
    }
    if (patched) {
        {
            struct timespec _t; clock_gettime(CLOCK_BOOTTIME, &_t);
            ahb_filelog("MAPS lib %s patched=%d t=%lld", so->path, patched,
                        (long long)_t.tv_sec * 1000000000LL + _t.tv_nsec);
        }
    } else if (so->has_target) {
        /* 有目标符号但一个槽都没写成功：必须留证，这类库会一直重试 */
        ahb_filelog("MAPS lib %s has_target_but_patched=0", so->path);
    }
    /*
     * 只有真的接管到槽才标记完成。
     *
     * 早期无条件标记，导致一个时序陷阱：某些库（如检测器自己的
     * libantihook.so）在第一次扫描时还没完成符号解析，一个槽都没接上，
     * 却被永久标记为"已处理"，后续轮次再也不会重试 ——
     * process_vm_readv 的接管因此丢失，ClassLoader 项直接翻红。
     *
     * 改为：patched > 0 才标记；没接到的库留给后续轮次继续尝试。
     */
    /*
     * 标记策略按"这个库到底需不需要接管"来定，而不是按尝试次数。
     *
     *  - has_target == 0：它的重定位表里根本没有 open/syscall/process_vm_readv
     *    这类目标符号，永远不用再扫 —— 直接标记完成。
     *    这一类占了系统库的绝大多数，是真正该跳过的。
     *
     *  - has_target == 1 但 patched == 0：有目标符号却没写成功，
     *    典型原因是当时符号还没解析完。这种必须继续重试，绝不能放弃 ——
     *    实测按"尝试 6 次就放弃"会让检测器自己的 libantihook.so
     *    在符号解析完成前被永久跳过，process_vm_readv 接管整轮丢失，
     *    ClassLoader 项直接翻红。
     *
     *  - patched > 0：已经接上了，标记完成。
     */
    if (patched > 0 || so->has_target == 0) {
        ahb_mark_done(so->path);
    }
    return patched;
}

/* 已加载模块计数：微秒级，用来判断"有没有新库加载" */
static int ahb_count_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)info; (void)sz;
    (*(int *)data)++;
    return 0;
}
int ahb_loaded_module_count(void) {
    int n = 0;
    dl_iterate_phdr(ahb_count_cb, &n);
    return n;
}

/* 扫全部已映射的 .so，收集基址与段保护位，再逐个按重定位接管 */
static int g_maps_no_debounce = 0;   /* 1 = 跳过去抖，供视图接管使用 */

/*
 * 串行化。
 *
 * maps_patch_got_all 会被三处并发调用：
 *   1) JNI_OnLoad 主线程
 *   2) clv_fast_patch_thread 抢跑线程
 *   3) guard_loop 守护线程
 * 它内部依赖 g_so_tab / g_seg_tab 两个全局表，并发进来必然互相踩：
 * 一个线程刚把 g_so_n 清零、表写到一半，另一个线程就遍历它 ——
 * 实测会读到半截表项，然后用错的 base 去解析 ELF，SIGSEGV。
 *
 * 用原子自旋锁而不是 pthread_mutex：这里临界区短、竞争极少，
 * 且不能依赖 pthread 初始化时机。
 */
static volatile int g_maps_lock = 0;

/*
 * 用内联汇编实现自旋锁，不依赖任何编译器内建。
 *
 * 踩过两次坑，都是同一类问题：
 *   __atomic_compare_exchange_n  -> 引用 __aarch64_cas4_acq
 *   __sync_lock_test_and_set     -> 引用 __aarch64_swp4_acq_rel
 * 这些 libatomic 符号 Bionic 不导出，dlopen 直接失败，
 * 整个模块装不上（"cannot locate symbol ..."）。
 *
 * 直接写 ldaxr/stxr：单条指令、无外部依赖、跨 clang 版本行为一致。
 * 其它 ABI（x86/x86_64/armv7）用对应指令。
 */
static int maps_try_lock(void) {
    int expected = 0;
#if defined(__aarch64__)
    int tmp, ok;
    __asm__ __volatile__(
        "ldaxr  %w0, [%2]\n"
        "cbnz   %w0, 1f\n"
        "stxr   %w1, %w3, [%2]\n"
        "b      2f\n"
        "1:\n"
        "mov    %w1, #1\n"
        "2:\n"
        : "=&r"(tmp), "=&r"(ok)
        : "r"(&g_maps_lock), "r"(1)
        : "memory");
    return ok == 0;
#elif defined(__x86_64__) || defined(__i386__)
    return __sync_bool_compare_and_swap(&g_maps_lock, expected, 1);
#else
    return __sync_lock_test_and_set(&g_maps_lock, 1) == 0;
#endif
}

static void maps_unlock(void) {
#if defined(__aarch64__)
    __asm__ __volatile__("stlrb wzr, [%0]" :: "r"(&g_maps_lock) : "memory");
#else
    __sync_lock_release(&g_maps_lock);
#endif
}

static int maps_patch_got_all_locked(void);

static int maps_patch_got_all(void) {
    int r;
    if (!maps_try_lock()) return 0;   /* 别人正在扫，直接跳过这一轮 */
    r = maps_patch_got_all_locked();
    maps_unlock();
    return r;
}

static int maps_patch_got_all_locked(void) {
    FILE *fp;
    char line[1024];
    int before, i;

    /*
     * 去抖：全量扫描要读 maps + 遍历上百个 .so 的 ELF 动态段与重定位表，
     * 是这条路径上最重的活。实测调用方会在几百毫秒内反复触发，
     * 每次都真扫一遍会明显拖慢宿主启动。
     *
     * 用 250ms 去抖窗口：窗口内的重复请求直接返回 0（无新增）。
     * 启动阶段总共只扫几次，之后由 guard 的 40 轮上限收尾。
     */
    if (!g_maps_no_debounce) {
        static time_t last_sec = 0;
        static long last_nsec = 0;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (last_sec != 0 &&
            (now.tv_sec - last_sec) * 1000L + (now.tv_nsec - last_nsec) / 1000000L < 250) {
            return 0;
        }
        last_sec = now.tv_sec;
        last_nsec = now.tv_nsec;
    }

    maps_resolve_reals();
    /*
     * 读 maps 不能依赖 g_real_fopen。
     *
     * dlsym(RTLD_NEXT, "fopen") 只在 maps_resolve_reals 里赋值，而这个函数
     * 本身又可能因为 g_real_fopen 为 NULL 提前返回 —— 自己把自己的门堵上。
     * 实测后果：整个补丁函数一声不响返回 0，一行 ahb_patch_one_so 都不执行，
     * 于是所有 GOT 补丁全都没装上，maps 过滤形同虚设。
     *
     * 改用 maps_read_all：它走真实的 openat/read/close syscall，不经过
     * 任何被自己接管的函数，不存在自锁。
     */
    {
        char *mbuf = NULL;
        size_t mcap = 0;
        int mlen = maps_read_all(&mbuf, &mcap);
        if (mlen <= 0) { if (mbuf) free(mbuf); return 0; }
        free(g_maps_snap);
        g_maps_snap = mbuf;        /* 交给下面的逐行解析 */
        g_maps_snap_len = (size_t)mlen;
    }

    if (!g_enable_maps_hide || g_disable_all_patch) return 0;
    before = g_maps_got_patched;
    /*
     * 用"已接管的库路径集合"代替每次重新试。
     *
     * 早期每次扫描都 g_so_n=0 重建表、再让每个库走一遍 ahb_patch_one_so。
     * tried 标记只活在单次扫描的表项里，下一轮重建就丢了，
     * 于是同一个库被反复接管 —— 实测累计值涨到 3000+，
     * 每轮都白做上百次 ELF 解析与 pwrite，这是启动慢的主因。
     *
     * 现在改成持久化的路径集合：接过的库直接跳过。
     */
    g_so_n = 0;
    ahb_seg_reset();
    /* 由调用方决定是否需要本次扫描，这里不再额外判断 */
    {
    const char *cur = g_maps_snap;
    const char *lim = g_maps_snap ? g_maps_snap + g_maps_snap_len : NULL;
    while (cur && lim && cur < lim) {
        const char *nl = (const char *)memchr(cur, '\n', (size_t)(lim - cur));
        size_t llen = nl ? (size_t)(nl - cur) : (size_t)(lim - cur);
        unsigned long long s = 0, e = 0, off = 0;
        char perm[16] = {0}, path[AHB_PATH_MAX] = {0};
        if (llen >= sizeof(line)) llen = sizeof(line) - 1;
        memcpy(line, cur, llen);
        line[llen] = 0;
        cur = nl ? nl + 1 : lim;
        if (sscanf(line, "%llx-%llx %15s %llx %*s %*s %319[^\n]",
                   &s, &e, perm, &off, path) < 4) continue;
        if (path[0] != '/') continue;
        if (!strstr(path, ".so")) continue;
        if (ahb_so_skip(path)) continue;
        /*
         * 段表只记录 .so 的段。
         *
         * 早期对每一条 maps 行都 ahb_seg_add，而进程 maps 有两三千行
         * （含大量匿名段、[anon:...]、堆栈等），表瞬间被填满，
         * 排在后面的库（libc 就在 apex 段，顺序靠后）连段都进不来，
         * 更不可能被校验通过。
         *
         * 只记 .so 段之后，条目数降到几百，表永远够用。
         */
        ahb_seg_add((uintptr_t)s, (uintptr_t)e, perm);
        ahb_so_note(path, (uintptr_t)s, (uintptr_t)off);
    }
    }

    {
        static int rep = 0;
        if (rep < 6) {
            rep++;
            ahb_filelog("MAPS scan so_n=%d seg_n=%d done_n=%d", g_so_n, g_seg_n, g_done_n);
        }
        /* 列出表里所有含 "libc.so" 的条目，确认它到底在不在 */
        if (rep <= 2) {
            int k;
            for (k = 0; k < g_so_n; k++) {
                if (strstr(g_so_tab[k].path, "/libc.so")) {
                    ahb_filelog("MAPS inlist %s base=%#lx done=%d",
                                g_so_tab[k].path, (unsigned long)g_so_tab[k].base,
                                ahb_already_done(g_so_tab[k].path));
                }
            }
        }
    }
    for (i = 0; i < g_so_n; i++) {
        ahb_patch_one_so(&g_so_tab[i]);
    }
    return g_maps_got_patched - before;
}


/* ================================================================== */
/* 库文件视图重定向：让"磁盘上的 libart.so"看起来就是内存当前的样子      */
/* ================================================================== */

/*
 * 方向与"把内存写回磁盘内容"正好相反：
 *
 *   旧做法：改真实内存去匹配磁盘  → 抹掉别人打在 libart 上的 inline hook
 *   新做法：改磁盘视图去匹配内存  → 真实内存一个字节都不动
 *
 * 依据（实测）：
 *   - 检测器会 open libart.so / libc.so 的磁盘文件，自己算 CRC；
 *   - LSPosed 注入后 libart 代码段有 191 字节与磁盘不同，
 *     关掉本模块 L1 之后差异量完全不变，说明它来自框架注入本身；
 *   - 所以只要交给检测器的"磁盘内容"带上这些字节，两边 CRC 自然一致。
 */

static int g_libview_fd = -1;
static char g_libview_path[AHB_PATH_MAX];
static int g_libview_busy = 0;
static struct timespec g_libview_t0;

int ahb_libview_fd_for(const char *path) {
    char *raw = NULL;
    size_t cap = 0;
    int n, sfd;
    size_t fsize = 0;
    int mfd = -1;
    int hit = 0;

    if (!path) return -1;
    if (g_libview_busy) return -1;

    /*
     * 同一路径在进程生命周期内只生成一次。
     *
     * 实测教训：最初加了 2 秒时间窗口，结果检测器分多次读、间隔超过窗口，
     * 同一个 23MB 文件被完整移植了 7 次，白多花几百毫秒。
     * libart 的代码段补丁在启动期一次装好后基本不变，可以永久复用。
     */
    if (g_libview_fd >= 0 && strcmp(g_libview_path, path) == 0) {
        return dup(g_libview_fd);
    }

    g_libview_busy = 1;

    sfd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (sfd < 0) { g_libview_busy = 0; return -1; }
    {
        struct stat st;
        if (fstat(sfd, &st) != 0 || st.st_size <= 0 || st.st_size > (64 << 20)) {
            syscall(SYS_close, sfd);
            g_libview_busy = 0;
            return -1;
        }
        fsize = (size_t)st.st_size;
    }

    mfd = (int)syscall(SYS_memfd_create, "ahb-libview", 0);
    clock_gettime(CLOCK_MONOTONIC, &g_libview_t0);
    if (mfd < 0) { syscall(SYS_close, sfd); g_libview_busy = 0; return -1; }

    /*
     * 必须先把整个文件内容填进去，再覆盖映射段。
     *
     * 这一步不能省。教训：曾经为省时间把 memfd 做成稀疏文件、
     * 只写 maps 里实际映射的段，未映射区域全是 0 —— 结果检测器
     * 按 ELF 结构去读时直接报 "ELF 解析失败: bad offset 0"，
     * 那一项从 SAFE 变回 RISK。
     *
     * 原因：一个 .so 在 maps 里只映射 PT_LOAD 段，而 ELF 结构里
     * 还有 section header table、符号表、字符串表、.comment 等区域
     * 并不出现在 maps 中，但检测器解析 ELF 时需要读到它们。
     * 只写映射段，这些区域就是 0，解析必挂。
     *
     * 用 copy_file_range 让内核直接把文件内容搬进 memfd（不进用户态），
     * 再把映射段覆盖成内存内容。整份 23MB 的拷贝成本放在后台预热里，
     * 不占检测器的扫描窗口。
     */
    if (syscall(SYS_ftruncate, mfd, (long long)fsize) != 0) {
        syscall(SYS_close, mfd); syscall(SYS_close, sfd);
        g_libview_busy = 0;
        return -1;
    }

    /* 先整份拷进来，保证 ELF 结构完整可解析 */
    {
        off_t in_off = 0, out_off = 0;
        size_t left = fsize;
        while (left > 0) {
            ssize_t r = syscall(SYS_copy_file_range, sfd, &in_off, mfd, &out_off,
                                left, 0);
            if (r > 0) { left -= (size_t)r; continue; }
            break;
        }
        if (left > 0) {
            /* copy_file_range 不可用时退回 pread+pwrite */
            unsigned char *tmp = (unsigned char *)malloc(1 << 20);
            if (!tmp) {
                syscall(SYS_close, mfd); syscall(SYS_close, sfd);
                g_libview_busy = 0;
                return -1;
            }
            while (left > 0) {
                size_t want = (left < (1u << 20)) ? left : (1u << 20);
                ssize_t r = syscall(SYS_pread64, sfd, tmp, want,
                                    (long long)(fsize - left));
                if (r <= 0) break;
                {
                    size_t put = 0;
                    while (put < (size_t)r) {
                        ssize_t w = syscall(SYS_pwrite64, mfd, tmp + put,
                                            (size_t)r - put,
                                            (long long)(fsize - left + put));
                        if (w <= 0) break;
                        put += (size_t)w;
                    }
                }
                left -= (size_t)r;
            }
            free(tmp);
        }
    }

    n = maps_read_all(&raw, &cap);
    if (n > 0) {
        char *line = raw, *end = raw + n;
        size_t plen = strlen(path);
        while (line < end) {
            char *nl = (char *)memchr(line, '\n', (size_t)(end - line));
            size_t L = nl ? (size_t)(nl - line) : (size_t)(end - line);
            unsigned long long lo = 0, hi = 0, off = 0;
            char perm[8] = {0};
            if (L > plen && memmem(line, L, path, plen) &&
                sscanf(line, "%llx-%llx %7s %llx", &lo, &hi, perm, &off) == 4) {
                size_t seg = (size_t)(hi - lo);
                if (seg > 0 && off < fsize && off + seg <= fsize) {
                    size_t put = 0;
                    while (put < seg) {
                        size_t chunk = (seg - put < (4 << 20)) ? (seg - put) : (4 << 20);
                        ssize_t w = syscall(SYS_pwrite64, mfd,
                                            (void *)(uintptr_t)(lo + put),
                                            chunk, (long long)(off + put));
                        if (w <= 0) break;
                        put += (size_t)w;
                    }
                    if (put > 0) hit = 1;
                }
            }
            if (!nl) break;
            line = nl + 1;
        }
        free(raw);
    }

    if (!hit) {
        syscall(SYS_close, mfd); syscall(SYS_close, sfd);
        g_libview_busy = 0;
        return -1;
    }

    syscall(SYS_close, sfd);
    syscall(SYS_lseek, mfd, 0, SEEK_SET);
    if (g_libview_fd >= 0) syscall(SYS_close, g_libview_fd);
    g_libview_fd = mfd;
    snprintf(g_libview_path, sizeof(g_libview_path), "%s", path);
    struct timespec _t1;
    long _ms;
    clock_gettime(CLOCK_MONOTONIC, &_t1);
    _ms = (_t1.tv_sec - g_libview_t0.tv_sec) * 1000 +
          (_t1.tv_nsec - g_libview_t0.tv_nsec) / 1000000;
    ahb_filelog("LIBVIEW ready %s size=%zu cost=%ldms", path, fsize, _ms);

    {
        int out = dup(g_libview_fd);
        g_libview_busy = 0;
        return out;
    }
}

/*
 * 只重定向 libart.so。
 * 六项检测里只有它做代码段 CRC；libc 段本来就与磁盘一致，不需要处理。
 */
static int ahb_is_libview_target(const char *path) {
    if (!path) return 0;
    return strstr(path, "libart.so") != NULL;
}

void ahb_libview_invalidate(void);
void ahb_libview_invalidate(void) {
    g_libview_path[0] = 0;
}

/* 在 maps 里找出 libart.so 的路径，供视图预热使用 */
int ahb_find_libart_path(char *out, size_t outlen);
int ahb_find_libart_path(char *out, size_t outlen) {
    char *raw = NULL;
    size_t cap = 0;
    int n;
    int ok = 0;
    n = maps_read_all(&raw, &cap);
    if (n > 0) {
        char *line = raw, *end = raw + n;
        while (line < end) {
            char *nl = (char *)memchr(line, '\n', (size_t)(end - line));
            size_t L = nl ? (size_t)(nl - line) : (size_t)(end - line);
            if (L > 9 && memmem(line, L, "libart.so", 9)) {
                char *slash = memchr(line, '/', L);
                if (slash) {
                    size_t pl = L - (size_t)(slash - line);
                    while (pl > 0 && (slash[pl-1] == ' ' || slash[pl-1] == '\r')) pl--;
                    if (pl > 0 && pl < outlen) {
                        memcpy(out, slash, pl);
                        out[pl] = 0;
                        ok = 1;
                        break;
                    }
                }
            }
            if (!nl) break;
            line = nl + 1;
        }
        free(raw);
    }
    return ok;
}

#endif /* AHB_MAPS_HIDE_H */

/* 供 native_main.c 的 fd 级过滤使用 */
int maps_make_clean_fd_public(void) { return maps_make_clean_fd(); }

/* 供 dlopen 包装在"新库映射完成、JNI_OnLoad 尚未执行"这个时刻强制补一遍 */
void ahb_force_rescan(void);

/*
 * 在 dlopen 返回点补丁，但**只补刚刚加载进来的那个库**。
 *
 * 为什么不做全量重扫：dlopen 会在图形驱动、编解码器等关键路径上被频繁调用，
 * 每次都在那里遍历几百个库的 ELF 重定位表，既慢又容易在别人的临界区里
 * 触发重入。实测全量重扫那次直接把 Vulkan 初始化搞崩了。
 *
 * 做法：记下调用前的模块数，返回后遍历 phdr，只处理新出现的那个。
 */
void ahb_force_rescan(void) {
    static int in_progress = 0;
    int old_deb;
    if (in_progress) return;             /* 防重入 */
    in_progress = 1;
    /*
     * 跳过去抖，让这次一定真扫。
     *
     * 真正的增量由 ahb_patch_one_so 的 tried 标记保证：已处理过的库直接
     * 返回，只有刚 dlopen 进来的那个会真正解析重定位表。所以这里调
     * 全量入口的开销只是"读一次 maps + 遍历一遍表"，几毫秒量级。
     */
    old_deb = g_maps_no_debounce;
    g_maps_no_debounce = 1;
    maps_patch_got_all();
    g_maps_no_debounce = old_deb;
    in_progress = 0;
}

/* dlopen 包装：真实加载完成后立刻补 GOT，早于 ART 调用 JNI_OnLoad */
typedef void *(*ahb_dlopen_fn)(const char *, int);
static ahb_dlopen_fn g_real_dlopen = NULL;
static int g_tr_in_dlopen = 0;

/* ================================================================== */
/* 拒绝加载 JVMTI 调试代理                                              */
/* ================================================================== */

/*
 * 依据（实测调用栈，不是推测）
 * ---------------------------
 * com.zhenxi.hunter 的主进程 abort，栈是这样的：
 *
 *   jit_code_cache.cc:1309  Check failed: !ContainsElement(zombie_code_, code_ptr)
 *   JitCodeCache::AddZombieCodeInternal
 *   JitCodeCache::AddZombieCode
 *   Instrumentation::InstallStubsForClass
 *   ClassLinker::VisitClasses -> VisitClassesInternal
 *   Instrumentation::UpdateEntrypointsForDebuggable
 *   openjdkjvmti::DeoptManager::FinishSetup
 *   ArtPlugin_Initialize
 *   libhunter.so            <-- 目标自己去加载了 JVMTI 代理
 *
 * 也就是说：目标把 libopenjdkjvmti 拉进进程，将运行时切到
 * "debuggable" 语义，然后对**每一个类**重装入口 stub。
 * 而 LSPosed 的 lsplant 已经把大量方法的入口寄存器改成了自己的跳板，
 * ART 在为这些方法登记 zombie code 时与既有记录撞车，直接 abort。
 *
 * 这不是本模块做了什么，而是"框架 hook"与"JVMTI 调试代理"天生冲突：
 * 只要框架在，目标一旦上 JVMTI 就会踩这个断言。
 *
 * 因此对 libopenjdkjvmti 的加载请求返回失败。目标拿不到 JVMTI，
 * 就不会走 UpdateEntrypointsForDebuggable，也就没有这次 abort。
 * 这与隐藏 maps 是同一类手段：让它拿不到那件东西，而不是改它的结论。
 */
#ifndef AHB_BLOCK_JVMTI
#define AHB_BLOCK_JVMTI 1
#endif

static int ahb_is_jvmti_path(const char *name) {
    if (!name) return 0;
    /*
     * 只认明确属于 JVMTI / 调试代理的库。
     * 不用宽泛匹配：误拦别的库会直接让目标功能缺失。
     */
    if (strstr(name, "libopenjdkjvmti.so")) return 1;
    if (strstr(name, "libjdwp.so")) return 1;
    if (strstr(name, "libdt_jdwp.so")) return 1;
    if (strstr(name, "libperfetto_hprofd.so")) return 1;
    return 0;
}

/* ================================================================== */
/* 让 JVMTI 的能力探测拿不到入口                                        */
/* ================================================================== */

/*
 * 依据（实测字符串 + 实测调用栈，不是推测）
 * ----------------------------------------
 * libhunter.so 里有这些字符串：
 *
 *   ZhenxiRuntime::JvmTi::init xdl_open ERROR
 *   JvmTi::init ArtPlugin_Initialize == null
 *   ArtPlugin_Initialize
 *   ZhenxiRuntime::JvmTi::init success !
 *   ZhenxiRuntime::JvmTi::Choose clazz == null
 *   ZhenxiRuntime::JvmTi::getMethodByteCode fail
 *   ro.debuggable
 *
 * 它用的是 **xDL**（xdl_open/xdl_sym）去加载并解析库，自己走 linker 内部
 * 结构，不经过 dlopen —— 实测拦 dlopen 一次都没命中，正是这个原因。
 *
 * 崩溃栈则明确显示它成功拿到了 ArtPlugin_Initialize 并调用：
 *
 *   Instrumentation::UpdateEntrypointsForDebuggable
 *   openjdkjvmti::DeoptManager::FinishSetup
 *   ArtPlugin_Initialize
 *   libhunter.so
 *
 * 之后 ART 把运行时当成 debuggable，对每个类重装入口 stub，
 * 与 lsplant 已改写的入口撞车，`zombie_code_` 断言失败并 abort。
 *
 * 好的一面：它自己就有 ArtPlugin_Initialize == null 的失败分支，
 * 也就是"拿不到入口"是被它正常处理的情形，不会崩。
 *
 * 因此这里让 dlsym/xdl_sym 对这一个符号返回 NULL。
 * 只拦这一个符号 —— 不做宽泛匹配，避免破坏目标的其它功能。
 */
#ifndef AHB_BLOCK_JVMTI_SYM
#define AHB_BLOCK_JVMTI_SYM 1
#endif

static int ahb_is_blocked_sym(const char *n) {
    if (!n) return 0;
    /*
     * ArtPlugin_Initialize 是 JVMTI 插件的唯一入口。
     * 另外把 JDWP 的 agent 入口一并挡掉：它们同样会把运行时切到
     * debuggable 语义，走同一条 UpdateEntrypointsForDebuggable 路径。
     */
    if (strcmp(n, "ArtPlugin_Initialize") == 0) return 1;
    if (strcmp(n, "Agent_OnAttach") == 0) return 1;
    if (strcmp(n, "Agent_OnLoad") == 0) return 1;
    return 0;
}

typedef void *(*ahb_dlsym_fn)(void *, const char *);

static void *ahb_dlsym_wrap(void *handle, const char *symbol) {
    static ahb_dlsym_fn real = NULL;
#if AHB_BLOCK_JVMTI_SYM
    if (ahb_is_blocked_sym(symbol)) {
        LOGI("JVMTI 符号屏蔽: %s", symbol);
        return NULL;
    }
#endif
    if (!real) real = (ahb_dlsym_fn)dlsym(RTLD_NEXT, "dlsym");
    if (!real) return NULL;
    return real(handle, symbol);
}

/* xDL 走自己的实现，但导出名就是 xdl_sym / xdl_open，一并接管 */
static void *ahb_xdl_sym_wrap(void *handle, const char *symbol, void *size) {
    typedef void *(*xf)(void *, const char *, void *);
    static xf real = NULL;
#if AHB_BLOCK_JVMTI_SYM
    if (ahb_is_blocked_sym(symbol)) {
        LOGI("JVMTI 符号屏蔽(xdl): %s", symbol);
        return NULL;
    }
#endif
    if (!real) real = (xf)dlsym(RTLD_NEXT, "xdl_sym");
    if (!real) return NULL;
    return real(handle, symbol, size);
}

void *ahb_real_dlopen_raw(const char *name) {
    if (!g_real_dlopen) g_real_dlopen = (ahb_dlopen_fn)dlsym(RTLD_NEXT, "dlopen");
    if (!g_real_dlopen) g_real_dlopen = (ahb_dlopen_fn)dlsym(RTLD_DEFAULT, "dlopen");
    if (!g_real_dlopen) return NULL;
    return g_real_dlopen(name, RTLD_NOW);
}

void *ahb_dlopen_wrap(const char *name, int flags) {
    void *h;
    {
        static int n = 0;
#if AHB_DIAG
        if (n < 24) {
            n++;
            LOGI("DLOPEN[%d] stage=%d jvmti=%d diag=%d art=%d elf=%d %s", n,
                 ahb_early_stage_get(), ahb_jvmti_result_get(),
                 ahb_jvmti_diag_get(), ahb_libart_diag_get(),
                 ahb_elf_diag_get(), name ? name : "(null)");
        }
#endif
    }
#if AHB_BLOCK_JVMTI
    if (ahb_is_jvmti_path(name)) {
        LOGE("JVMTI 拒绝加载: %s", name);
        return NULL;
    }
#endif
    if (!g_real_dlopen) g_real_dlopen = (ahb_dlopen_fn)dlsym(RTLD_NEXT, "dlopen");
    if (!g_real_dlopen) g_real_dlopen = (ahb_dlopen_fn)dlsym(RTLD_DEFAULT, "dlopen");
    if (!g_real_dlopen) return NULL;
    h = g_real_dlopen(name, flags);
    if (h && !g_tr_in_dlopen) {
        g_tr_in_dlopen = 1;
        ahb_force_rescan();
        g_tr_in_dlopen = 0;
    }
    return h;
}

void *ahb_android_dlopen_ext_wrap(const char *name, int flags, const void *extinfo) {
    typedef void *(*ext_fn)(const char *, int, const void *);
    static ext_fn real = NULL;
    static int n2 = 0;
    void *h;
    if (n2 < 24) {
        n2++;
        #if AHB_DIAG
        LOGI("DLOPEN_EXT[%d] %s", n2, name ? name : "(null)");
        #endif
    }
#if AHB_BLOCK_JVMTI
    if (ahb_is_jvmti_path(name)) {
        LOGE("JVMTI 拒绝加载(ext): %s", name);
        return NULL;
    }
#endif
    if (!real) real = (ext_fn)dlsym(RTLD_NEXT, "android_dlopen_ext");
    if (!real) return NULL;
    h = real(name, flags, extinfo);
    if (h && !g_tr_in_dlopen) {
        g_tr_in_dlopen = 1;
        ahb_force_rescan();
        g_tr_in_dlopen = 0;
    }
    return h;
}

/* ================= 供 Zygisk 宿主使用的官方接口桥 ================= */

/*
 * 这套 GOT 补丁原本是手工实现的：自己读 maps、自己解析 ELF 动态段、
 * 自己算重定位表偏移、自己 pwrite 改 GOT 槽。
 *
 * 它能用，但代价已经实测过好几轮：
 *   - 曾出现 TTL 缓存堆竞态（double free / use-after-free）
 *   - 曾因 mprotect 拆出 4KB 碎片被目标判"库被改"
 *   - 曾因 .dynsym 第 0 项是全零而一进循环就 break，一个符号都没扫到
 * 这些都是"自己在实现一个已经有官方实现的机制"必然要踩的坑。
 *
 * Zygisk 提供了等价能力：
 *     pltHookRegister(dev, inode, symbol, newFunc, oldFunc)
 *     pltHookCommit()
 * 它按 dev+inode 定位库、按符号名替换，重定位表解析由框架负责。
 *
 * 所以 Zygisk 宿主下默认走官方接口，本文件的手工实现只作为
 * 「宿主没提供接口」时的兜底（例如旧版 Zygisk 或纯 LSPosed 环境）。
 *
 * 下面两个函数就是给宿主查表用的：符号名清单 + 名字到替换函数的映射。
 */

/* 所有要接管的符号名，NULL 结尾。与 ahb_repl_for 必须保持一致。 */
static const char *const g_ahb_got_syms[] = {
    "open", "openat", "open64", "fopen", "fopen64",
    "__open_2", "__openat_2", "__open64_2", "popen",
    "read", "pread", "pread64", "fread",
    "dl_iterate_phdr", "dlopen", "dlsym", "android_dlopen_ext",
    "xdl_sym", "syscall", "process_vm_readv",
    "fstat", "fstat64", "__fstat64", "fstatat", "fstatat64", "__fstatat64",
    "stat", "stat64", "__stat64", "lstat", "lstat64",
    "statfs", "statfs64", "fstatfs", "fstatfs64",
    "readlink", "readlinkat",
    "exit", "_exit", "exit_group", "kill", "raise", "abort", "tgkill",
    NULL
};

const char *const *ahb_got_sym_list(void) { return g_ahb_got_syms; }

/*
 * 名字到替换函数的映射。
 *
 * 直接转调 ahb_repl_for：两处必须始终一致，
 * 让它成为唯一事实来源，避免清单与分发表漂移。
 */
void *ahb_got_repl(const char *name) {
    uintptr_t p = ahb_repl_for(name);
    return p ? (void *)p : NULL;
}
