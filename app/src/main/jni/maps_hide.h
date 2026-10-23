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
static int maps_line_is_trace(const char *line) {
    const char *const *m;
    for (m = g_trace_markers; *m; m++) {
        if (strstr(line, *m)) return 1;
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
        unsigned long long s = 0, e = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perm) == 3 &&
            strncmp(perm, "r-x", 3) == 0) {
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

/* ---------------- 状态 ---------------- */

static unsigned long g_maps_open_calls = 0;
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
static int g_disable_all_patch = 0;   /* 对照实验：完全不接管任何槽 */
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
static int maps_path_is_self(const char *path) {
    char want[64];
    if (!path) return 0;
    if (!strstr(path, "/maps")) return 0;
    if (strcmp(path, "/proc/self/maps") == 0) return 1;
    snprintf(want, sizeof(want), "/proc/%d/maps", (int)getpid());
    if (strcmp(path, want) == 0) return 1;
    snprintf(want, sizeof(want), "/proc/%d/task/%d/maps", (int)getpid(), (int)getpid());
    if (strcmp(path, want) == 0) return 1;
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

static char *g_saved_maps_path = NULL;

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
#define MAPS_CACHE_MAX 4

typedef struct {
    int      fd;
    uint64_t sig;
} maps_cache_ent;

static maps_cache_ent g_maps_cache[MAPS_CACHE_MAX];
static int            g_maps_cache_n = 0;
static uint64_t       g_maps_pending_sig = 0;
static int            g_maps_pending = 0;

#define MAPS_TTL_MS 120
static int      g_maps_ttl_fd   = -1;
static time_t   g_maps_ttl_sec  = 0;
static long     g_maps_ttl_nsec = 0;
static unsigned long g_maps_ttl_hits = 0;

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

static int maps_make_clean_fd(void) {
    char *raw = NULL, *out = NULL;
    size_t cap = 0, w = 0;
    int n, dropped = 0;
    char *line;
    long fd;

    if (!g_saved_maps_path) {
        char p[128];
        snprintf(p, sizeof(p), "/data/local/tmp/.ahbmaps_%d", (int)getpid());
        g_saved_maps_path = strdup(p);
    }

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
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (g_maps_ttl_fd >= 0 &&
            (now.tv_sec - g_maps_ttl_sec) * 1000L +
            (now.tv_nsec - g_maps_ttl_nsec) / 1000000L < MAPS_TTL_MS) {
            int dup_fd = (int)syscall(SYS_dup, g_maps_ttl_fd);
            if (dup_fd >= 0) {
                syscall(SYS_lseek, dup_fd, 0, SEEK_SET);
                g_maps_ttl_hits++;
                return dup_fd;
            }
        }
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
        unsigned long long prev_s = 0, prev_e = 0, prev_off = 0;
        char prev_perm[8] = {0}, prev_path[AHB_PATH_MAX] = {0};
        int have_prev = 0;

        line = raw;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            size_t len = nl ? (size_t)(nl - line + 1) : strlen(line);

            if (maps_line_is_trace(line)) {
                dropped++;
                if (!nl) break;
                line = nl + 1;
                continue;
            }

            {
                unsigned long long cs = 0, ce = 0, co = 0, cinode = 0;
                char cperm[8] = {0}, cdev[16] = {0}, cpath[AHB_PATH_MAX] = {0};
                int ok = sscanf(line, "%llx-%llx %7s %llx %15s %llu %319[^\n]",
                                &cs, &ce, cperm, &co, cdev, &cinode, cpath);

                /*
                 * 显式丢弃匿名可执行段。
                 *
                 * 不能只依赖 maps_line_is_trace()：实测过滤产物里
                 * 仍出现 "30f938e000-30f938f000 rw-p 0 00:00 0
                 * 30f938f000-30f9537000 r-xp 00000000 00:00 0" ——
                 * 匿名 r-x 行没被丢掉，而是被拼进了上一行末尾，
                 * 检测器按行解析时仍把它当成一条独立段，数出 3 个判 RISK。
                 *
                 * 这里按字段直接判：权限是 r-x 且路径字段为空 = 匿名可执行段。
                 * 与 sscanf 返回值无关，不依赖任何"抑制赋值"的语义。
                 */
                if (ok >= 4 && cperm[0] == 'r' && cperm[1] == '-' &&
                    cperm[2] == 'x' && cpath[0] == '\0') {
                    dropped++;
                    if (!nl) break;
                    line = nl + 1;
                    continue;
                }

                if (ok >= 7 && have_prev &&
                    strncmp(cperm, "r-x", 3) == 0 &&
                    strcmp(prev_perm, cperm) == 0 &&
                    strcmp(prev_path, cpath) == 0 &&
                    cs == prev_e) {
                    /* 相邻同文件可执行段：只把上一段的结束地址往后延 */
                    prev_e = ce;
                    if (!nl) break;
                    line = nl + 1;
                    continue;
                }

                if (have_prev) {
                    char obuf[1024];
                    int on = snprintf(obuf, sizeof(obuf),
                                      "%llx-%llx %s %llx %s %llu %s\n",
                                      prev_s, prev_e, prev_perm, prev_off,
                                      "00:00", (unsigned long long)0, prev_path);
                    if (on > 0 && w + (size_t)on < cap) {
                        memcpy(out + w, obuf, (size_t)on);
                        w += (size_t)on;
                    }
                }

                if (ok >= 7) {
                    prev_s = cs; prev_e = ce; prev_off = co;
                    strncpy(prev_perm, cperm, sizeof(prev_perm) - 1);
                    strncpy(prev_path, cpath, sizeof(prev_path) - 1);
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
            char obuf[1024];
            int on = snprintf(obuf, sizeof(obuf), "%llx-%llx %s %llx %s %llu %s\n",
                              prev_s, prev_e, prev_perm, prev_off,
                              "00:00", (unsigned long long)0, prev_path);
            if (on > 0 && w + (size_t)on < cap) {
                memcpy(out + w, obuf, (size_t)on);
                w += (size_t)on;
            }
        }
    }
    g_maps_filtered++;
    (void)dropped;

    /*
     * 落一份过滤结果用于离线核对。
     * 只在头几次生成，避免长期占空间；路径固定，方便直接 diff。
     */
    /*
     * 诊断 dump：只在指纹变化时写一次，且最多 4 次。
     * 用真实 syscall 打开，避免经过自己的包装。
     */
    if (g_maps_filtered <= 4) {
        /* 写到本进程自己的数据目录：app 身份写不了 /data/local/tmp */
        char dpath[256];
        char cmd[128] = {0};
        int cf = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/cmdline", O_RDONLY, 0);
        if (cf >= 0) {
            syscall(SYS_read, cf, cmd, sizeof(cmd) - 1);
            syscall(SYS_close, cf);
        }
        { char *c = strchr(cmd, ':'); if (c) *c = 0; }
        snprintf(dpath, sizeof(dpath), "/data/user/0/%s/files/maps_filtered", cmd);
        int dfd = (int)syscall(SYS_openat, AT_FDCWD, dpath,
                               O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (dfd >= 0) {
            size_t o = 0;
            while (o < w) {
                long k = syscall(SYS_write, dfd, out + o, w - o);
                if (k <= 0) break;
                o += (size_t)k;
            }
            syscall(SYS_close, dfd);
        }
    }

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

    /* 刷新时间窗口缓存 */
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (g_maps_ttl_fd >= 0) syscall(SYS_close, g_maps_ttl_fd);
        g_maps_ttl_fd = (int)syscall(SYS_dup, (int)fd);
        g_maps_ttl_sec = now.tv_sec;
        g_maps_ttl_nsec = now.tv_nsec;
    }

    /* 入缓存（复用最旧的一格），调用方拿 dup 的句柄 */
    if (g_maps_pending) {
        int slot = g_maps_cache_n;
        if (slot >= MAPS_CACHE_MAX) {
            slot = 0;
            for (int i = 1; i < MAPS_CACHE_MAX; i++) {
                if (g_maps_cache[i].sig < g_maps_cache[slot].sig) slot = i;
            }
            if (g_maps_cache[slot].fd >= 0) syscall(SYS_close, g_maps_cache[slot].fd);
        } else {
            g_maps_cache_n++;
        }
        g_maps_cache[slot].sig = g_maps_pending_sig;
        g_maps_cache[slot].fd  = (int)fd;
        g_maps_pending = 0;

        {
            int dup_fd = (int)syscall(SYS_dup, (int)fd);
            if (dup_fd >= 0) {
                syscall(SYS_lseek, dup_fd, 0, SEEK_SET);
                free(raw); free(out);
                return dup_fd;
            }
        }
    }

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

static int maps_open_wrap(const char *path, int flags, mode_t mode) {
    maps_resolve_reals();
    g_maps_open_calls++;
    maps_lazy_rescan();
    /* 诊断：记录实际经过的路径，确认目标用什么姿势读 maps */
    {
        static int dbg_left = 20;   /* 限量：高频调用时反复写日志本身很贵 */
        if (dbg_left > 0 && path && strstr(path, "/proc/")) {
            dbg_left--;
            ahb_filelog("OPEN %s", path);
        }
    }
    if (maps_path_is_self(path)) {
        int fd = maps_make_clean_fd();
        if (fd >= 0) return fd;
    }
    if (g_real_open) return g_real_open(path, flags, mode);
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

static int maps_openat_wrap(int dirfd, const char *path, int flags, mode_t mode) {
    maps_resolve_reals();
    g_maps_open_calls++;
    if (maps_path_is_self(path)) {
        int fd = maps_make_clean_fd();
        if (fd >= 0) return fd;
    }
    if (g_real_openat) return g_real_openat(dirfd, path, flags, mode);
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

static void *maps_fopen_wrap(const char *path, const char *mode) {
    maps_resolve_reals();
    g_maps_open_calls++;
    maps_lazy_rescan();
    {
        static int dbg_left = 20;
        if (dbg_left > 0 && path && strstr(path, "/proc/")) {
            dbg_left--;
            ahb_filelog("FOPEN %s", path);
        }
    }
    if (maps_path_is_self(path)) {
        int fd = maps_make_clean_fd();
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
    maps_resolve_reals();
    g_maps_open_calls++;
    if (maps_path_is_self(path)) {
        int fd = maps_make_clean_fd();
        if (fd >= 0) return fd;
        }
    if (g_real_open_2) return g_real_open_2(path, flags);
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, 0);
}

static int maps_open64_wrap(const char *path, int flags, mode_t mode) {
    maps_resolve_reals();
    g_maps_open_calls++;
    if (maps_path_is_self(path)) {
        int fd = maps_make_clean_fd();
        if (fd >= 0) return fd;
        }
    if (g_real_open64) return g_real_open64(path, flags, mode);
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

static int maps_openat_2_wrap(int dirfd, const char *path, int flags) {
    maps_resolve_reals();
    g_maps_open_calls++;
    if (maps_path_is_self(path)) {
        int fd = maps_make_clean_fd();
        if (fd >= 0) return fd;
        }
    if (g_real_openat_2) return g_real_openat_2(dirfd, path, flags);
    return (int)syscall(SYS_openat, dirfd, path, flags, 0);
}

static int maps_open64_2_wrap(const char *path, int flags) {
    maps_resolve_reals();
    g_maps_open_calls++;
    if (maps_path_is_self(path)) {
        int fd = maps_make_clean_fd();
        if (fd >= 0) return fd;
        }
    if (g_real_open64_2) return g_real_open64_2(path, flags);
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, 0);
}

/* opendir("/proc/self") 本身不含 maps，但目录项会暴露；只拦 maps 路径 */
static struct __dirstream *maps_opendir_wrap(const char *path) {
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
    maps_resolve_reals();
    if (cmd && strstr(cmd, "/proc/self/maps")) {
        g_maps_open_calls++;
        int fd = maps_make_clean_fd();
        if (fd >= 0) {
            /* 把干净内容落成一个匿名可读文件，再让 cat 去读它 */
            char tmpl[] = "/data/local/tmp/.ahbmapsXXXXXX";
            (void)tmpl;
            FILE *f = fdopen(fd, "r");
            if (f) {
                if (g_saved_maps_path) {
                    FILE *out = g_real_fopen ? g_real_fopen(g_saved_maps_path, "w") : NULL;
                    if (out) {
                        char buf[8192];
                        size_t k;
                        while ((k = fread(buf, 1, sizeof(buf), f)) > 0) {
                            fwrite(buf, 1, k, out);
                        }
                        fclose(out);
                        char nc[512];
                        snprintf(nc, sizeof(nc), "cat %s", g_saved_maps_path);
                        fclose(f);
                        if (g_real_popen) return g_real_popen(nc, mode);
                    } else {
                        fclose(f);
                    }
                } else {
                    fclose(f);
                }
            } else {
                syscall(SYS_close, fd);
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

static int ahb_so_skip(const char *path) {
    /*
     * 绝不动 libc/libart/linker：那会破坏系统调用层与 ART 自身。
     *
     * 也绝不动**本模块自己**：模块的日志函数用 open 写文件，
     * 一旦自己的 open 槽也被改到包装上，就变成
     * ahb_filelog -> open -> maps_open_wrap -> ahb_filelog 无限递归，
     * 表现是日志写不出来、进程卡死或栈溢出。
     */
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
        if (path && maps_path_is_self(path)) {
            int fd = maps_make_clean_fd();
            if (fd >= 0) return (long)fd;
        }
    }
    if (g_raw_syscall)
        return ((syscall6_fn)g_raw_syscall)(number, a1, a2, a3, a4, a5, a6);
    return -1;
}

/* process_vm_readv 的包装体在 native_main.c 里，这里只做转发声明 */
static ssize_t clv_pvr_entry(pid_t pid, const struct iovec *local, unsigned long liovcnt,
                             const struct iovec *remote, unsigned long riovcnt,
                             unsigned long flags);

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
    if (strcmp(name, "exit") == 0)            return (uintptr_t)ep_exit;
    if (strcmp(name, "_exit") == 0)           return (uintptr_t)ep__exit;
    if (strcmp(name, "kill") == 0)            return (uintptr_t)ep_kill;
    if (strcmp(name, "raise") == 0)           return (uintptr_t)ep_raise;
    if (strcmp(name, "abort") == 0)           return (uintptr_t)ep_abort;
    if (strcmp(name, "tgkill") == 0)          return (uintptr_t)ep_tgkill;
    if (strcmp(name, "exit_group") == 0)      return (uintptr_t)ep_exit_group;
    if (strcmp(name, "syscall") == 0)         return (uintptr_t)maps_syscall_wrap;
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
    ElfW(Ehdr) *eh;
    ElfW(Phdr) *ph;
    ElfW(Dyn)  *dyn = NULL;
    const ElfW(Sym)  *symtab = NULL;
    const char       *strtab = NULL;
    const ElfW(Rela) *jmprel = NULL, *rela = NULL;
    size_t pltrelsz = 0, relasz = 0, relaent = sizeof(ElfW(Rela));
    size_t i;
    int patched = 0;
    uintptr_t dyn_addr = 0;

    if (so->tried) return 0;
    so->tried = 1;
    if (ahb_already_done(so->path)) return 0;
    if (!so->base) return 0;
    if (so->base & 0xfff) return 0;

    if (!ahb_addr_mapped(so->base, sizeof(ElfW(Ehdr)))) return 0;
    eh = (ElfW(Ehdr) *)so->base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return 0;
    if (eh->e_machine != EM_AARCH64 && eh->e_machine != EM_X86_64) return 0;
    if (eh->e_phentsize != sizeof(ElfW(Phdr))) return 0;
    if (eh->e_phnum == 0 || eh->e_phnum > 64) return 0;
    if (!ahb_addr_mapped(so->base + eh->e_phoff,
                         (size_t)eh->e_phnum * sizeof(ElfW(Phdr)))) return 0;

    ph = (ElfW(Phdr) *)(so->base + eh->e_phoff);
    for (i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn_addr = so->base + ph[i].p_vaddr;
            if (!ahb_addr_mapped(dyn_addr, sizeof(ElfW(Dyn)) * 2)) return 0;
            dyn = (ElfW(Dyn) *)dyn_addr;
            break;
        }
    }
    if (!dyn) return 0;

    for (i = 0; i < 512 && dyn[i].d_tag != DT_NULL; i++) {
        uintptr_t raw = (uintptr_t)dyn[i].d_un.d_ptr;
        switch (dyn[i].d_tag) {
        case DT_PLTRELSZ: pltrelsz = (size_t)raw; break;
        case DT_RELASZ:   relasz   = (size_t)raw; break;
        case DT_RELAENT:  relaent  = (size_t)raw; break;
        case DT_SYMTAB:
        case DT_STRTAB:
        case DT_JMPREL:
        case DT_RELA: {
            uintptr_t v = raw;
            if (!raw) break;
            /* 已重定位就是绝对地址；没重定位就补上基址。两种都接受，
               但都必须落在已映射区间内才敢用。 */
            if (!ahb_addr_mapped(raw, 8)) {
                if (ahb_addr_mapped(so->base + raw, 8)) v = so->base + raw;
                else break;
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
            if (!ahb_addr_mapped((uintptr_t)r, bytes)) continue;
            n = bytes / relaent;
            for (k = 0; k < n; k++) {
                uint32_t sym, type;
                const char *nm;
                uintptr_t repl, slot;
                sym  = (uint32_t)(r[k].r_info >> 32);
                type = (uint32_t)(r[k].r_info & 0xffffffffu);
                if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT) continue;
                /* 符号表项与字符串都要先确认可读 */
                if (!ahb_addr_mapped((uintptr_t)&symtab[sym], sizeof(ElfW(Sym)))) continue;
                nm = strtab + symtab[sym].st_name;
                if (!ahb_addr_mapped((uintptr_t)nm, 2)) continue;
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
                if (ahb_is_libc(so->path) && strcmp(nm, "process_vm_readv") != 0) {
                    continue;
                }
                so->has_target = 1;
                if (strstr(so->path, "/libc.so")) {
                    ahb_filelog("MAPS libc-target %s slot=%p", nm, (void *)(so->base + r[k].r_offset));
                }
                slot = so->base + (uintptr_t)r[k].r_offset;
                if (!ahb_addr_mapped(slot, sizeof(uintptr_t))) continue;
                if (!ahb_write_slot(slot, repl)) continue;
                patched++;
                g_maps_got_patched++;
                /* 记录接管的符号名：排查"pvr 到底接没接上"必须看到这一行 */
                if (strcmp(nm, "process_vm_readv") == 0 || strcmp(nm, "syscall") == 0) {
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
        ahb_filelog("MAPS lib %s patched=%d", so->path, patched);
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
    if (!g_real_fopen) return 0;
    fp = g_real_fopen("/proc/self/maps", "r");
    if (!fp) return 0;

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
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long s = 0, e = 0, off = 0;
        char perm[16] = {0}, path[AHB_PATH_MAX] = {0};
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
    fclose(fp);

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

#endif /* AHB_MAPS_HIDE_H */
