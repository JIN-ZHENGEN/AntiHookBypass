// AntiHook Bypass — 引擎（由薄加载器 dlopen 进来）
//
// 与原 LSPosed 版的区别只在"宿主"，不在"引擎"：
//   LSPosed 版：APK + Java 层 + native 库，靠 LSPosed 注入
//   Zygisk 版：纯 native .so，由 Zygisk 在 specialize 前后直接调进来
//
// 因此不需要 APK、不需要 LSPosed 条目、进程里也不会出现
// InMemoryDexClassLoader（那是 LSPosed 自己的内存 dex）。
//
// 本文件只做四件事：
//   1) 拿到 Api 句柄
//   2) preAppSpecialize 里读包名，决定是否在本进程生效
//   3) postAppSpecialize 里调既有引擎（maps 过滤 / JVMTI 中和 / GOT 补丁）
//   4) 全程不申请 root、不用 companion，减少可见面

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <sys/stat.h>
#include "zygisk.hpp"

#define LOG_TAG "AHBZYG"
#define ZLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 既有引擎的入口（来自 native_main.c，同一个构建单元）
extern "C" {
    void ahb_zygisk_engine_init(JNIEnv *env, const char *pkg);
    void ahb_zygisk_engine_set_scope(int on);
    /* maps_hide.h 暴露的桥：符号清单 + 名字到替换函数的映射 */
    const char *const *ahb_got_sym_list(void);
    void *ahb_got_repl(const char *name);
    /* jnihooks.c：用官方 hookJniNativeMethods 装 JNI 层 hook */
    int ahb_install_jni_hooks(JNIEnv *env,
                              void (*hk)(JNIEnv *, const char *, JNINativeMethod *, int));
    /* maps_hide.h：判断某库是否值得用官方接口装补丁 */
    int ahb_got_should_hook(const char *path);
    int ahb_got_should_hook_main(void);
}

/*
 * 作用域：从模块目录下的 scope.txt 读，**不编进 so**。
 *
 * 为什么这么做：把包名编进二进制，意味着"多加一个应用就要重编 + 重装 + 重启"，
 * 这是最难受的迭代成本。改成读文件后，加应用只要：
 *     echo 包名 >> /data/adb/modules/antihookbypass_zygisk/scope.txt
 * 然后重开那个应用，一个字节都不用重编。
 *
 * 读取时机必须在 preAppSpecialize：那时进程还是 zygote 权限，
 * 能读到 /data/adb；到 postAppSpecialize 已经被沙箱限制。
 *
 * 格式：一行一个包名，支持前缀匹配；空行和 # 开头忽略。
 * 文件不存在时用下面的内置默认值。
 */
#define SCOPE_FILE "/data/adb/modules/antihookbypass_zygisk/scope.txt"
#define SCOPE_MAX  32
#define SCOPE_LEN  128

static char g_scope[SCOPE_MAX][SCOPE_LEN];
static int  g_scope_n = 0;
static int  g_scope_loaded = 0;

static const char *const kScopeDefault[] = {
    "com.zhenxi.hunter",
    "com.cshlolss.antihook.detect",
};

static void scope_load(void) {
    FILE *f;
    char line[SCOPE_LEN];
    if (g_scope_loaded) return;
    g_scope_loaded = 1;

    f = fopen(SCOPE_FILE, "r");
    if (!f) {
        for (unsigned i = 0; i < sizeof(kScopeDefault) / sizeof(kScopeDefault[0]); i++) {
            if (g_scope_n >= SCOPE_MAX) break;
            strncpy(g_scope[g_scope_n], kScopeDefault[i], SCOPE_LEN - 1);
            g_scope_n++;
        }
        ZLOGE("scope: 用内置默认 %d 条", g_scope_n);
        return;
    }
    while (fgets(line, sizeof(line), f) && g_scope_n < SCOPE_MAX) {
        char *p = line;
        char *e;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == 0) continue;
        e = p + strlen(p);
        while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) e--;
        *e = 0;
        if (!*p) continue;
        strncpy(g_scope[g_scope_n], p, SCOPE_LEN - 1);
        g_scope[g_scope_n][SCOPE_LEN - 1] = 0;
        g_scope_n++;
    }
    fclose(f);
    ZLOGE("scope: 从文件读到 %d 条", g_scope_n);
}

static int pkg_in_scope(const char *pkg) {
    int i;
    if (!pkg) return 0;
    scope_load();
    for (i = 0; i < g_scope_n; i++) {
        if (strncmp(pkg, g_scope[i], strlen(g_scope[i])) == 0) return 1;
    }
    return 0;
}


/*
 * ===== 为什么必须按"库里真实存在的重定位项"注册 =====
 *
 * 官方 API v4+ 底层是 LSPlt，pltHookCommit 对应 lsplt_commit_hook()：
 * 它要把所有登记过的 (库, 符号) 挨个落到 GOT 槽上，
 * 只要有一个找不到就整体返回 false —— 全部白做。
 *
 * 第一版对每个已加载库都登记全部 44 个符号，实测：
 *
 *     448 库 × 44 符号 = 19712 条
 *     pltHookCommit 失败，已注册 19712 条
 *
 * 一条都没装上，目标应用启动即被系统判超时杀掉。
 *
 * 根因不是"数量多"，而是"登记了大量该库里根本不存在的符号"。
 * 一个库只有它自己 import 的符号才有对应的 GOT 槽可以改。
 *
 * 所以改成：遍历该库的 PLT 重定位表（DT_JMPREL），
 * 只登记解析出的、且在我们清单里的符号。
 *
 * 实测效果（微信进程 92 个 App 库）：
 *     全量登记 4048 条 → 按重定位表 547 条
 * 而且每一条都必然找得到，commit 不会再失败。
 */

/* ELF 重定位里取符号下标：32/64 位布局不同 */
#if defined(__LP64__)
#define AHB_R_SYM(i)  ((unsigned long)((i) >> 32))
#else
#define AHB_R_SYM(i)  ((unsigned long)((i) >> 8))
#endif

/* 把符号下标转成名字，越界一律当没有 */
static const char *ahb_sym_name(const ElfW(Sym) *symtab, unsigned long nsym,
                                const char *strtab, size_t strsz,
                                unsigned long idx) {
    if (!symtab || !strtab || idx >= nsym) return NULL;
    if (symtab[idx].st_name >= strsz) return NULL;
    if (!strtab[symtab[idx].st_name]) return NULL;
    return strtab + symtab[idx].st_name;
}

/*
 * 遍历一个库的 PLT 重定位项，对每个符号名调用 cb。
 * 返回遍历到的项数。
 *
 * 找不到 DT_JMPREL 就直接返回 0 —— 说明这个库没有可 hook 的 PLT 槽。
 */
extern "C" __attribute__((visibility("default"), noinline))
int ahb_walk_plt(const struct dl_phdr_info *info,
                        void (*cb)(void *ud, const char *name),
                        void *ud) {
    const ElfW(Phdr) *ph;
    ElfW(Addr) base;
    const ElfW(Dyn) *dyn = NULL;
    const ElfW(Sym) *symtab = NULL;
    const char *strtab = NULL;
    size_t strsz = 0;
    ElfW(Addr) jmprel = 0;
    size_t jmprelsz = 0;
    int plt_is_rela = 1;
    int i;
    unsigned long nsym = 0;

    if (!info || !info->dlpi_phdr) return 0;
    base = (ElfW(Addr))info->dlpi_addr;
    ph = info->dlpi_phdr;

    for (i = 0; i < info->dlpi_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn) *)(base + ph[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB: symtab = (const ElfW(Sym) *)(base + dyn[i].d_un.d_ptr); break;
        case DT_STRTAB: strtab = (const char *)(base + dyn[i].d_un.d_ptr); break;
        case DT_STRSZ:  strsz  = (size_t)dyn[i].d_un.d_val; break;
        case DT_JMPREL: jmprel = (ElfW(Addr))(base + dyn[i].d_un.d_ptr); break;
        case DT_PLTRELSZ: jmprelsz = (size_t)dyn[i].d_un.d_val; break;
        case DT_PLTREL:   plt_is_rela = (dyn[i].d_un.d_val == DT_RELA); break;
        case DT_HASH: {
            const unsigned *h = (const unsigned *)(base + dyn[i].d_un.d_ptr);
            if (h) nsym = h[1];
            break;
        }
        default: break;
        }
    }

    if (!symtab || !strtab || !jmprel || !jmprelsz) return 0;
    if (!nsym) nsym = 1u << 20;   /* 没有 DT_HASH 时给个宽松上界 */

    if (plt_is_rela) {
        const ElfW(Rela) *r = (const ElfW(Rela) *)jmprel;
        size_t n = jmprelsz / sizeof(ElfW(Rela));
        size_t k;
        for (k = 0; k < n; k++) {
            const char *nm = ahb_sym_name(symtab, nsym, strtab, strsz,
                                          AHB_R_SYM(r[k].r_info));
            if (nm && cb) cb(ud, nm);
        }
        return (int)n;
    } else {
        const ElfW(Rel) *r = (const ElfW(Rel) *)jmprel;
        size_t n = jmprelsz / sizeof(ElfW(Rel));
        size_t k;
        for (k = 0; k < n; k++) {
            const char *nm = ahb_sym_name(symtab, nsym, strtab, strsz,
                                          AHB_R_SYM(r[k].r_info));
            if (nm && cb) cb(ud, nm);
        }
        return (int)n;
    }
}

/*
 * 用官方 pltHookRegister 安装 GOT 补丁。
 *
 * 与手工实现的差别：
 *   - 重定位表解析、ELF 动态段遍历由框架负责，不用我们碰
 *   - 按 dev+inode 定位库，天然不会认错同名库
 *   - 一次 commit 生效，没有"扫一半崩了"的中间态
 *
 * 逐个 ELF 注册的原因：官方接口是按（库, 符号）为单位注册的，
 * 而我们要对所有已加载库生效，所以每个 ELF 都要过一遍。
 */
/* 回调上下文：把 Api 指针和计数传进 dl_iterate_phdr 的回调。
 * 不能用 lambda capture：这里禁 STL、禁异常，且 dl_iterate_phdr
 * 的 C 回调签名是裸函数指针。 */
struct GotCtx {
    zygisk::Api *api;
    const char *const *syms;
    int nreg;
    int nlib;
    int nskip;
    int capped;
};

/*
 * 每个已加载的库走一遍，只对"值得 hook 的库"注册。
 *
 * ===== 为什么不能对所有库都注册 =====
 *
 * 第一版对 448 个库 × 44 条符号全注册，实测 19712 条，
 * pltHookCommit 直接失败，一条都没装上，进程启动即被判超时杀掉。
 *
 * 现在先用 ahb_got_should_hook 过滤（复用引擎验证过的规则），
 * 再加一道硬上限兜底：万一将来规则放宽导致数量暴涨，
 * 宁可少装也不要把 commit 撑崩。
 */
static const int kMaxRegister = 2000;

/* ahb_walk_plt 的回调上下文：一个库一趟，边遍历边登记 */
struct PltCtx {
    GotCtx *g;
    dev_t dev;
    ino_t ino;
};

extern "C" __attribute__((visibility("default"), noinline))
void got_one_reloc(void *ud, const char *name) {
    PltCtx *p = (PltCtx *)ud;
    GotCtx *ctx;
    void *fn;
    int i;

    if (!p || !(ctx = p->g)) return;
    if (ctx->nreg >= kMaxRegister) { ctx->capped = 1; return; }

    /* 只关心清单里的符号 */
    for (i = 0; ctx->syms[i]; i++) {
        if (strcmp(ctx->syms[i], name) != 0) continue;
        fn = ahb_got_repl(name);
        if (!fn) return;
        ctx->api->pltHookRegister(p->dev, p->ino, ctx->syms[i], fn, nullptr);
        ctx->nreg++;
        return;
    }
}

static int got_phdr_cb(struct dl_phdr_info *info, size_t, void *data) {
    GotCtx *ctx = (GotCtx *)data;
    const char *name;
    struct stat st;
    int is_main;
    PltCtx pc;

    if (!ctx || !ctx->api || !ctx->syms) return 0;

    is_main = (info && info->dlpi_name && info->dlpi_name[0]) ? 0 : 1;
    name = is_main ? "/system/bin/app_process64" : info->dlpi_name;

    ctx->nlib++;

    /* 先过滤再 stat，stat 也有开销 */
    if (!is_main && !ahb_got_should_hook(name)) {
        ctx->nskip++;
        return 0;
    }

    if (stat(name, &st) != 0) {
        ctx->nskip++;
        return 0;
    }

    /*
     * 关键：只登记这个库 PLT 表里真实存在的符号。
     *
     * 不能对每个库都试着登记全部 44 个 —— 一个库里没被 import 的符号
     * 压根没有对应的 GOT 槽，登记了只会让 commit 整体失败。
     */
    pc.g = ctx;
    pc.dev = st.st_dev;
    pc.ino = st.st_ino;
    ahb_walk_plt(info, got_one_reloc, &pc);

    if (ctx->capped) return 1;
    return 0;
}

/*
 * 用官方 pltHookRegister 安装 GOT 补丁。
 *
 * 与手工实现的差别：
 *   - 重定位表解析、ELF 动态段遍历由框架负责，不用我们碰
 *   - 按 dev+inode 定位库，天然不会认错同名库
 *   - 一次 commit 生效，没有"扫一半崩了"的中间态
 */
/* 给 C 侧用的 api 句柄（JNI hook 安装需要一个裸函数指针，不能带 C++ this） */
static zygisk::Api *g_api_for_jni = nullptr;
static zygisk::Api *zygisk_api_for_jni(void) { return g_api_for_jni; }

static int install_got_hooks_via_api(zygisk::Api *api) {
    const char *const *syms;
    GotCtx ctx;

    if (!api) return 0;
    syms = ahb_got_sym_list();
    if (!syms) return 0;

    ctx.api = api;
    ctx.syms = syms;
    ctx.nreg = 0;
    ctx.nlib = 0;
    ctx.nskip = 0;
    ctx.capped = 0;

    dl_iterate_phdr(got_phdr_cb, &ctx);

    ZLOGE("官方接口：扫描 %d 库，命中 %d 库，注册 %d 条%s",
          ctx.nlib, ctx.nlib - ctx.nskip, ctx.nreg, ctx.capped ? "（已封顶）" : "");

    if (ctx.nreg == 0) {
        ZLOGE("没有需要注册的库，跳过 commit");
        return 0;
    }

    if (!api->pltHookCommit()) {
        ZLOGE("pltHookCommit 失败，已注册 %d 条", ctx.nreg);
        return 0;
    }
    ZLOGE("官方接口安装完成：注册 %d 条", ctx.nreg);
    return ctx.nreg;
}

/*
 * 引擎对外入口 —— 薄加载器通过 dlsym 找到这个函数。
 *
 * 签名固定为 (JNIEnv*, const char*, void*)，第三个参数是 zygisk::Api*。
 * 加载器不认识引擎内部结构，引擎也不认识加载器，两边只靠这一个符号对接。
 */
extern "C" __attribute__((visibility("default")))
int ahb_engine_entry(JNIEnv *env, const char *pkg, void *api) {
    zygisk::Api *za = (zygisk::Api *)api;
    g_api_for_jni = za;
    install_got_hooks_via_api(za);
    ahb_install_jni_hooks(env,
        [](JNIEnv *e, const char *cn, JNINativeMethod *m, int n) {
            zygisk_api_for_jni()->hookJniNativeMethods(e, cn, m, n);
        });
    ahb_zygisk_engine_init(env, pkg);
    return 0;
}

