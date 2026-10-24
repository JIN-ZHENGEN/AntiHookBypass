// AntiHook Bypass — Zygisk 宿主版
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
};

static int got_phdr_cb(struct dl_phdr_info *info, size_t, void *data) {
    GotCtx *ctx = (GotCtx *)data;
    const char *name;
    struct stat st;
    int i;

    if (!ctx || !ctx->api || !ctx->syms) return 0;

    name = (info && info->dlpi_name && info->dlpi_name[0])
           ? info->dlpi_name : "/system/bin/app_process64";

    if (stat(name, &st) != 0) return 0;

    for (i = 0; ctx->syms[i]; i++) {
        void *fn = ahb_got_repl(ctx->syms[i]);
        if (!fn) continue;
        ctx->api->pltHookRegister(st.st_dev, st.st_ino, ctx->syms[i], fn, nullptr);
        ctx->nreg++;
    }
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

    dl_iterate_phdr(got_phdr_cb, &ctx);

    if (!api->pltHookCommit()) {
        ZLOGE("pltHookCommit 失败，已注册 %d 条", ctx.nreg);
        return 0;
    }
    ZLOGE("官方接口安装完成：注册 %d 条", ctx.nreg);
    return ctx.nreg;
}

class AhbModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api_ = api;
        this->env_ = env;
        ZLOGE("onLoad api=%p env=%p", (void *)api, (void *)env);
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // 取包名。nice_name 在 specialize 前就可用。
        const char *pkg = nullptr;
        char buf[256];
        buf[0] = 0;
        if (args && args->nice_name) {
            const char *s = env_->GetStringUTFChars(args->nice_name, nullptr);
            if (s) {
                strncpy(buf, s, sizeof(buf) - 1);
                env_->ReleaseStringUTFChars(args->nice_name, s);
                pkg = buf;
            }
        }
        in_scope_ = pkg_in_scope(pkg);
        ZLOGE("preAppSpecialize pkg=%s in_scope=%d uid=%d",
              pkg ? pkg : "(null)", in_scope_, args ? args->uid : -1);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!in_scope_) return;
        const char *pkg = nullptr;
        char buf[256];
        buf[0] = 0;
        if (args && args->nice_name) {
            const char *s = env_->GetStringUTFChars(args->nice_name, nullptr);
            if (s) {
                strncpy(buf, s, sizeof(buf) - 1);
                env_->ReleaseStringUTFChars(args->nice_name, s);
                pkg = buf;
            }
        }
        ZLOGE("postAppSpecialize 启动引擎 pkg=%s", pkg ? pkg : "(null)");
        g_api_for_jni = api_;

        /*
         * 先走官方 pltHookRegister 装 GOT 补丁，再启动引擎。
         *
         * 顺序有讲究：引擎里的视图过滤依赖 open/read 等已被接管，
         * 所以官方接口必须先 commit 完成。反过来的话，
         * 引擎先跑起来那几毫秒里读到的是未过滤视图。
         */
        install_got_hooks_via_api(api_);

        /*
         * 再装 JNI 层 hook。
         *
         * 顺序在 GOT 之后：Field.get 的改写依赖 String 的 value 字段
         * 能被正常读到，而那条路走 GetFieldID，不经过 GOT；
         * 放后面只是为了让日志顺序和依赖链条一致，便于排查。
         */
        ahb_install_jni_hooks(env_,
            [](JNIEnv *e, const char *cn, JNINativeMethod *m, int n) {
                zygisk_api_for_jni()->hookJniNativeMethods(e, cn, m, n);
            });

        ahb_zygisk_engine_init(env_, pkg);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    int in_scope_ = 0;
};

REGISTER_ZYGISK_MODULE(AhbModule)
