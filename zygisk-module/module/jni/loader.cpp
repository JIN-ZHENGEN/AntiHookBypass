// AntiHook Bypass — Zygisk 薄加载器
//
// ===== 为什么要有这一层 =====
//
// Zygisk Next 在开机时把所有模块 .so 读进内存并记录 (dev, inode, size)，
// 之后每次注入都用内存里那份。实测：直接替换磁盘上的 .so 完全无效 ——
// 换 inode（写新文件再 mv）也没用，日志里跑的还是旧代码。
//
// 也就是说，只要逻辑写在模块 .so 里，每改一行都得重启设备才能验证。
// 这对开发是灾难。
//
// 解决办法：把模块拆成两半。
//   1) 本文件（加载器）：只做 zygisk 注册 + 把引擎 .so 加载进来。
//      逻辑极少，几乎不需要改，因此几乎不需要重启。
//   2) 引擎 .so（engine/<abi>.so）：真正的业务代码。
//      它在每次应用启动时从磁盘现读，改完保存即生效，不用重启。
//
// 加载路径有两个：
//   - 优先直接 dlopen 绝对路径（大多数情况下 /data/adb/modules 可读）
//   - 读不到就用 preAppSpecialize 阶段（还有 zygote 权限）读进来的字节，
//     落到 memfd 再 dlopen，绕过沙箱限制

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
#include <android/log.h>
#include <dlfcn.h>
#include "zygisk.hpp"

#define LOG_TAG "AHBZYG"
#define ZLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define MOD_DIR   "/data/adb/modules/antihookbypass_zygisk"
#define SCOPE_FILE MOD_DIR "/scope.txt"
#define SCOPE_MAX  32
#define SCOPE_LEN  128

static char g_scope[SCOPE_MAX][SCOPE_LEN];
static int  g_scope_n = 0;
static int  g_scope_loaded = 0;

/* preAppSpecialize 阶段读进来的引擎字节（那时还能读 /data/adb） */
static unsigned char *g_eng = NULL;
static size_t g_eng_len = 0;

static void scope_load(void) {
    FILE *f;
    char line[SCOPE_LEN + 8];
    if (g_scope_loaded) return;
    g_scope_loaded = 1;
    f = fopen(SCOPE_FILE, "r");
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        size_t n;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || !*p) continue;
        n = strlen(p);
        while (n && (p[n-1] == '\n' || p[n-1] == '\r' || p[n-1] == ' ')) p[--n] = 0;
        if (!n || g_scope_n >= SCOPE_MAX) continue;
        strncpy(g_scope[g_scope_n], p, SCOPE_LEN - 1);
        g_scope[g_scope_n][SCOPE_LEN - 1] = 0;
        g_scope_n++;
    }
    fclose(f);
    ZLOGE("scope: %d 条", g_scope_n);
}

static int pkg_in_scope(const char *pkg) {
    int i;
    if (!pkg) return 0;
    scope_load();
    for (i = 0; i < g_scope_n; i++)
        if (strncmp(pkg, g_scope[i], strlen(g_scope[i])) == 0) return 1;
    return 0;
}

/* 当前 ABI 的引擎文件名 */
static const char *engine_name(void) {
#if defined(__aarch64__)
    return "arm64-v8a.so";
#elif defined(__arm__)
    return "armeabi-v7a.so";
#elif defined(__x86_64__)
    return "x86_64.so";
#else
    return "x86.so";
#endif
}

/* preAppSpecialize 用：把引擎 .so 整个读进内存 */
static void engine_prefetch(void) {
    char path[256];
    int fd;
    struct stat st;
    if (g_eng) return;
    snprintf(path, sizeof(path), MOD_DIR "/engine/%s", engine_name());
    fd = open(path, O_RDONLY);
    if (fd < 0) { ZLOGE("引擎读不到: %s", path); return; }
    if (fstat(fd, &st) != 0 || st.st_size <= 0 || st.st_size > (64 << 20)) {
        close(fd);
        return;
    }
    g_eng = (unsigned char *)malloc((size_t)st.st_size);
    if (!g_eng) { close(fd); return; }
    {
        ssize_t got = read(fd, g_eng, (size_t)st.st_size);
        if (got != (ssize_t)st.st_size) { free(g_eng); g_eng = NULL; close(fd); return; }
    }
    close(fd);
    g_eng_len = (size_t)st.st_size;
}

typedef int (*engine_entry_fn)(JNIEnv *env, const char *pkg, void *api);

static void *load_engine(void) {
    void *h = NULL;
    char path[256];

    /*
     * 路线一优先：走 preAppSpecialize 预读好的字节。
     *
     * 为什么它才是主路线：应用进程被沙箱后读不到 /data/adb
     * （实测 uid 10123 直接 open 返回 errno=13 Permission denied）。
     * 引擎字节只能在 specialize 之前读，之后靠 memfd 交给沙箱内的进程。
     *
     * memfd_create 不需要任何文件权限，所以这一步在沙箱内也能做。
     */
    if (g_eng && g_eng_len) {
        int fd = (int)syscall(__NR_memfd_create, "ahb-engine", 1u /* MFD_CLOEXEC */);
        if (fd >= 0) {
            ssize_t w = write(fd, g_eng, g_eng_len);
            if (w == (ssize_t)g_eng_len) {
                char p[64];
                snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
                h = dlopen(p, RTLD_NOW);
                ZLOGE("引擎加载（memfd %d / %zu 字节）= %s", fd, g_eng_len,
                      h ? "成功" : dlerror());
            } else {
                ZLOGE("memfd 写入不全 %zd/%zu", w, g_eng_len);
            }
            /* dlopen 已经把内容映射进去了，fd 可以关 */
            close(fd);
        } else {
            ZLOGE("memfd_create 失败 errno=%d", errno);
        }
    }

    /*
     * 路线二兜底：直接按绝对路径加载。
     *
     * 只有少数情况会走到这里 —— 比如预读失败（文件不存在 / 权限异常），
     * 或者运在某些 /data/adb 仍然可读的环境里。沙箱下这条会失败，
     * 所以它不能当主路线。
     */
    if (!h) {
        snprintf(path, sizeof(path), MOD_DIR "/engine/%s", engine_name());
        h = dlopen(path, RTLD_NOW);
        ZLOGE("引擎加载（磁盘路径）= %s", h ? "成功" : dlerror());
    }

    if (!h) ZLOGE("引擎加载彻底失败");
    return h;
}

class AhbLoader : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
        g_api_ = api;
        ZLOGE("loader onLoad api=%p", (void *)api);
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *pkg = NULL;
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
        if (in_scope_) {
            /* 此刻还在 zygote 权限，能读 /data/adb */
            engine_prefetch();
            ZLOGE("preAppSpecialize pkg=%s in_scope=1 引擎预读=%zu 字节",
                  pkg ? pkg : "(null)", g_eng_len);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs * /*args*/) override {
        if (!in_scope_) return;
        g_api_for_jni_ = api_;
        {
            void *h = load_engine();
            if (!h) return;
            engine_entry_fn fn = (engine_entry_fn)dlsym(h, "ahb_engine_entry");
            if (!fn) { ZLOGE("引擎里没有 ahb_engine_entry"); return; }
            fn(env_, NULL, (void *)api_);
        }
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    int in_scope_ = 0;

public:
    static zygisk::Api *g_api_;
    static zygisk::Api *g_api_for_jni_;
};

zygisk::Api *AhbLoader::g_api_ = nullptr;
zygisk::Api *AhbLoader::g_api_for_jni_ = nullptr;

REGISTER_ZYGISK_MODULE(AhbLoader)
