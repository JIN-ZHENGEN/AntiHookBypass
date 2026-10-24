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
#include "zygisk.hpp"

#define LOG_TAG "AHBZYG"
#define ZLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 既有引擎的入口（来自 native_main.c，同一个构建单元）
extern "C" {
    void ahb_zygisk_engine_init(JNIEnv *env, const char *pkg);
    void ahb_zygisk_engine_set_scope(int on);
}

// 作用域：只有这些包在进程内启用引擎。
// 留空字符串表示"全部进程"，便于先验证通路。
static const char *const kScopePkgs[] = {

    "com.zhenxi.hunter",
    "com.cshlolss.antihook.detect",
};

static int pkg_in_scope(const char *pkg) {
    if (!pkg) return 0;
    for (unsigned i = 0; i < sizeof(kScopePkgs) / sizeof(kScopePkgs[0]); i++) {
        const char *s = kScopePkgs[i];
        if (strncmp(pkg, s, strlen(s)) == 0) return 1;
    }
    return 0;
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
        ahb_zygisk_engine_init(env_, pkg);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    int in_scope_ = 0;
};

REGISTER_ZYGISK_MODULE(AhbModule)
