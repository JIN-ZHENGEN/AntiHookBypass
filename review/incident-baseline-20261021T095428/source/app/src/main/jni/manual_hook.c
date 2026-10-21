/*
 * 手动安装 hook（不依赖 LSPosed 的 native_init 回调）
 *
 * ============================ 为什么要这样 ============================
 *
 * LSPosed 的 native hook 有两个入口：
 *   1. META-INF/xposed/native_init.list + 导出 native_init
 *      —— 由框架在加载模块 so 时调用
 *   2. 模块自己调用（本文件）
 *
 * 问题在于第 1 条路要求 so 由**框架**从 APK 的 lib/<abi>/ 解压加载。
 * 而我们的 so 是 Java 层自己从 APK 里解出来、用绝对路径 System.load()
 * 加载的 —— 框架不知道这件事，自然不会调用 native_init。
 *
 * 结果是：so 加载了、符号也在，但 hook 一个都没装上。检测器照跑不误。
 *
 * 解法：导出一个普通 JNI 函数，Java 层加载完 so 后主动调用它，
 * 由它完成和 native_init 完全一样的初始化。
 * 这样无论 so 是谁加载的，hook 都能装上。
 */
#define _GNU_SOURCE
#include <jni.h>
#include <dlfcn.h>

/* 主文件里的安装函数 */
extern void install_all(void *handle);
extern void set_hook_func(void *fn);

/*
 * JNI 入口：org.example.YYY 之类不需要 —— 这里用动态注册，
 * 由 Java 侧用原生方法名直接调用。
 *
 * 返回装上的 hook 数量，便于 Java 层判断是否成功。
 */
__attribute__((visibility("default")))
jint JNICALL
Java_com_rev_antihookbypass_NativeLayer_nativeInstallHooks(JNIEnv *env, jclass cls,
                                                           jobject hookFunc) {
    (void) env;
    (void) cls;

    /* hookFunc 是 LSPosed 传下来的 NativeHookFunc 指针（long） */
    void *fn = NULL;
    if (hookFunc != NULL) {
        jclass lc = (*env)->FindClass(env, "java/lang/Long");
        if (lc) {
            jmethodID mid = (*env)->GetMethodID(env, lc, "longValue", "()J");
            if (mid) fn = (void *) (intptr_t) (*env)->CallLongMethod(env, hookFunc, mid);
        }
    }
    if (!fn) return 0;

    set_hook_func(fn);

    void *libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) return 0;
    install_all(libc);
    return 1;
}

/*
 * 备用入口：不需要 Java 传函数指针，自己从 liblspd 里取。
 *
 * 有些 LSPosed 版本不暴露 hook 函数指针给模块，这时走这条路：
 * 直接 dlopen liblspd.so，找它的 inline hook 导出符号。
 */
__attribute__((visibility("default")))
jint JNICALL
Java_com_rev_antihookbypass_NativeLayer_nativeInstallHooksAuto(JNIEnv *env, jclass cls) {
    (void) env;
    (void) cls;

    static const char *CANDIDATES[] = {
            "liblspd.so", "liblsposed.so", "libsandhook.so",
            "libdobby.so", "liblsplant.so", NULL
    };
    for (int i = 0; CANDIDATES[i]; i++) {
        void *h = dlopen(CANDIDATES[i], RTLD_NOW | RTLD_NOLOAD);
        if (!h) continue;
        void *fn = dlsym(h, "inlineHook");
        if (!fn) fn = dlsym(h, "HookFunction");
        if (!fn) fn = dlsym(h, "hook");
        if (fn) {
            set_hook_func(fn);
            void *libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
            if (libc) install_all(libc);
            return 1;
        }
    }
    return 0;
}


/*
 * JNI_OnLoad —— 很多框架（含 LSPosed 的 native hook 通道）在 dlopen
 * 一个模块 so 之后，会期望它像普通 JNI 库一样提供这个入口。
 *
 * 参考 Hide My Emulator 的 libnative_entry.so，它同时导出了
 * JNI_OnLoad 和 native_init；只导出后者时，框架可能不会走到
 * native_init 回调。
 */
__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    /*
     * 这里不做实际初始化 —— 真正的 hook 安装依赖 native_init 拿到
     * 框架的 hook_func。只需返回一个合法的 JNI 版本号，表示"加载成功"。
     */
    if (vm == NULL) return JNI_ERR;
    return JNI_VERSION_1_6;
}
