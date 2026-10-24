/*
 * 引擎胶水层：把既有 native 引擎接到 Zygisk 宿主上。
 *
 * 为什么不重写引擎：native_main.c + maps_hide.h 一共 8800 行，
 * 里面的 maps 过滤、GOT/PLT 热补丁、JVMTI 中和、路径/dev/inode 自洽、
 * 匿名段剔除、readlink 伪装，全是经过实机多轮验证的东西。
 * 换宿主不需要动引擎，只需要换个调用入口。
 *
 * 原引擎的两个 JNI 入口（nativeEarlyInit / nativeSanitizeRuntime）
 * 本来就是普通 C 函数（带 JNIEXPORT 修饰），C 里可以直接按名调用，
 * 不需要任何 JavaVM 环境。
 */
#include <jni.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <android/log.h>

#define LOG_TAG "AHBZYG"
#define GLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* 原引擎导出的入口 */
extern void Java_com_rev_antihookbypass_NativeLayer_nativeEarlyInit(JNIEnv *env, jclass cls);
extern jint Java_com_rev_antihookbypass_NativeLayer_nativeSanitizeRuntime(JNIEnv *env, jclass cls, jint ops);

/* 与 native_main.c 里的 NATIVE_OP_* 保持一致 */
#define OP_ART   (1 << 0)
#define OP_LINKER (1 << 1)
#define OP_TRAMP (1 << 2)
#define OP_CL    (1 << 3)
#define OP_GUARD (1 << 4)
#define OP_ALL   (OP_ART | OP_LINKER | OP_TRAMP | OP_CL | OP_GUARD)

/*
 * Zygisk 版本的引擎启动。
 *
 * 差别（和 LSPosed 版相比）：
 *  - LSPosed 版把 ART/LINKER 的"还原"开着，因为 lsplant 改过那些代码段
 *  - Zygisk 版没有 lsplant，代码段本来就是干净的，还原是空操作，
 *    所以只留真正需要的：视图过滤、跳板收敛、class_loaders 净化、周期复查
 */
void ahb_zygisk_engine_init(JNIEnv *env, const char *pkg) {
    static int done = 0;
    jint mask;
    if (done) return;
    done = 1;

    GLOGE("engine 初始化 pkg=%s", pkg ? pkg : "(null)");

    Java_com_rev_antihookbypass_NativeLayer_nativeEarlyInit(env, NULL);

    mask = Java_com_rev_antihookbypass_NativeLayer_nativeSanitizeRuntime(
        env, NULL, (jint)(OP_TRAMP | OP_CL | OP_GUARD));

    GLOGE("engine 完成 mask=%d", (int)mask);
}

void ahb_zygisk_engine_set_scope(int on) { (void)on; }
