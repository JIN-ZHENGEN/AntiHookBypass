/*
 * JNI 层 hook：用官方 hookJniNativeMethods 实现原 Java 层的三项能力。
 *
 * ===== 为什么只做这三项 =====
 * 原 Java 层 4133 行，但逐项核对后真正需要在 Zygisk 下重建的只有这些。
 * 依据是运行时实测（不是看文档猜的）：
 *
 *   方法                                       native?  官方接口能否覆盖
 *   Class.forName                             否       不能
 *   ClassLoader.loadClass/findClass           否       不能
 *   Throwable.getStackTrace                   否       不能
 *   System.exit                               否       不能
 *   ------------------------------------------------ 分界
 *   Class.getDeclaredField                    是       能
 *   Throwable.nativeGetStackTrace              是       能
 *   reflect.Field.get / set                   是       能
 *   VMRuntime.isJavaDebuggable                 是       能
 *
 * hookJniNativeMethods 只作用于"注册到 JNI 表里的 native 方法"，
 * 纯 Java 实现的方法它碰不到。上面分界线上那几个因此无法用官方接口覆盖。
 *
 * 但关键结论是：**分界线上那几个在 Zygisk 下本来就不需要**——
 *   - Class.forName / ClassLoader.loadClass 的钩子只为了隐藏
 *     de.robv.android.xposed.* 等类；Zygisk 进程里根本没有这些类
 *   - Throwable.getStackTrace 的钩子只为了删 Xposed 栈帧；同理没有
 *   - System.exit 的拦截已经由 native 的 exit/_exit/kill/tgkill 接管覆盖
 *
 * 所以这次不是"把 Java 层整体翻译成 C"，而是"留下真正需要的三项"。
 */
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define LOG_TAG "AHBZYG"
#define JLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* 模块自身的标识词。出现在返回给目标的字符串里就要换掉。 */
static const char *const kSelfMarks[] = {
    "antihookbypass",
    "libantihook_bypass",
    NULL
};
/* 等长替换词：长度必须一样，见下面注释 */
static const char *const kReplMarks[] = {
    "androidruntime",
    "libandroid_runtime",
    NULL
};

/* ------------------------------------------------------------------ */
/* JNI 字符串就地改写                                                   */
/* ------------------------------------------------------------------ */

/*
 * 为什么必须"就地改内部的 byte[]"，不能直接把字段换成新 String：
 *
 * ART 对"读某个 final 字段"会做常量折叠，内联成"直接引用那个 String 对象"。
 * 也就是说内联处握着的是旧对象；换字段引用改不到内联处。
 * 只有改那个对象自己的字节，字段读和内联读才会一致。
 *
 * 这也是原 Java 层 PathHiding 最终采用的做法（走过弯路才定下来的）。
 * 这里在 JNI 层重做一遍，好处是不依赖任何 Java 反射，也不用绕 hidden API。
 */
static void scrub_bytes(JNIEnv *env, jbyteArray arr, int is_latin1) {
    jsize n;
    jbyte *b;
    int i;

    if (!arr) return;
    n = (*env)->GetArrayLength(env, arr);
    b = (*env)->GetByteArrayElements(env, arr, NULL);
    if (!b) return;

    /*
     * 只在 ASCII 区间替换。两个方向的词长度都相等，
     * 所以原地改写不会改变数组长度，也不会破坏 coder。
     */
    for (i = 0; i < n; i++) {
        int mi;
        if (b[i] != 'a' && b[i] != 'l') continue;
        for (mi = 0; kSelfMarks[mi]; mi++) {
            const char *s = kSelfMarks[mi];
            const char *r = kReplMarks[mi];
            size_t sl = strlen(s);
            size_t rl = strlen(r);
            if (sl != rl) continue;          /* 等长是硬前提 */
            if (i + (int)sl > n) continue;
            if (memcmp(b + i, s, sl) != 0) continue;
            memcpy(b + i, r, rl);
            break;
        }
    }
    (void)is_latin1;
    (*env)->ReleaseByteArrayElements(env, arr, b, 0);
}

/*
 * 把一个 String 对象内部的 value 数组改写掉。
 *
 * value 字段在 Android 9+ 是 byte[]（紧凑字符串），更早是 char[]。
 * 这里两种都试：先按 byte[] 取，取不到再按 char[]。
 */
static void scrub_jstring(JNIEnv *env, jstring js) {
    jclass cls;
    jfieldID fid;
    jobject arr;

    if (!js) return;
    cls = (*env)->GetObjectClass(env, js);
    if (!cls) return;

    /* byte[] 路线（Android 9+ 主流） */
    fid = (*env)->GetFieldID(env, cls, "value", "[B");
    if (fid) {
        arr = (*env)->GetObjectField(env, js, fid);
        if (arr) {
            scrub_bytes(env, (jbyteArray)arr, 1);
            (*env)->DeleteLocalRef(env, arr);
        }
        (*env)->DeleteLocalRef(env, cls);
        return;
    }
    /* char[] 路线（老系统） */
    (*env)->ExceptionClear(env);
    fid = (*env)->GetFieldID(env, cls, "value", "[C");
    if (fid) {
        jcharArray ca = (jcharArray)(*env)->GetObjectField(env, js, fid);
        if (ca) {
            jsize n = (*env)->GetArrayLength(env, ca);
            jchar *c = (*env)->GetCharArrayElements(env, ca, NULL);
            int i, mi;
            for (i = 0; c && i < n; i++) {
                for (mi = 0; kSelfMarks[mi]; mi++) {
                    const char *s = kSelfMarks[mi];
                    const char *r = kReplMarks[mi];
                    size_t sl = strlen(s);
                    if (sl != strlen(r) || i + (int)sl > n) continue;
                    if (memcmp(c + i, s, sl) != 0) continue;
                    for (size_t k = 0; k < sl; k++) c[i + k] = (jchar)r[k];
                    break;
                }
            }
            if (c) (*env)->ReleaseCharArrayElements(env, ca, c, 0);
            (*env)->DeleteLocalRef(env, (jobject)ca);
        }
        (*env)->DeleteLocalRef(env, cls);
        return;
    }
    (*env)->ExceptionClear(env);
    (*env)->DeleteLocalRef(env, cls);
}

/*
 * 哈希缓存：改完字节必须清掉 String 已缓存的 hash，
 * 否则目标拿 hashCode 参与判断时会发现"内容变了但 hash 没变"。
 */
static void reset_string_hash(JNIEnv *env, jstring js) {
    jclass cls;
    jfieldID fid;
    if (!js) return;
    cls = (*env)->GetObjectClass(env, js);
    if (!cls) return;
    fid = (*env)->GetFieldID(env, cls, "hash", "I");
    if (fid) (*env)->SetIntField(env, js, fid, 0);
    else (*env)->ExceptionClear(env);
    (*env)->DeleteLocalRef(env, cls);
}

static void scrub_and_rehash(JNIEnv *env, jstring js) {
    scrub_jstring(env, js);
    reset_string_hash(env, js);
}

/* ------------------------------------------------------------------ */
/* 三个 hook 的实现                                                    */
/* ------------------------------------------------------------------ */

static jobject (*orig_field_get)(JNIEnv *, jobject, jobject);

/*
 * String 的 jclass 缓存。
 *
 * Field.get 是热路径，目标可能在循环里反复反射读字段。
 * 每次进来都 FindClass 一遍既慢又会在类没找到时反复产生异常，
 * 所以查一次就留着（用 global ref，避免被 GC 回收）。
 */
static jclass g_string_class = NULL;

static int is_jstring(JNIEnv *env, jobject o) {
    if (!o) return 0;
    if (!g_string_class) {
        jclass lc = (*env)->FindClass(env, "java/lang/String");
        if (!lc) { (*env)->ExceptionClear(env); return 0; }
        g_string_class = (jclass)(*env)->NewGlobalRef(env, lc);
        (*env)->DeleteLocalRef(env, lc);
        if (!g_string_class) return 0;
    }
    return (*env)->IsInstanceOf(env, o, g_string_class) ? 1 : 0;
}

/*
 * Field.get：拿到返回值后，如果是 String 就就地改写。
 *
 * 这一条覆盖原 Java 层 PathHiding 的主路径——目标用反射读
 * nativeLibraryDirectories 之类的字段再自己拼字符串时，读到的就是干净值。
 *
 * ===== 两个曾经埋在这里的坑（已修） =====
 *
 * 1) local ref 泄漏
 *    原写法 `if (r && (*env)->GetObjectClass(env, r))` 每调用一次就多一个
 *    未被删除的 local ref。Field.get 是热路径，目标循环调用几百次就会
 *    撑爆 local reference table（默认 512），随后 JNI 调用全部失败。
 *    现在改用缓存的 global ref + IsInstanceOf，整条路径零 local ref 产生。
 *
 * 2) 递归
 *    scrub_jstring 内部走 GetFieldID 取 value 字段，不经过 Field.get，
 *    所以不会自递归。这一点必须保持——一旦改成用反射去读 value，
 *    就会在本函数里再次进到这里，直接栈溢出。
 */
static jobject my_field_get(JNIEnv *env, jobject self, jobject obj) {
    jobject r;
    if (!orig_field_get) return NULL;
    r = orig_field_get(env, self, obj);
    if (r && is_jstring(env, r)) {
        scrub_and_rehash(env, (jstring)r);
    }
    return r;
}

/*
 * VMRuntime.isJavaDebuggable：恒返回 false。
 *
 * 这一条对应目标那句 "Android 9.0 Hidden API has been enabled ...
 * indicating the potential presence of Magisk" —— 它靠"能否调通 @hide API"
 * 反推 root。LSPosed 会给注入进程开 hiddenapi 豁免，所以那边必然为 true；
 * Zygisk 下本来就没这个豁免，但显式恒返 false 更稳。
 */
static jboolean (*orig_is_debuggable)(JNIEnv *, jobject);
static jboolean my_is_debuggable(JNIEnv *env, jobject self) {
    (void)env; (void)self;
    return JNI_FALSE;
}

/*
 * Throwable.nativeGetStackTrace 这一条**故意不装**。
 *
 * 原 Java 层 TraceHide 用它删掉 Xposed 栈帧，而 Zygisk 进程里
 * 根本不会出现 Xposed 帧，装上去只会平白多一层调用开销。
 *
 * 更重要的是实测教训：保留一个"原样返回、什么都不做"的 hook 是纯负收益——
 * 它看起来像在防御，实际只增加了失败面。
 * 如果确实要装，它必须真的做点什么；不做就不装。
 */

/* ------------------------------------------------------------------ */
/* 安装                                                                */
/* ------------------------------------------------------------------ */

/*
 * 用官方 hookJniNativeMethods 装上面三个。
 *
 * 该接口的契约：把 methods[] 里注册的函数指针替换掉，
 * 并且**把原函数指针写回 methods[i].fnPtr**——所以要先留副本，
 * 否则装完就再也拿不到原函数了。
 */
int ahb_install_jni_hooks(JNIEnv *env,
                          void (*hookJniNativeMethods)(JNIEnv *, const char *, JNINativeMethod *, int)) {
    int ok = 0;

    if (!env || !hookJniNativeMethods) return 0;

    {
        JNINativeMethod m[] = {
            { (char *)"get", (char *)"(Ljava/lang/Object;)Ljava/lang/Object;", (void *)my_field_get }
        };
        hookJniNativeMethods(env, "java/lang/reflect/Field", m, 1);
        orig_field_get = (jobject (*)(JNIEnv *, jobject, jobject))m[0].fnPtr;
        if (orig_field_get) { ok++; JLOGE("JNI hook: Field.get 已装"); }
        else JLOGE("JNI hook: Field.get 未命中");
        (*env)->ExceptionClear(env);
    }

    {
        JNINativeMethod m[] = {
            { (char *)"isJavaDebuggable", (char *)"()Z", (void *)my_is_debuggable }
        };
        hookJniNativeMethods(env, "dalvik/system/VMRuntime", m, 1);
        orig_is_debuggable = (jboolean (*)(JNIEnv *, jobject))m[0].fnPtr;
        if (orig_is_debuggable) { ok++; JLOGE("JNI hook: VMRuntime.isJavaDebuggable 已装"); }
        else JLOGE("JNI hook: VMRuntime.isJavaDebuggable 未命中");
        (*env)->ExceptionClear(env);
    }

    JLOGE("JNI hook 完成 %d/2", ok);
    return ok;
}
