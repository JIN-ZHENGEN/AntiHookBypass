/*
 * 退出探针：只在被调用时记录调用方返回地址，不改变任何行为。
 * 用途是回答"到底是哪一步检查把它杀了"，而不是自己去猜。
 */
#ifndef AHB_EXIT_PROBE_H
#define AHB_EXIT_PROBE_H

#include <unwind.h>

typedef void (*exit_fn)(int);
typedef void (*_exit_fn)(int);
typedef int  (*kill_fn)(pid_t, int);
typedef int  (*raise_fn)(int);
typedef void (*abort_fn)(void);
typedef int  (*tgkill_fn)(pid_t, pid_t, int);
typedef void (*exit_group_fn)(int);

static exit_fn       g_real_exit       = NULL;
static _exit_fn      g_real__exit      = NULL;
static kill_fn       g_real_kill       = NULL;
static raise_fn      g_real_raise      = NULL;
static abort_fn      g_real_abort      = NULL;
static tgkill_fn     g_real_tgkill     = NULL;
static exit_group_fn g_real_exit_group = NULL;

#define EXITPROBE_FRAMES 6

/*
 * 只取调用栈上的返回地址，**不用 _Unwind_Backtrace**。
 *
 * 原因是一段实测教训：ART 在持锁状态下 abort 时（典型是
 * "Jit code cache for mutator"(exclusive held)），如果退出探针里
 * 调 _Unwind_Backtrace 去遍历栈，会读取正在被 ART 改写的栈帧与
 * 异常表，导致 ART 直接 runtime abort。也就是说探针本身把
 * "目标主动退出"变成了"ART 崩溃"，反而制造了新问题。
 *
 * 这里改成只取固定几层的返回地址：纯读寄存器与栈槽，不做任何
 * 需要解析 unwind 信息的动作，任何上下文下都安全。
 */
static void ep_report(const char *what, int code) {
    uintptr_t f0 = (uintptr_t)__builtin_return_address(0);
    uintptr_t f1 = (uintptr_t)__builtin_return_address(1);
    uintptr_t f2 = (uintptr_t)__builtin_return_address(2);
    LOGI("EXITPROBE %s code=%d ret=%lx/%lx/%lx", what, code,
         (unsigned long)f0, (unsigned long)f1, (unsigned long)f2);
    ahb_filelog("EXITPROBE %s code=%d ret=%lx/%lx/%lx", what, code,
                (unsigned long)f0, (unsigned long)f1, (unsigned long)f2);
}

static void ep_exit(int code) {
    ep_report("exit", code);
    if (!g_real_exit) g_real_exit = (exit_fn)dlsym(RTLD_NEXT, "exit");
    if (g_real_exit) g_real_exit(code);
    syscall(SYS_exit_group, code);
    __builtin_unreachable();
}

static void ep__exit(int code) {
    ep_report("_exit", code);
    if (!g_real__exit) g_real__exit = (_exit_fn)dlsym(RTLD_NEXT, "_exit");
    if (g_real__exit) g_real__exit(code);
    syscall(SYS_exit_group, code);
    __builtin_unreachable();
}

static int ep_kill(pid_t pid, int sig) {
    static int depth = 0;
    if (depth == 0 && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT)) {
        depth = 1;
        ep_report("kill", (int)sig);
        depth = 0;
    }
    if (!g_real_kill) g_real_kill = (kill_fn)dlsym(RTLD_NEXT, "kill");
    if (g_real_kill) return g_real_kill(pid, sig);
    return (int)syscall(SYS_kill, pid, sig);
}

static int ep_raise(int sig) {
    static int depth = 0;
    if (depth == 0 && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT)) {
        depth = 1;
        ep_report("raise", sig);
        depth = 0;
    }
    if (!g_real_raise) g_real_raise = (raise_fn)dlsym(RTLD_NEXT, "raise");
    if (g_real_raise) return g_real_raise(sig);
    return (int)syscall(SYS_tgkill, getpid(), (int)gettid(), sig);
}

static void ep_abort(void) {
    ep_report("abort", 0);
    if (!g_real_abort) g_real_abort = (abort_fn)dlsym(RTLD_NEXT, "abort");
    if (g_real_abort) g_real_abort();
    syscall(SYS_exit_group, 134);
    __builtin_unreachable();
}

static int ep_tgkill(pid_t tgid, pid_t tid, int sig) {
    static int depth = 0;
    if (depth == 0) {
        depth = 1;
        ep_report("tgkill", sig);
        depth = 0;
    }
    if (!g_real_tgkill) g_real_tgkill = (tgkill_fn)dlsym(RTLD_NEXT, "tgkill");
    if (g_real_tgkill) return g_real_tgkill(tgid, tid, sig);
    return (int)syscall(SYS_tgkill, tgid, tid, sig);
}

static void ep_exit_group(int code) {
    ep_report("exit_group", code);
    if (!g_real_exit_group) g_real_exit_group = (exit_group_fn)dlsym(RTLD_NEXT, "exit_group");
    if (g_real_exit_group) g_real_exit_group(code);
    syscall(SYS_exit_group, code);
    __builtin_unreachable();
}



#endif
