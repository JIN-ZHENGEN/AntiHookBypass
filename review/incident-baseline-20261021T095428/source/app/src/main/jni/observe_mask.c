/*
 * 观测面伪装层（L2 核心）
 *
 * ============================ 设计原则 ============================
 *
 * 检测工具判断"有没有被 hook"，唯一的依据是它读到的数据。
 * 而它能读的东西是有限的、固定的：
 *
 *   1. /proc/self/maps      —— 内存里有没有匿名可执行段、有没有 frida/gum 字样
 *   2. /proc/self/status    —— TracerPid 是不是非 0（有没有被 ptrace）
 *   3. /proc/self/task/*    —— 线程名里有没有 gum-js-loop / gmain / pool-frida
 *   4. /proc/self/cmdline   —— 命令行里有没有 frida、gdbserver
 *   5. 自身 so 的内存 CRC    —— 代码段有没有被改过
 *
 * 只要把这些"读到的内容"过滤干净，它算出来的结论必然是"安全"，
 * 跟它用什么语言写、返回什么格式、有没有混淆，全部无关。
 *
 * 这就是通杀 —— 我们没有利用任何"某个检测工具的特征"，
 * 只利用了"所有检测工具都必须读这些路径"这个事实。
 *
 * ============================ 关键约束 ============================
 *
 * 过滤必须"看起来自然"：
 *   - 不能整行删除后留下空行（maps 格式校验会失败）
 *   - 不能把行数改得和真实文件对不上（有些检测会比对行数）
 *   - 过滤后的内容必须仍是合法格式
 *
 * 所以做法是：读进缓冲区，逐行扫描，把命中的行替换成
 * "同等长度、格式合法、内容无害"的行，而不是直接删除。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>

/* ---------- 干扰词表：命中的行一律伪装 ---------- */

/* 这些词出现在 maps 里就说明有注入框架 */
static const char *const MAPS_MARKS[] = {
    "frida", "gum-js-loop", "gmain", "gdbus", "pool-frida",
    "linjector", "gadget", "magisk", "riru", "zygisk", "lsposed",
    "edxposed", "xposed", "substrate", "frida-agent", "frida-gadget",
    NULL
};

/* 这些词出现在线程名里就说明有 frida */
static const char *const THREAD_MARKS[] = {
    "gum-js-loop", "gmain", "gdbus", "pool-frida", "frida",
    NULL
};

static int contains_any(const char *hay, const char *const *marks) {
    if (!hay) return 0;
    for (int i = 0; marks[i]; i++) {
        if (strstr(hay, marks[i])) return 1;
    }
    return 0;
}

/* ---------- 通用：按行过滤，把命中行替换成无害的同形状行 ---------- */

/*
 * 返回 malloc 出来的新缓冲区（调用方 free），长度写回 *out_len。
 * 返回 NULL 表示不需要过滤（原样返回）。
 */
static char *filter_lines(const char *src, size_t len, size_t *out_len,
                          const char *const *marks,
                          const char *dummy_line) {
    if (!src || len == 0) return NULL;

    size_t cap = len + 64;
    char *out = (char *) malloc(cap);
    if (!out) return NULL;
    size_t w = 0;
    int changed = 0;

    const char *p = src;
    const char *end = src + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t) (end - p));
        size_t line_len = nl ? (size_t) (nl - p + 1) : (size_t) (end - p);

        /* 取一份可判定的副本 */
        char *line = (char *) malloc(line_len + 1);
        if (!line) { free(out); return NULL; }
        memcpy(line, p, line_len);
        line[line_len] = '\0';

        if (contains_any(line, marks)) {
            changed = 1;
            /* 用无害行替换，并补齐到原长度以保持总体形状 */
            size_t dl = strlen(dummy_line);
            if (w + dl + 2 > cap) {
                cap = (w + dl + 2) * 2;
                char *n = (char *) realloc(out, cap);
                if (!n) { free(line); free(out); return NULL; }
                out = n;
            }
            memcpy(out + w, dummy_line, dl);
            w += dl;
            /* 补空格到原行长，避免行数/列数出现异常 */
            if (dl + 1 < line_len) {
                size_t pad = line_len - dl - 1;
                if (w + pad + 2 > cap) {
                    cap = (w + pad + 2) * 2;
                    char *n = (char *) realloc(out, cap);
                    if (!n) { free(line); free(out); return NULL; }
                    out = n;
                }
                memset(out + w, ' ', pad);
                w += pad;
            }
            out[w++] = '\n';
        } else {
            if (w + line_len + 2 > cap) {
                cap = (w + line_len + 2) * 2;
                char *n = (char *) realloc(out, cap);
                if (!n) { free(line); free(out); return NULL; }
                out = n;
            }
            memcpy(out + w, p, line_len);
            w += line_len;
        }
        free(line);
        p += line_len;
    }

    if (!changed) { free(out); return NULL; }
    out[w] = '\0';
    *out_len = w;
    return out;
}

/* ---------- 把 fd 的内容替换成我们过滤后的内容 ---------- */

/*
 * 思路：不拦截 open（那会暴露），而是在 read 时做手脚太复杂。
 * 改用"内存文件"方案：
 *   1. 先正常 open 到临时文件
 *   2. 读出来、过滤、写回一个 memfd
 *   3. 把 memfd 重定向到原 fd 号
 *
 * 这样调用方完全感知不到，且后续 lseek/read 全部正常。
 */
int mask_fd_by_path(int fd, const char *path);

/* 判断路径是否需要伪装 */
int is_sensitive_path(const char *path) {
    if (!path) return 0;
    return (strstr(path, "/proc/self/maps") != NULL)
        || (strstr(path, "/proc/self/smaps") != NULL)
        || (strstr(path, "/proc/self/status") != NULL)
        || (strstr(path, "/proc/self/task") != NULL && strstr(path, "/comm") != NULL)
        || (strstr(path, "/proc/self/cmdline") != NULL);
}

/* 对外接口：给指定路径生成伪装后的内容 */
char *mask_content_for(const char *path, const char *src, size_t len, size_t *out_len) {
    if (!path || !src) return NULL;

    if (strstr(path, "/proc/self/maps") || strstr(path, "/proc/self/smaps")) {
        /* maps 里的可疑行替换成"一段普通匿名读写内存"的描述，
           格式与真实行一致：地址-地址 权限 偏移 设备 inode */
        return filter_lines(src, len, out_len, MAPS_MARKS,
                            "7f0000000000-7f0000001000 rw-p 00000000 00:00 0 ");
    }

    if (strstr(path, "/proc/self/status")) {
        /* status 里把 TracerPid 清零。这一项要单独处理，
           因为它是 key: value 形式。 */
        const char *tracer = "TracerPid:";
        char *copy = (char *) malloc(len + 1);
        if (!copy) return NULL;
        memcpy(copy, src, len);
        copy[len] = '\0';

        char *line = copy;
        int changed = 0;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            if (strncmp(line, tracer, strlen(tracer)) == 0) {
                /* 找到行尾，把数字部分改成 0 */
                char *colon = strchr(line, ':');
                if (colon) {
                    colon++;
                    while (*colon == ' ' || *colon == '\t') colon++;
                    char *num_end = colon;
                    while (*num_end && *num_end != '\n') num_end++;
                    /* 覆盖为 0 加空格填充 */
                    size_t span = (size_t) (num_end - colon);
                    memset(colon, ' ', span);
                    colon[0] = '0';
                    changed = 1;
                }
            }
            line = nl ? nl + 1 : NULL;
        }
        if (!changed) { free(copy); return NULL; }
        *out_len = len;
        return copy;
    }

    if (strstr(path, "/proc/self/task") || strstr(path, "/proc/self/cmdline")) {
        return filter_lines(src, len, out_len, THREAD_MARKS, "kworker/u8:1");
    }

    return NULL;
}
