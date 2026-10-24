package com.rev.antihookbypass;

/**
 * 实验开关集中处。
 *
 * <p>全部是编译期常量：改值重新构建即生效，不做任何文件读写。
 * 模块刻意不落任何开关文件——目标应用只要看一眼自己的目录
 * 就能发现陌生文件，那比开关带来的便利重要得多。
 */
final class ExpFlags {
    private ExpFlags() { }

    /** 空转：只让 LSPosed 注入，模块自身什么都不做。 */
    static final boolean NOOP = false;

    /**
     * 界面诊断（把界面文字抄到 logcat）。
     *
     * <p>交付版必须是 false：这些日志会把模块存在写进 logcat，
     * 本身就是痕迹。排查界面问题时临时改 true 重新打包。
     */
    static final boolean UIPEEK = false;
}
