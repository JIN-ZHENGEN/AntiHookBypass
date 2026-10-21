package com.rev.antihookbypass;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * 模块可滚动说明页（原生 ScrollView + TextView，零外部依赖）。
 */
public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(0xFF101418);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(20);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = new TextView(this);
        title.setText("AntiHook Bypass");
        title.setTextSize(22);
        title.setTextColor(0xFF7DD3A8);
        title.setGravity(Gravity.START);
        title.setPadding(0, 0, 0, dp(4));
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("LSPosed/Xposed 通用痕迹还原与防检测模块 · L1 + L2 + L3 全启用 · 四架构支持");
        sub.setTextSize(12);
        sub.setTextColor(0xFF8899A6);
        sub.setPadding(0, 0, 0, dp(16));
        root.addView(sub);

        TextView body = new TextView(this);
        body.setText(CONTENT);
        body.setTextSize(13);
        body.setTextColor(0xFFD5DEE7);
        body.setLineSpacing(dp(3), 1f);
        body.setTextIsSelectable(true);
        root.addView(body);

        setContentView(scroll);
        setTitle("AntiHook Bypass");
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }

    private static final String CONTENT =
            "════════════════════════════\n"
          + "一、启用方式（即开即用）\n"
          + "════════════════════════════\n"
          + "\n"
          + "1. 在 LSPosed 管理器中启用本模块\n"
          + "2. 勾选需要保护的目标应用（作用域）\n"
          + "3. 强制停止目标应用并重新打开\n"
          + "\n"
          + "无需任何额外开关配置，L1 / L2 / L3 三层默认全量启用。\n"
          + "\n"
          + "════════════════════════════\n"
          + "二、三层架构与对抗方向（按检测原理通杀）\n"
          + "════════════════════════════\n"
          + "\n"
          + "【L1 · Java 运行时痕迹压制与保护】\n"
          + "· 类加载与反射隔离（TraceHide）：拦截外部对 XposedBridge、\n"
          + "  XposedHelpers、LspModuleClassLoader 等框架类的直接探测，\n"
          + "  同时保留模块自身与框架内部的正常类加载。\n"
          + "· 全路径调用栈清洗（TraceHide）：覆盖 Throwable.getStackTrace、\n"
          + "  getSuppressed、getCause、Thread.getAllStackTraces、\n"
          + "  StackWalker 与 StackTraceElement.toString。\n"
          + "· 调试状态与异常自杀拦截（KillGuard / CrashGuard）：\n"
          + "  压制 Debug.isDebuggerConnected 探测，拦截检测栈发起的\n"
          + "  Process.killProcess / System.exit / Runtime.halt / sendSignal。\n"
          + "\n"
          + "【L2 · Native 代码段磁盘字节还原与跳板收敛】\n"
          + "· libc.so 零污染：不在 libc.so 代码段安装任何持久 inline hook，\n"
          + "  确保 libc.so 可执行段与磁盘 ELF 100% 字节一致。\n"
          + "· libart.so / linker 代码段原位还原：在模块完成 Java 钩子注册\n"
          + "  与核心类预热后，直接对照磁盘 ELF 的 PT_LOAD 段，将 LSPlant\n"
          + "  写入 libart.so 与 linker 的 inline hook 远跳指令逐字节还原，\n"
          + "  并刷新指令缓存（icache）。\n"
          + "· 匿名可执行跳板页收敛：代码段还原后，将进程内残留的匿名\n"
          + "  r-xp 跳板页权限收敛为只读（PROT_READ），消除 /proc/self/maps\n"
          + "  中的小体积无路径可执行段与跨段异常跳转。\n"
          + "\n"
          + "【L3 · ART GC 结构保护】\n"
          + "· ClassLinker::class_loaders_ 链表保持原样，不摘除运行时节点。\n"
          + "  ART 的 MarkCompact GC 与 Profile Saver 依赖这些节点追踪\n"
          + "  ClassLoader 根；强行缩短链表会导致延迟 GC 崩溃。\n"
          + "  因此该检测可能仍报告额外 ClassLoader，不以稳定性换取伪绿。\n"
          + "\n"
          + "【外部视角一致性】\n"
          + "· 子进程 ptrace 校验读取的代码段与磁盘一致。\n"
          + "  由于物理内存中的 libc.so 与 libart.so 代码段均已真实还原为\n"
          + "  磁盘原始字节，无论是进程内直接切片读取，还是 fork 子进程\n"
          + "  通过 ptrace + process_vm_readv 跨进程校验，算出的 CRC 均与\n"
          + "  磁盘文件完全一致。\n"
          + "\n"
          + "════════════════════════════\n"
          + "三、设计原则\n"
          + "════════════════════════════\n"
          + "\n"
          + "· 不接管检测器方法、不伪造 JSON 返回值\n"
          + "· 不通过返回 EPERM / ENOENT 阻断读取来制造「读失败」假象\n"
          + "· 完全面向底层检测方向还原真实内存与结构状态\n"
          + "\n"
          + "════════════════════════════\n"
          + "四、支持架构（四 ABI 单包）\n"
          + "════════════════════════════\n"
          + "\n"
          + "· arm64-v8a\n"
          + "· armeabi-v7a\n"
          + "· x86\n"
          + "· x86_64\n";
}
