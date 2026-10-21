package com.rev.antihookbypass;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * 模块说明页。
 *
 * <h2>为什么要有这个页面</h2>
 * 用户装完模块后需要一个地方确认"它到底能做什么"，
 * 而不只是看到模块列表里的一个开关。这里直接展示能力清单。
 *
 * <h2>为什么用原生 View 而不是 WebView / Markdown 渲染</h2>
 * 三个原因：
 * <ol>
 *   <li><b>零依赖</b>：不引任何第三方 Markdown 库，也不用 WebView
 *       （很多设备 WebView 版本老旧，渲染出来的排版还不如纯文本）。</li>
 *   <li><b>启动快</b>：纯 View 构建，冷启动几十毫秒。</li>
 *   <li><b>不会崩</b>：没有解析器、没有 JS、没有外部资源。</li>
 * </ol>
 * 内容本身就是排版好的文本，用等宽字体呈现，效果等同看一份 Markdown 文档。
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
        sub.setText("Hook 检测对抗模块 · v2.0");
        sub.setTextSize(12);
        sub.setTextColor(0xFF8899A6);
        sub.setPadding(0, 0, 0, dp(16));
        root.addView(sub);

        TextView body = new TextView(this);
        body.setText(CONTENT);
        body.setTextSize(13);
        body.setTextColor(0xFFD5DEE7);
        body.setLineSpacing(dp(3), 1f);
        body.setTextIsSelectable(true);          // 允许长按复制
        root.addView(body);

        setContentView(scroll);
        setTitle("AntiHook Bypass");
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }

    /**
     * 页面正文。
     *
     * <p>写作原则：说人话，讲清"能绕过什么、为什么能绕过什么、
     * 什么情况下不行"。不堆术语，不夸大。
     */
    private static final String CONTENT =
            "════════════════════════════\n"
          + "一、怎么用\n"
          + "════════════════════════════\n"
          + "\n"
          + "1. 在 LSPosed 里启用本模块\n"
          + "2. 把要保护的应用勾进作用域\n"
          + "3. 强制停止那个应用，再重新打开\n"
          + "\n"
          + "不需要额外配置，装好即生效。\n"
          + "\n"
          + "════════════════════════════\n"
          + "二、当前实测结果（6 项检测）\n"
          + "════════════════════════════\n"
          + "\n"
          + "风险 0 / 可疑 2 / 安全 4 / 共 6 项\n"
          + "连续 3 次冷启动结果一致，无崩溃。\n"
          + "\n"
          + "【真正通过的 2 项】\n"
          + "\n"
          + "✓ libc.so 内存 CRC 校验 —— 正常\n"
          + "  本模块不在 libc 代码段上打 hook，\n"
          + "  机器码字节与磁盘文件一致，\n"
          + "  检测方自己算 CRC 就得到一致结果。\n"
          + "\n"
          + "✓ Inline Hook 跳转模式扫描 —— 正常\n"
          + "  检测方在代码段里找「跳向匿名内存」的指令。\n"
          + "  本模块不产生这类跳转，所以扫不到。\n"
          + "\n"
          + "【仍为异常的 4 项及原因】\n"
          + "\n"
          + "· ART ClassLoader 计数（42 个，正常 2-5）\n"
          + "  LSPosed 为每个模块创建额外 ClassLoader，\n"
          + "  这是运行模块的必要条件。\n"
          + "  实测：把本模块从作用域移除后仍为 42 个，\n"
          + "  即这一项不由本模块造成。\n"
          + "\n"
          + "· libart.so 内存 CRC\n"
          + "  框架改写了 libart 的代码字节来完成 Java hook。\n"
          + "  本模块从未 hook libart，但它照样不一致。\n"
          + "\n"
          + "· 匿名可执行段扫描（1 个）\n"
          + "  已从 3 个降到 1 个。\n"
          + "  剩下的这个来自框架注入，非本模块。\n"
          + "\n"
          + "· 子进程外部视角 CRC\n"
          + "  子进程用 ptrace 从外部读父进程内存，\n"
          + "  读到的仍是上面那个被改写的 libart。\n"
          + "\n"
          + "════════════════════════════\n"
          + "三、本模块实际做了什么\n"
          + "════════════════════════════\n"
          + "\n"
          + "· 痕迹压制（TraceHide）\n"
          + "  过滤堆栈里的框架类名。\n"
          + "\n"
          + "· 自杀拦截（KillGuard）\n"
          + "  检测方若调 killProcess/exit/halt 杀进程，\n"
          + "  本模块拦下来，让你看到结果而不是闪退。\n"
          + "\n"
          + "· Frida 隐藏（FridaHide）\n"
          + "  端口 27042/27043、文件列举、进程命令三条路径。\n"
          + "  注意：本机未装 frida-server，此项未做端到端验证。\n"
          + "\n"
          + "· 原生层（native）\n"
          + "  刻意不在 libc 上安装任何 inline hook。\n"
          + "  只要用 hook 引擎改写 libc 入口字节，\n"
          + "  CRC 就一定对不上。\n"
          + "  实测：装 3 个 hook → CRC 异常；全撤 → 正常。\n"
          + "  代价是外部调试器仍可用 ptrace 附加本进程。\n"
          + "\n"
          + "════════════════════════════\n"
          + "四、明确的边界\n"
          + "════════════════════════════\n"
          + "\n"
          + "本模块不会：\n"
          + "· 拦截扫描方法并返回伪造结果\n"
          + "· 把「异常」改写成「安全」\n"
          + "· 让检测读不到数据以蒙混过关\n"
          + "\n"
          + "以上做法虽能让界面变绿，但那是骗检测器，\n"
          + "换个检测方式就失效，也掩盖真实状态。\n"
          + "\n"
          + "要让它余 4 项真正通过，需要在内核或系统服务层\n"
          + "抹掉注入痕迹，那不是单个 LSPosed 模块能做到的。\n"
          + "\n"
          + "════════════════════════════\n"
          + "五、支持架构\n"
          + "════════════════════════════\n"
          + "\n"
          + "arm64-v8a、armeabi-v7a、x86、x86_64\n"
          + "（四个 .so 均已编译打包；\n"
          + " 仅 arm64-v8a 做过真机运行验证）\n";
}
