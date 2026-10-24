#!/usr/bin/env python3
"""
生成模块的 AndroidManifest.xml（AXML 二进制格式）。

用自写生成器而不是 aapt2，因为 aapt2 是 x86_64 原生程序，
在 arm64 Android 上没有 x86 翻译层就跑不起来。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from axml import XmlWriter, ANDROID_NS


def build():
    NS = ANDROID_NS
    w = XmlWriter()

    w.start_ns('android', NS)

    # <manifest>
    # 注意：package 是"无命名空间"属性（不属于 android:），
    # 但它是 APK 的身份标识，缺了系统直接报 Failed to parse APK。
    w.start('manifest', [
        ('package', 'com.rev.antihookbypass', 'str'),
        ('versionCode', 8, 'int'),
        ('versionName', '2.7', 'str'),
    ], ns=NS)

    # <uses-sdk> —— 显式声明，apksigner 靠它判断 minSdk
    w.start('uses-sdk', [
        ('minSdkVersion', 21, 'int'),
        ('targetSdkVersion', 34, 'int'),
    ], ns=NS)
    w.end('uses-sdk', ns=NS)

    # <application>
    w.start('application', [
        ('label', 'AntiHook Bypass', 'str'),
        ('allowBackup', False, 'bool'),
        ('hasCode', True, 'bool'),
        ('extractNativeLibs', True, 'bool'),
    ], ns=NS)

    # LSPosed 模块声明
    w.start('meta-data', [('name', 'xposedmodule', 'str'),
                          ('value', 'true', 'str')], ns=NS)
    w.end('meta-data', ns=NS)

    w.start('meta-data', [
        ('name', 'xposeddescription', 'str'),
        ('value', '通用 Hook 检测对抗：结果伪造 + 痕迹压制 + native 层拦截，'
                  '按观测面覆盖，不绑定特定应用。', 'str'),
    ], ns=NS)
    w.end('meta-data', ns=NS)

    w.start('meta-data', [('name', 'xposedminversion', 'str'),
                          ('value', '16', 'str')], ns=NS)
    w.end('meta-data', ns=NS)

    # xposedscope：声明"本模块对所有应用生效"。
    # 缺这个 LSPosed 也能用（用户手动勾选），但新版框架在判断
    # "是否为完整模块"时会更保守 —— 不声明就可能不启用 native 通道。
    w.start('meta-data', [('name', 'xposedscope', 'str'),
                          ('value', 'all', 'str')], ns=NS)
    w.end('meta-data', ns=NS)

    w.start('meta-data', [('name', 'xposedsharedprefs', 'str'),
                          ('value', 'true', 'str')], ns=NS)
    w.end('meta-data', ns=NS)

    # 说明页 Activity
    w.start('activity', [
        ('name', '.MainActivity', 'str'),
        ('exported', True, 'bool'),
        ('label', 'AntiHook Bypass', 'str'),
    ], ns=NS)

    # LAUNCHER intent-filter，让模块出现在桌面
    w.start('intent-filter', ns=NS)
    w.start('action', [('name', 'android.intent.action.MAIN', 'str')], ns=NS)
    w.end('action', ns=NS)
    w.start('category', [('name', 'android.intent.category.LAUNCHER', 'str')], ns=NS)
    w.end('category', ns=NS)
    w.end('intent-filter', ns=NS)

    w.end('activity', ns=NS)

    w.end('application', ns=NS)
    w.end('manifest', ns=NS)
    w.end_ns('android', NS)

    return w.build()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: make_manifest.py <output>')
        sys.exit(1)
    data = build()
    with open(sys.argv[1], 'wb') as f:
        f.write(data)
    print('    manifest: %d bytes' % len(data))
