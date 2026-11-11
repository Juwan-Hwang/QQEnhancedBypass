package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Crash-Report Disable Hook
 *
 * 思路源自 QAuxiliary(DisableQQCrashReportManager) 与 TCQT(DisableCrashReport)。
 *
 * QQ 崩溃时会通过 Bugly / QQCrashReportManager 把崩溃栈上报到腾讯，而崩溃栈里
 * 很可能带有模块注入的类名/so 名，等于把自己交出去。这里把这些上报入口打空。
 * 全部 try/catch，类不存在就跳过（不同版本类名不一定都在）。
 */
public class CrashReportHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        XposedEntry.log("Initializing Crash-Report Disable Hook");

        // QQ 自带崩溃上报管理器（类名未混淆）
        neutralize("com.tencent.qqperf.monitor.crash.QQCrashReportManager", "initCrashReport");
        // Bugly 崩溃上报
        neutralize("com.tencent.bugly.crashreport.CrashReport", "initCrashReport");
        neutralize("com.tencent.bugly.agent.CrashReport", "initCrashReport");
        // 兜底：旧统计入口
        neutralize("com.tencent.mobileqq.statistics.StatisticCollector", "initCrashReport");

        // QQCrashHandleListener 的三个回调也打空（源自 QwQ），避免崩溃处理阶段再落盘/上报带模块信息。
        neutralize("com.tencent.qqperf.monitor.crash.QQCrashHandleListener", "onCrashHandleStart");
        neutralize("com.tencent.qqperf.monitor.crash.QQCrashHandleListener", "onCrashHandleEnd");
        neutralize("com.tencent.qqperf.monitor.crash.QQCrashHandleListener", "onCrashSaving");
    }

    private static void neutralize(String className, String methodName) {
        try {
            HookUtils.hookAllMethods(className, methodName,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        // 直接短路，不执行原初始化逻辑
                        param.setResult(null);
                        XposedEntry.log("Neutralized crash report: " + className + "." + methodName);
                    }
                });
        } catch (Throwable ignored) {
            // 该版本没有这个类/方法，跳过
        }
    }
}
