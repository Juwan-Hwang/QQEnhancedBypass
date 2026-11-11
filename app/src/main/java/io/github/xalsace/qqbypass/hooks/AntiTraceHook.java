package io.github.xalsace.qqbypass.hooks;

import android.os.Looper;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Anti Stack-Trace Hook
 *
 * 源自 OpenShamrock (callng/OpenShamrock, GPL-3.0) AntiDetection.antiTrace。
 *
 * XposedDetectionHook 只过滤了 Throwable.getStackTrace。QQ 还会从
 * Thread.getStackTrace / Throwable.getOurStackTrace 取栈，并用 Thread.getName
 * 找线程名里的模块特征。这里补齐这几个入口：剔除模块相关帧，若过滤后主线程栈
 * 顶不再是 ZygoteInit，则补一个合成的 ZygoteInit.main 帧，让栈看起来"干净又正常"。
 */
public class AntiTraceHook {

    private static final String ZYGOTE_NAME = "com.android.internal.os.ZygoteInit";

    private static final String[] MODULE_FOOTPRINTS = {
        "xposed", "lsposed", "edxposed", "xalsace", "qqbypass",
        "de.robv.android", "io.github.lsposed", "org.lsposed"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        XposedEntry.log("Initializing Anti-Trace (stacktrace/thread-name) Bypass");

        XC_MethodHook stackFilter = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object result = param.getResult();
                if (!(result instanceof StackTraceElement[])) return;
                StackTraceElement[] original = (StackTraceElement[]) result;

                boolean sawZygote = false;
                List<StackTraceElement> filtered = new ArrayList<>();
                for (StackTraceElement e : original) {
                    if (ZYGOTE_NAME.equals(e.getClassName())) sawZygote = true;
                    if (!isModuleFrame(e.getClassName())) filtered.add(e);
                }
                if (filtered.size() == original.length) return; // nothing removed

                boolean onMainThread = Thread.currentThread() == Looper.getMainLooper().getThread();
                if (!sawZygote && onMainThread) {
                    filtered.add(new StackTraceElement(ZYGOTE_NAME, "main", ZYGOTE_NAME, 0));
                }
                param.setResult(filtered.toArray(new StackTraceElement[0]));
            }
        };

        HookUtils.hookMethod(Thread.class, "getStackTrace", stackFilter);
        HookUtils.hookMethod(Throwable.class, "getOurStackTrace", stackFilter);

        // 线程名里的模块特征 -> 伪装成 "android"
        HookUtils.hookMethod(Thread.class, "getName",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object result = param.getResult();
                    if (result instanceof String && isModuleFrame((String) result)) {
                        param.setResult("android");
                    }
                }
            });
    }

    private static boolean isModuleFrame(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        for (String f : MODULE_FOOTPRINTS) {
            if (lower.contains(f)) return true;
        }
        return false;
    }
}
