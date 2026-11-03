package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Xposed/LSPosed/Hook Framework Detection Bypass
 *
 * Mitigates detection of:
 * - LSPosed/Xposed installer package
 * - Xposed framework artifacts
 * - /proc/self/maps scanning for hook libraries
 * - Cydia Substrate detection
 * - ART method hook detection (limited effectiveness)
 *
 * Note: Native-layer detection (libfekit.so, libturingxq.so) requires native hooks
 * This module can only handle Java-layer checks and file I/O interception
 */
public class XposedDetectionHook {

    private static final java.util.concurrent.atomic.AtomicInteger mapsFilteredCount = new java.util.concurrent.atomic.AtomicInteger();

    /**
     * 要从 QQ 视角藏掉的包（合并版清单，2026-11-03）：Xposed 系 4 + Root 系 3 + Shizuku/Scene/GKD + 本模块自己。
     * 注意 LSPosed 管理器的真包名是 org.lsposed.manager——旧清单里的 io.github.lsposed.manager 是错的，
     * 两个都留着（旧名无害）。不要往里加系统/小米/腾讯自家包：QQ 查它们是自身功能，拦了反而出问题。
     */
    private static final String[] HIDDEN_PACKAGES = {
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "org.lsposed.manager",
        "io.github.lsposed.manager",
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        "moe.shizuku.privileged.api",
        "com.omarea.vtools",
        "li.songe.gkd",
        "io.github.xalsace.qqbypass"
    };

    private static final String[] HOOK_LIBRARY_PATTERNS = {
        "lsposed",
        "xposed",
        "libriru",
        "zygisk",
        "edxposed",
        "libsubstrate",
        "libAndroidCydia",
        "libDalvikLoader"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        XposedEntry.log("Initializing Xposed Detection Bypass");

        // Hook 1: PackageManager to hide Xposed packages
        hookPackageManagerForXposed();

        // Hook 2: File I/O to filter /proc/self/maps
        hookProcMapsReading();

        // Hook 3: Stack trace filtering
        hookStackTrace();

        // Hook 4: ClassLoader detection
        hookClassLoaderCheck();
    }

    private static void hookPackageManagerForXposed() {
        // Hide Xposed-related packages from PackageManager queries
        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getPackageInfo",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0) {
                        String packageName = (String) param.args[0];
                        if (isHiddenPackage(packageName)) {
                            XposedEntry.log("Blocked PackageManager query for: " + packageName);
                            // 用 setThrowable 而不是在回调里 throw：效果一样（调用方收到 NameNotFoundException），
                            // 但不会在 LSPosed 日志里留一串 Exception in hooker 噪声
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException());
                        }
                    }
                }
            });

        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getApplicationInfo",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0) {
                        String packageName = (String) param.args[0];
                        if (isHiddenPackage(packageName)) {
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException());
                        }
                    }
                }
            });

        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getInstalledPackages",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() != null) {
                        @SuppressWarnings("unchecked")
                        List<Object> packages = (List<Object>) param.getResult();
                        List<Object> filtered = new ArrayList<>();

                        for (Object pkg : packages) {
                            String pkgName = (String) XposedHelpers.getObjectField(pkg, "packageName");
                            if (!isHiddenPackage(pkgName)) {
                                filtered.add(pkg);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getInstalledApplications",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() != null) {
                        @SuppressWarnings("unchecked")
                        List<Object> apps = (List<Object>) param.getResult();
                        List<Object> filtered = new ArrayList<>();
                        for (Object app : apps) {
                            String pkgName = (String) XposedHelpers.getObjectField(app, "packageName");
                            if (!isHiddenPackage(pkgName)) {
                                filtered.add(app);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

        // getPackageUid 是包存在性探测的轻量入口（不走 getPackageInfo 也能确认装没装），一并藏
        for (String uidMethod : new String[]{"getPackageUid", "getPackageUidAsUser"}) {
            HookUtils.hookAllMethods("android.app.ApplicationPackageManager", uidMethod,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args.length > 0 && param.args[0] instanceof String) {
                            String packageName = (String) param.args[0];
                            if (isHiddenPackage(packageName)) {
                                param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException());
                            }
                        }
                    }
                });
        }

        // 按 Intent 枚举组件（queryIntent*）的结果里也要滤掉隐藏包，只过滤不阻断
        // ResolveInfo 里组件信息的字段名随查询类型不同：服务是 serviceInfo，活动/广播都是 activityInfo
        for (String queryMethod : new String[]{"queryIntentActivities", "queryIntentServices", "queryIntentBroadcastReceivers"}) {
            final String compField = queryMethod.contains("Services") ? "serviceInfo" : "activityInfo";
            HookUtils.hookAllMethods("android.app.ApplicationPackageManager", queryMethod,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() != null) {
                            @SuppressWarnings("unchecked")
                            List<Object> infos = (List<Object>) param.getResult();
                            List<Object> filtered = new ArrayList<>();
                            for (Object info : infos) {
                                Object comp = XposedHelpers.getObjectField(info, compField);
                                String pkgName = comp != null ? (String) XposedHelpers.getObjectField(comp, "packageName") : null;
                                if (!isHiddenPackage(pkgName)) {
                                    filtered.add(info);
                                }
                            }
                            param.setResult(filtered);
                        }
                    }
                });
        }
    }

    private static void hookProcMapsReading() {
        // Hook file reading to filter /proc/self/maps content
        HookUtils.hookMethod(FileReader.class, "read", char[].class,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    // This is complex - would need to track file paths and filter content
                    // Simplified implementation: just log the attempt
                }
            });

        // Hook BufferedReader.readLine for /proc/self/maps
        HookUtils.hookMethod(BufferedReader.class, "readLine",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    String line = (String) param.getResult();
                    if (line != null && containsHookLibrary(line)) {
                        // Try to filter out hook library references
                        // This is tricky because we need context about which file is being read
                        Object reader = param.thisObject;
                        // Check if this BufferedReader is reading from /proc/self/maps
                        try {
                            Object lock = XposedHelpers.getObjectField(reader, "lock");
                            if (lock instanceof FileReader) {
                                // We can't easily get the file path, so this is limited
                                // Return null to skip this line
                                param.setResult(null);
                                // maps 一读就是几百行，逐行打日志会刷屏：只记每 200 条里的第一条
                                if (mapsFilteredCount.incrementAndGet() % 200 == 1) {
                                    XposedEntry.log("Filtered hook library from maps: " + line.substring(0, Math.min(50, line.length())));
                                }
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                }
            });

        // Hook File.exists for LSPosed artifacts
        HookUtils.hookMethod(File.class, "exists",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    File file = (File) param.thisObject;
                    String path = file.getAbsolutePath();

                    if (isXposedArtifact(path)) {
                        param.setResult(false);
                        XposedEntry.log("Hidden Xposed artifact: " + path);
                    }
                }
            });
    }

    private static void hookStackTrace() {
        // Filter Xposed from stack traces
        HookUtils.hookMethod(Throwable.class, "getStackTrace",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    StackTraceElement[] original = (StackTraceElement[]) param.getResult();
                    if (original == null) return;

                    List<StackTraceElement> filtered = new ArrayList<>();
                    for (StackTraceElement element : original) {
                        String className = element.getClassName();
                        if (!className.contains("xposed") &&
                            !className.contains("lsposed") &&
                            !className.contains("edxposed")) {
                            filtered.add(element);
                        }
                    }

                    if (filtered.size() != original.length) {
                        param.setResult(filtered.toArray(new StackTraceElement[0]));
                    }
                }
            });
    }

    private static void hookClassLoaderCheck() {
        // Some apps check the ClassLoader chain for Xposed
        HookUtils.hookMethod(ClassLoader.class, "toString",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    String result = (String) param.getResult();
                    if (result != null && (result.contains("xposed") || result.contains("lsposed"))) {
                        // Sanitize the string
                        result = result.replaceAll("(?i)xposed", "dalvik")
                                       .replaceAll("(?i)lsposed", "dalvik");
                        param.setResult(result);
                    }
                }
            });
    }

    private static boolean isHiddenPackage(String packageName) {
        if (packageName == null) return false;
        for (String hiddenPkg : HIDDEN_PACKAGES) {
            if (packageName.equals(hiddenPkg)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsHookLibrary(String line) {
        if (line == null) return false;
        String lowerLine = line.toLowerCase();
        for (String pattern : HOOK_LIBRARY_PATTERNS) {
            if (lowerLine.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isXposedArtifact(String path) {
        return path != null && (
            path.contains("/data/user_de/0/org.lsposed.manager") ||
            path.contains("/data/user/0/org.lsposed.manager") ||
            path.contains("/data/data/de.robv.android.xposed.installer") ||
            path.contains("XposedBridge") ||
            path.contains("/system/framework/XposedBridge")
        );
    }
}
