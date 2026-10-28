package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.io.File;
import java.lang.reflect.Member;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * DexKit-based Root Detection Bypass
 * Dynamically locates and hooks obfuscated su path checkers
 */
public class DynamicRootDetectionHook {

    private static final String[] SU_PATHS = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/adb/magisk",
        "/data/adb/ksu"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_ROOT_BYPASS) return;

        XposedEntry.log("Initializing DexKit-based Root Detection Bypass");

        // Universal hook: File.exists() - catches all path checks
        hookFileExists();

        // Dynamic hooks: DexKit-discovered su path checkers
        new Thread(() -> {
            try {
                // Wait for the shared scan to finish instead of a fixed sleep.
                // The old sleep(5000) raced the scan and read an empty cache;
                // awaitReady() blocks until the bridge is up (false = subprocess).
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("DynamicRoot: DexKit not available, skipping dynamic hooks");
                    return;
                }
                hookSuPathCheckers(lpparam);
                hookPackageQueries(lpparam);

            } catch (Exception e) {
                XposedEntry.log("Dynamic root detection hook failed: " + e.getMessage());
            }
        }).start();
    }

    private static void hookFileExists() {
        HookUtils.hookMethod(File.class, "exists",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    File file = (File) param.thisObject;
                    String path = file.getAbsolutePath();

                    if (isSuspiciousPath(path)) {
                        param.setResult(false);
                        XposedEntry.log("File.exists blocked: " + path);
                    }
                }
            });
    }

    private static void hookSuPathCheckers(XC_LoadPackage.LoadPackageParam lpparam) {
        List<String> suCheckers = DexKitDetector.findSuPathCheckers();
        if (suCheckers.isEmpty()) {
            XposedEntry.log("DynamicRoot: No su path checkers found by DexKit");
            return;
        }

        XposedEntry.log("DynamicRoot: Hooking " + suCheckers.size() + " su path checkers");

        for (String descriptor : suCheckers) {
            try {
                String className = DexKitDetector.descriptorClassName(descriptor);
                String methodName = DexKitDetector.descriptorMethodName(descriptor);

                Member method = DexKitDetector.resolveDescriptor(descriptor, lpparam.classLoader);
                if (method == null) continue;

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        // If method returns boolean (isRooted check), force false
                        if (param.getResult() instanceof Boolean && (Boolean) param.getResult()) {
                            param.setResult(false);
                            XposedEntry.log("Su path checker neutralized: " + className);
                        }
                    }
                });

                XposedEntry.log("Hooked su path checker: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook su checker: " + e.getMessage());
            }
        }
    }

    private static void hookPackageQueries(XC_LoadPackage.LoadPackageParam lpparam) {
        List<String> packageQueries = DexKitDetector.findSuspiciousPackageQueries();
        if (packageQueries.isEmpty()) {
            XposedEntry.log("DynamicRoot: No package queries found by DexKit");
            return;
        }

        XposedEntry.log("DynamicRoot: Hooking " + packageQueries.size() + " package queries");

        for (String descriptor : packageQueries) {
            try {
                String className = DexKitDetector.descriptorClassName(descriptor);
                String methodName = DexKitDetector.descriptorMethodName(descriptor);

                Member method = DexKitDetector.resolveDescriptor(descriptor, lpparam.classLoader);
                if (method == null) continue;

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        // Check if querying for suspicious packages
                        for (Object arg : param.args) {
                            if (arg instanceof String) {
                                String pkg = (String) arg;
                                if (isSuspiciousPackage(pkg)) {
                                    // Throw NameNotFoundException
                                    throw new android.content.pm.PackageManager.NameNotFoundException(
                                        "Package not found: " + pkg);
                                }
                            }
                        }
                    }
                });

                XposedEntry.log("Hooked package query: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook package query: " + e.getMessage());
            }
        }
    }

    private static boolean isSuspiciousPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();

        for (String suPath : SU_PATHS) {
            if (lower.contains(suPath)) return true;
        }

        return lower.contains("magisk") || lower.contains("supersu")
            || lower.contains("superuser") || lower.contains("ksu")
            || lower.contains("xposed") || lower.contains("lsposed")
            || lower.contains("/data/adb");
    }

    private static boolean isSuspiciousPackage(String pkg) {
        if (pkg == null) return false;
        String lower = pkg.toLowerCase();

        return lower.contains("magisk") || lower.contains("supersu")
            || lower.contains("superuser") || lower.contains("xposed")
            || lower.contains("lsposed") || lower.contains("edxposed")
            || lower.contains("kernelsu");
    }
}
