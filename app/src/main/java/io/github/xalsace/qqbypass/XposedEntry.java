package io.github.xalsace.qqbypass;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.hooks.*;

/**
 * QQ Enhanced Bypass - Comprehensive Detection Bypass Module
 *
 * This module provides multi-layered protection against QQ's environment detection:
 * - Java Layer: Root/Xposed/Debug detection bypass (30%)
 * - Native Layer: libc/libfekit/libturingxq hooks (70%)
 * - Network reporting interception
 * - Device info spoofing with cross-validation protection
 */
public class XposedEntry implements IXposedHookLoadPackage {

    private static final String TAG = "QQEnhancedBypass";
    private static final String TARGET_PACKAGE = "com.tencent.mobileqq";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!TARGET_PACKAGE.equals(lpparam.packageName)) {
            return;
        }

        log("=== QQ Enhanced Bypass v2.0 ===");
        log("Package: " + lpparam.packageName);
        log("Process: " + lpparam.processName);

        // Initialize configuration
        HookConfig.init(lpparam);

        // Process gate: DexKitBridge.create() parses the whole ~112MB APK. QQ runs
        // several processes (main, :MSF, ...); parsing in every one caused a
        // memory/CPU spike that could get the process killed on cold start (the
        // "1-2s flash-exit"). Only the main process runs DexKit; subprocesses keep
        // the cheap universal framework hooks. main process: processName == packageName.
        boolean isMainProcess = lpparam.packageName.equals(lpparam.processName);
        DexKitDetector.setEnabled(isMainProcess);
        log("DexKit enabled for this process: " + isMainProcess);

        // === DexKit Dynamic Detection (Background Thread) ===
        // Scan for obfuscated detection points to avoid version-specific hardcoding
        if (isMainProcess) new Thread(() -> {
            try {
                log("=== DexKit: Starting dynamic scan ===");
                Thread.sleep(3000); // Wait for app context

                android.content.Context context = (android.content.Context)
                    de.robv.android.xposed.XposedHelpers.callStaticMethod(
                        de.robv.android.xposed.XposedHelpers.findClass(
                            "android.app.ActivityThread", lpparam.classLoader),
                        "currentApplication");

                if (context != null) {
                    // 版本闸（合并版）：把真实 QQ 版本/SDK/ABI 打进日志，适配排障先看这一行
                    try {
                        android.content.pm.PackageInfo pi = context.getPackageManager()
                            .getPackageInfo(TARGET_PACKAGE, 0);
                        log("[VER] QQ=" + pi.versionName + " (" + pi.versionCode + ") sdk="
                            + android.os.Build.VERSION.SDK_INT + " abi=" + android.os.Build.SUPPORTED_ABIS[0]);
                    } catch (Exception ignored) {
                    }
                    DexKitDetector.init(context);

                    // Scan all detection points
                    log("DexKit: Scanning Runtime.exec callers...");
                    int runtimeExec = DexKitDetector.findRuntimeExecCallers().size();

                    log("DexKit: Scanning ProcessBuilder callers...");
                    int processBuilder = DexKitDetector.findProcessBuilderCallers().size();

                    log("DexKit: Scanning su path checkers...");
                    int suPath = DexKitDetector.findSuPathCheckers().size();

                    log("DexKit: Scanning package queries...");
                    int packageQuery = DexKitDetector.findSuspiciousPackageQueries().size();

                    log("DexKit: Scanning ArtMethod hook detectors...");
                    int artHook = DexKitDetector.findArtHookDetectors().size();

                    log("DexKit: Scanning /proc/self/maps readers...");
                    int mapsReader = DexKitDetector.findMapsReaders().size();

                    log("DexKit: Scanning wtlogin error handlers...");
                    int wtlogin = DexKitDetector.findWtloginErrorHandlers().size();

                    log("DexKit: Scanning QSec hook detectors...");
                    int qsec = DexKitDetector.findQSecHookDetectors().size();

                    log("=== DexKit Scan Complete ===");
                    log("  Runtime.exec callers: " + runtimeExec);
                    log("  ProcessBuilder callers: " + processBuilder);
                    log("  Su path checkers: " + suPath);
                    log("  Package queries: " + packageQuery);
                    log("  ArtMethod detectors: " + artHook);
                    log("  Maps readers: " + mapsReader);
                    log("  Wtlogin handlers: " + wtlogin);
                    log("  QSec detectors: " + qsec);

                    // Keep DexKit alive for runtime queries
                    // DexKitDetector.release(); // Don't release yet - hooks may need it
                }
            } catch (Exception e) {
                log("DexKit scan failed: " + e.getMessage());
            }
        }).start();

        // 进程白名单（合并版，2026-11-03）：静态钩子与 native 层只装主进程与 :MSF——
        // 检测与上报都发生在这两个进程里；:qzone 等子进程全量装钩只增加崩溃面和日志噪声（TY 合并版同口径）。
        boolean installHooks = isMainProcess || lpparam.processName.endsWith(":MSF");
        if (!installHooks) {
            log("[PROC] skip hooks for process=" + lpparam.processName + " (not whitelisted)");
            return;
        }

        try {
            // === Initialize Unified Hook Coordinator ===
            // This coordinates Java and Native layers seamlessly
            UnifiedHookCoordinator.initialize(lpparam);

            // === Java Layer Hooks (30% detection coverage) ===

            // Layer 1: Network reporting interception (highest priority)
            NetworkReportHook.hook(lpparam);

            // Layer 2: Root detection bypass (DexKit-based dynamic version)
            DynamicRootDetectionHook.hook(lpparam);

            // Layer 3: Xposed/Hook framework detection mitigation (DexKit-based dynamic version)
            DynamicXposedDetectionHook.hook(lpparam);

            // Layer 3.5: 静态 Xposed 检测兜底（包名黑名单/getPackageUid/queryIntent 过滤都在这一层；
            // dexkit-dynamic-detection 分支起入口只调了动态版、静态 hook() 没人调，黑名单整体失效——合并版恢复）
            XposedDetectionHook.hook(lpparam);

            // Layer 4: Device info consistency protection (DexKit-based dynamic version)
            DynamicDeviceInfoHook.hook(lpparam);

            // Layer 5: Debug/Emulator detection bypass (DexKit-based dynamic version)
            DynamicDebugDetectionHook.hook(lpparam);

            // Layer 6: Runtime monitoring bypass (DexKit-based dynamic version)
            DynamicRuntimeMonitorHook.hook(lpparam);

            // Layer 7: QQ 9.3.50 detection-point completion (real risk/kick targets)
            QQ950PatchHook.hook(lpparam);

            // === Report Status ===
            log("=== Java Hooks Initialized ===");
            log("Initial Protection Level: " + UnifiedHookCoordinator.getProtectionLevel());
            // Native 层在后台线程异步安装，稍后报告最终等级
            UnifiedHookCoordinator.reportFinalProtectionLevelAsync();

        } catch (Throwable t) {
            log("Error during hook initialization: " + t.getMessage());
            t.printStackTrace();
        }
    }

    /**
     * Initialize native layer hooks (deprecated - now handled by UnifiedHookCoordinator)
     */
    @Deprecated
    private void initNativeHooks() {
        // This method is kept for compatibility but functionality moved to UnifiedHookCoordinator
    }

    public static void log(String message) {
        Log.i(TAG, message);
    }

    public static void logError(String message, Throwable t) {
        Log.e(TAG, message, t);
    }
}
