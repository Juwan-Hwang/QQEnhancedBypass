package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Member;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;

/**
 * DexKit-based Xposed/LSPosed Detection Bypass
 * Dynamically locates and hooks obfuscated framework detection methods
 */
public class DynamicXposedDetectionHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        XposedEntry.log("Initializing DexKit-based Xposed Detection Bypass");

        // Dynamic hooks: DexKit-discovered detection points
        new Thread(() -> {
            try {
                // Wait for the shared scan instead of a fixed sleep (the old
                // sleep(5000) raced the scan and read an empty cache).
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("DynamicXposed: DexKit not available, skipping dynamic hooks");
                    return;
                }
                hookArtMethodDetectors(lpparam);
                hookMapsReaders(lpparam);
                hookQSecDetectors(lpparam);

            } catch (Exception e) {
                XposedEntry.log("Dynamic Xposed detection hook failed: " + e.getMessage());
            }
        }).start();
    }

    private static void hookArtMethodDetectors(XC_LoadPackage.LoadPackageParam lpparam) {
        List<String> artDetectors = DexKitDetector.findArtHookDetectors();
        if (artDetectors.isEmpty()) {
            XposedEntry.log("DynamicXposed: No ArtMethod detectors found by DexKit");
            return;
        }

        XposedEntry.log("DynamicXposed: Hooking " + artDetectors.size() + " ArtMethod detectors");

        for (String descriptor : artDetectors) {
            try {
                String className = DexKitDetector.descriptorClassName(descriptor);
                String methodName = DexKitDetector.descriptorMethodName(descriptor);

                Member method = DexKitDetector.resolveDescriptor(descriptor, lpparam.classLoader);
                if (method == null) continue;

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();

                        // If returns boolean (isHooked check), force false
                        if (result instanceof Boolean && (Boolean) result) {
                            param.setResult(false);
                            XposedEntry.log("ArtMethod detector neutralized: " + className);
                        }

                        // If returns int (hook count), force 0
                        if (result instanceof Integer && (Integer) result > 0) {
                            param.setResult(0);
                            XposedEntry.log("ArtMethod hook count zeroed: " + className);
                        }

                        // If returns List/Array (hooked methods list), force empty
                        if (result instanceof java.util.List && !((java.util.List<?>) result).isEmpty()) {
                            param.setResult(new java.util.ArrayList<>());
                            XposedEntry.log("ArtMethod hook list cleared: " + className);
                        }
                    }
                });

                XposedEntry.log("Hooked ArtMethod detector: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook ArtMethod detector: " + e.getMessage());
            }
        }
    }

    private static void hookMapsReaders(XC_LoadPackage.LoadPackageParam lpparam) {
        List<String> mapsReaders = DexKitDetector.findMapsReaders();
        if (mapsReaders.isEmpty()) {
            XposedEntry.log("DynamicXposed: No maps readers found by DexKit");
            return;
        }

        XposedEntry.log("DynamicXposed: Hooking " + mapsReaders.size() + " /proc/self/maps readers");

        for (String descriptor : mapsReaders) {
            try {
                String className = DexKitDetector.descriptorClassName(descriptor);
                String methodName = DexKitDetector.descriptorMethodName(descriptor);

                Member method = DexKitDetector.resolveDescriptor(descriptor, lpparam.classLoader);
                if (method == null) continue;

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();

                        // If returns String (maps content), filter suspicious lines
                        if (result instanceof String) {
                            String filtered = filterMapsContent((String) result);
                            if (!filtered.equals(result)) {
                                param.setResult(filtered);
                                XposedEntry.log("Maps reader output filtered: " + className);
                            }
                        }

                        // If returns List<String> (maps lines), filter
                        if (result instanceof java.util.List) {
                            java.util.List<?> list = (java.util.List<?>) result;
                            if (!list.isEmpty() && list.get(0) instanceof String) {
                                @SuppressWarnings("unchecked")
                                java.util.List<String> lines = (java.util.List<String>) list;
                                java.util.List<String> filtered = filterMapsList(lines);
                                if (filtered.size() != lines.size()) {
                                    param.setResult(filtered);
                                    XposedEntry.log("Maps reader list filtered: " + className);
                                }
                            }
                        }
                    }
                });

                XposedEntry.log("Hooked maps reader: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook maps reader: " + e.getMessage());
            }
        }
    }

    private static void hookQSecDetectors(XC_LoadPackage.LoadPackageParam lpparam) {
        List<String> qsecDetectors = DexKitDetector.findQSecHookDetectors();
        if (qsecDetectors.isEmpty()) {
            XposedEntry.log("DynamicXposed: No QSec detectors found by DexKit");
            return;
        }

        XposedEntry.log("DynamicXposed: Hooking " + qsecDetectors.size() + " QSec hook detectors");

        for (String descriptor : qsecDetectors) {
            try {
                String className = DexKitDetector.descriptorClassName(descriptor);
                String methodName = DexKitDetector.descriptorMethodName(descriptor);

                Member method = DexKitDetector.resolveDescriptor(descriptor, lpparam.classLoader);
                if (method == null) continue;

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();

                        // Neutralize positive detection results
                        if (result instanceof Boolean && (Boolean) result) {
                            param.setResult(false);
                            XposedEntry.log("QSec detector neutralized: " + className);
                        }

                        if (result instanceof Integer && (Integer) result != 0) {
                            param.setResult(0);
                            XposedEntry.log("QSec detection code zeroed: " + className);
                        }
                    }
                });

                XposedEntry.log("Hooked QSec detector: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook QSec detector: " + e.getMessage());
            }
        }
    }

    private static String filterMapsContent(String content) {
        if (content == null) return content;

        StringBuilder filtered = new StringBuilder();
        for (String line : content.split("\n")) {
            if (!isSuspiciousMapLine(line)) {
                filtered.append(line).append("\n");
            }
        }
        return filtered.toString();
    }

    private static java.util.List<String> filterMapsList(java.util.List<String> lines) {
        java.util.List<String> filtered = new java.util.ArrayList<>();
        for (String line : lines) {
            if (!isSuspiciousMapLine(line)) {
                filtered.add(line);
            }
        }
        return filtered;
    }

    private static boolean isSuspiciousMapLine(String line) {
        if (line == null) return false;
        String lower = line.toLowerCase();

        return lower.contains("xposed") || lower.contains("lsposed")
            || lower.contains("edxposed") || lower.contains("magisk")
            || lower.contains("zygisk") || lower.contains("riru")
            || lower.contains("frida") || lower.contains("substrate")
            || lower.contains("/data/adb") || lower.contains("shamiko")
            // Filter our own module
            || lower.contains("xalsace") || lower.contains("bypass")
            || lower.contains("libnative-bypass.so");
    }
}
