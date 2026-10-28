package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Member;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * DexKit-based Runtime Monitor Bypass
 * Dynamically locates and hooks obfuscated runtime command detection methods
 */
public class DynamicRuntimeMonitorHook {

    private static final String[] MONITORED_COMMANDS = {
        "ip", "pm", "getprop", "sh", "/system/bin/sh",
        "ps", "cat", "mount", "which", "su"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_RUNTIME_BYPASS) return;

        XposedEntry.log("Initializing DexKit-based Runtime Monitor Bypass");

        // Universal hook: ProcessBuilder.start() - catches all command execution
        hookProcessBuilder();

        // Dynamic hooks: DexKit-discovered Runtime.exec callers
        // Run in background thread; wait for the shared scan instead of a fixed
        // sleep (the old sleep(5000) raced the scan and read an empty cache).
        new Thread(() -> {
            try {
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("DynamicRuntime: DexKit not available, skipping dynamic hooks");
                    return;
                }
                hookRuntimeExecCallers(lpparam);
                hookProcessBuilderCallers(lpparam);

            } catch (Exception e) {
                XposedEntry.log("Dynamic runtime hook setup failed: " + e.getMessage());
            }
        }).start();
    }

    private static void hookProcessBuilder() {
        // ProcessBuilder.start() is the UNIVERSAL choke point for command execution
        HookUtils.hookMethod(ProcessBuilder.class, "start",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    ProcessBuilder pb = (ProcessBuilder) param.thisObject;
                    java.util.List<String> command = pb.command();
                    if (command == null || command.isEmpty()) return;

                    String joined = joinCommand(command);

                    if (isRootProbe(joined)) {
                        // Rewrite to harmless no-op: exit 1 (non-zero = su not found)
                        pb.command("/system/bin/sh", "-c", "exit 1");
                        XposedEntry.log("Neutralized ProcessBuilder root probe: " + joined);
                    } else if (isMonitoredCommand(joined)) {
                        XposedEntry.log("ProcessBuilder command intercepted: " + joined);
                    }
                }
            });
    }

    private static void hookRuntimeExecCallers(XC_LoadPackage.LoadPackageParam lpparam) {
        List<String> execCallers = DexKitDetector.findRuntimeExecCallers();
        if (execCallers.isEmpty()) {
            XposedEntry.log("DynamicRuntime: No Runtime.exec callers found by DexKit");
            return;
        }

        XposedEntry.log("DynamicRuntime: Hooking " + execCallers.size() + " Runtime.exec callers");

        for (String descriptor : execCallers) {
            try {
                String className = DexKitDetector.descriptorClassName(descriptor);
                String methodName = DexKitDetector.descriptorMethodName(descriptor);

                Member method = DexKitDetector.resolveDescriptor(descriptor, lpparam.classLoader);
                if (method == null) continue;

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        logCommandArgs("Runtime.exec caller: " + className, param.args);
                    }
                });

                XposedEntry.log("Hooked Runtime.exec caller: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook Runtime.exec caller: " + e.getMessage());
            }
        }
    }

    private static void hookProcessBuilderCallers(XC_LoadPackage.LoadPackageParam lpparam) {
        List<String> pbCallers = DexKitDetector.findProcessBuilderCallers();
        if (pbCallers.isEmpty()) {
            XposedEntry.log("DynamicRuntime: No ProcessBuilder callers found by DexKit");
            return;
        }

        XposedEntry.log("DynamicRuntime: Hooking " + pbCallers.size() + " ProcessBuilder callers");

        for (String descriptor : pbCallers) {
            try {
                String className = DexKitDetector.descriptorClassName(descriptor);
                String methodName = DexKitDetector.descriptorMethodName(descriptor);

                Member method = DexKitDetector.resolveDescriptor(descriptor, lpparam.classLoader);
                if (method == null) continue;

                XposedBridge.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        logCommandArgs("ProcessBuilder caller: " + className, param.args);
                    }
                });

                XposedEntry.log("Hooked ProcessBuilder caller: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook ProcessBuilder caller: " + e.getMessage());
            }
        }
    }

    private static void logCommandArgs(String tag, Object[] args) {
        if (args == null) return;
        for (Object arg : args) {
            if (arg == null) continue;
            String s;
            if (arg instanceof String[]) {
                s = java.util.Arrays.toString((String[]) arg);
            } else {
                s = arg.toString();
            }
            if (isMonitoredCommand(s)) {
                XposedEntry.log(tag + " observed monitored command: " + s);
            }
        }
    }

    private static String joinCommand(java.util.List<String> command) {
        StringBuilder sb = new StringBuilder();
        for (String part : command) {
            if (part == null) continue;
            if (sb.length() > 0) sb.append(' ');
            sb.append(part);
        }
        return sb.toString();
    }

    private static boolean isRootProbe(String joined) {
        if (joined == null) return false;
        String s = joined.toLowerCase();

        if (s.contains("magisk") || s.contains("supersu") || s.contains("superuser")
                || s.contains("busybox") || s.contains("ksud")
                || s.contains("which su") || s.contains("type su") || s.contains("command -v su")
                || s.contains("/system/bin/su") || s.contains("/system/xbin/su")
                || s.contains("/sbin/su") || s.contains("/su/bin")
                || s.contains("/data/local/su")) {
            return true;
        }

        for (String tok : s.split("\\s+")) {
            if (tok.equals("su")) return true;
        }
        return false;
    }

    private static boolean isMonitoredCommand(String command) {
        if (command == null) return false;
        for (String monitored : MONITORED_COMMANDS) {
            if (command.contains(monitored)) {
                return true;
            }
        }
        return false;
    }
}
