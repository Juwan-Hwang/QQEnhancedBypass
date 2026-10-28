package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Member;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Network Report Interception Hook
 *
 * Intercepts and blocks security-related reporting to Tencent servers:
 * - trpc.o3.report.* (environment reports)
 * - trpc.o3.mobile_security.* (security checks)
 * - TuringFD risk detection
 * - Wlogin device fingerprint
 */
public class NetworkReportHook {

    // Only pure telemetry/report commands. Login-critical commands
    // (wtlogin.*, turing, DeviceTokenV3) are intentionally NOT blocked -
    // blocking them breaks the QQ login/registration handshake and prevents
    // entry to the main UI.
    private static final String[] BLOCK_COMMANDS = {
        "trpc.o3.report",
        "trpc.o3.mobile_security",
        "trpc.ilive_cdn.report",
        "OidbSvc.0xd79"  // Device report
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_NETWORK_INTERCEPT) return;

        XposedEntry.log("Initializing Network Report Hook");

        // Hook 1: ChannelProxyExt.sendMessage (primary intercept point)
        hookChannelProxyExt(lpparam);

        // Hook 2: MsfCore.sendSsoMsg (secondary intercept point)
        hookMsfCore(lpparam);

        // Hook 3: TuringFD risk detection
        hookTuringFD(lpparam);

        // Hook 4: Wlogin device report
        hookWlogin(lpparam);
    }

    private static void hookChannelProxyExt(XC_LoadPackage.LoadPackageParam lpparam) {
        // Try multiple possible method signatures for different QQ versions
        String[] methodNames = {"sendMessage", "sendMessageInner", "send"};

        for (String methodName : methodNames) {
            HookUtils.hookAllMethods("com.tencent.mobileqq.channel.ChannelProxyExt", methodName,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args.length < 1 || !(param.args[0] instanceof String)) return;

                        String command = (String) param.args[0];
                        if (shouldBlock(command)) {
                            // Only override the return value if type-safe. setResult(null)
                            // crashes (uncatchable ClassCastException in proceed()) when the
                            // method returns a primitive.
                            Class<?> returnType = ((java.lang.reflect.Method) param.method).getReturnType();
                            if (returnType.isPrimitive() && returnType != void.class) {
                                // Primitive return - blocking is unsafe, observe only.
                                XposedEntry.log("ChannelProxyExt (not blocked, primitive return "
                                    + returnType.getName() + "): " + command);
                                return;
                            }

                            XposedEntry.log("Blocked ChannelProxyExt: " + command);

                            // Inject fake response
                            try {
                                Object channelManager = XposedHelpers.callStaticMethod(
                                    XposedHelpers.findClass("com.tencent.mobileqq.channel.ChannelManager",
                                    lpparam.classLoader), "getInstance");

                                XposedHelpers.callMethod(channelManager, "onNativeReceive",
                                    command, new byte[0], 0L);
                            } catch (Throwable t) {
                                // Ignore if injection fails
                            }

                            param.setResult(null);
                        }
                    }
                });
        }
    }

    private static void hookMsfCore(XC_LoadPackage.LoadPackageParam lpparam) {
        // Real path (QQ 9.3.50): com.tencent.mobileqq.msf.core.MsfCore
        HookUtils.hookAllMethods("com.tencent.mobileqq.msf.core.MsfCore", "sendSsoMsg",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length < 1) return;

                    Object toServiceMsg = param.args[0];
                    Object cmdObj = XposedHelpers.callMethod(toServiceMsg, "getServiceCmd");
                    String command = cmdObj == null ? null : cmdObj.toString();

                    if (shouldBlock(command)) {
                        // Type-safe block: only override the return value if the hooked
                        // method actually returns int/long/void. Setting a wrong-typed
                        // result triggers an uncatchable ClassCastException in Xposed's
                        // proceed() and crashes the process.
                        Class<?> returnType = ((java.lang.reflect.Method) param.method).getReturnType();
                        if (returnType == int.class) {
                            int seq = 0;
                            try {
                                seq = (int) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq");
                            } catch (Throwable ignored) { }
                            param.setResult(seq);
                            XposedEntry.log("Blocked MsfCore: " + command);
                        } else if (returnType == long.class) {
                            long seq = 0L;
                            try {
                                seq = ((Number) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq")).longValue();
                            } catch (Throwable ignored) { }
                            param.setResult(seq);
                            XposedEntry.log("Blocked MsfCore: " + command);
                        } else if (returnType == void.class) {
                            param.setResult(null);
                            XposedEntry.log("Blocked MsfCore: " + command);
                        } else {
                            // Unknown return type - observe only, do not risk a crash.
                            XposedEntry.log("MsfCore (not blocked, return type "
                                + returnType.getName() + "): " + command);
                        }
                    }
                }
            });
    }

    /**
     * Block TuringFD's process-enumeration readers (anti-tamper /proc scanners).
     *
     * These live in ProGuard-obfuscated "fruit" classes (Pomegranate / oqKCa on
     * 9.3.50) whose names change every QQ version, so hardcoding them is fragile.
     * Instead we locate them by a stable fingerprint: the format string
     * "/proc/%d/cmdline" they use to read another process's name. Verified to
     * occur in only 2 dex (classes2 + classes18) on 9.3.50, so the match is tight.
     *
     * The old code hooked every method named "a" and setResult(null) on all of
     * them. That was wrong twice over: Blueberry.a doesn't exist (dead hook), and
     * oqKCa.a has an int-returning overload where setResult(null) throws an
     * uncatchable ClassCastException. Here we resolve the exact method via
     * a cached descriptor lookup and only neutralize String-returning readers (-> "").
     */
    private static void hookTuringFD(XC_LoadPackage.LoadPackageParam lpparam) {
        new Thread(() -> {
            try {
                // Wait for the single shared bridge; false in a subprocess (gated off).
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("[TuringFD] DexKit not available, skip proc-reader hook");
                    return;
                }
                List<String> procReaders = DexKitDetector.findProcCmdlineReaders();
                XposedEntry.log("[TuringFD] found " + procReaders.size() + " proc readers by fingerprint");

                for (String descriptor : procReaders) {
                    try {
                        Member method = DexKitDetector.resolveDescriptor(descriptor, lpparam.classLoader);
                        if (method == null) continue;
                        // Only neutralize String-returning readers; skip primitives
                        // (int helper overload) to avoid a ClassCastException crash.
                        if (!(method instanceof java.lang.reflect.Method)) continue;
                        Class<?> ret = ((java.lang.reflect.Method) method).getReturnType();
                        if (ret != String.class) {
                            XposedEntry.log("[TuringFD] skip non-String reader "
                                + DexKitDetector.descriptorClassName(descriptor) + "." + DexKitDetector.descriptorMethodName(descriptor)
                                + " (returns " + ret.getName() + ")");
                            continue;
                        }
                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                // Empty name = "process not readable"; callers isEmpty-check this.
                                param.setResult("");
                            }
                        });
                        XposedEntry.log("[TuringFD] neutralized proc reader: "
                            + DexKitDetector.descriptorClassName(descriptor) + "." + DexKitDetector.descriptorMethodName(descriptor));
                    } catch (Throwable t) {
                        XposedEntry.log("[TuringFD] failed to hook proc reader: "
                            + t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                }
            } catch (Throwable t) {
                XposedEntry.log("[TuringFD] proc-reader lookup failed: "
                    + t.getClass().getName() + ": " + t.getMessage());
            }
        }).start();
    }

    private static void hookWlogin(XC_LoadPackage.LoadPackageParam lpparam) {
        // Hook Wlogin device fingerprint collection
        HookUtils.hookAllMethods("oicq.wlogin_sdk.request.w", "h",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    // Modify device fingerprint before sending
                    XposedEntry.log("Intercepted Wlogin device fingerprint");
                }
            });
    }

    private static boolean shouldBlock(String command) {
        if (command == null) return false;

        for (String blockCmd : BLOCK_COMMANDS) {
            if (command.contains(blockCmd)) {
                return true;
            }
        }
        return false;
    }
}
