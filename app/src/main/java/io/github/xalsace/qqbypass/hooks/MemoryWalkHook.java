package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Anti Memory-Walk Hook
 *
 * 源自 OpenShamrock (callng/OpenShamrock, GPL-3.0) AntiDetection.antiMemoryWalking。
 *
 * QQ 可以通过 dalvik.system.VMDebug 的实例统计接口在堆上"数"出模块注入的类，
 * 从而绕过所有基于 /proc 文件和 PackageManager 的隐藏。这里拦截三个接口，当被
 * 统计的类属于 Xposed/LSPosed/本模块命名空间时，返回 0 / 空数组。
 *
 * - countInstancesOfClass(Class, boolean) -> long
 * - countInstancesOfClasses(Class[], boolean) -> long[]
 * - getInstancesOfClasses(Class[], boolean) -> Object[][]
 */
public class MemoryWalkHook {

    // 需要在堆统计里"消失"的类命名空间特征
    private static final String[] MODULE_FOOTPRINTS = {
        "xposed", "lsposed", "edxposed", "xalsace", "qqbypass",
        "de.robv.android", "io.github.lsposed", "org.lsposed"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        XposedEntry.log("Initializing Memory-Walk Bypass (VMDebug)");

        // countInstancesOfClass(Class, boolean) -> long
        HookUtils.hookAllMethods("dalvik.system.VMDebug", "countInstancesOfClass",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length >= 1 && param.args[0] instanceof Class
                            && isModuleClass((Class<?>) param.args[0])) {
                        param.setResult(0L);
                    }
                }
            });

        // countInstancesOfClasses(Class[], boolean) -> long[]
        HookUtils.hookAllMethods("dalvik.system.VMDebug", "countInstancesOfClasses",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length < 1 || !(param.args[0] instanceof Class<?>[])) return;
                    Class<?>[] classes = (Class<?>[]) param.args[0];
                    Object result = param.getResult();
                    if (!(result instanceof long[])) return;
                    long[] counts = (long[]) result;
                    boolean changed = false;
                    for (int i = 0; i < classes.length && i < counts.length; i++) {
                        if (isModuleClass(classes[i]) && counts[i] != 0L) {
                            counts[i] = 0L;
                            changed = true;
                        }
                    }
                    if (changed) param.setResult(counts);
                }
            });

        // getInstancesOfClasses(Class[], boolean) -> Object[][]
        HookUtils.hookAllMethods("dalvik.system.VMDebug", "getInstancesOfClasses",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length < 1 || !(param.args[0] instanceof Class<?>[])) return;
                    Class<?>[] classes = (Class<?>[]) param.args[0];
                    Object result = param.getResult();
                    if (!(result instanceof Object[])) return;
                    Object[] instances = (Object[]) result;
                    boolean changed = false;
                    for (int i = 0; i < classes.length && i < instances.length; i++) {
                        if (isModuleClass(classes[i]) && instances[i] instanceof Object[]
                                && ((Object[]) instances[i]).length != 0) {
                            instances[i] = new Object[0];
                            changed = true;
                        }
                    }
                    if (changed) param.setResult(instances);
                }
            });
    }

    private static boolean isModuleClass(Class<?> clazz) {
        if (clazz == null) return false;
        String name = clazz.getName();
        if (name == null) return false;
        String lower = name.toLowerCase();
        for (String f : MODULE_FOOTPRINTS) {
            if (lower.contains(f)) return true;
        }
        return false;
    }
}
