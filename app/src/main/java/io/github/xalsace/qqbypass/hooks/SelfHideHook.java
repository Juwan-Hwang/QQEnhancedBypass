package io.github.xalsace.qqbypass.hooks;

import android.content.pm.PackageManager;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Self-Hide Hook
 *
 * 源自 OpenShamrock AntiDetection.antiFindPackage / antiGetPackageGidsDetection /
 * antiProviderDetection。
 *
 * QEB 自己是一个独立安装的 LSPosed 模块 APK（io.github.xalsace.qqbypass）。
 * XposedDetectionHook 只隐藏了 LSPosed/Magisk 管理器这些第三方包，却没隐藏 QEB 自身。
 * 这里在 QQ 进程里把对 QEB 自身包的查询全部打成"查不到"：getPackageInfo /
 * getApplicationInfo / getPackageGids / ContentResolver 查询。
 */
public class SelfHideHook {

    private static final String OWN_PACKAGE = "io.github.xalsace.qqbypass";

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        XposedEntry.log("Initializing Self-Hide Hook for " + OWN_PACKAGE);

        XC_MethodHook notFound = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args.length > 0 && OWN_PACKAGE.equals(param.args[0])) {
                    param.setThrowable(new PackageManager.NameNotFoundException(OWN_PACKAGE));
                }
            }
        };

        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getPackageInfo", notFound);
        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getApplicationInfo", notFound);
        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getPackageGids", notFound);
        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getPackageUid", notFound);

        // ContentResolver.acquireContentProviderClient / acquireUnstableContentProviderClient
        XC_MethodHook providerNull = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args.length > 0 && param.args[0] instanceof String
                        && ((String) param.args[0]).contains(OWN_PACKAGE)) {
                    param.setResult(null);
                }
            }
        };
        HookUtils.hookAllMethods("android.content.ContentResolver", "acquireContentProviderClient", providerNull);
        HookUtils.hookAllMethods("android.content.ContentResolver", "acquireUnstableContentProviderClient", providerNull);
    }
}
