package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Login Downgrade Hook (NT -> WT)
 *
 * 源自 callng/QQHook 与 OpenShamrock(GPL-3.0) AntiDetection.disableSwitch。
 *
 * 旧版本 QQ 的 NT 登录链路环境检测更严，这些模块通过 hook
 * UnitedConfig.isSwitchOn 关掉 msf_init_optimize / msf_network_service_switch_new /
 * wt_login_upgrade、强制 nt_login_downgrade=true，并让 MobileQQ.isLoginByNT=false，
 * 从而回退到老的 WT 登录流程。
 *
 * ⚠️ 版本门控：原模块只在 QQ <= 9.2.10 (versionCode 29175) 或 TIM 上生效。
 * 本仓库主力目标 QQ 9.3.50 / 真机验证 9.3.75 都在门控之外，因此这段在当前目标版本上
 * 不会触发（保持惰性，绝不影响新版登录）。迁移到 QEB 仅为完整收录开源手段。
 */
public class LoginDowngradeHook {

    // QQ 9.2.10 versionCode；高于此不启用降级。
    private static final long QQ_9_2_10_VERSION_CODE = 29175L;

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_NETWORK_INTERCEPT) return;

        if (!isSupported(lpparam)) {
            XposedEntry.log("LoginDowngradeHook skipped (version > 9.2.10, inert on this target)");
            return;
        }

        XposedEntry.log("Initializing Login Downgrade Hook (NT->WT)");

        // UnitedConfig.isSwitchOn(context?, tag) -> boolean；tag 是第二个参数
        HookUtils.hookAllMethods("com.tencent.freesia.UnitedConfig", "isSwitchOn",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    String tag = null;
                    for (Object a : param.args) {
                        if (a instanceof String) { tag = (String) a; break; }
                    }
                    if (tag == null) return;
                    switch (tag) {
                        case "msf_init_optimize":
                        case "msf_network_service_switch_new":
                        case "wt_login_upgrade":
                            param.setResult(false);
                            break;
                        case "nt_login_downgrade":
                            param.setResult(true);
                            break;
                        default:
                            break;
                    }
                }
            });

        // MobileQQ.isLoginByNT() -> false
        HookUtils.hookAllMethods("mqq.app.MobileQQ", "isLoginByNT",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                }
            });
    }

    private static boolean isSupported(XC_LoadPackage.LoadPackageParam lpparam) {
        // TIM 一律支持；QQ 仅 <= 9.2.10 支持。版本读不到时保守返回 false。
        try {
            String pkg = lpparam.packageName;
            if ("com.tencent.tim".equals(pkg)) return true;
            android.content.Context ctx = (android.content.Context)
                de.robv.android.xposed.XposedHelpers.callStaticMethod(
                    Class.forName("android.app.ActivityThread"), "currentApplication");
            if (ctx == null) return false;
            android.content.pm.PackageInfo pi = ctx.getPackageManager().getPackageInfo(pkg, 0);
            long vc;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                vc = pi.getLongVersionCode();
            } else {
                vc = pi.versionCode;
            }
            return vc <= QQ_9_2_10_VERSION_CODE;
        } catch (Throwable t) {
            return false;
        }
    }
}
