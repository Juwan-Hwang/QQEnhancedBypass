package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Hot-Update Disable Hook
 *
 * 源自 QwQ(HotUpdateSoPatch) 与 TCQT(DisableHotPatch) 思路。
 *
 * QQ 会通过 earlydownload 的 XmlData 下发/热更新 so 与补丁；一旦热更，可能悄悄把
 * 新版检测库拉下来，让已有的 bypass 失效，甚至在旧版上重新引入检测点。这里拦住
 * XmlData.updateServerInfo，把各档位下载开关全部关掉，禁止按流量热更。
 *
 * 用反射设字段，避免在编译期依赖 QQ 的 XmlData 类。
 */
public class HotUpdateHook {

    private static final String[] FALSE_FIELDS = {
        "StoreBackup", "load2G", "load3G", "net_2_2G", "net_2_3G"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        XposedEntry.log("Initializing Hot-Update Disable Hook");

        HookUtils.hookAllMethods("com.tencent.mobileqq.earlydownload.xmldata.XmlData", "updateServerInfo",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object xmlData = param.thisObject;
                    if (xmlData == null) return;
                    for (String f : FALSE_FIELDS) {
                        try {
                            XposedHelpers.setBooleanField(xmlData, f, false);
                        } catch (Throwable ignored) {
                            // 字段在该版本不存在就跳过
                        }
                    }
                }
            });
    }
}
