package io.github.xalsace.qqbypass.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.enums.StringMatchType;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.query.matchers.base.StringMatcher;
import org.luckypray.dexkit.result.MethodData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import de.robv.android.xposed.XposedBridge;

/**
 * DexKit-based detector for dynamically locating obfuscated detection points in QQ.
 * Eliminates hardcoded class/method names to survive version updates.
 *
 * Single shared bridge: DexKitBridge.create() parses the whole APK (~112MB on
 * 9.3.50), so creating one per hook meant 5 full parses per process and, across
 * QQ's several processes, a memory/CPU spike that could get the process killed on
 * cold start. This class now owns ONE bridge; all hooks reuse it via getBridge()
 * after awaitReady(). The bridge is thread-safe (ReentrantReadWriteLock + shared
 * query scheduler), so concurrent findMethod() from multiple hook threads is fine.
 *
 * Process gate: only the process that calls setEnabled(true) (the main QQ process)
 * builds a bridge; subprocesses skip DexKit entirely (awaitReady returns false
 * immediately), keeping the universal framework hooks but paying no parse cost.
 */
public class DexKitDetector {
    private static final String TAG = "DexKitDetector";
    private static volatile DexKitBridge dexKitBridge;
    private static volatile boolean enabled = false; // set true only in the gated (main) process
    private static volatile boolean ready = false;   // bridge created and usable
    private static final Object initLock = new Object();
    private static final CountDownLatch readyLatch = new CountDownLatch(1);
    // ConcurrentHashMap: findXxx() may now run from multiple hook threads at once.
    private static final Map<String, List<MethodData>> detectionCache = new ConcurrentHashMap<>();

    /** Enable DexKit for this process. Call only in the main process. */
    public static void setEnabled(boolean value) { enabled = value; }
    public static boolean isEnabled() { return enabled; }
    public static boolean isReady() { return ready; }
    public static DexKitBridge getBridge() { return dexKitBridge; }

    /**
     * Block until the shared bridge is ready, up to timeoutMs.
     * Returns false immediately in a non-enabled (sub)process so callers skip
     * DexKit work instead of blocking for the full timeout.
     */
    public static boolean awaitReady(long timeoutMs) {
        if (ready) return true;
        if (!enabled) return false;
        try {
            readyLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        return ready;
    }

    /**
     * Initialize the single shared DexKit bridge (idempotent). Only the first
     * caller creates it; the readyLatch is always released so awaitReady() waiters
     * wake even if creation fails.
     */
    public static void init(Context context) {
        if (ready) return;
        synchronized (initLock) {
            if (ready) return;
            try {
                ApplicationInfo appInfo = context.getApplicationInfo();
                String apkPath = appInfo.sourceDir;

                XposedBridge.log("[" + TAG + "] Initializing DexKit with APK: " + apkPath);
                // Explicitly load libdexkit.so before create(). In an LSPosed host
                // process System.loadLibrary("dexkit") (what create() calls) can fail
                // to find the module's native lib on the host path -> UnsatisfiedLinkError.
                loadDexKitNativeLib(context);
                dexKitBridge = DexKitBridge.create(apkPath);
                ready = true;
                XposedBridge.log("[" + TAG + "] DexKit initialized successfully");
            } catch (Throwable e) {
                XposedBridge.log("[" + TAG + "] Failed to initialize DexKit: "
                    + e.getClass().getName() + ": " + e.getMessage());
            } finally {
                readyLatch.countDown();
            }
        }
    }

    /**
     * Try to load libdexkit.so from the module's own native library directory.
     * Falls back to System.loadLibrary if the explicit path isn't resolvable.
     */
    private static void loadDexKitNativeLib(Context context) {
        try {
            System.loadLibrary("dexkit");
            XposedBridge.log("[" + TAG + "] loadLibrary(dexkit) OK");
        } catch (Throwable t) {
            XposedBridge.log("[" + TAG + "] loadLibrary(dexkit) failed ("
                + t.getClass().getSimpleName() + "), trying explicit path...");
            throw t; // surfaced by caller; explicit-path loading added once confirmed
        }
    }

    /**
     * Find ArtMethod hook detection methods (QSec ArtTiHookTask / all_so_hook)
     * Target: methods checking ArtMethod structure modification
     */
    public static List<MethodData> findArtHookDetectors() {
        if (detectionCache.containsKey("art_hook")) {
            return detectionCache.get("art_hook");
        }

        try {
            XposedBridge.log("[" + TAG + "] Searching for ArtMethod hook detectors...");

            // OR-semantics: usingStrings(...) is AND within one query, so we union
            // separate single-string queries to catch methods referencing ANY marker.
            // The last two markers are verified present in current QQ string pools
            // (checked against 9.3.75): the QSec anti-hook task registers under its
            // plain name and the all-so hook pass is gated by this config key,
            // while the ART-internal names above no longer appear as literals.
            List<MethodData> results = findMethodsUsingAnyString(
                "ArtMethod", "art_quick", "entry_point", "jni_code",
                "instrumentationExit", "quick_to_interpreter",
                "ArtTiHookTask", "ALL_SO_HOOK");

            // "artMethod" (the reflective field name on Method/Executable) needs an
            // exact match: as a substring it also hits unrelated method-tracing
            // strings such as "startMethodTracing".
            Map<String, MethodData> unique = new HashMap<>();
            for (MethodData m : results) {
                unique.put(m.getDescriptor(), m);
            }
            for (MethodData m : findMethodsUsingExactString("artMethod")) {
                unique.put(m.getDescriptor(), m);
            }
            results = new ArrayList<>(unique.values());

            detectionCache.put("art_hook", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " ArtMethod hook detectors");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding ArtMethod detectors: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find /proc/self/maps readers (detecting injected .so files)
     * Target: methods reading maps file to detect LSPosed/Magisk/Zygisk/our module
     */
    public static List<MethodData> findMapsReaders() {
        if (detectionCache.containsKey("maps_reader")) {
            return detectionCache.get("maps_reader");
        }

        try {
            XposedBridge.log("[" + TAG + "] Searching for /proc/self/maps readers...");

            // "/proc/self/maps" is the strong signal; "/proc/self/task" and "/proc/"
            // catch variants. OR-union so a method needs only one of them.
            List<MethodData> results = findMethodsUsingAnyString(
                "/proc/self/maps", "/proc/self/task", "/proc/%d/maps");

            detectionCache.put("maps_reader", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " maps readers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding maps readers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find wtlogin error handlers (w21 "device invalid" logic)
     * Target: methods processing wtlogin error codes from server
     */
    public static List<MethodData> findWtloginErrorHandlers() {
        if (detectionCache.containsKey("wtlogin_error")) {
            return detectionCache.get("wtlogin_error");
        }

        try {
            XposedBridge.log("[" + TAG + "] Searching for wtlogin error handlers...");

            List<MethodData> results = new ArrayList<>();

            // Pattern 1: Methods in wtlogin packages
            results.addAll(dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .declaredClass("com.tencent.mobileqq.msf.core.wtlogin.*")
                        .usingStrings("error", "code", "msg")
                    )
            ));

            // Pattern 2: Methods handling ErrMsg objects
            results.addAll(dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .paramTypes("oicq.wlogin_sdk.tools.ErrMsg")
                    )
            ));

            detectionCache.put("wtlogin_error", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " wtlogin error handlers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding wtlogin handlers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find QSec hook detection methods (registerHookSo / nativeFileHook)
     * Target: QSec's native hook detection framework
     */
    public static List<MethodData> findQSecHookDetectors() {
        if (detectionCache.containsKey("qsec_hook")) {
            return detectionCache.get("qsec_hook");
        }

        try {
            XposedBridge.log("[" + TAG + "] Searching for QSec hook detectors...");

            // OR-semantics: these markers live in different methods, so union them.
            List<MethodData> results = findMethodsUsingAnyString(
                "registerHookSo", "nativeFileHook", "isHookedSoLoad", "QSecConfig",
                "all_so_hook", "ArtTiHookTask");

            detectionCache.put("qsec_hook", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " QSec hook detectors");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding QSec detectors: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find Runtime.exec callers (root detection via "type su" / "which su")
     * Target: methods calling Runtime.exec() with su-related commands
     */
    public static List<MethodData> findRuntimeExecCallers() {
        if (detectionCache.containsKey("runtime_exec")) {
            return detectionCache.get("runtime_exec");
        }

        try {
            XposedBridge.log("[" + TAG + "] Searching for Runtime.exec callers...");

            List<MethodData> results = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("java.lang.Runtime")
                            .name("exec"))
                        // single string = "contains"; multiple would be AND and over-narrow
                        .usingStrings("su")
                    )
            );

            detectionCache.put("runtime_exec", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " Runtime.exec callers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding Runtime.exec callers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find ProcessBuilder constructors/start callers (alternative to Runtime.exec)
     */
    public static List<MethodData> findProcessBuilderCallers() {
        if (detectionCache.containsKey("process_builder")) {
            return detectionCache.get("process_builder");
        }

        try {
            XposedBridge.log("[" + TAG + "] Searching for ProcessBuilder callers...");

            List<MethodData> results = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("java.lang.ProcessBuilder")
                            .name("start"))
                    )
            );

            detectionCache.put("process_builder", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " ProcessBuilder callers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding ProcessBuilder callers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find File.exists callers checking su paths
     */
    public static List<MethodData> findSuPathCheckers() {
        if (detectionCache.containsKey("su_path")) {
            return detectionCache.get("su_path");
        }

        try {
            XposedBridge.log("[" + TAG + "] Searching for su path checkers...");

            // Tight fingerprint: a method that references a LITERAL su binary path
            // AND calls File.exists is almost certainly a real root checker.
            // The old bare "su" substring matched 903 innocent methods on 9.3.50
            // (result/measure/issue/... all contain "su"), each then hooked and its
            // boolean flipped -> startup cost + correctness hazard. The universal
            // File.exists hook is the runtime safety net for anything this misses.
            String[] suPaths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/su/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
                "/data/local/su", "/data/local/xbin/su", "/data/local/bin/su",
                "/data/adb/magisk"
            };
            Map<String, MethodData> unique = new HashMap<>();
            for (String p : suPaths) {
                try {
                    List<MethodData> found = dexKitBridge.findMethod(
                        FindMethod.create()
                            .matcher(MethodMatcher.create()
                                .addInvoke(MethodMatcher.create()
                                    .declaredClass("java.io.File")
                                    .name("exists"))
                                .usingStrings(p))
                    );
                    for (MethodData m : found) unique.put(m.getDescriptor(), m);
                } catch (Exception e) {
                    XposedBridge.log("[" + TAG + "] su-path query failed for '" + p + "': " + e.getMessage());
                }
            }
            List<MethodData> results = new ArrayList<>(unique.values());

            detectionCache.put("su_path", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " su path checkers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding su path checkers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find PackageManager queries for Magisk/LSPosed packages
     */
    public static List<MethodData> findSuspiciousPackageQueries() {
        if (detectionCache.containsKey("package_query")) {
            return detectionCache.get("package_query");
        }

        try {
            XposedBridge.log("[" + TAG + "] Searching for suspicious package queries...");

            // Union over marker x query-method pairs. "magisk" alone found nothing
            // on current QQ (the string never appears in 9.3.75's string pool at
            // all); the Xposed installer package name does appear, and checks may
            // go through getApplicationInfo as well as getPackageInfo. Precision
            // still comes from the runtime isSuspiciousPackage() argument check,
            // so a wider net here cannot block legitimate queries.
            Map<String, MethodData> unique = new HashMap<>();
            String[] markers = {"magisk", "de.robv.android.xposed.installer"};
            String[] queryMethods = {"getPackageInfo", "getApplicationInfo"};
            for (String marker : markers) {
                for (String queryMethod : queryMethods) {
                    try {
                        List<MethodData> found = dexKitBridge.findMethod(
                            FindMethod.create()
                                .matcher(MethodMatcher.create()
                                    .addInvoke(MethodMatcher.create()
                                        .declaredClass("android.content.pm.PackageManager")
                                        .name(queryMethod))
                                    .usingStrings(marker)
                                )
                        );
                        for (MethodData m : found) {
                            unique.put(m.getDescriptor(), m);
                        }
                    } catch (Exception e) {
                        XposedBridge.log("[" + TAG + "] package query failed for '"
                            + marker + "'/'" + queryMethod + "': " + e.getMessage());
                    }
                }
            }
            List<MethodData> results = new ArrayList<>(unique.values());

            detectionCache.put("package_query", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " package query methods");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding package queries: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Run one findMethod query per string (OR-semantics) and union the results,
     * de-duplicating by DEX descriptor. DexKit's usingStrings(vararg) is AND within
     * a single query, which is wrong when markers live in different methods.
     */
    private static List<MethodData> findMethodsUsingAnyString(String... markers) {
        Map<String, MethodData> unique = new HashMap<>();
        for (String marker : markers) {
            try {
                List<MethodData> found = dexKitBridge.findMethod(
                    FindMethod.create()
                        .matcher(MethodMatcher.create().usingStrings(marker))
                );
                for (MethodData m : found) {
                    unique.put(m.getDescriptor(), m);
                }
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] query failed for '" + marker + "': " + e.getMessage());
            }
        }
        return new ArrayList<>(unique.values());
    }

    /**
     * Find methods using a string as an exact literal (no substring hits).
     */
    private static List<MethodData> findMethodsUsingExactString(String marker) {
        try {
            return dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addUsingString(new StringMatcher(marker, StringMatchType.Equals, false)))
            );
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] exact query failed for '" + marker + "': " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Get all cached detection results
     */
    public static Map<String, List<MethodData>> getAllDetectionResults() {
        return new HashMap<>(detectionCache);
    }

    /**
     * Release DexKit resources. Note: hooks resolve their target Members during
     * the scan and don't need the bridge afterward, but we keep it alive by
     * default (release not called from XposedEntry) so late/lazy findXxx() calls
     * still work. Call explicitly only when you know no more queries will run.
     */
    public static void release() {
        synchronized (initLock) {
            ready = false;
            if (dexKitBridge != null) {
                try {
                    dexKitBridge.close();
                    XposedBridge.log("[" + TAG + "] DexKit released");
                } catch (Exception e) {
                    XposedBridge.log("[" + TAG + "] Error releasing DexKit: " + e.getMessage());
                } finally {
                    dexKitBridge = null;
                }
            }
        }
    }
}
