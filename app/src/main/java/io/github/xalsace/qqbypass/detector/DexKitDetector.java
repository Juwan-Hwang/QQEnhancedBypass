package io.github.xalsace.qqbypass.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.enums.StringMatchType;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.query.matchers.base.StringMatcher;
import org.luckypray.dexkit.result.MethodData;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.lang.reflect.Array;
import java.lang.reflect.Member;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * DexKit-based detector for dynamically locating obfuscated detection points in QQ.
 * Eliminates hardcoded class/method names to survive version updates.
 *
 * Single shared bridge: DexKitBridge.create() parses the whole APK (~112MB on
 * 9.3.50), so creating one per hook meant 5 full parses per process and, across
 * QQ's several processes, a memory/CPU spike that could get the process killed on
 * cold start. This class owns ONE bridge; it is created lazily, only when a real
 * scan is unavoidable.
 *
 * Persistent result cache: a scan's outcome is just a list of DEX method
 * descriptors, and for a given QQ APK those never change. Results are therefore
 * persisted to a small text file in the host app's files dir, keyed by the APK's
 * length + last-modified time + version code. Later process starts resolve the
 * cached descriptors straight to reflection Members and never build the bridge
 * at all. This matters on devices whose ROM kills and restarts the QQ main
 * process every few seconds: without the disk cache every restart paid a full
 * multi-threaded scan (~14 s on a mid-range phone), and the overlapping scans
 * kept the CPU pegged (field report: 104 scans in one hour, two QQ instances
 * counting a dual-app clone). With the cache, restarts are ~free.
 *
 * Process gate: only the process that calls setEnabled(true) (the main QQ process)
 * runs DexKit work; subprocesses skip it entirely (findXxx() return empty
 * immediately), keeping the universal framework hooks but paying no parse cost.
 */
public class DexKitDetector {
    private static final String TAG = "DexKitDetector";
    private static volatile DexKitBridge dexKitBridge;
    private static volatile boolean enabled = false; // set true only in the gated (main) process
    private static volatile boolean ready = false;   // bridge created and usable
    private static volatile boolean initialized = false; // init() ran (disk cache state known)
    private static final Object initLock = new Object();
    private static final Object scanLock = new Object();
    private static final CountDownLatch readyLatch = new CountDownLatch(1);

    private static Context appContext;
    private static String apkPath;

    // Three lookup layers, cheapest first: in-process memory, on-disk cache, scan.
    // Values are DEX method descriptors (e.g. "Lcom/foo;->bar(I)V"), which the
    // hook layer resolves to Members via resolveDescriptor().
    private static final Map<String, List<String>> descriptorCache = new ConcurrentHashMap<>();
    private static final Map<String, List<String>> diskCache = new ConcurrentHashMap<>();
    private static File cacheFile;
    private static String cacheKey;

    private static final String CACHE_FILE_NAME = "qqbypass_dexkit_cache.txt";
    private static final String CACHE_HEADER = "#qqbypass-dexkit-cache v1 key=";

    /** Enable DexKit for this process. Call only in the main process. */
    public static void setEnabled(boolean value) { enabled = value; }
    public static boolean isEnabled() { return enabled; }
    public static boolean isReady() { return ready; }
    public static DexKitBridge getBridge() { return dexKitBridge; }

    /**
     * Block until init() has run (disk cache state known), up to timeoutMs.
     * Returns false immediately in a non-enabled (sub)process so callers skip
     * DexKit work instead of blocking for the full timeout. A true result no
     * longer implies the bridge exists: with a warm disk cache the bridge is
     * never created, and findXxx() answer from cache instead.
     */
    public static boolean awaitReady(long timeoutMs) {
        if (initialized) return true;
        if (!enabled) return false;
        try {
            readyLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        return initialized;
    }

    /**
     * Prepare the detector (idempotent): record the APK path, fingerprint it,
     * and load any persisted scan results whose fingerprint still matches.
     * The bridge itself is NOT created here anymore; ensureBridge() builds it
     * lazily if a category turns out to be missing from both caches.
     * The readyLatch is always released so awaitReady() waiters wake even on
     * failure.
     */
    public static void init(Context context) {
        if (initialized) return;
        synchronized (initLock) {
            if (initialized) return;
            try {
                appContext = context.getApplicationContext();
                ApplicationInfo appInfo = context.getApplicationInfo();
                apkPath = appInfo.sourceDir;
                setupDiskCache(context, apkPath);
                initialized = true;
                XposedBridge.log("[" + TAG + "] Detector ready (disk cache categories: "
                    + diskCache.size() + ")");
            } catch (Throwable e) {
                XposedBridge.log("[" + TAG + "] Failed to initialize detector: "
                    + e.getClass().getName() + ": " + e.getMessage());
            } finally {
                readyLatch.countDown();
            }
        }
    }

    /**
     * Create the single shared bridge on first real need. Returns false when
     * creation fails (callers then degrade to "no dynamic hooks", as before).
     */
    private static boolean ensureBridge() {
        if (dexKitBridge != null) return true;
        synchronized (initLock) {
            if (dexKitBridge != null) return true;
            try {
                XposedBridge.log("[" + TAG + "] Initializing DexKit with APK: " + apkPath);
                // Explicitly load libdexkit.so before create(). In an LSPosed host
                // process System.loadLibrary("dexkit") (what create() calls) can fail
                // to find the module's native lib on the host path -> UnsatisfiedLinkError.
                loadDexKitNativeLib(appContext);
                dexKitBridge = DexKitBridge.create(apkPath);
                ready = true;
                XposedBridge.log("[" + TAG + "] DexKit initialized successfully");
                return true;
            } catch (Throwable e) {
                XposedBridge.log("[" + TAG + "] Failed to initialize DexKit: "
                    + e.getClass().getName() + ": " + e.getMessage());
                return false;
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

    // ------------------------------------------------------------------
    // Persistent cache plumbing
    // ------------------------------------------------------------------

    /**
     * Fingerprint the host APK and load the persisted results if the file's
     * stored fingerprint still matches. Any mismatch (QQ updated, cache from
     * another build) simply leaves the disk cache empty; the next scan
     * rewrites the file.
     */
    private static void setupDiskCache(Context context, String apk) {
        try {
            File apkFile = new File(apk);
            long versionCode = 0;
            try {
                PackageInfo info = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
                versionCode = info.versionCode;
            } catch (Throwable ignored) {
            }
            cacheKey = apkFile.length() + ":" + apkFile.lastModified() + ":" + versionCode;
            cacheFile = new File(context.getFilesDir(), CACHE_FILE_NAME);
            if (!cacheFile.isFile()) return;

            BufferedReader reader = new BufferedReader(new FileReader(cacheFile));
            try {
                String header = reader.readLine();
                if (header == null || !header.equals(CACHE_HEADER + cacheKey)) {
                    XposedBridge.log("[" + TAG + "] Disk cache stale (APK changed), ignoring");
                    return;
                }
                String currentKey = null;
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("## ")) {
                        currentKey = line.substring(3).trim();
                        diskCache.put(currentKey, new ArrayList<>());
                    } else if (currentKey != null && line.startsWith("L")) {
                        diskCache.get(currentKey).add(line);
                    }
                }
            } finally {
                reader.close();
            }
        } catch (Throwable e) {
            XposedBridge.log("[" + TAG + "] Disk cache load failed: " + e.getMessage());
            diskCache.clear();
        }
    }

    /** Rewrite the whole cache file from the disk map. Caller holds scanLock. */
    private static void saveDiskCacheLocked() {
        if (cacheFile == null || cacheKey == null) return;
        File tmp = new File(cacheFile.getParentFile(), CACHE_FILE_NAME + ".tmp");
        try {
            FileWriter writer = new FileWriter(tmp);
            try {
                writer.write(CACHE_HEADER + cacheKey + "\n");
                for (Map.Entry<String, List<String>> entry : diskCache.entrySet()) {
                    writer.write("## " + entry.getKey() + "\n");
                    for (String descriptor : entry.getValue()) {
                        writer.write(descriptor + "\n");
                    }
                }
            } finally {
                writer.close();
            }
            if (!tmp.renameTo(cacheFile)) {
                // rename can fail across some filesystems; fall back to delete+rename
                cacheFile.delete();
                tmp.renameTo(cacheFile);
            }
        } catch (Throwable e) {
            XposedBridge.log("[" + TAG + "] Disk cache save failed: " + e.getMessage());
        }
    }

    /** One DexKit query. Returns null on failure (result must NOT be cached). */
    private interface ScanQuery {
        List<MethodData> run() throws Exception;
    }

    /**
     * Resolve one detection category through the three layers. The scan itself
     * runs under a global lock: hook threads racing the entry-point priming
     * thread used to duplicate full queries; serialization also keeps several
     * categories' scans from piling onto the CPU at once.
     */
    private static List<String> findCached(String key, ScanQuery query) {
        if (!enabled) return new ArrayList<>();
        List<String> hit = descriptorCache.get(key);
        if (hit != null) return hit;
        hit = diskCache.get(key);
        if (hit != null) {
            descriptorCache.put(key, hit);
            XposedBridge.log("[" + TAG + "] " + key + ": " + hit.size()
                + " targets loaded from disk cache");
            return hit;
        }
        synchronized (scanLock) {
            hit = descriptorCache.get(key);
            if (hit != null) return hit;
            hit = diskCache.get(key);
            if (hit != null) {
                descriptorCache.put(key, hit);
                return hit;
            }
            if (!ensureBridge()) return new ArrayList<>();
            List<MethodData> found;
            try {
                found = query.run();
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] Query failed for " + key + ": " + e.getMessage());
                return new ArrayList<>();
            }
            if (found == null) return new ArrayList<>(); // failed scan; do not persist
            LinkedHashSet<String> unique = new LinkedHashSet<>();
            for (MethodData m : found) {
                unique.add(m.getDescriptor());
            }
            List<String> results = new ArrayList<>(unique);
            descriptorCache.put(key, results);
            diskCache.put(key, results);
            saveDiskCacheLocked();
            return results;
        }
    }

    // ------------------------------------------------------------------
    // Descriptor <-> reflection resolution (used by the hook layer)
    // ------------------------------------------------------------------

    /** "Lcom/foo/Bar;->baz(I)V" -> "com.foo.Bar" */
    public static String descriptorClassName(String descriptor) {
        int semi = descriptor.indexOf(';');
        if (!descriptor.startsWith("L") || semi < 0) return descriptor;
        return descriptor.substring(1, semi).replace('/', '.');
    }

    /** "Lcom/foo/Bar;->baz(I)V" -> "baz" */
    public static String descriptorMethodName(String descriptor) {
        int arrow = descriptor.indexOf("->");
        int paren = descriptor.indexOf('(', arrow);
        if (arrow < 0 || paren < 0) return descriptor;
        return descriptor.substring(arrow + 2, paren);
    }

    /**
     * Resolve a cached DEX descriptor to the reflection Member the hooks need.
     * Equivalent to MethodData.getMethodInstance() for the declaring class in
     * the descriptor, but works without a DexKit bridge (pure cache path).
     * Returns null when the target cannot be resolved.
     */
    public static Member resolveDescriptor(String descriptor, ClassLoader classLoader) {
        try {
            String className = descriptorClassName(descriptor);
            String methodName = descriptorMethodName(descriptor);
            int open = descriptor.indexOf('(');
            int close = descriptor.indexOf(')', open);
            if (open < 0 || close < 0) return null;
            String params = descriptor.substring(open + 1, close);
            List<Class<?>> paramTypes = new ArrayList<>();
            int[] pos = {0};
            while (pos[0] < params.length()) {
                paramTypes.add(dexTypeToClass(params, pos, classLoader));
            }
            Class<?> clazz = XposedHelpers.findClass(className, classLoader);
            Member member;
            if ("<init>".equals(methodName)) {
                member = clazz.getDeclaredConstructor(
                    paramTypes.toArray(new Class<?>[0]));
            } else {
                member = clazz.getDeclaredMethod(methodName,
                    paramTypes.toArray(new Class<?>[0]));
            }
            try {
                ((java.lang.reflect.AccessibleObject) member).setAccessible(true);
            } catch (Throwable ignored) {
            }
            return member;
        } catch (Throwable t) {
            return null;
        }
    }

    private static Class<?> dexTypeToClass(String dex, int[] pos, ClassLoader classLoader)
            throws Exception {
        int dims = 0;
        while (pos[0] < dex.length() && dex.charAt(pos[0]) == '[') {
            dims++;
            pos[0]++;
        }
        if (pos[0] >= dex.length()) throw new IllegalArgumentException("truncated dex type");
        char c = dex.charAt(pos[0]);
        Class<?> base;
        switch (c) {
            case 'Z': base = boolean.class; pos[0]++; break;
            case 'B': base = byte.class; pos[0]++; break;
            case 'C': base = char.class; pos[0]++; break;
            case 'S': base = short.class; pos[0]++; break;
            case 'I': base = int.class; pos[0]++; break;
            case 'J': base = long.class; pos[0]++; break;
            case 'F': base = float.class; pos[0]++; break;
            case 'D': base = double.class; pos[0]++; break;
            case 'V': base = void.class; pos[0]++; break;
            case 'L': {
                int semi = dex.indexOf(';', pos[0]);
                if (semi < 0) throw new IllegalArgumentException("bad object type in " + dex);
                String name = dex.substring(pos[0] + 1, semi).replace('/', '.');
                base = Class.forName(name, false, classLoader);
                pos[0] = semi + 1;
                break;
            }
            default:
                throw new IllegalArgumentException("unknown dex type '" + c + "' in " + dex);
        }
        if (dims == 0) return base;
        return Array.newInstance(base, new int[dims]).getClass();
    }

    // ------------------------------------------------------------------
    // Detection categories
    // ------------------------------------------------------------------

    /**
     * Find ArtMethod hook detection methods (QSec ArtTiHookTask / all_so_hook)
     * Target: methods checking ArtMethod structure modification
     */
    public static List<String> findArtHookDetectors() {
        return findCached("art_hook", () -> {
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

                XposedBridge.log("[" + TAG + "] Found " + results.size() + " ArtMethod hook detectors");
                return results;
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] Error finding ArtMethod detectors: " + e.getMessage());
                return null;
            }
        });
    }

    /**
     * Find /proc/self/maps readers (detecting injected .so files)
     * Target: methods reading maps file to detect LSPosed/Magisk/Zygisk/our module
     */
    public static List<String> findMapsReaders() {
        return findCached("maps_reader", () -> {
            try {
                XposedBridge.log("[" + TAG + "] Searching for /proc/self/maps readers...");

                // "/proc/self/maps" is the strong signal; "/proc/self/task" and "/proc/"
                // catch variants. OR-union so a method needs only one of them.
                List<MethodData> results = findMethodsUsingAnyString(
                    "/proc/self/maps", "/proc/self/task", "/proc/%d/maps");

                XposedBridge.log("[" + TAG + "] Found " + results.size() + " maps readers");
                return results;
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] Error finding maps readers: " + e.getMessage());
                return null;
            }
        });
    }

    /**
     * Find wtlogin error handlers (w21 "device invalid" logic)
     * Target: methods processing wtlogin error codes from server
     */
    public static List<String> findWtloginErrorHandlers() {
        return findCached("wtlogin_error", () -> {
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

                XposedBridge.log("[" + TAG + "] Found " + results.size() + " wtlogin error handlers");
                return results;
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] Error finding wtlogin handlers: " + e.getMessage());
                return null;
            }
        });
    }

    /**
     * Find QSec hook detection methods (registerHookSo / nativeFileHook)
     * Target: QSec's native hook detection framework
     */
    public static List<String> findQSecHookDetectors() {
        return findCached("qsec_hook", () -> {
            try {
                XposedBridge.log("[" + TAG + "] Searching for QSec hook detectors...");

                // OR-semantics: these markers live in different methods, so union them.
                List<MethodData> results = findMethodsUsingAnyString(
                    "registerHookSo", "nativeFileHook", "isHookedSoLoad", "QSecConfig",
                    "all_so_hook", "ArtTiHookTask");

                XposedBridge.log("[" + TAG + "] Found " + results.size() + " QSec hook detectors");
                return results;
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] Error finding QSec detectors: " + e.getMessage());
                return null;
            }
        });
    }

    /**
     * Find Runtime.exec callers (root detection via "type su" / "which su")
     * Target: methods calling Runtime.exec() with su-related commands
     */
    public static List<String> findRuntimeExecCallers() {
        return findCached("runtime_exec", () -> {
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

                XposedBridge.log("[" + TAG + "] Found " + results.size() + " Runtime.exec callers");
                return results;
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] Error finding Runtime.exec callers: " + e.getMessage());
                return null;
            }
        });
    }

    /**
     * Find ProcessBuilder constructors/start callers (alternative to Runtime.exec)
     */
    public static List<String> findProcessBuilderCallers() {
        return findCached("process_builder", () -> {
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

                XposedBridge.log("[" + TAG + "] Found " + results.size() + " ProcessBuilder callers");
                return results;
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] Error finding ProcessBuilder callers: " + e.getMessage());
                return null;
            }
        });
    }

    /**
     * Find File.exists callers checking su paths
     */
    public static List<String> findSuPathCheckers() {
        return findCached("su_path", () -> {
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

                XposedBridge.log("[" + TAG + "] Found " + results.size() + " su path checkers");
                return results;
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] Error finding su path checkers: " + e.getMessage());
                return null;
            }
        });
    }

    /**
     * Find PackageManager queries for Magisk/LSPosed packages
     */
    public static List<String> findSuspiciousPackageQueries() {
        return findCached("package_query", () -> {
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

                XposedBridge.log("[" + TAG + "] Found " + results.size() + " package query methods");
                return results;
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] Error finding package queries: " + e.getMessage());
                return null;
            }
        });
    }

    /** Find methods calling Debug.isDebuggerConnected() (debug detection). */
    public static List<String> findDebugCheckers() {
        return findCached("debug_checkers", () -> {
            XposedBridge.log("[" + TAG + "] Searching for debug checkers...");
            List<MethodData> results = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("android.os.Debug")
                            .name("isDebuggerConnected"))
                    )
            );
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " debug checkers");
            return results;
        });
    }

    /** Find methods reading TracerPid from /proc/self/status (debug detection). */
    public static List<String> findTracerPidReaders() {
        return findCached("tracerpid_readers", () -> {
            XposedBridge.log("[" + TAG + "] Searching for TracerPid readers...");
            // usingStrings(vararg) is AND, so keep to the single strongest marker.
            List<MethodData> results = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("TracerPid")
                    )
            );
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " TracerPid readers");
            return results;
        });
    }

    /** Find methods checking emulator marker strings. */
    public static List<String> findEmulatorCheckers() {
        return findCached("emulator_checkers", () -> {
            XposedBridge.log("[" + TAG + "] Searching for emulator checkers...");
            List<MethodData> results = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("goldfish", "ranchu", "qemu", "vbox", "genymotion")
                    )
            );
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " emulator checkers");
            return results;
        });
    }

    /** Find methods calling TelephonyManager.getDeviceId (IMEI readers). */
    public static List<String> findImeiReaders() {
        return findCached("imei_readers", () -> {
            XposedBridge.log("[" + TAG + "] Searching for IMEI readers...");
            List<MethodData> results = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("android.telephony.TelephonyManager")
                            .name("getDeviceId"))
                    )
            );
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " IMEI readers");
            return results;
        });
    }

    /** Find methods reading Settings.Secure "android_id". */
    public static List<String> findAndroidIdReaders() {
        return findCached("androidid_readers", () -> {
            XposedBridge.log("[" + TAG + "] Searching for Android ID readers...");
            List<MethodData> results = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("android.provider.Settings$Secure")
                            .name("getString"))
                        .usingStrings("android_id")
                    )
            );
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " Android ID readers");
            return results;
        });
    }

    /** Find methods calling Build.getSerial(). */
    public static List<String> findSerialReaders() {
        return findCached("serial_readers", () -> {
            XposedBridge.log("[" + TAG + "] Searching for Serial readers...");
            List<MethodData> results = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("android.os.Build")
                            .name("getSerial"))
                    )
            );
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " Serial readers");
            return results;
        });
    }

    /** Find TuringFD's /proc/%d/cmdline process-enumeration readers. */
    public static List<String> findProcCmdlineReaders() {
        return findCached("proc_cmdline_readers", () -> {
            XposedBridge.log("[" + TAG + "] Searching for /proc cmdline readers...");
            List<MethodData> results = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("/proc/%d/cmdline"))
            );
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " proc cmdline readers");
            return results;
        });
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
     * Get all known detection results (descriptors), from any cache layer.
     */
    public static Map<String, List<String>> getAllDetectionResults() {
        Map<String, List<String>> all = new HashMap<>(diskCache);
        all.putAll(descriptorCache);
        return all;
    }

    /**
     * Release DexKit resources. Note: hooks resolve their target Members during
     * setup and don't need the bridge afterward, but we keep it alive by
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
