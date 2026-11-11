#include "hook_libc.h"
#include "../utils/log.h"
#include <bytehook.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <atomic>

namespace hook_libc {

// 直接从 libc 取到的真实函数指针（绕过 PLT，避免在辅助函数里再次触发 hook 造成递归）
static FILE* (*real_fopen)(const char*, const char*) = nullptr;
static char* (*real_fgets)(char*, int, FILE*) = nullptr;
static int (*real_memcmp)(const void*, const void*, size_t) = nullptr;
static int (*real_sys_prop_get)(const char*, char*) = nullptr;

static void ensure_real_funcs() {
    if (!real_fopen) {
        real_fopen = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen");
    }
    if (!real_fgets) {
        real_fgets = (char* (*)(char*, int, FILE*))dlsym(RTLD_NEXT, "fgets");
    }
    if (!real_memcmp) {
        real_memcmp = (int (*)(const void*, const void*, size_t))dlsym(RTLD_NEXT, "memcmp");
    }
    if (!real_sys_prop_get) {
        real_sys_prop_get = (int (*)(const char*, char*))dlsym(RTLD_NEXT, "__system_property_get");
    }
}

// 不触发 PLT hook 的本地 strstr（memcmp 代理里用，避免递归）
static const char* local_strstr(const char* hay, const char* needle) {
    if (!hay || !needle || !*needle) return hay;
    for (const char* p = hay; *p; p++) {
        const char* a = p; const char* b = needle;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return p;
    }
    return nullptr;
}

// 构造过滤掉 hook 特征库的 maps 临时文件
static FILE* build_filtered_maps() {
    ensure_real_funcs();
    if (!real_fopen || !real_fgets) return nullptr;

    FILE* real = real_fopen("/proc/self/maps", "r");
    if (!real) return nullptr;

    FILE* fake = tmpfile();
    if (!fake) {
        fclose(real);
        return nullptr;
    }

    char line[512];
    const char* blacklist[] = {
        // Third-party hook/root frameworks
        "lsposed", "xposed", "riru", "zygisk", "edxposed",
        "frida", "substrate", "libDalvikLoader", "libAndroidCydia",
        "magisk", "ksu", "kernelsu", "supersu", "superuser",
        // OUR OWN injection footprint - previously leaked in the "filtered" maps,
        // exposing the module to any /proc/self/maps scan (a self-own).
        "libnative-bypass", "libbytehook", "xalsace", "qq_hook",
        nullptr
    };

    while (real_fgets(line, sizeof(line), real)) {
        bool filter = false;
        for (int i = 0; blacklist[i]; i++) {
            if (strstr(line, blacklist[i])) { filter = true; break; }
        }
        if (!filter) fputs(line, fake);
    }
    fclose(real);
    rewind(fake);
    return fake;
}

// maps 拦截日志采样：读一次 maps 就触发一次，全量打会刷屏，只记每 200 次里的第一次（合并版）
static std::atomic<int> g_maps_intercepts{0};
static void log_maps_intercept(const char* via) {
    if (g_maps_intercepts.fetch_add(1) % 200 == 0) {
        LOGI("Intercepted %s: /proc/self/maps", via);
    }
}

// fopen 代理：重定向 /proc/self/maps
static FILE* fake_fopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();

    if (path && strcmp(path, "/proc/self/maps") == 0) {
        log_maps_intercept("fopen");
        FILE* fake = build_filtered_maps();
        if (fake) return fake;
    }
    // 源自 TCQT：libfekit 的内存完整性检测会读 /proc/self/smaps 找注入痕迹。
    // smaps 与 maps 是不同的 proc 文件，上面的 maps 过滤不覆盖它，直接喂空。
    if (path && strcmp(path, "/proc/self/smaps") == 0) {
        LOGI("Intercepted fopen: /proc/self/smaps -> /dev/null");
        FILE* devnull = real_fopen ? real_fopen("/dev/null", mode)
                                   : BYTEHOOK_CALL_PREV(fake_fopen, "/dev/null", mode);
        if (devnull) return devnull;
    }
    // 源自 OpenShamrock clover.cpp：挡模拟器特征文件与 dobby 注入库探测。
    // 真机(9.3.75)上这些路径本就不存在，返回 nullptr 不改变正常行为；仅对
    // 跑在模拟器/用 dobby 做二次检测的环境有意义。
    if (path) {
        static const char* emu_or_hook_files[] = {
            "libhoudini.so", "libndk_translation", "libnb.so",
            "libnoxd.so", "libnoxspeedup.so", "nox-prop", "nox-vbox-sf", "noxd",
            "qemu_pipe", "libdobby.so", "libwhale.so", nullptr
        };
        for (int i = 0; emu_or_hook_files[i]; i++) {
            if (strstr(path, emu_or_hook_files[i])) {
                LOGD("Blocked emu/hook file fopen: %s", path);
                return nullptr;
            }
        }
    }
    return BYTEHOOK_CALL_PREV(fake_fopen, path, mode);
}

// openat 代理（合并版新增）：Android 16 上文件访问主要走 openat，只钩 fopen 会漏掉这条路。
// /proc/self/maps 换成过滤后的内容；access 藏掉的那批路径在这里同样按不存在处理。
static int fake_openat(int dirfd, const char* pathname, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();

    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    if (pathname && strcmp(pathname, "/proc/self/maps") == 0) {
        log_maps_intercept("openat");
        FILE* fake = build_filtered_maps();
        // 返回过滤文件的 fd；FILE 本体故意不释放（调用方只拿 fd，close 时 fd 关闭即可，
        // 每读一次 maps 漏一个小 FILE 结构，可接受）
        if (fake) return fileno(fake);
    }
    if (pathname) {
        const char* hidden[] = {
            "/data/local/tmp/frida", "re.frida.server", "/system/xposed",
            "/data/adb/lsposed", "/data/adb/modules/lsposed", "/data/adb/magisk", nullptr
        };
        for (int i = 0; hidden[i]; i++) {
            if (strstr(pathname, hidden[i])) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    return BYTEHOOK_CALL_PREV(fake_openat, dirfd, pathname, flags, mode);
}

// memcmp 代理：源自 OpenShamrock clover.cpp。
// QQ 底层会用 memcmp 在广播/缓冲区里逐字节比对查找模块特征串；当比对双方都带有
// 模块命名特征时，返回"不相等"，让这种底层扫描查不到自己。其它所有调用透传。
static int fake_memcmp(const void* lhs, const void* rhs, size_t n) {
    BYTEHOOK_STACK_SCOPE();
    if (!real_memcmp) ensure_real_funcs();
    if (lhs == nullptr || rhs == nullptr) {
        return real_memcmp ? real_memcmp(lhs, rhs, n) : BYTEHOOK_CALL_PREV(fake_memcmp, lhs, rhs, n);
    }
    static const char* footprints[] = { "xalsace", "qqbypass", "lsposed", "xposed", "zygisk", nullptr };
    for (int i = 0; footprints[i]; i++) {
        if (local_strstr((const char*)rhs, footprints[i]) && local_strstr((const char*)lhs, footprints[i])) {
            LOGD("memcmp scanning for module footprint, spoof mismatch");
            return -1;
        }
    }
    return real_memcmp ? real_memcmp(lhs, rhs, n) : BYTEHOOK_CALL_PREV(fake_memcmp, lhs, rhs, n);
}

// __system_property_get 代理：源自 OpenShamrock clover.cpp，挡模拟器系统属性。
static int fake_sys_prop_get(const char* name, char* value) {
    BYTEHOOK_STACK_SCOPE();
    if (name && value) {
        static const char* emu_props[] = {
            "ro.kernel.qemu", "ro.kernel.android.qemud", "init.svc.qemud",
            "init.svc.qemu-props", "qemu.hw.mainkeys", "qemu.sf.fake_camera",
            "qemu.sf.lcd_density", "ro.bootmode.unknown", nullptr
        };
        for (int i = 0; emu_props[i]; i++) {
            if (strcmp(name, emu_props[i]) == 0) {
                value[0] = '\0';
                return 0;
            }
        }
    }
    if (!real_sys_prop_get) ensure_real_funcs();
    return real_sys_prop_get ? real_sys_prop_get(name, value)
                             : BYTEHOOK_CALL_PREV(fake_sys_prop_get, name, value);
}

// fgets 代理：伪造 TracerPid 为 0
static char* fake_fgets(char* s, int size, FILE* stream) {
    BYTEHOOK_STACK_SCOPE();

    char* result = BYTEHOOK_CALL_PREV(fake_fgets, s, size, stream);
    if (result && s && strncmp(s, "TracerPid:", 10) == 0) {
        snprintf(s, size, "TracerPid:\t0\n");
    }
    return result;
}

// readlink 代理：隐藏进程真实路径
static ssize_t fake_readlink(const char* path, char* buf, size_t bufsiz) {
    BYTEHOOK_STACK_SCOPE();

    if (path && strcmp(path, "/proc/self/exe") == 0) {
        const char* fake_path = "/system/bin/app_process64";
        size_t len = strlen(fake_path);
        if (len > bufsiz) len = bufsiz;
        memcpy(buf, fake_path, len);
        return (ssize_t)len;
    }
    return BYTEHOOK_CALL_PREV(fake_readlink, path, buf, bufsiz);
}

// access 代理：隐藏可疑文件
static int fake_access(const char* pathname, int mode) {
    BYTEHOOK_STACK_SCOPE();

    if (pathname) {
        const char* hidden[] = {
            "/data/local/tmp/frida", "re.frida.server", "/system/xposed",
            "/data/adb/lsposed", "/data/adb/modules/lsposed", "/data/adb/magisk", nullptr
        };
        for (int i = 0; hidden[i]; i++) {
            if (strstr(pathname, hidden[i])) {
                LOGD("Hidden path access: %s", pathname);
                return -1;
            }
        }
    }
    return BYTEHOOK_CALL_PREV(fake_access, pathname, mode);
}

void install_hooks() {
    LOGI("Installing libc hooks (ByteHook)...");
    ensure_real_funcs();

    bytehook_hook_all(nullptr, "fopen", (void*)fake_fopen, nullptr, nullptr);
    bytehook_hook_all(nullptr, "openat", (void*)fake_openat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fgets", (void*)fake_fgets, nullptr, nullptr);
    bytehook_hook_all(nullptr, "readlink", (void*)fake_readlink, nullptr, nullptr);
    bytehook_hook_all(nullptr, "access", (void*)fake_access, nullptr, nullptr);
    // 源自 OpenShamrock：挡广播层 memcmp 扫描 + 模拟器系统属性
    bytehook_hook_all(nullptr, "memcmp", (void*)fake_memcmp, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__system_property_get", (void*)fake_sys_prop_get, nullptr, nullptr);

    LOGI("libc hooks installed");
}

} // namespace hook_libc
