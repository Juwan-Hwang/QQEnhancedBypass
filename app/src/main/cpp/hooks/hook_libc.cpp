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

static void ensure_real_funcs() {
    if (!real_fopen) {
        real_fopen = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen");
    }
    if (!real_fgets) {
        real_fgets = (char* (*)(char*, int, FILE*))dlsym(RTLD_NEXT, "fgets");
    }
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

    LOGI("libc hooks installed");
}

} // namespace hook_libc
