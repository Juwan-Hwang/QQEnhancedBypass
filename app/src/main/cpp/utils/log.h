#ifndef NATIVE_BYPASS_LOG_H
#define NATIVE_BYPASS_LOG_H

#include <android/log.h>

#define TAG "QQNativeBypass"

// LOGD 仅在 debug 构建输出。release(NDEBUG) 下编译为空，避免把注入痕迹刷进
// logcat（memcmp/maps 等代理会被高频调用，debug 日志会刷屏且泄露自身）。
#ifdef NDEBUG
#define LOGD(...) ((void)0)
#else
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#endif
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#endif // NATIVE_BYPASS_LOG_H
