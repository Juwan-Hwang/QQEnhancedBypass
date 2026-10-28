# Keep Xposed entry point (its name is referenced from assets/xposed_init)
-keep class io.github.xalsace.qqbypass.XposedEntry {
    *;
}

# Keep the whole module package: hook classes are wired up dynamically and
# DexKit / native code refers to classes and members by name at runtime.
# (The previous rules referenced the pre-rename package
#  io.github.qqenhanced.bypass, so R8 shrank the entire module away and the
#  published release APKs shipped with an effectively empty dex.)
-keep class io.github.xalsace.qqbypass.** {
    *;
}

# Don't warn about Xposed API
-dontwarn de.robv.android.xposed.**
