#ifndef NATIVE_BYPASS_HOOK_LIBC_H
#define NATIVE_BYPASS_HOOK_LIBC_H

namespace hook_libc {

/**
 * Hook libc functions to intercept file I/O and low-level probes
 * - fopen: redirect /proc/self/maps (filtered), /proc/self/smaps (-> /dev/null),
 *          block emulator/dobby probe files
 * - fgets: fake TracerPid: 0
 * - readlink: hide /proc/self/exe path
 * - access: hide suspicious files
 * - memcmp: spoof mismatch on module-footprint byte scans (OpenShamrock)
 * - __system_property_get: mask emulator props (OpenShamrock)
 */
void install_hooks();

} // namespace hook_libc

#endif // NATIVE_BYPASS_HOOK_LIBC_H
