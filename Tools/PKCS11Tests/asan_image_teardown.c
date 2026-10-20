// Test infrastructure only: the native mock is repeatedly unloaded/reloaded.
// Apple Clang emits its ASAN image destructor in legacy __mod_term_func, which
// modern dyld may not run. Leftover global redzones then poison a later image.
// A C frontend destructor is registered via __cxa_atexit and runs at dlclose.
// Delegate to ASAN's *same* image flag/function: it retires image globals and
// clears their shadow once, including if a loader also runs the legacy dtor.
// Keep this separate from mock_provider.c: an extern-only TU contributes no
// instrumented globals of its own. No checking/unload is disabled or bypassed.
#include <stdint.h>
#if defined(__APPLE__) && __has_feature(address_sanitizer)
// LLVM's Mach-O ASAN image ABI (default global dead stripping). An incompatible
// compiler/runtime must fail the link or loader contract test, never silently
// lose global checks. See docs/SIGNUM_0.4_C1_ASAN_GATE.md.
extern uintptr_t ___asan_globals_registered;
extern void __asan_unregister_image_globals(uintptr_t *);
__attribute__((destructor)) static void signum_test_unregister_asan_image(void) {
    __asan_unregister_image_globals(&___asan_globals_registered);
}
#endif
