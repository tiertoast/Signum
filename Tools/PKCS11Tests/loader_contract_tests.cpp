#include "pkcs11.h"
#include <dlfcn.h>
#include <filesystem>
#include <future>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <stdexcept>
#include <unistd.h>
#if __has_feature(address_sanitizer)
#include <sanitizer/asan_interface.h>
#endif
namespace fs = std::filesystem;
static void require(bool condition, const char *message) {
    if (!condition) throw std::runtime_error(message);
}
static void round(const fs::path &module, bool concurrent) {
    void *owner = dlopen(module.c_str(), RTLD_NOW | RTLD_LOCAL);
    require(owner, "Cannot load synthetic module");
    auto get = reinterpret_cast<CK_C_GetFunctionList>(dlsym(owner, "C_GetFunctionList"));
    require(get, "Missing function-list entry point");
    CK_FUNCTION_LIST_PTR api = nullptr;
    require(get(&api) == CKR_OK && api && api->C_Initialize && api->C_Finalize,
            "Invalid live function table");
#if __has_feature(address_sanitizer)
    const auto tableEnd = reinterpret_cast<uintptr_t>(api) + sizeof(*api);
    require(!__asan_region_is_poisoned(api, sizeof(*api)), "Live table is poisoned");
    require(__asan_address_is_poisoned(reinterpret_cast<void *>(tableEnd)),
            "ASAN global redzone is missing while module is live");
#endif
    if (concurrent) {
        std::vector<std::future<void>> uses;
        for (int i = 0; i < 12; ++i) uses.push_back(std::async(std::launch::async, [&] {
            void *handle = dlopen(module.c_str(), RTLD_NOW | RTLD_LOCAL);
            require(handle, "Concurrent load failed");
            auto entry = reinterpret_cast<CK_C_GetFunctionList>(dlsym(handle, "C_GetFunctionList"));
            CK_FUNCTION_LIST_PTR other = nullptr;
            require(entry && entry(&other) == CKR_OK && other == api && other->C_Initialize,
                    "Concurrent handle has wrong table");
            require(dlclose(handle) == 0, "Concurrent release failed");
        }));
        for (auto &use : uses) use.get();
    }
    require(api->C_Initialize && api->C_Finalize, "Owner lost live table");
    require(dlclose(owner) == 0, "Final release failed");
    // Never dereference table/function pointers after close. RTLD_NOLOAD asks
    // the loader about this image; the ASAN query reads shadow, not unmapped data.
    void *remaining = dlopen(module.c_str(), RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
    if (remaining) { dlclose(remaining); throw std::runtime_error("Module still loaded after final release"); }
#if __has_feature(address_sanitizer)
    require(!__asan_address_is_poisoned(reinterpret_cast<void *>(tableEnd)),
            "Unloaded module left a global redzone in ASAN shadow");
#endif
}
int main(int argc, char **argv) {
    fs::path folder;
    try {
        require(argc == 2, "Expected synthetic provider path");
        char pattern[] = "/tmp/signum-loader-contract-XXXXXX";
        const char *temp = mkdtemp(pattern); require(temp, "mkdtemp failed"); folder = temp;
        for (bool concurrent : {false, true}) {
            for (int i = 0; i < 8; ++i) {
                const auto copy = folder / (std::to_string(concurrent) + "-" + std::to_string(i) + ".so");
                fs::copy_file(argv[1], copy); round(copy, concurrent); fs::remove(copy);
            }
            std::printf("PASS %s load/release: 8 rounds, unload verified\n", concurrent ? "concurrent" : "serial");
        }
        fs::remove_all(folder);
        std::puts("2 loader contracts passed; global redzones checked when ASAN is enabled");
        return 0;
    } catch (const std::exception &error) {
        std::fprintf(stderr, "FAIL %s\n", error.what());
        if (!folder.empty()) { std::error_code ignored; fs::remove_all(folder, ignored); }
        return 1;
    }
}
