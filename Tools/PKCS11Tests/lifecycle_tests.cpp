#include "SignumPKCS11.h"
#include "mock_provider.h"
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
extern char** environ;
namespace fs = std::filesystem;
static int passed;
static void require(bool value, const std::string& why) { if (!value) throw std::runtime_error(why); }
static void test(const char* name, const std::function<void()>& body) { body(); ++passed; std::cout << "PASS " << name << '\n'; }
using Context = std::unique_ptr<SGContext, decltype(&sg_close)>;
struct Provider {
    fs::path folder, path;
    void* library = nullptr;
    void (*statsFn)(MockStats*);
    void (*fault)(int, CK_RV);
    void (*preinitialized)(int);
    void (*sharedLogin)(int);
    void (*alwaysAuth)(int);
    void (*delay)(unsigned);
    void (*block)(int);
    int (*waitBlocked)();
    void (*release)();
    template<typename T> T symbol(const char* name) { auto fn = reinterpret_cast<T>(dlsym(library, name)); require(fn, std::string("Missing mock control ") + name); return fn; }
    explicit Provider(const fs::path& source) {
        char pattern[] = "/tmp/signum-provider-XXXXXX"; auto temp = mkdtemp(pattern); require(temp, "mkdtemp"); folder = temp;
        path = folder / "provider.so"; fs::copy_file(source, path);
        library = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL); require(library, "Cannot load test provider");
        statsFn = symbol<decltype(statsFn)>("mock_stats"); fault = symbol<decltype(fault)>("mock_fail");
        preinitialized = symbol<decltype(preinitialized)>("mock_preinitialized"); sharedLogin = symbol<decltype(sharedLogin)>("mock_shared_login");
        alwaysAuth = symbol<decltype(alwaysAuth)>("mock_always_authenticate"); delay = symbol<decltype(delay)>("mock_delay");
        block = symbol<decltype(block)>("mock_block"); waitBlocked = symbol<decltype(waitBlocked)>("mock_wait_blocked"); release = symbol<decltype(release)>("mock_release");
    }
    ~Provider() { dlclose(library); std::error_code error; fs::remove_all(folder, error); }
    MockStats stats() { MockStats out{}; statsFn(&out); return out; }
    Context open(fs::path alias = {}) {
        SGContext* ctx = nullptr; char message[512]{};
        int status = sg_open((alias.empty() ? path : alias).c_str(), &ctx, message, sizeof(message));
        require(status == 0 && ctx, message); return Context(ctx, sg_close);
    }
    std::string rejectedOpen() {
        SGContext* ctx = nullptr; char message[512]{};
        require(sg_open(path.c_str(), &ctx, message, sizeof(message)) != 0 && !ctx, "Unsafe provider reopen accepted"); return message;
    }
};
struct SignatureResult { int status; size_t length; std::string error; };
static SignatureResult sign(SGContext* ctx, bool encoded = false) {
    const uint8_t id = 0x53, credential = 0xA5, message[] = {0x53,0x47}; // placeholders, never a real PIN/document
    uint8_t signature[8192]; std::memset(signature, 0xFF, sizeof(signature));
    size_t length = 123; char error[512]{};
    int status;
    if (encoded) {
        uint8_t info[51] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
        status = sg_sign_encoded_digest(ctx, 7, &id, 1, &credential, 1, info, sizeof(info), signature, sizeof(signature), &length, error, sizeof(error));
    } else status = sg_sign_test(ctx, 7, &id, 1, &credential, 1, message, sizeof(message), signature, sizeof(signature), &length, error, sizeof(error));
    return {status, length, error};
}
static void tokens(SGContext* ctx) {
    SGToken rows[8]; size_t count = 0, missing = 0; char error[512]{};
    require(sg_tokens(ctx, rows, 8, &count, &missing, error, sizeof(error)) == 0 && count == 1 && missing == 0, error);
}
int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string(argv[2]) == "--child-registry") {
            // Exec starts a separate registry and mock memory image; no real
            // provider or shared hardware is accessed by this boundary test.
            void* handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
            require(handle, "Child mock load failed");
            auto get = reinterpret_cast<void(*)(MockStats*)>(dlsym(handle, "mock_stats"));
            SGContext* ctx = nullptr; char error[512]{};
            require(sg_open(argv[1], &ctx, error, sizeof(error)) == 0, error);
            tokens(ctx); require(sg_close_checked(ctx, error, sizeof(error)) == 0, error);
            MockStats stats{}; get(&stats);
            require(stats.calls[M_INIT] == 1 && stats.calls[M_FINALIZE] == 1, "Child registry ownership failed");
            dlclose(handle); return 0;
        }
        require(argc == 2, "Expected test-only provider library"); const fs::path module = argv[1];
        for (bool reverse : {false, true}) test(reverse ? "two contexts, reverse release" : "two contexts, original release order", [&] {
            Provider p(module); auto first = p.open(), second = p.open();
            require(p.stats().calls[M_INIT] == 1 && p.stats().initialize_flags == CKF_OS_LOCKING_OK, "Initialization not coordinated");
            if (reverse) second.reset(); else first.reset();
            require(p.stats().calls[M_FINALIZE] == 0, "Premature finalization");
            tokens(reverse ? first.get() : second.get());
            if (reverse) first.reset(); else second.reset();
            require(p.stats().calls[M_FINALIZE] == 1 && !p.stats().initialized, "Last owner did not finalize");
        });
        test("canonical symlink/dot and hard-link aliases share ownership", [&] {
            Provider p(module); auto link = p.folder / "symbolic.so", hard = p.folder / "hard.so";
            fs::create_symlink(p.path, link); fs::create_hard_link(p.path, hard); fs::create_directory(p.folder / "sub");
            auto a = p.open(), b = p.open(link), c = p.open(hard), d = p.open(p.folder / "sub/../provider.so");
            require(std::string(sg_canonical_path(b.get())) == fs::canonical(p.path).string() && p.stats().calls[M_INIT] == 1, "Alias created independent owner");
            a.reset(); b.reset(); c.reset(); require(p.stats().calls[M_FINALIZE] == 0, "Alias finalization early");
            d.reset(); require(p.stats().calls[M_FINALIZE] == 1, "Alias finalization missing");
        });
        test("concurrent opens create one owner", [&] {
            Provider p(module); std::vector<Context> contexts; std::vector<std::future<Context>> opens;
            for (int i = 0; i < 12; ++i) opens.push_back(std::async(std::launch::async, [&] { return p.open(); }));
            for (auto& open : opens) contexts.push_back(open.get());
            require(p.stats().calls[M_INIT] == 1, "Multiple concurrent initialization"); contexts.clear();
            require(p.stats().calls[M_FINALIZE] == 1, "Multiple concurrent finalization");
        });
        test("concurrent signing transactions serialize across contexts", [&] {
            Provider p(module); auto a = p.open(), b = p.open(); p.delay(300);
            std::vector<std::future<SignatureResult>> work;
            for (int i = 0; i < 12; ++i) work.push_back(std::async(std::launch::async, [&, i] { return sign(i % 2 ? a.get() : b.get(), i % 3 == 0); }));
            for (auto& job : work) { auto result = job.get(); require(result.status == 0 && result.length == 32, result.error); }
            auto stats = p.stats();
            require(stats.maximum_calls == 1 && stats.maximum_sessions == 1 && stats.sessions == 0, "Provider calls/sessions overlapped");
            require(stats.calls[M_LOGIN_USER] == 12 && stats.calls[M_SIGN] == 12 && stats.calls[M_CLOSE] == 12 && stats.calls[M_LOGOUT] == 0, "Unexpected authentication/cleanup calls");
        });
        test("release another context while a signature is blocked", [&] {
            Provider p(module); auto a = p.open(), b = p.open(); p.block(M_SIGN);
            auto job = std::async(std::launch::async, [&] { return sign(a.get()); });
            bool blocked = p.waitBlocked();
            if (!blocked) { p.release(); (void)job.get(); throw std::runtime_error("Signature barrier not reached"); }
            b.reset(); const auto before = p.stats(); p.release(); const auto result = job.get();
            require(before.calls[M_FINALIZE] == 0 && result.status == 0, "Finalization interrupted live operation");
            a.reset(); require(p.stats().calls[M_FINALIZE] == 1, "Final release failed");
        });
        test("new context waits for an active provider transaction", [&] {
            Provider p(module); auto first = p.open(); p.block(M_SIGN);
            auto operation = std::async(std::launch::async, [&] { return sign(first.get()); });
            if (!p.waitBlocked()) { p.release(); (void)operation.get(); throw std::runtime_error("Missing operation barrier"); }
            std::promise<void> started; auto opening = std::async(std::launch::async, [&] { started.set_value(); return p.open(); });
            started.get_future().wait(); const bool waited = opening.wait_for(std::chrono::milliseconds(25)) == std::future_status::timeout;
            p.release(); auto result = operation.get(); auto second = opening.get();
            require(waited && result.status == 0 && p.stats().calls[M_INIT] == 1, "Attach bypassed active transaction or reinitialized");
        });
        test("exec helper has a separate in-process registry, not a shared process lock", [&] {
            Provider p(module); auto parent = p.open();
            std::string executable = fs::absolute(argv[0]).string(), provider = p.path.string(), flag = "--child-registry";
            char* args[] = {executable.data(), provider.data(), flag.data(), nullptr};
            pid_t child; require(posix_spawn(&child, executable.c_str(), nullptr, nullptr, args, environ) == 0, "Cannot exec registry fixture");
            int status = 0; require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "Child registry failed");
            require(p.stats().calls[M_INIT] == 1 && !p.stats().calls[M_FINALIZE] && p.stats().initialized, "Child affected parent ownership");
            tokens(parent.get());
        });
        for (int phase : {M_INIT, M_FINALIZE}) test(phase == M_INIT ? "blocked initialization does not lock out an independent provider" : "blocked finalization does not lock out an independent provider", [&] {
            Provider slow(module), independent(module);
            Context initial(nullptr, sg_close);
            if (phase == M_FINALIZE) initial = slow.open();
            slow.block(phase);
            auto work = std::async(std::launch::async, [&] {
                if (phase == M_INIT) return slow.open();
                char error[512]{}; require(sg_close_checked(initial.release(), error, sizeof(error)) == 0, error);
                return Context(nullptr, sg_close);
            });
            if (!slow.waitBlocked()) { slow.release(); (void)work.get(); throw std::runtime_error("Lifecycle barrier not reached"); }
            auto other = std::async(std::launch::async, [&] { return independent.open(); });
            const bool ready = other.wait_for(std::chrono::seconds(1)) == std::future_status::ready;
            slow.release(); auto slowContext = work.get(); auto otherContext = other.get();
            require(ready, "Vendor lifecycle call held the global registry mutex");
            tokens(otherContext.get());
        });
        test("same-provider reinitialization waits for last finalization", [&] {
            Provider p(module); auto first = p.open(); p.block(M_FINALIZE);
            auto closing = std::async(std::launch::async, [&] { char error[512]{}; return sg_close_checked(first.release(), error, sizeof(error)); });
            if (!p.waitBlocked()) { p.release(); (void)closing.get(); throw std::runtime_error("Finalize barrier not reached"); }
            std::promise<void> started;
            auto opening = std::async(std::launch::async, [&] { started.set_value(); return p.open(); });
            started.get_future().wait(); bool waited = opening.wait_for(std::chrono::milliseconds(25)) == std::future_status::timeout;
            const auto before = p.stats(); p.release(); auto result = closing.get(); auto fresh = opening.get();
            require(waited && before.calls[M_INIT] == 1 && result == 0 && p.stats().calls[M_INIT] == 2, "Reinitialize raced finalization");
            tokens(fresh.get());
        });
        test("externally initialized provider is neither finalized nor reinitialized at ref zero", [&] {
            Provider p(module); p.preinitialized(1); { auto a = p.open(), b = p.open(); tokens(a.get()); }
            require(p.stats().calls[M_INIT] == 1 && p.stats().calls[M_FINALIZE] == 0 && p.stats().initialized, "External initialization stolen");
            { auto again = p.open(); tokens(again.get()); }
            require(p.stats().calls[M_INIT] == 1 && p.stats().calls[M_FINALIZE] == 0, "External initialization modified on reattach");
        });
        test("owned provider can be loaded again after clean last release", [&] {
            Provider p(module); { auto a = p.open(); } { auto b = p.open(); tokens(b.get()); }
            require(p.stats().calls[M_INIT] == 2 && p.stats().calls[M_FINALIZE] == 2, "Clean provider not reusable");
        });
        test("initialization error never grants ownership or triggers finalize/retry", [&] {
            Provider p(module); p.fault(M_INIT, CKR_CANT_LOCK); auto error = p.rejectedOpen();
            require(error.find("C_Initialize") != std::string::npos && p.stats().calls[M_INIT] == 1 && p.stats().calls[M_FINALIZE] == 0, "Initialization retried/finalized");
        });
        test("finalize error quarantines and pins provider without retry", [&] {
            Provider p(module); auto a = p.open(); p.fault(M_FINALIZE, CKR_GENERAL_ERROR); char error[512]{};
            require(sg_close_checked(a.release(), error, sizeof(error)) != 0 && std::strstr(error, "C_Finalize"), "Finalize error ignored");
            p.rejectedOpen(); require(p.stats().calls[M_INIT] == 1 && p.stats().calls[M_FINALIZE] == 1, "Finalize/init retried after uncertain finalization");
        });
        for (bool encoded : {false, true}) {
            test(encoded ? "raw digest signing mechanism and one authentication" : "CAdES signing mechanism and one authentication", [&] {
                Provider p(module); auto a = p.open(); auto result = sign(a.get(), encoded); auto stats = p.stats();
                require(result.status == 0 && stats.last_mechanism == (encoded ? CKM_RSA_PKCS : CKM_SHA256_RSA_PKCS) && stats.calls[M_LOGIN_USER] == 1 && stats.calls[M_LOGOUT] == 0, "Signature flow changed");
            });
            for (CK_RV rv : {CKR_PIN_INCORRECT, CKR_PIN_LOCKED}) test("authentication failure is never retried", [&] {
                Provider p(module); auto a = p.open(); p.fault(M_LOGIN_USER, rv); auto result = sign(a.get(), encoded); auto stats = p.stats();
                require(result.status != 0 && result.length == 0 && stats.calls[M_LOGIN_USER] == 1 && !stats.calls[M_SIGN] && stats.calls[M_CLOSE] == 1 && !stats.sessions && !stats.calls[M_LOGOUT], "PIN error retried or session leaked");
            });
        }
        test("shared authenticated session is refused without login/logout or signature", [&] {
            Provider p(module); p.preinitialized(1); p.sharedLogin(1); auto a = p.open(); auto result = sign(a.get()); auto stats = p.stats();
            require(result.status != 0 && result.error.find("already authenticated") != std::string::npos && !stats.calls[M_LOGIN_USER] && !stats.calls[M_LOGOUT] && !stats.calls[M_SIGN] && stats.logged_in, "Shared authentication consumed or logged out");
        });
        test("already-logged-in race does not authenticate this request or retry", [&] {
            Provider p(module); auto a = p.open(); p.fault(M_LOGIN_USER, CKR_USER_ALREADY_LOGGED_IN); auto result = sign(a.get(), true);
            require(result.status != 0 && result.length == 0 && p.stats().calls[M_LOGIN_USER] == 1 && !p.stats().calls[M_SIGN] && !p.stats().calls[M_LOGOUT], "Already logged in treated as verified PIN");
        });
        test("always-authenticate requires one context-specific login, not a retry", [&] {
            Provider p(module); auto a = p.open(); p.alwaysAuth(1); require(sign(a.get(), true).status == 0, "Context authentication failed");
            require(p.stats().calls[M_LOGIN_USER] == 1 && p.stats().calls[M_LOGIN_CONTEXT] == 1 && p.stats().calls[M_SIGN] == 1, "Unexpected context authentication count");
        });
        test("context-specific PIN failure is never retried", [&] {
            Provider p(module); auto a = p.open(); p.alwaysAuth(1); p.fault(M_LOGIN_CONTEXT, CKR_PIN_INCORRECT);
            require(sign(a.get()).status != 0 && p.stats().calls[M_LOGIN_CONTEXT] == 1 && !p.stats().calls[M_SIGN] && !p.stats().sessions, "Context PIN retried or session leaked");
        });
        for (int stage : {M_OPEN, M_SESSION_INFO, M_FIND_INIT, M_FIND, M_FIND_FINAL, M_ATTRIBUTE, M_SIGN_INIT, M_SIGN}) test("session pipeline error closes only acquired session", [&] {
            Provider p(module); auto a = p.open(); p.fault(stage, CKR_DEVICE_ERROR); auto result = sign(a.get()); auto stats = p.stats();
            require(result.status != 0 && result.length == 0 && !stats.calls[M_LOGOUT] && stats.sessions == 0, "Pipeline error leaked/authenticated");
            require(stats.calls[M_CLOSE] == unsigned(stage != M_OPEN), "Wrong number of session closes");
            require(stats.calls[M_LOGIN_USER] <= 1 && stats.calls[M_SIGN] <= 1, "Unexpected retry");
        });
        test("close error suppresses signature and quarantines other contexts", [&] {
            Provider p(module); auto a = p.open(), b = p.open(); p.fault(M_CLOSE, CKR_DEVICE_ERROR);
            auto result = sign(a.get()); require(result.status != 0 && result.length == 0 && result.error.find("C_CloseSession") != std::string::npos, "Cleanup error yielded signature");
            const auto count = p.stats().calls[M_OPEN]; require(sign(b.get()).status != 0 && p.stats().calls[M_OPEN] == count, "Quarantined provider reused");
            a.reset(); require(!p.stats().calls[M_FINALIZE], "Quarantine finalized before last owner");
            b.reset(); require(p.stats().calls[M_FINALIZE] == 1 && !p.stats().sessions, "Owned cleanup recovery failed");
            p.fault(M_CLOSE, CKR_OK); { auto fresh = p.open(); require(sign(fresh.get()).status == 0, "Explicit fresh context failed"); }
        });
        test("primary and cleanup errors are both reported", [&] {
            Provider p(module); auto a = p.open(); p.fault(M_LOGIN_USER, CKR_PIN_INCORRECT); p.fault(M_CLOSE, CKR_DEVICE_ERROR);
            auto result = sign(a.get()); require(result.status != 0 && result.error.find("C_Login USER") != std::string::npos && result.error.find("cleanup C_CloseSession") != std::string::npos && !p.stats().calls[M_SIGN], "Primary failure lost");
        });
        test("external owner is not finalized to repair failed session cleanup", [&] {
            Provider p(module); p.preinitialized(1); { auto a = p.open(); p.fault(M_CLOSE, CKR_DEVICE_ERROR); require(sign(a.get(), true).status != 0, "Close failure ignored"); }
            require(!p.stats().calls[M_FINALIZE] && p.stats().initialized, "External provider finalized for cleanup"); p.rejectedOpen();
        });
        test("simulated device removal during signature returns error without retry", [&] {
            Provider p(module); auto a = p.open(), b = p.open(); p.fault(M_SIGN, CKR_DEVICE_REMOVED); auto result = sign(a.get(), true); auto stats = p.stats();
            require(result.status != 0 && result.length == 0 && result.error.find("C_Sign failed") != std::string::npos && result.error.find("cleanup C_CloseSession") != std::string::npos, "Removal not propagated");
            require(stats.calls[M_LOGIN_USER] == 1 && stats.calls[M_SIGN] == 1 && !stats.calls[M_LOGOUT], "Removal retried");
            require(sign(b.get()).status != 0 && p.stats().calls[M_SIGN] == 1, "Stale context reused after removal");
        });
        test("removal before session open never submits a credential", [&] {
            Provider p(module); auto a = p.open(); p.fault(M_OPEN, CKR_DEVICE_REMOVED); require(sign(a.get()).status != 0, "Missing device accepted");
            require(!p.stats().calls[M_LOGIN_USER] && !p.stats().calls[M_CLOSE], "Credential/close used without session");
            p.fault(M_OPEN, CKR_OK); require(sign(a.get()).status == 0, "Fresh manual operation after reinsertion failed");
        });
        for (bool der : {false, true}) test("read-only certificate cleanup failures propagate", [&] {
            Provider p(module); auto a = p.open(); p.fault(M_CLOSE, CKR_DEVICE_ERROR); char error[512]{}; size_t count = 0;
            int rv;
            if (der) { const uint8_t id = 0x53; rv = sg_certificate_der(a.get(), 7, &id, 1, nullptr, 0, &count, error, sizeof(error)); }
            else { SGCertificate certificate[2]; rv = sg_certificates(a.get(), 7, certificate, 2, &count, error, sizeof(error)); }
            require(rv != 0 && std::strstr(error, "C_CloseSession"), "Read cleanup failure lost");
        });
        std::cout << passed << " provider cases passed; synthetic credentials only, no physical token\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL after " << passed << ": " << error.what() << '\n'; return 1; }
}
