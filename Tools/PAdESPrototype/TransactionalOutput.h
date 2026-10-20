#pragma once
#include "PAdESVerification.h"
#include "output_permissions.h"
#include <functional>
#include <optional>
#include <sys/stat.h>
namespace signum {
// Native counterpart of SignumFileOutput for the standalone helper. It never
// hands a writable pathname to PoDoFo. No runtime/CLI fault-injection switches.
struct OutputDirectoryIdentity { int64_t device; uint64_t inode; };
struct OutputOperations {
    std::function<int(const char*)> openParent;
    std::function<int(int, struct stat*)> identifyParent;
    std::function<void()> beforePublish, afterPublish;
    std::function<ssize_t(int, const void*, size_t)> write;
    std::function<int(int)> sync;
    std::function<int(int)> close;
    std::function<int(int, mode_t)> harden;
    std::function<int(int, acl_t)> applyACL;
    OutputOperations();
};
class TransactionalOutput {
public:
    explicit TransactionalOutput(const std::string& destination, OutputOperations operations = {}, std::optional<OutputDirectoryIdentity> expected = std::nullopt);
    ~TransactionalOutput();
    TransactionalOutput(const TransactionalOutput&) = delete;
    TransactionalOutput& operator=(const TransactionalOutput&) = delete;
    void write(const Bytes& bytes);
    void verifyAndPublish(const Bytes& source, const std::string& expectedCertificate);
private:
    std::string parentPath;
    std::optional<OutputDirectoryIdentity> expectedDirectory;
    void requireApprovedPath();
    int parent = -1, stage = -1, file = -1;
    std::string directoryName, destinationName;
    struct stat directoryIdentity{}, fileIdentity{};
    bool haveDirectory = false, haveFile = false, written = false;
    acl_t finalACL = nullptr;
    OutputOperations ops;
    void cleanup() noexcept;
};
}
