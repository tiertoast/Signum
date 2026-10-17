#pragma once
#include "PAdESVerification.h"
#include <functional>
#include <sys/stat.h>
namespace signum {
// Native counterpart of SignumFileOutput for the standalone helper. It never
// hands a writable pathname to PoDoFo. No runtime/CLI fault-injection switches.
struct OutputOperations {
    std::function<ssize_t(int, const void*, size_t)> write;
    std::function<int(int)> sync;
    std::function<int(int)> close;
    OutputOperations();
};
class TransactionalOutput {
public:
    explicit TransactionalOutput(const std::string& destination, OutputOperations operations = {});
    ~TransactionalOutput();
    TransactionalOutput(const TransactionalOutput&) = delete;
    TransactionalOutput& operator=(const TransactionalOutput&) = delete;
    void write(const Bytes& bytes);
    void verifyAndPublish(const Bytes& source, const std::string& expectedCertificate);
private:
    int parent = -1, stage = -1, file = -1;
    std::string directoryName, destinationName;
    struct stat directoryIdentity{}, fileIdentity{};
    bool haveDirectory = false, haveFile = false, written = false;
    OutputOperations ops;
    void cleanup() noexcept;
};
}
