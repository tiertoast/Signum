#include "TransactionalOutput.h"
#include <filesystem>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <stdexcept>
#include <sys/file.h>
#include <unistd.h>
#include <uuid/uuid.h>
namespace signum {
namespace {
constexpr const char* prefix = ".signum-pades-staging-";
constexpr const char* payload = "output.pdf";
void check(bool condition, const char* operation) {
    if (!condition) throw std::runtime_error(std::string(operation) + " (errno " + std::to_string(errno) + ")");
}
bool same(int directory, const std::string& name, const struct stat& expected) {
    struct stat current{};
    return fstatat(directory, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) == 0 &&
           current.st_dev == expected.st_dev && current.st_ino == expected.st_ino;
}
bool knownLayout(int fd) {
    const int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (scan < 0) return false;
    DIR* directory = fdopendir(scan);
    if (!directory) { close(scan); return false; }
    bool known = true;
    while (true) {
        errno = 0;
        auto entry = readdir(directory);
        if (!entry) { if (errno) known = false; break; }
        const std::string name = entry->d_name;
        if (name != "." && name != ".." && name != payload) { known = false; break; }
    }
    closedir(directory);
    return known;
}
void recover(int parent) {
    const int scan = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (scan < 0) return;
    DIR* directory = fdopendir(scan);
    if (!directory) { close(scan); return; }
    while (auto entry = readdir(directory)) {
        const std::string name = entry->d_name;
        uuid_t parsed{};
        const size_t prefixLength = std::strlen(prefix);
        if (name.compare(0, prefixLength, prefix) != 0 || uuid_parse(name.c_str() + prefixLength, parsed) != 0) continue;
        const int stage = openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (stage < 0) continue;
        struct stat info{};
        if (fstat(stage, &info) == 0 && info.st_uid == getuid() && (info.st_mode & 0777) == 0700 &&
            flock(stage, LOCK_EX | LOCK_NB) == 0 && knownLayout(stage)) {
            struct stat data{};
            if (fstatat(stage, payload, &data, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(data.st_mode) &&
                data.st_uid == getuid() && (data.st_mode & 0777) == 0600 && data.st_nlink == 1 && same(stage, payload, data))
                unlinkat(stage, payload, 0);
            if (same(parent, name, info)) unlinkat(parent, name.c_str(), AT_REMOVEDIR);
        }
        close(stage);
    }
    closedir(directory);
}
}
OutputOperations::OutputOperations() :
    write([](int fd, const void* p, size_t n) { return ::write(fd, p, n); }),
    sync([](int fd) { return fsync(fd); }), close([](int fd) { return ::close(fd); }) {}
TransactionalOutput::TransactionalOutput(const std::string& destination, OutputOperations operations) : ops(std::move(operations)) {
    try {
        const std::filesystem::path path(destination);
        destinationName = path.filename().string();
        check(!destinationName.empty() && destinationName != "." && destinationName != "..", "Invalid destination");
        auto folder = path.parent_path();
        if (folder.empty()) folder = ".";
        parent = open(folder.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(parent >= 0, "Cannot open destination folder");
        recover(parent);
        struct stat existing{};
        const int exists = fstatat(parent, destinationName.c_str(), &existing, AT_SYMLINK_NOFOLLOW);
        check(exists < 0 && errno == ENOENT, "Destination exists or cannot be inspected");
        uuid_t uuid; char text[37]; uuid_generate_random(uuid); uuid_unparse_lower(uuid, text);
        directoryName = std::string(prefix) + text;
        check(mkdirat(parent, directoryName.c_str(), 0700) == 0, "Cannot create private staging");
        stage = openat(parent, directoryName.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        check(stage >= 0 && fstat(stage, &directoryIdentity) == 0, "Cannot identify private staging");
        haveDirectory = true;
        check(flock(stage, LOCK_EX | LOCK_NB) == 0, "Cannot lock private staging");
        file = openat(stage, payload, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        check(file >= 0 && fstat(file, &fileIdentity) == 0, "Cannot create staged PDF");
        haveFile = true;
    } catch (...) { cleanup(); throw; }
}
void TransactionalOutput::cleanup() noexcept {
    if (haveFile && same(stage, payload, fileIdentity)) unlinkat(stage, payload, 0);
    if (file >= 0) ::close(file);
    if (haveDirectory && same(parent, directoryName, directoryIdentity)) unlinkat(parent, directoryName.c_str(), AT_REMOVEDIR);
    if (stage >= 0) ::close(stage);
    if (parent >= 0) ::close(parent);
    file = stage = parent = -1;
}
TransactionalOutput::~TransactionalOutput() { cleanup(); }
void TransactionalOutput::write(const Bytes& bytes) {
    check(!written && !bytes.empty() && bytes.size() <= maxOutput, "Invalid staged PDF size/state");
    size_t offset = 0;
    while (offset < bytes.size()) {
        const auto n = ops.write(file, bytes.data() + offset, bytes.size() - offset);
        if (n < 0 && errno == EINTR) continue;
        check(n > 0 && static_cast<size_t>(n) <= bytes.size() - offset, "PDF write failed");
        offset += static_cast<size_t>(n);
    }
    check(ops.sync(file) == 0, "PDF fsync failed");
    written = true;
}
void TransactionalOutput::verifyAndPublish(const Bytes& source, const std::string& expectedCertificate) {
    check(written && file >= 0, "PDF not staged");
    struct stat info{};
    check(fstat(file, &info) == 0 && info.st_size > 0 && static_cast<uint64_t>(info.st_size) <= maxOutput, "Invalid staged PDF size");
    Bytes bytes(static_cast<size_t>(info.st_size));
    size_t offset = 0;
    while (offset < bytes.size()) {
        auto n = pread(file, bytes.data() + offset, bytes.size() - offset, static_cast<off_t>(offset));
        if (n < 0 && errno == EINTR) continue;
        check(n > 0, "PDF readback failed");
        offset += static_cast<size_t>(n);
    }
    verifyPDF(bytes, source, expectedCertificate);
    // Do not retry close even on error; the descriptor may already be released.
    const int closing = file; file = -1;
    check(ops.close(closing) == 0, "PDF close failed");
    check(same(stage, payload, fileIdentity), "Staged PDF was replaced");
    check(renameatx_np(stage, payload, parent, destinationName.c_str(), RENAME_EXCL) == 0, "Cannot publish PDF exclusively");
    // Commit succeeded. Cleanup is best effort and cannot change the outcome.
}
}
