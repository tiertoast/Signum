#pragma once
#include "output_permissions.h"
#include <array>
#include <CoreFoundation/CoreFoundation.h>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <vector>

namespace signum {
// Public context only. Contract v1 is carried by the bound PAdES v5 request.
// This checks observable middleware properties, never physical attestation.
struct SigningProviderContext {
    std::string provider, objectID, certificateSHA256, routeID, discoveryID;
    std::array<uint64_t, 7> file; // dev, ino, size, mtime s/ns, ctime s/ns
    bool automatic;
    uint64_t slot;
    std::array<std::string, 5> token; // label, manufacturer, model, reader, serial
    static void require(bool value) { if (!value) throw std::runtime_error("Invalid/changed provider context"); }
    static bool digest(const std::string& value) {
        if (value.size() != 64) return false;
        for (auto c : value) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    }
    static bool uuid(const std::string& value) {
        if (value.size() != 36) return false;
        for (size_t i = 0; i < value.size(); ++i) {
            if (i == 8 || i == 13 || i == 18 || i == 23) { if (value[i] != '-') return false; }
            else if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f') || (value[i] >= 'A' && value[i] <= 'F'))) return false;
        }
        return true;
    }
    static uint64_t number(const std::string& value, uint64_t maximum = std::numeric_limits<int64_t>::max()) {
        require(!value.empty() && value.size() <= 20);
        for (auto c : value) require(c >= '0' && c <= '9');
        uint64_t result = 0; auto parsed = std::from_chars(value.data(), value.data()+value.size(), result);
        require(parsed.ec == std::errc() && parsed.ptr == value.data()+value.size() && result <= maximum); return result;
    }
    static std::string hex(const std::string& value, size_t maximum, bool allowEmpty = true, bool allowNUL = false) {
        require(value.size() % 2 == 0 && value.size()/2 <= maximum && (allowEmpty || !value.empty()));
        auto nibble = [](char c) -> unsigned { if (c >= '0' && c <= '9') return c-'0'; require(c >= 'a' && c <= 'f'); return c-'a'+10; };
        std::string result;
        for (size_t i = 0; i < value.size(); i += 2) { char c = static_cast<char>((nibble(value[i])<<4)|nibble(value[i+1])); require(allowNUL || c != 0); result += c; }
        return result;
    }
    explicit SigningProviderContext(const std::string& wire) {
        require(!wire.empty() && wire.size() <= 16384);
        std::vector<std::string> fields; size_t begin = 0;
        for (;;) { auto end = wire.find(':', begin); fields.push_back(wire.substr(begin, end == std::string::npos ? end : end-begin));
            require(fields.size() <= 20); if (end == std::string::npos) break; begin = end+1; }
        require(fields.size() == 20 && fields[0] == "1");
        provider = hex(fields[1], 4096, false); require(provider[0] == '/');
        for (size_t i = 0; i < file.size(); ++i) file[i] = number(fields[i+2], i == 1 ? std::numeric_limits<uint64_t>::max() : std::numeric_limits<int64_t>::max());
        require(file[1] > 0 && file[4] < 1000000000 && file[6] < 1000000000);
        require(fields[9] == "0" || fields[9] == "1"); automatic = fields[9] == "1";
        slot = number(fields[10], std::numeric_limits<unsigned long>::max());
        const size_t limits[] = {128,128,128,256,32};
        for (size_t i = 0; i < token.size(); ++i) token[i] = hex(fields[i+11], limits[i]);
        objectID = hex(fields[16], 64, false, true);
        certificateSHA256 = fields[17]; routeID = fields[18]; discoveryID = fields[19];
        require(digest(certificateSHA256) && digest(routeID) && uuid(discoveryID));
    }
    void requireCurrentModule(const std::string& path) const {
        require(path == provider && std::filesystem::canonical(path).string() == provider);
        struct stat info{}; require(lstat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode));
        const std::array<uint64_t,7> actual = {static_cast<uint64_t>(info.st_dev), static_cast<uint64_t>(info.st_ino),
            static_cast<uint64_t>(info.st_size), static_cast<uint64_t>(info.st_mtimespec.tv_sec), static_cast<uint64_t>(info.st_mtimespec.tv_nsec),
            static_cast<uint64_t>(info.st_ctimespec.tv_sec), static_cast<uint64_t>(info.st_ctimespec.tv_nsec)};
        require(actual == file);
        if (automatic) for (auto current = std::filesystem::path(path); !current.empty(); current = current.parent_path()) {
            require(lstat(current.c_str(), &info) == 0 && !S_ISLNK(info.st_mode) && info.st_uid == 0 && (info.st_mode & 0022) == 0 && sg_discovery_acl_safe(current.c_str()) == 1);
            if (current == current.root_path()) break;
        }
    }
    static std::string normalizedTokenString(const char* value) {
        // Mirror the Swift discovery representation for conforming UTF-8 token metadata.
        auto source = CFStringCreateWithCString(nullptr, value, kCFStringEncodingUTF8); require(source != nullptr);
        auto text = CFStringCreateMutableCopy(nullptr, 0, source); CFRelease(source); require(text != nullptr);
        CFStringTrimWhitespace(text);
        std::vector<char> bytes(static_cast<size_t>(CFStringGetMaximumSizeForEncoding(CFStringGetLength(text), kCFStringEncodingUTF8))+1);
        bool encoded = CFStringGetCString(text, bytes.data(), bytes.size(), kCFStringEncodingUTF8); CFRelease(text); require(encoded);
        return std::string(bytes.data());
    }
    bool matchesToken(unsigned long actualSlot, const char* label, const char* manufacturer, const char* model, const char* reader, const char* serial) const {
        if (slot != actualSlot) return false;
        return token == std::array<std::string,5>{normalizedTokenString(label),normalizedTokenString(manufacturer),normalizedTokenString(model),normalizedTokenString(reader),normalizedTokenString(serial)};
    }
};
}
