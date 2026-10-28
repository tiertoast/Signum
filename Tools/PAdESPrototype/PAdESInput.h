#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <unistd.h>
#include <cerrno>
namespace signum {
static std::vector<uint8_t> readPAdESPIN(int fd) {
    std::vector<uint8_t> pin;
    // Allocate before receiving secret bytes: no retired growth buffers.
    pin.reserve(64);
    char value = 0;
    bool transferred = false;
    struct WipeScope {
        std::vector<uint8_t>& pin; char& value; bool& transferred;
        ~WipeScope() noexcept {
            *reinterpret_cast<volatile char*>(&value) = 0;
            if (!transferred) {
                volatile uint8_t* p = pin.data();
                for (size_t i = 0; i < pin.size(); ++i) p[i] = 0;
            }
        }
    } scope{pin, value, transferred};
    bool terminated = false;
    for (;;) {
        auto count = ::read(fd, &value, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count != 1) break;
        if (value == '\n') { terminated = true; break; }
        if (value == '\r' || value == '\0' || pin.size() >= 64)
            throw std::runtime_error("Invalid PIN frame");
        pin.push_back(static_cast<uint8_t>(value));
    }
    if (!terminated || pin.empty()) throw std::runtime_error("Incomplete PIN frame");
    transferred = true; // The caller's PINScope owns and wipes the moved buffer.
    return pin;
}

}
