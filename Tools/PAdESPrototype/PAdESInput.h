#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <unistd.h>
#include <cerrno>
namespace signum {
static std::vector<uint8_t> readPAdESPIN(int fd) {
    std::vector<uint8_t> pin;
    char value = 0;
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
    return pin;
}

}
