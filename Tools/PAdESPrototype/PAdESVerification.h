#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace signum {
using Bytes = std::vector<uint8_t>;
constexpr size_t maxInput = 64 * 1024 * 1024;
constexpr size_t maxOutput = 96 * 1024 * 1024;
// Integrity only: no chain, revocation, timestamp or eIDAS qualification.
void verifyPDF(const Bytes& pdf, const Bytes& source, const std::string& expectedCertificate);
void requireExpectedCertificate(const std::string& certificate, const std::string& sha256);
void requireExpectedDocument(const Bytes& document, const std::string& sha256);
Bytes readSource(const std::string& path);
}
