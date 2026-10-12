// Experimental local PAdES-B proof of concept.
// Uses PoDoFo for incremental PDF signing, Bit4id/OpenSC PKCS#11 for RSA.
// Does NOT export the private key, validate trust, or generate a visible AP stream.
// This is NOT built or invoked by the Signum SwiftUI app yet.
#include <podofo/podofo.h>
#include "SignumPKCS11.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace PoDoFo;

// Portable best-effort PIN erasure for Apple Clang, which does not expose
// explicit_bzero in all macOS SDK configurations. Volatile stores prevent
// the compiler from eliding these specific writes.
static void wipe_secret(void* buffer, size_t size) noexcept {
    auto* bytes = reinterpret_cast<volatile unsigned char*>(buffer);
    for (size_t i = 0; i < size; ++i)
        bytes[i] = 0;
}

static void wipe_pin(std::vector<uint8_t>& pin) noexcept {
    if (!pin.empty())
        wipe_secret(pin.data(), pin.size());
}

static void require_driver_readonly(const fs::path& path) {
    if (!path.is_absolute()) throw std::runtime_error("Module path must be absolute");
    const auto resolved = fs::canonical(path);
    for (auto p = resolved; !p.empty(); p = p.parent_path()) {
        struct stat info {};
        if (::stat(p.c_str(), &info) != 0) throw std::runtime_error("Cannot inspect middleware path");
        if ((info.st_mode & 0022) != 0)
            throw std::runtime_error("Middleware path is group/other writable: " + p.string());
        if (p == p.root_path()) break;
    }
    for (const auto& suffix : {std::string(".conf"), std::string(".rc")}) {
        auto sidecar = fs::path(resolved.string() + suffix);
        if (fs::exists(sidecar)) {
            struct stat info {};
            if (::stat(sidecar.c_str(), &info) != 0)
                throw std::runtime_error("Cannot inspect Bit4id configuration: " + sidecar.string());
            if ((info.st_mode & 0022) != 0)
                throw std::runtime_error("Unsafe Bit4id configuration permissions: " + sidecar.string());
            if (fs::is_directory(sidecar)) {
                size_t checked = 0;
                for (const auto& entry : fs::recursive_directory_iterator(sidecar)) {
                    if (++checked > 1000) throw std::runtime_error("Too many middleware resources");
                    struct stat child {};
                    if (::stat(entry.path().c_str(), &child) != 0)
                        throw std::runtime_error("Cannot inspect Bit4id resource: " + entry.path().string());
                    if ((child.st_mode & 0022) != 0)
                        throw std::runtime_error("Unsafe Bit4id configuration resource: " + entry.path().string());
                }
            }
        }
    }
}

static std::vector<uint8_t> parse_hex(const std::string& hex) {
    if (hex.empty() || hex.size() > 128 || hex.size() % 2 != 0)
        throw std::runtime_error("Invalid certificate ID");
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto hi = hex[i], lo = hex[i + 1];
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::runtime_error("Certificate ID is not hexadecimal");
        };
        result.push_back(static_cast<uint8_t>((nibble(hi) << 4) | nibble(lo)));
    }
    return result;
}

struct PKCS11 {
    SGContext* context = nullptr;
    std::array<char, 512> error{};
    explicit PKCS11(const char* path) {
        if (sg_open(path, &context, error.data(), error.size()) != 0)
            throw std::runtime_error(error.data());
    }
    ~PKCS11() { sg_close(context); }
    PKCS11(const PKCS11&) = delete;
    PKCS11& operator=(const PKCS11&) = delete;

    std::string certificate(unsigned long slot, const std::vector<uint8_t>& id) {
        size_t n = 0;
        if (sg_certificate_der(context, slot, id.data(), id.size(), nullptr, 0,
                               &n, error.data(), error.size()) != 0 || n == 0 || n > 65536)
            throw std::runtime_error("Certificate DER: " + std::string(error.data()));
        std::string der(n, '\0');
        if (sg_certificate_der(context, slot, id.data(), id.size(),
                               reinterpret_cast<uint8_t*>(der.data()), der.size(),
                               &n, error.data(), error.size()) != 0)
            throw std::runtime_error("Certificate DER: " + std::string(error.data()));
        der.resize(n);
        return der;
    }

    void sign_encoded_digest(unsigned long slot, const std::vector<uint8_t>& id,
                             const std::vector<uint8_t>& pin, bufferview digestInfo,
                             charbuff& signedHash) {
        std::array<uint8_t, 8192> signature{};
        size_t length = 0;
        const auto* message = reinterpret_cast<const uint8_t*>(digestInfo.data());
        if (sg_sign_encoded_digest(context, slot, id.data(), id.size(),
                                   pin.data(), pin.size(), message, digestInfo.size(),
                                   signature.data(), signature.size(), &length,
                                   error.data(), error.size()) != 0)
            throw std::runtime_error("PKCS#11 signing: " + std::string(error.data()));
        signedHash.assign(reinterpret_cast<const char*>(signature.data()),
                          reinterpret_cast<const char*>(signature.data() + length));
        std::fill(signature.begin(), signature.end(), 0);
    }
};

// GUI mode reads the PIN only from an anonymous stdin pipe, never argv/env.
static std::vector<uint8_t> read_stdin_pin() {
    std::vector<uint8_t> pin;
    char value = 0;
    while (::read(STDIN_FILENO, &value, 1) == 1) {
        if (value == '\n') break;
        if (value == '\r') continue;
        if (value == '\0' || pin.size() >= 64)
            throw std::runtime_error("Invalid PIN input");
        pin.push_back(static_cast<uint8_t>(value));
    }
    if (pin.empty()) throw std::runtime_error("PIN missing");
    return pin;
}

int main(int argc, char** argv) {
    const bool pinFromPipe = argc > 1 && std::strcmp(argv[argc - 1], "--pin-stdin") == 0;
    const int positionalCount = argc - (pinFromPipe ? 1 : 0);
    if (positionalCount != 6 && positionalCount != 11) {
        std::cerr << "Usage: signum-pades-local INPUT.pdf OUTPUT.pdf MODULE SLOT CERT_ID_HEX"
                  << " [PAGE_ZERO_BASED X Y WIDTH HEIGHT] [--pin-stdin]\n";
        return 2;
    }
    fs::path output;
    bool outputCreated = false;
    try {
        const fs::path input = argv[1];
        output = argv[2];
        const fs::path middleware = argv[3];
        const auto slot = static_cast<unsigned long>(std::stoul(argv[4]));
        auto certificateID = parse_hex(argv[5]);
        require_driver_readonly(middleware);

        if (!fs::is_regular_file(input) || fs::file_size(input) == 0 ||
            fs::file_size(input) > 64 * 1024 * 1024)
            throw std::runtime_error("Input must be a local PDF smaller than 64 MiB");
        if (fs::exists(output) || fs::absolute(input) == fs::absolute(output))
            throw std::runtime_error("Output already exists or conflicts with input");

        // Check the input header; PoDoFo performs full PDF parsing.
        std::ifstream header(input, std::ios::binary);
        char magic[5]{};
        header.read(magic, 5);
        if (std::memcmp(magic, "%PDF-", 5) != 0)
            throw std::runtime_error("Input is not a PDF");

        // Create the output exclusively with owner-only access before the
        // incremental update; never modify the user's original PDF.
        const int fd = ::open(output.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (fd < 0) throw std::runtime_error("Cannot create new output PDF");
        outputCreated = true;
        try {
            std::ifstream source(input, std::ios::binary);
            if (!source) throw std::runtime_error("Cannot read source PDF");
            std::array<char, 65536> buffer{};
            while (source) {
                source.read(buffer.data(), buffer.size());
                auto remaining = source.gcount();
                const char* ptr = buffer.data();
                while (remaining > 0) {
                    const auto n = ::write(fd, ptr, static_cast<size_t>(remaining));
                    if (n <= 0) throw std::runtime_error("Cannot copy PDF to protected output");
                    ptr += n;
                    remaining -= n;
                }
            }
            if (!source.eof()) throw std::runtime_error("Error while reading source PDF");
            ::close(fd);
        } catch (...) {
            ::close(fd);
            throw;
        }

        PKCS11 token(middleware.c_str());
        const auto der = token.certificate(slot, certificateID);
        std::vector<uint8_t> pin;
        if (pinFromPipe) {
            pin = read_stdin_pin();
        } else {
            char* userPIN = ::getpass("Token PIN (not echoed): ");
            if (!userPIN || !*userPIN) throw std::runtime_error("PIN missing");
            pin.assign(userPIN, userPIN + std::strlen(userPIN));
            wipe_secret(userPIN, std::strlen(userPIN));
        }

        try {
            auto io = std::make_shared<FileStreamDevice>(output.string(), FileMode::Open);
            PdfMemDocument doc(io);
            unsigned pageIndex = 0;
            Rect rectangle;
            if (positionalCount == 11) {
                pageIndex = static_cast<unsigned>(std::stoul(argv[6]));
                const double x = std::stod(argv[7]);
                const double y = std::stod(argv[8]);
                const double width = std::stod(argv[9]);
                const double height = std::stod(argv[10]);
                if (!(width > 0.0 && height > 0.0 && width < 1000.0 && height < 1000.0))
                    throw std::runtime_error("Invalid signature rectangle");
                rectangle = Rect(x, y, width, height);
            }
            if (pageIndex >= doc.GetPages().GetCount())
                throw std::runtime_error("Page index exceeds PDF page count");
            auto& page = doc.GetPages().GetPageAt(pageIndex);
            auto& field = page.CreateField<PdfSignature>("SignumSignature", rectangle);
            field.SetSignatureDate(PdfDate::UtcNow());

            PdfSignerCmsParams params;
            params.SignatureType = PdfSignatureType::PAdES_B;
            params.Hashing = PdfHashingAlgorithm::SHA256;
            params.Flags = PdfSignerCmsFlags::ServiceDoWrapDigest;
            params.SigningService = [&](bufferview digestInfo, bool dryrun, charbuff& signedHash) {
                if (dryrun) {
                    signedHash.resize(256);
                    return;
                }
                token.sign_encoded_digest(slot, certificateID, pin, digestInfo, signedHash);
            };
            PdfSignerCms signer(der, params);
            PoDoFo::SignDocument(doc, *io, signer, field);
        } catch (...) {
            wipe_pin(pin);
            throw;
        }
        wipe_pin(pin);
        std::cout << "PAdES prototype output written: " << output << "\n"
                  << "VERIFY WITH AN INDEPENDENT PDF VALIDATOR BEFORE ANY USE.\n";
        return 0;
    } catch (const std::exception& error) {
        if (outputCreated) {
            std::error_code ec;
            fs::remove(output, ec);
        }
        std::cerr << "PAdES proof of concept failed: " << error.what() << "\n";
        return 1;
    }
}
