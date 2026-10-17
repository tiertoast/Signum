#include "process_coordination.h"
#include "SignumCertificatePolicy.h"
#include <cctype>
// Experimental local PAdES-B proof of concept.
// Uses PoDoFo for incremental PDF signing, Bit4id/OpenSC PKCS#11 for RSA.
// Does NOT export the private key or validate trust; visible AP is an experimental text-only stream.
// Invoked by SignumApp when bundled; success means integrity verified and published.
#include <podofo/podofo.h>
#include "SignumPKCS11.h"
#include "TransactionalOutput.h"
#include "PAdESAppearance.h"

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
                    // lstat inspects the link itself. stat() follows symlinks and
                    // fails with ELOOP for Bit4id's installed self-referential
                    // link inside its .rc resource directory.
                    if (::lstat(entry.path().c_str(), &child) != 0)
                        throw std::runtime_error("Cannot inspect Bit4id resource: " + entry.path().string());

                    if (S_ISLNK(child.st_mode)) {
                        const auto link = fs::read_symlink(entry.path());
                        const auto target = (link.is_absolute()
                            ? link : entry.path().parent_path() / link).lexically_normal();
                        const auto self = entry.path().lexically_normal();

                        // The exact self-loop is an unusable, inert vendor
                        // artifact. Ignore only when root-owned and inside
                        // an already verified non-writable .rc directory.
                        if (target == self && child.st_uid == 0)
                            continue;
                        throw std::runtime_error(
                            "Unexpected Bit4id resource symlink: " + entry.path().string());
                    }
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
                             const std::vector<uint8_t>& pin, const std::string& approved, bufferview digestInfo,
                             charbuff& signedHash) {
        std::array<uint8_t, 8192> signature{};
        size_t length = 0;
        const auto* message = reinterpret_cast<const uint8_t*>(digestInfo.data());
        if (sg_sign_encoded_digest_checked(context, slot, id.data(), id.size(),
                                   reinterpret_cast<const uint8_t*>(approved.data()), approved.size(),
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

// Name is only a visible descriptive label. Use conservative printable ASCII
// for the standard Helvetica PDF font; never interpret text as PDF operators.
static std::string read_appearance_name() {
    std::string name;
    char value = 0;
    while (::read(STDIN_FILENO, &value, 1) == 1) {
        if (value == '\n') break;
        if (value == '\r') continue;
        if (name.size() >= 100 || static_cast<unsigned char>(value) < 32 ||
            static_cast<unsigned char>(value) > 126)
            throw std::runtime_error("Invalid signature appearance name");
        name.push_back(value);
    }
    if (name.empty()) throw std::runtime_error("Missing appearance name");
    return name;
}


int main(int argc, char** argv) {
    if (sg_worker_watch_parent() != 0) return 2;
    // GUI requires this protocol marker, so an older bundled helper fails closed.
    const bool verifiedProtocol = argc > 1 && std::strcmp(argv[argc - 1], "--verified-output-v3") == 0;
    int protocolCount = argc - (verifiedProtocol ? 1 : 0);
    auto option = [&](const char* key) -> std::string {
        if (protocolCount >= 3 && std::strcmp(argv[protocolCount - 2], key) == 0) {
            std::string value = argv[protocolCount - 1]; protocolCount -= 2; return value;
        }
        return {};
    };
    const auto expectedFingerprint = option("--expected-cert-sha256");
    const auto expectedDocument = option("--expected-document-sha256");
    const auto snapshotID = option("--snapshot-id");
    const auto jobID = option("--job-id");
    auto uuid = [](const std::string& text) {
        if (text.size() != 36) return false;
        for (size_t i = 0; i < text.size(); ++i) {
            if (i == 8 || i == 13 || i == 18 || i == 23) { if (text[i] != '-') return false; }
            else if (!std::isxdigit(static_cast<unsigned char>(text[i]))) return false;
        }
        return true;
    };
    if (!verifiedProtocol || expectedFingerprint.size() != 64 || expectedDocument.size() != 64 || !uuid(snapshotID) || !uuid(jobID)) {
        std::cerr << "Snapshot protocol v3 requires job, snapshot and both approved SHA-256 fingerprints\n";
        return 2;
    }
    const bool appearanceFromPipe = protocolCount > 1 &&
        std::strcmp(argv[protocolCount - 1], "--appearance-stdin") == 0;
    const int afterAppearance = protocolCount - (appearanceFromPipe ? 1 : 0);
    const bool pinFromPipe = afterAppearance > 1 &&
        std::strcmp(argv[afterAppearance - 1], "--pin-stdin") == 0;
    const int positionalCount = afterAppearance - (pinFromPipe ? 1 : 0);
    if ((positionalCount != 6 && positionalCount != 11) ||
        (appearanceFromPipe && (!pinFromPipe || positionalCount != 11))) {
        std::cerr << "Usage: signum-pades-local INPUT.pdf OUTPUT.pdf MODULE SLOT CERT_ID_HEX"
                  << " [PAGE_ZERO_BASED X Y WIDTH HEIGHT] [--pin-stdin] [--appearance-stdin]\n";
        return 2;
    }
    fs::path output;
    try {
        const fs::path input = argv[1];
        output = argv[2];
        const fs::path middleware = argv[3];
        const auto slot = static_cast<unsigned long>(std::stoul(argv[4]));
        auto certificateID = parse_hex(argv[5]);

        if (fs::absolute(input).lexically_normal() == fs::absolute(output).lexically_normal())
            throw std::runtime_error("Output conflicts with input");
        const auto source = signum::readSource(input.string());
        signum::requireExpectedDocument(source, expectedDocument);
        require_driver_readonly(middleware);
        signum::TransactionalOutput transaction(output.string());
        // PoDoFo operates on the bounded source bytes, never on a public or
        // re-opened temporary pathname. The input is never opened for writing.
        charbuff pdfBytes(std::string(reinterpret_cast<const char*>(source.data()), source.size()));

        std::unique_ptr<SGTokenLease, decltype(&sg_token_lease_release)> lease(
            sg_token_lease_acquire(middleware.c_str(), slot, 0, 10000), sg_token_lease_release);
        if (!lease) throw std::runtime_error("Dispositivo occupato o coordinamento non disponibile; nessun PIN inviato al provider");
        PKCS11 token(middleware.c_str());
        const auto der = token.certificate(slot, certificateID);
        // Bind to the exact certificate shown by the GUI, before any PIN read
        // or private-key operation.
        if (!expectedFingerprint.empty()) signum::requireExpectedCertificate(der, expectedFingerprint);
        const auto assessment = sg_certificate_assess(reinterpret_cast<const uint8_t*>(der.data()), der.size(), sg_certificate_now());
        if (assessment.status != SG_CERT_ELIGIBLE) {
            std::string reason = assessment.status == SG_CERT_INELIGIBLE ? "Non idoneo: " : "Idoneità indeterminata: ";
            for (unsigned bit = 0; bit < 32; ++bit)
                if (assessment.reasons & (1u << bit)) reason += std::string(sg_certificate_reason_message(1u << bit)) + " ";
            throw std::runtime_error(reason);
        }
        std::vector<uint8_t> pin;
        if (pinFromPipe) {
            pin = read_stdin_pin();
        } else {
            char* userPIN = ::getpass("Token PIN (not echoed): ");
            if (!userPIN || !*userPIN) throw std::runtime_error("PIN missing");
            pin.assign(userPIN, userPIN + std::strlen(userPIN));
            wipe_secret(userPIN, std::strlen(userPIN));
        }

        std::string appearanceName;
        if (appearanceFromPipe) {
            try {
                appearanceName = read_appearance_name();
            } catch (...) {
                wipe_pin(pin);
                throw;
            }
        }

        try {
            auto io = std::make_shared<BufferStreamDevice>(pdfBytes);
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
            auto& field = page.CreateField<PdfSignature>("SignumSignature-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()), rectangle);
            field.SetSignatureDate(PdfDate::UtcNow());
            if (!appearanceName.empty())
                signum::setTextAppearance(doc, field, rectangle, appearanceName);

            PdfSignerCmsParams params;
            params.SignatureType = PdfSignatureType::PAdES_B;
            params.Hashing = PdfHashingAlgorithm::SHA256;
            params.Flags = PdfSignerCmsFlags::ServiceDoWrapDigest;
            params.SigningService = [&](bufferview digestInfo, bool dryrun, charbuff& signedHash) {
                if (dryrun) {
                    signedHash.resize(static_cast<size_t>((assessment.public_key_bits + 7) / 8));
                    return;
                }
                token.sign_encoded_digest(slot, certificateID, pin, der, digestInfo, signedHash);
            };
            PdfSignerCms signer(der, params);
            PoDoFo::SignDocument(doc, *io, signer, field);
        } catch (...) {
            wipe_pin(pin);
            throw;
        }
        wipe_pin(pin);
        transaction.write(signum::Bytes(pdfBytes.begin(), pdfBytes.end()));
        transaction.verifyAndPublish(source, der);
        std::cout << "PAdES integrity verified and output published: " << output << "\n"
                  << "Certificate trust and eIDAS qualification NOT checked.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "PAdES proof of concept failed: " << error.what() << "\n";
        return 1;
    }
}
