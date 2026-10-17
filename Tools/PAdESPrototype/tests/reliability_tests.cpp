#include "SignumCertificatePolicy.h"
#include "TransactionalOutput.h"
#include <uuid/uuid.h>
#include <CoreGraphics/CoreGraphics.h>
#include "PAdESAppearance.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/rsa.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <functional>
#include <map>
#include <chrono>
#include <thread>
#include <regex>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
extern char** environ;
namespace fs = std::filesystem;
using namespace signum;
using namespace PoDoFo;
static int checks = 0;
static void expect(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
static void test(const std::string& name, const std::function<void()>& body) {
    body(); ++checks; std::cout << "PASS " << name << "\n";
}
struct Folder {
    fs::path path;
    explicit Folder(const fs::path& parent = "/tmp") {
        auto pattern = (parent / "signum-pades-tests-XXXXXX").string();
        auto p = mkdtemp(pattern.data()); expect(p, "mkdtemp failed"); path = p;
    }
    ~Folder() { std::error_code error; fs::remove_all(path, error); }
};
struct Identity {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{nullptr, EVP_PKEY_free};
    std::unique_ptr<X509, decltype(&X509_free)> certificate{X509_new(), X509_free};
    std::string der, privateDER;
    explicit Identity(size_t bits = 2048, bool signingUsage = false) {
        key.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", bits));
        expect(key && certificate, "Cannot create synthetic identity");
        X509_set_version(certificate.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1);
        X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
        X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
        X509_set_pubkey(certificate.get(), key.get());
        auto name = X509_get_subject_name(certificate.get());
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("Signum synthetic signer"), -1, -1, 0);
        X509_set_issuer_name(certificate.get(), name);
        if (signingUsage) {
            auto extension = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, "critical,digitalSignature,nonRepudiation");
            expect(extension && X509_add_ext(certificate.get(), extension, -1) == 1, "Cannot set fixture KeyUsage");
            X509_EXTENSION_free(extension);
        }
        expect(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0, "Cannot sign synthetic certificate");
        unsigned char* bytes = nullptr;
        int count = i2d_X509(certificate.get(), &bytes);
        expect(count > 0, "Certificate encoding failed"); der.assign(reinterpret_cast<char*>(bytes), count); OPENSSL_free(bytes);
        bytes = nullptr; count = i2d_PrivateKey(key.get(), &bytes);
        expect(count > 0, "Key encoding failed"); privateDER.assign(reinterpret_cast<char*>(bytes), count); OPENSSL_free(bytes);
    }
};
static std::string sha256(const Bytes& data) {
    unsigned char digest[32]; unsigned int count = 0;
    expect(EVP_Digest(data.data(), data.size(), digest, &count, EVP_sha256(), nullptr) == 1 && count == 32, "Hash fixture failed");
    std::string result; const char* hex = "0123456789abcdef";
    for (auto byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
static Bytes sourcePDF() {
    PdfMemDocument doc;
    auto& page = doc.GetPages().CreatePage(PoDoFo::Rect(0, 0, 595, 842));
    PdfPainter painter; painter.SetCanvas(page);
    auto& font = doc.GetFonts().GetStandard14Font(PdfStandard14FontType::Helvetica);
    painter.TextState.SetFont(font, 12); painter.DrawText("Signum synthetic PDF", 72, 720); painter.FinishDrawing();
    charbuff buffer; BufferStreamDevice device(buffer); doc.Save(device);
    return Bytes(buffer.begin(), buffer.end());
}
static Bytes signedPDF(const Bytes& source, const Identity& identity, bool visible = true, bool corrupt = false, bool alterPage = false, bool killInCallback = false, bool alterAnnotation = false) {
    charbuff buffer(reinterpret_cast<const char*>(source.data()), source.size());
    auto io = std::make_shared<BufferStreamDevice>(buffer);
    PdfMemDocument doc(io);
    if (alterPage) {
        PdfPainter painter; painter.SetCanvas(doc.GetPages().GetPageAt(0));
        auto& font = doc.GetFonts().GetStandard14Font(PdfStandard14FontType::Helvetica);
        painter.TextState.SetFont(font, 12); painter.DrawText("Undesired signed change", 72, 700); painter.FinishDrawing();
    }
    if (alterAnnotation) {
        doc.GetPages().GetPageAt(0).GetAnnotations().GetAnnotAt(0).SetRect(PoDoFo::Rect(72, 200, 190, 62));
    }
    const PoDoFo::Rect rectangle = visible ? PoDoFo::Rect(72, 100, 190, 62) : PoDoFo::Rect();
    auto& field = doc.GetPages().GetPageAt(0).CreateField<PdfSignature>(
        "SignumFixture-" + std::to_string(source.size()), rectangle);
    field.SetSignatureDate(PdfDate::UtcNow());
    if (visible) setTextAppearance(doc, field, rectangle, "Synthetic Signer");
    PdfSignerCmsParams params;
    params.SignatureType = PdfSignatureType::PAdES_B;
    params.Hashing = PdfHashingAlgorithm::SHA256;
    // Same external DigestInfo/RSA PKCS#1 v1.5 callback contract as PKCS#11,
    // backed only by an ephemeral software key in this offline fixture.
    params.Flags = PdfSignerCmsFlags::ServiceDoWrapDigest;
    params.SigningService = [&](bufferview digestInfo, bool dryrun, charbuff& result) {
        if (killInCallback) { kill(getpid(), SIGKILL); _exit(90); }
        if (dryrun || corrupt) { result.assign(static_cast<size_t>(EVP_PKEY_get_size(identity.key.get())), 'x'); return; }
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new(identity.key.get(), nullptr), EVP_PKEY_CTX_free);
        expect(context && EVP_PKEY_sign_init(context.get()) == 1 &&
               EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_PADDING) == 1, "Software RSA setup failed");
        size_t length = static_cast<size_t>(EVP_PKEY_get_size(identity.key.get())); result.resize(length);
        expect(EVP_PKEY_sign(context.get(), reinterpret_cast<unsigned char*>(result.data()), &length,
                            reinterpret_cast<const unsigned char*>(digestInfo.data()), digestInfo.size()) == 1, "Software RSA signing failed");
        result.resize(length);
    };
    PdfSignerCms signer(identity.der, params); SignDocument(doc, *io, signer, field);

    return Bytes(buffer.begin(), buffer.end());
}
static size_t find(const Bytes& data, const std::string& text, size_t from = 0) {
    auto position = std::search(data.begin() + from, data.end(), text.begin(), text.end());
    expect(position != data.end(), "Missing fixture token " + text);
    return size_t(position - data.begin());
}
static Bytes fileBytes(const fs::path& path) { std::ifstream file(path, std::ios::binary); return Bytes(std::istreambuf_iterator<char>(file), {}); }
static void put(const fs::path& path, const Bytes& bytes) { std::ofstream file(path, std::ios::binary); file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); expect(bool(file), "Fixture write failed"); }
static fs::path stageIn(const fs::path& folder) {
    for (auto& entry : fs::directory_iterator(folder)) if (entry.path().filename().string().find(".signum-pades-staging-") == 0) return entry.path();
    throw std::runtime_error("No staging directory");
}
static std::string aclText(const fs::path& path) {
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    expect(fd >= 0, "Cannot open ACL fixture");
    errno = 0; auto acl = acl_get_fd(fd); int saved = errno; close(fd);
    if (!acl) { expect(saved == ENOENT, "Cannot read ACL"); return {}; }
    char* text = acl_to_text(acl, nullptr); expect(text != nullptr, "Cannot format ACL");
    std::string result(text); acl_free(text); acl_free(acl); return result;
}
static void inheritedACL(const fs::path& path, bool write,
                         std::vector<acl_flag_t> inheritance = {ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT}) {
    auto acl = acl_init(1); acl_entry_t entry; uuid_t everyone;
    expect(acl && acl_create_entry(&acl, &entry) == 0 &&
        uuid_parse("ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C", everyone) == 0 &&
        acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0 && acl_set_qualifier(entry, everyone) == 0, "Cannot create ACL fixture");
    acl_permset_t perms; expect(acl_get_permset(entry, &perms) == 0, "ACL permissions");
    for (auto right : {ACL_READ_DATA, ACL_EXECUTE, ACL_READ_ATTRIBUTES, ACL_READ_SECURITY})
        expect(acl_add_perm(perms, right) == 0, "ACL read grant");
    if (write) for (auto right : {ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_WRITE_ATTRIBUTES})
        expect(acl_add_perm(perms, right) == 0, "ACL write grant");
    acl_flagset_t flags; expect(acl_get_flagset_np(entry, &flags) == 0, "ACL inheritance flags");
    for (auto flag : inheritance) expect(acl_add_flag_np(flags, flag) == 0, "ACL inheritance flag");
    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    expect(fd >= 0 && acl_set_fd(fd, acl) == 0, "Cannot set ACL fixture"); close(fd); acl_free(acl);
}
static void rejects(const std::string& name, const Bytes& candidate, const Bytes& source, const std::string& certificate) {
    test(name, [&] {
        Folder folder; auto original = folder.path / "source.pdf", output = folder.path / "signed.pdf";
        put(original, source);
        bool failed = false;
        try { TransactionalOutput tx(output.string()); tx.write(candidate); tx.verifyAndPublish(source, certificate); }
        catch (const std::exception&) { failed = true; }
        expect(failed, "Invalid PDF accepted: " + name);
        expect(!fs::exists(output), "Final output exposed on failure");
        expect(fileBytes(original) == source, "Source changed");
        expect(std::distance(fs::directory_iterator(folder.path), fs::directory_iterator{}) == 1, "Failure leaked staging");
    });
}
int main(int argc, char** argv) {
    try {
        if (argc == 3) {
            const std::string phase = argv[1];
            OutputOperations ops;
            if (phase == "partial") ops.write = [](int fd, const void* bytes, size_t count) -> ssize_t {
                ::write(fd, bytes, std::min(count, size_t(31))); kill(getpid(), SIGKILL); _exit(90);
            };
            if (phase == "close") ops.close = [](int fd) -> int { ::close(fd); kill(getpid(), SIGKILL); _exit(90); };
            TransactionalOutput tx(argv[2], ops);
            Identity identity; auto source = sourcePDF(), pdf = signedPDF(source, identity, true, false, false, phase == "generation");
            tx.write(pdf);
            if (phase == "written") { kill(getpid(), SIGKILL); return 90; }
            tx.verifyAndPublish(source, identity.der); return 91;
        }
        Folder folder; Identity identity, other;
        const auto source = sourcePDF(), valid = signedPDF(source, identity);
        test("selected certificate fingerprint binding before authentication", [&] {
            unsigned char digest[32]; unsigned int count = 0;
            expect(EVP_Digest(identity.der.data(), identity.der.size(), digest, &count, EVP_sha256(), nullptr) == 1 && count == 32, "Fixture fingerprint failed");
            const char* hex = "0123456789abcdef"; std::string expected;
            for (auto byte : digest) { expected += hex[byte >> 4]; expected += hex[byte & 15]; }
            requireExpectedCertificate(identity.der, expected);
            for (auto fingerprint : {std::string(64, '0'), std::string(64, 'Z'), std::string()}) {
                bool failed = false; try { requireExpectedCertificate(identity.der, fingerprint); } catch (...) { failed = true; }
                expect(failed, "Wrong/invalid expected fingerprint accepted");
            }
            bool failed = false; try { requireExpectedCertificate(other.der, expected); } catch (...) { failed = true; }
            expect(failed, "Replacement certificate accepted");
        });
        test("valid visible PDF, source unchanged, private staging, atomic publication", [&] {
            auto input = folder.path / "source.pdf", output = folder.path / "signed.pdf";
            put(input, source); TransactionalOutput tx(output.string());
            expect(!fs::exists(output), "Final appeared during generation");
            auto stage = stageIn(folder.path); struct stat info{};
            expect(stat(stage.c_str(), &info) == 0 && (info.st_mode & 0777) == 0700, "Staging permissions");
            tx.write(valid);
            expect(!fs::exists(output), "Final appeared before verification");
            expect(stat((stage / "output.pdf").c_str(), &info) == 0 && (info.st_mode & 0777) == 0600, "Payload permissions");
            tx.verifyAndPublish(source, identity.der);
            expect(fileBytes(output) == valid && fileBytes(input) == source, "Published/source bytes differ");
        });
        for (bool writable : {false, true}) test(writable ? "inherited write ACL: private staging and final sharing" : "inherited read ACL: private staging and final sharing", [&] {
            Folder f; inheritedACL(f.path, writable);
            auto control = f.path / "control", output = f.path / "signed.pdf";
            int controlFD = open(control.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
            expect(controlFD >= 0, "Cannot create inheritance control"); close(controlFD);
            const auto expected = aclText(control); fs::remove(control);
            expect(expected.find("everyone") != std::string::npos, "ACL did not inherit");
            struct stat payloadIdentity{}; bool checked = false;
            OutputOperations ops;
            ops.close = [&](int fd) {
                const auto stage = stageIn(f.path);
                expect(aclText(stage).empty(), "Stage exposed during final ACL restoration");
                struct stat now{}; expect(fstat(fd, &now) == 0 && now.st_ino == payloadIdentity.st_ino, "Payload inode changed");
                expect(!fs::exists(output), "Output visible before commit"); checked = true; return close(fd);
            };
            TransactionalOutput tx(output.string(), ops);
            const auto stage = stageIn(f.path);
            expect(aclText(stage).empty() && aclText(stage / "output.pdf").empty(), "Inherited ACL survived hardening");
            expect(lstat((stage / "output.pdf").c_str(), &payloadIdentity) == 0, "Cannot identify payload");
            tx.write(valid); tx.verifyAndPublish(source, identity.der);
            struct stat published{}; expect(lstat(output.c_str(), &published) == 0 && published.st_ino == payloadIdentity.st_ino, "Final inode changed");
            expect(checked && fileBytes(output) == valid && aclText(output) == expected, "Final bytes/sharing differ");
        });
        for (int phase = 0; phase < 4; ++phase) test("ACL failure stops publication, phase " + std::to_string(phase), [&] {
            Folder f; inheritedACL(f.path, true); OutputOperations ops; int hardened = 0, writes = 0;
            ops.harden = [&](int fd, mode_t mode) {
                if (phase == 3) return 0; // Verification must reject ineffective hardening.
                if (++hardened == phase + 1) { errno = EPERM; return -1; }
                return sg_output_make_private(fd, mode);
            };
            if (phase == 2) ops.applyACL = [](int, acl_t) { errno = EPERM; return -1; };
            ops.write = [&](int fd, const void* p, size_t n) -> ssize_t { ++writes; return ::write(fd, p, n); };
            bool failed = false;
            try { TransactionalOutput tx((f.path / "signed.pdf").string(), ops); tx.write(valid); tx.verifyAndPublish(source, identity.der); }
            catch (...) { failed = true; }
            expect(failed && fs::is_empty(f.path) && writes == (phase == 2 ? 1 : 0), "ACL failure wrote/published/leaked data");
        });
        test("final ACL matches direct kernel inheritance for file-only, directory-only, limited and inherit-only ACE", [&] {
            const std::vector<std::vector<acl_flag_t>> variants = {{ACL_ENTRY_FILE_INHERIT}, {ACL_ENTRY_DIRECTORY_INHERIT},
                {ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT, ACL_ENTRY_LIMIT_INHERIT},
                {ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT, ACL_ENTRY_ONLY_INHERIT}};
            for (const auto& flags : variants) {
                Folder f; inheritedACL(f.path, true, flags);
                auto control = f.path / "control", output = f.path / "signed.pdf";
                int fd = open(control.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600); expect(fd >= 0, "Cannot create control"); close(fd);
                auto expected = aclText(control); fs::remove(control);
                TransactionalOutput tx(output.string()); tx.write(valid); tx.verifyAndPublish(source, identity.der);
                expect(aclText(output) == expected, "Final inheritance semantics changed");
            }
        });
        test("inherited ACL with substituted payload symlink is refused", [&] {
            Folder f; inheritedACL(f.path, true); auto output = f.path / "signed.pdf", foreign = f.path / "foreign";
            put(foreign, source); bool failed = false; fs::path stage;
            try {
                TransactionalOutput tx(output.string()); stage = stageIn(f.path); tx.write(valid);
                fs::rename(stage / "output.pdf", stage / "moved"); fs::create_symlink(foreign, stage / "output.pdf");
                tx.verifyAndPublish(source, identity.der);
            } catch (...) { failed = true; }
            expect(failed && !fs::exists(output) && fs::is_symlink(stage / "output.pdf") && fileBytes(foreign) == source,
                   "Substituted symlink was published or its target changed");
        });
        test("crashed empty ACL inheritance fixture is recovered", [&] {
            Folder f; const auto abandoned = f.path / ".signum-pades-staging-33333333-3333-4333-8333-333333333333";
            fs::create_directories(abandoned / ".permissions"); chmod(abandoned.c_str(), 0700);
            put(abandoned / ".permissions" / "empty", {});
            { TransactionalOutput tx((f.path / "signed.pdf").string()); }
            expect(fs::is_empty(f.path), "Empty inheritance fixture leaked");
        });
        test("appearance stream text and placement preserved", [&] {
            auto provider = CGDataProviderCreateWithData(nullptr, valid.data(), valid.size(), nullptr);
            auto pdf = CGPDFDocumentCreateWithProvider(provider);
            expect(pdf != nullptr, "CoreGraphics cannot open fixture");
            auto page = CGPDFPageGetDictionary(CGPDFDocumentGetPage(pdf, 1));
            CGPDFArrayRef annotations = nullptr;
            expect(CGPDFDictionaryGetArray(page, "Annots", &annotations) && CGPDFArrayGetCount(annotations) == 1, "Signature widget missing");
            CGPDFDictionaryRef widget = nullptr, appearance = nullptr;
            CGPDFArrayRef rectangle = nullptr; CGPDFStreamRef stream = nullptr;
            expect(CGPDFArrayGetDictionary(annotations, 0, &widget) && CGPDFDictionaryGetArray(widget, "Rect", &rectangle) &&
                   CGPDFDictionaryGetDictionary(widget, "AP", &appearance) && CGPDFDictionaryGetStream(appearance, "N", &stream), "Appearance stream missing");
            const double expected[] = {72, 100, 262, 162};
            for (size_t i = 0; i < 4; ++i) { CGPDFReal value; expect(CGPDFArrayGetNumber(rectangle, i, &value) && value == expected[i], "Signature rectangle changed"); }
            CGPDFDataFormat format; auto data = CGPDFStreamCopyData(stream, &format);
            expect(data != nullptr, "Cannot decode appearance stream");
            const std::string text(reinterpret_cast<const char*>(CFDataGetBytePtr(data)), CFDataGetLength(data));
            CGPDFDictionaryRef resources = nullptr, fonts = nullptr, font = nullptr; CGPDFStreamRef unicode = nullptr;
            expect(CGPDFDictionaryGetDictionary(CGPDFStreamGetDictionary(stream), "Resources", &resources) &&
                   CGPDFDictionaryGetDictionary(resources, "Font", &fonts) && CGPDFDictionaryGetDictionary(fonts, "Ft0", &font) &&
                   CGPDFDictionaryGetStream(font, "ToUnicode", &unicode), "Appearance font mapping missing");
            auto cmapData = CGPDFStreamCopyData(unicode, &format);
            expect(cmapData != nullptr, "Cannot read appearance font mapping");
            const std::string cmap(reinterpret_cast<const char*>(CFDataGetBytePtr(cmapData)), CFDataGetLength(cmapData));
            CFRelease(cmapData);
            // PoDoFo subsets Helvetica and writes glyph codes. Decode the
            // ToUnicode mapping rather than expecting plain text in the AP.
            std::map<unsigned, unsigned> mapping;
            const std::regex pairs(R"(<([0-9A-Fa-f]{2})>\s*<([0-9A-Fa-f]{4})>)");
            for (auto it = std::sregex_iterator(cmap.begin(), cmap.end(), pairs); it != std::sregex_iterator(); ++it)
                mapping.emplace(std::stoul((*it)[1], nullptr, 16), std::stoul((*it)[2], nullptr, 16));
            const std::regex strings(R"(<([0-9A-Fa-f]+)> Tj)");
            std::string decoded;
            for (auto it = std::sregex_iterator(text.begin(), text.end(), strings); it != std::sregex_iterator(); ++it) {
                const auto encoded = (*it)[1].str();
                for (size_t i = 0; i < encoded.size(); i += 2) {
                    const auto glyph = std::stoul(encoded.substr(i, 2), nullptr, 16);
                    expect(mapping.count(glyph) && mapping.at(glyph) < 128, "Unmapped appearance glyph");
                    decoded.push_back(static_cast<char>(mapping.at(glyph)));
                }
            }
            const bool correct = decoded.find("Synthetic Signer") != std::string::npos;
            CFRelease(data); CGPDFDocumentRelease(pdf); CGDataProviderRelease(provider);
            expect(correct, "Appearance signer text changed");
        });
        test("valid invisible PDF", [&] { verifyPDF(signedPDF(source, identity, false), source, identity.der); });
        test("incremental second signature preserves and verifies prior signature", [&] { verifyPDF(signedPDF(valid, other), valid, other.der); });
        rejects("valid CMS with undesired existing annotation update", signedPDF(valid, other, true, false, false, false, true), valid, other.der);
        rejects("corrupt cryptographic signature", signedPDF(source, identity, true, true), source, identity.der);
        rejects("valid CMS with undesired page content update", signedPDF(source, identity, true, false, true), source, identity.der);
        rejects("wrong expected signer certificate", valid, source, other.der);
        auto changed = valid; auto contents = find(changed, "/Contents", source.size());
        auto hex = find(changed, "<", contents) + 1;
        changed[hex + 20] = changed[hex + 20] == '0' ? '1' : '0';
        rejects("altered CMS", changed, source, identity.der);
        changed = valid; changed[hex] = 'Z'; rejects("malformed Contents", changed, source, identity.der);
        changed = valid; auto range = find(changed, "/ByteRange", source.size());
        auto first = find(changed, "0", range); changed[first] = '1'; rejects("altered ByteRange", changed, source, identity.der);
        changed = valid; changed.resize(changed.size() - 20); rejects("truncated PDF", changed, source, identity.der);
        changed = valid; changed.insert(changed.end(), {'\n','%','%','E','O','F','\n'}); rejects("unsigned trailing revision", changed, source, identity.der);
        changed = valid; changed[20] ^= 1; rejects("source bytes changed", changed, source, identity.der);
        for (const std::string phase : {"write", "zero", "sync", "close"}) test("injected " + phase + " error leaves no final", [&] {
            Folder f; auto output = f.path / "result.pdf"; OutputOperations ops;
            if (phase == "write") { int calls = 0; ops.write = [calls](int fd, const void* p, size_t n) mutable -> ssize_t {
                if (++calls == 1) return ::write(fd, p, std::min(n, size_t(31))); errno = ENOSPC; return -1;
            }; }
            if (phase == "zero") ops.write = [](int, const void*, size_t) -> ssize_t { return 0; };
            if (phase == "sync") ops.sync = [](int) { errno = EIO; return -1; };
            if (phase == "close") ops.close = [](int fd) { ::close(fd); errno = EIO; return -1; };
            bool failed = false; try { TransactionalOutput tx(output.string(), ops); tx.write(valid); tx.verifyAndPublish(source, identity.der); } catch (...) { failed = true; }
            expect(failed && !fs::exists(output) && fs::is_empty(f.path), "Failure published or leaked staging");
        });
        test("short writes and EINTR", [&] {
            Folder f; OutputOperations ops; int calls = 0;
            ops.write = [&calls](int fd, const void* p, size_t n) -> ssize_t { if (++calls == 1) { errno = EINTR; return -1; } return ::write(fd, p, std::min(n, size_t(31))); };
            auto output = f.path / "result.pdf"; TransactionalOutput tx(output.string(), ops); tx.write(valid); tx.verifyAndPublish(source, identity.der);
            expect(fileBytes(output) == valid, "Short write failed");
        });
        test("existing destination and dangling symlink are preserved", [&] {
            Folder f; inheritedACL(f.path, true); auto output = f.path / "result.pdf"; put(output, source);
            bool failed = false; try { TransactionalOutput tx(output.string()); } catch (...) { failed = true; }
            expect(failed && fileBytes(output) == source, "Existing destination changed");
            fs::remove(output); fs::create_symlink(f.path / "absent", output);
            failed = false; try { TransactionalOutput tx(output.string()); } catch (...) { failed = true; }
            expect(failed && fs::is_symlink(output) && !fs::exists(f.path / "absent"), "Symlink modified");
        });
        test("destination race is refused at commit", [&] {
            Folder f; inheritedACL(f.path, true); auto output = f.path / "result.pdf"; bool failed = false;
            try { TransactionalOutput tx(output.string()); tx.write(valid); put(output, source); tx.verifyAndPublish(source, identity.der); } catch (...) { failed = true; }
            expect(failed && fileBytes(output) == source, "Concurrent winner overwritten");
        });
        test("replaced staged path is neither published nor removed", [&] {
            Folder f; auto output = f.path / "result.pdf"; bool failed = false; fs::path staged;
            try { TransactionalOutput tx(output.string()); tx.write(valid); staged = stageIn(f.path);
                fs::rename(staged / "output.pdf", staged / "moved.pdf"); put(staged / "output.pdf", source);
                tx.verifyAndPublish(source, identity.der);
            } catch (...) { failed = true; }
            expect(failed && !fs::exists(output) && fileBytes(staged / "output.pdf") == source, "Foreign staged replacement changed");
        });
        test("recovery skips active staging", [&] {
            Folder f; auto output = f.path / "result.pdf";
            TransactionalOutput active(output.string()); active.write(valid);
            { TransactionalOutput second((f.path / "second.pdf").string()); }
            active.verifyAndPublish(source, identity.der); expect(fileBytes(output) == valid, "Active transaction reclaimed");
        });
        test("recovery preserves unknown layouts and symlink targets", [&] {
            Folder f;
            const auto foreign = f.path / "foreign"; fs::create_directory(foreign); put(foreign / "output.pdf", source);
            fs::create_directory_symlink(foreign, f.path / ".signum-pades-staging-11111111-1111-4111-8111-111111111111");
            const auto unknown = f.path / ".signum-pades-staging-22222222-2222-4222-8222-222222222222";
            fs::create_directory(unknown); chmod(unknown.c_str(), 0700);
            put(unknown / "output.pdf", source); chmod((unknown / "output.pdf").c_str(), 0600);
            put(unknown / "unknown", source);
            { TransactionalOutput recovery((f.path / "result.pdf").string()); }
            expect(fileBytes(unknown / "output.pdf") == source && fs::exists(unknown / "unknown") &&
                   fileBytes(foreign / "output.pdf") == source, "Recovery removed unrelated bytes");
        });
        for (const std::string phase : {"generation", "partial", "written", "close"}) test("SIGKILL at " + phase + ", no final and conservative recovery", [&] {
            Folder f; auto output = f.path / "result.pdf";
            std::string executable = fs::absolute(argv[0]).string(), destination = output.string();
            char* args[] = {executable.data(), const_cast<char*>(phase.c_str()), destination.data(), nullptr};
            pid_t pid; expect(posix_spawn(&pid, executable.c_str(), nullptr, nullptr, args, environ) == 0, "Cannot spawn crash fixture");
            int status; expect(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "Fixture not killed");
            expect(!fs::exists(output) && !fs::is_empty(f.path), "Crash exposed final or did not exercise staging");
            { TransactionalOutput recovery(output.string()); }
            expect(fs::is_empty(f.path), "Abandoned staging not recovered");
        });
        for (int scenario = 0; scenario < 7; ++scenario) test(scenario == 0
            ? "standalone helper rejects malformed mock certificate before reading PIN"
            : "helper snapshot failure before PIN, scenario " + std::to_string(scenario), [&] {
            expect(argc == 4 && std::string(argv[1]) == "--helper-integration", "Pass helper and synthetic provider paths to this suite");
            Folder f(fs::absolute(argv[0]).parent_path());
            auto input = f.path / "source.pdf", output = f.path / "result.pdf", log = f.path / "diagnostic";
            auto mock = f.path / "mock.dylib";
            fs::copy_file(argv[3], mock); chmod(mock.c_str(), 0700); put(input, source);
            int channel[2]; expect(pipe(channel) == 0, "Cannot create synthetic stdin");
            const int diagnostics = open(log.c_str(), O_CREAT | O_WRONLY | O_EXCL, 0600);
            expect(diagnostics >= 0, "Cannot capture helper diagnostics");
            posix_spawn_file_actions_t actions; posix_spawn_file_actions_init(&actions);
            posix_spawn_file_actions_adddup2(&actions, channel[0], STDIN_FILENO);
            posix_spawn_file_actions_addclose(&actions, channel[0]);
            posix_spawn_file_actions_addclose(&actions, channel[1]);
            posix_spawn_file_actions_adddup2(&actions, diagnostics, STDERR_FILENO);
            posix_spawn_file_actions_adddup2(&actions, diagnostics, STDOUT_FILENO);
            posix_spawn_file_actions_addclose(&actions, diagnostics);
            std::string executable = argv[2], sourcePath = input.string(), destination = output.string(), middleware = mock.string();
            std::string expectedHash = scenario == 1 ? std::string(64, '0') : scenario == 6 ? std::string(64, 'Z') : sha256(source);
            if (scenario == 2) fs::remove(input);
            if (scenario == 3) { auto alias = f.path / "alias.pdf"; fs::create_symlink(input, alias); sourcePath = alias.string(); }
            if (scenario == 5) { auto changed = source; changed.push_back(' '); put(input, changed); }
            const Bytes mockDER{0x30,0x03,0x02,0x01,0x01};
            std::vector<std::string> values{executable, sourcePath, destination, middleware, "7", "53", "--pin-stdin",
                "--job-id", "11111111-1111-4111-8111-111111111111", "--snapshot-id", "22222222-2222-4222-8222-222222222222",
                "--expected-document-sha256", expectedHash, "--expected-cert-sha256", sha256(mockDER)};
            if (scenario != 4) values.push_back("--verified-output-v3");
            std::vector<char*> args; for (auto& value : values) args.push_back(value.data()); args.push_back(nullptr);
            pid_t pid; const int spawned = posix_spawn(&pid, executable.c_str(), &actions, nullptr, args.data(), environ);
            posix_spawn_file_actions_destroy(&actions); close(channel[0]); close(diagnostics);
            if (spawned) { close(channel[1]); throw std::runtime_error("Cannot spawn helper fixture"); }
            // Keep stdin's writer open without writing credentials. A helper
            // that attempts to read a PIN will block and fail this deadline.
            int status = 0; pid_t result = 0;
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while ((result = waitpid(pid, &status, WNOHANG)) == 0 && std::chrono::steady_clock::now() < deadline)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (result == 0) { kill(pid, SIGKILL); waitpid(pid, &status, 0); }
            close(channel[1]);
            expect(result == pid && WIFEXITED(status) && WEXITSTATUS(status) == (scenario == 4 ? 2 : 1), "Helper waited for PIN or failed unexpectedly");
            auto bytes = fileBytes(log); std::string reason(bytes.begin(), bytes.end());
            const std::string expected = scenario == 0 ? "malformato" : scenario == 2 || scenario == 3 ? "Cannot open" :
                scenario == 4 ? "Snapshot protocol" : scenario == 6 ? "Invalid expected document" : "approved SHA-256";
            expect(reason.find(expected) != std::string::npos, "Missing rejection diagnostic: " + reason);
            expect(!fs::exists(output), "Rejected certificate exposed output");
            for (const auto& entry : fs::directory_iterator(f.path))
                expect(entry.path().filename().string().find(".signum-pades-staging-") != 0, "Rejected helper leaked staging");
        });
        test("document SHA-256 is checked against the exact PDF source", [&] {
            requireExpectedDocument(source, sha256(source));
            auto changed = source; changed.push_back(' ');
            bool rejected = false; try { requireExpectedDocument(changed, sha256(source)); } catch (...) { rejected = true; }
            expect(rejected, "Different approved content accepted");
        });
        test("shared certificate policy keeps missing KeyUsage indeterminate", [&] {
            const auto a = sg_certificate_assess(reinterpret_cast<const uint8_t*>(identity.der.data()), identity.der.size(), sg_certificate_now());
            expect(a.status == SG_CERT_INDETERMINATE && (a.reasons & SG_CERT_MISSING_KEY_USAGE), "Missing usage accepted");
        });
        for (size_t bits : {size_t(3072), size_t(4096)}) test("eligible RSA " + std::to_string(bits) + " PDF with matching signature reservation", [&] {
            Identity signer(bits, true);
            const auto a = sg_certificate_assess(reinterpret_cast<const uint8_t*>(signer.der.data()), signer.der.size(), sg_certificate_now());
            expect(a.status == SG_CERT_ELIGIBLE && a.public_key_bits == static_cast<int>(bits), "RSA policy mismatch");
            verifyPDF(signedPDF(source, signer), source, signer.der);
        });
        std::cout << checks << " native cases passed; no token or PIN used\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL after " << checks << " cases: " << error.what() << "\n"; return 1; }
}
