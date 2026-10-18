#include "PAdESVerification.h"
#include "UnifiedVerification.h"
#include <CoreGraphics/CoreGraphics.h>
#include <openssl/cms.h>
#include <openssl/x509.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <map>
#include <set>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace signum {
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct Document {
    CGDataProviderRef provider = nullptr;
    CGPDFDocumentRef value = nullptr;
    explicit Document(const Bytes& data) {
        provider = CGDataProviderCreateWithData(nullptr, data.data(), data.size(), nullptr);
        if (provider) value = CGPDFDocumentCreateWithProvider(provider);
        if (!value) { if (provider) CGDataProviderRelease(provider); throw std::runtime_error("Invalid PDF structure"); }
        if (CGPDFDocumentIsEncrypted(value)) {
            CGPDFDocumentRelease(value); CGDataProviderRelease(provider);
            throw std::runtime_error("Encrypted PDFs are not supported");
        }
    }
    ~Document() { CGPDFDocumentRelease(value); CGDataProviderRelease(provider); }
};
bool nameIs(CGPDFDictionaryRef dictionary, const char* key, const char* expected) {
    const char* name = nullptr;
    return CGPDFDictionaryGetName(dictionary, key, &name) && std::strcmp(name, expected) == 0;
}
void fields(CGPDFArrayRef array, std::vector<CGPDFDictionaryRef>& signatures, unsigned depth, size_t& budget,
            bool inheritedSignature = false) {
    require(depth < 16, "PDF field tree too deep or cyclic");
    for (size_t i = 0; i < CGPDFArrayGetCount(array); ++i) {
        require(budget++ < 1024, "Too many PDF fields");
        CGPDFDictionaryRef field = nullptr;
        require(CGPDFArrayGetDictionary(array, i, &field), "Invalid PDF field");
        const char* type = nullptr;
        const bool signature = CGPDFDictionaryGetName(field, "FT", &type) ? std::strcmp(type, "Sig") == 0 : inheritedSignature;
        CGPDFDictionaryRef value = nullptr;
        CGPDFObjectRef rawValue = nullptr;
        if (signature && CGPDFDictionaryGetObject(field, "V", &rawValue) && CGPDFObjectGetType(rawValue) != kCGPDFObjectTypeNull) {
            require(CGPDFDictionaryGetDictionary(field,"V",&value),"Invalid signature value");
            signatures.push_back(value);
        }
        CGPDFArrayRef kids = nullptr;
        if (CGPDFDictionaryGetArray(field, "Kids", &kids)) fields(kids, signatures, depth + 1, budget, signature);
    }
}
std::vector<CGPDFDictionaryRef> signatures(Document& doc) {
    std::vector<CGPDFDictionaryRef> result;
    CGPDFDictionaryRef form = nullptr;
    CGPDFArrayRef array = nullptr;
    if (CGPDFDictionaryGetDictionary(CGPDFDocumentGetCatalog(doc.value), "AcroForm", &form) &&
        CGPDFDictionaryGetArray(form, "Fields", &array)) {
        size_t budget = 0;
        fields(array, result, 0, budget);
    }
    require(result.size() <= 32, "Too many PDF signatures");
    // Widget kids can inherit the same signature dictionary; don't count twice.
    std::sort(result.begin(), result.end(), std::less<CGPDFDictionaryRef>());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}
// Compare the resolved page content/resource graph, independently of xref
// layout and object numbers. A preserved byte prefix alone does not prevent an
// incremental update from replacing a page's contents or fonts/images.
struct CanonicalPageObjects {
    size_t budget = 0;
    std::set<CGPDFObjectRef> active;
    std::string result;
    void append(const void* bytes, size_t count) {
        require(count <= maxOutput - result.size(), "PDF resource graph too large");
        result.append(static_cast<const char*>(bytes), count);
    }
    void token(const std::string& value) { append(value.data(), value.size()); const char zero = 0; append(&zero, 1); }
    static void collect(const char* key, CGPDFObjectRef value, void* context) {
        static_cast<std::map<std::string, CGPDFObjectRef>*>(context)->emplace(key, value);
    }
    void dictionary(CGPDFDictionaryRef dict, unsigned depth) {
        require(CGPDFDictionaryGetCount(dict) <= 4096, "Too many PDF resource keys");
        std::map<std::string, CGPDFObjectRef> entries;
        CGPDFDictionaryApplyFunction(dict, collect, &entries);
        for (const auto& entry : entries) { token(entry.first); object(entry.second, depth + 1); }
        token("enddict");
    }
    void object(CGPDFObjectRef value, unsigned depth = 0) {
        require(depth < 32 && ++budget <= 16384, "PDF resources too deep, large or cyclic");
        if (!value) { token("absent"); return; }
        require(active.insert(value).second, "Cyclic PDF resources are not supported");
        const auto type = CGPDFObjectGetType(value);
        token(std::to_string(type));
        switch (type) {
        case kCGPDFObjectTypeNull: break;
        case kCGPDFObjectTypeBoolean: { CGPDFBoolean b; require(CGPDFObjectGetValue(value, type, &b), "Invalid PDF bool"); token(b ? "true" : "false"); break; }
        case kCGPDFObjectTypeInteger: { CGPDFInteger n; require(CGPDFObjectGetValue(value, type, &n), "Invalid PDF integer"); token(std::to_string(n)); break; }
        case kCGPDFObjectTypeReal: { CGPDFReal n; require(CGPDFObjectGetValue(value, type, &n), "Invalid PDF real"); std::ostringstream out; out << std::setprecision(17) << n; token(out.str()); break; }
        case kCGPDFObjectTypeName: { const char* name; require(CGPDFObjectGetValue(value, type, &name), "Invalid PDF name"); token(name); break; }
        case kCGPDFObjectTypeString: { CGPDFStringRef string; require(CGPDFObjectGetValue(value, type, &string), "Invalid PDF string"); token(std::to_string(CGPDFStringGetLength(string))); append(CGPDFStringGetBytePtr(string), CGPDFStringGetLength(string)); break; }
        case kCGPDFObjectTypeArray: { CGPDFArrayRef array; require(CGPDFObjectGetValue(value, type, &array), "Invalid PDF array"); const auto count = CGPDFArrayGetCount(array); require(count <= 4096, "PDF array too large"); token(std::to_string(count)); for (size_t i = 0; i < count; ++i) { CGPDFObjectRef child; require(CGPDFArrayGetObject(array, i, &child), "Invalid PDF array item"); object(child, depth + 1); } break; }
        case kCGPDFObjectTypeDictionary: { CGPDFDictionaryRef dict; require(CGPDFObjectGetValue(value, type, &dict), "Invalid PDF dictionary"); dictionary(dict, depth); break; }
        case kCGPDFObjectTypeStream: {
            CGPDFStreamRef stream; require(CGPDFObjectGetValue(value, type, &stream), "Invalid PDF stream");
            dictionary(CGPDFStreamGetDictionary(stream), depth);
            CGPDFDataFormat format; auto data = CGPDFStreamCopyData(stream, &format);
            require(data != nullptr, "Cannot decode PDF resource stream");
            const auto count = static_cast<size_t>(CFDataGetLength(data));
            if (count > maxOutput - result.size()) { CFRelease(data); throw std::runtime_error("Decoded PDF resource too large"); }
            token(std::to_string(format)); token(std::to_string(count)); append(CFDataGetBytePtr(data), count); CFRelease(data); break;
        }
        }
        active.erase(value);
    }
};
CGPDFObjectRef pageObject(CGPDFDictionaryRef page, const char* key, bool inherited) {
    for (unsigned depth = 0; depth < 32; ++depth) {
        CGPDFObjectRef value = nullptr;
        if (CGPDFDictionaryGetObject(page, key, &value)) return value;
        if (!inherited) return nullptr;
        CGPDFDictionaryRef parent = nullptr;
        if (!CGPDFDictionaryGetDictionary(page, "Parent", &parent)) return nullptr;
        page = parent;
    }
    throw std::runtime_error("Cyclic PDF page tree");
}
std::vector<CGPDFDictionaryRef> comparePages(Document& original, Document& result) {
    std::vector<CGPDFDictionaryRef> added;
    const auto count = CGPDFDocumentGetNumberOfPages(original.value);
    for (size_t index = 1; index <= count; ++index) {
        auto before = CGPDFDocumentGetPage(original.value, index), after = CGPDFDocumentGetPage(result.value, index);
        require(before && after && CGPDFPageGetRotationAngle(before) == CGPDFPageGetRotationAngle(after), "PDF page rotation changed");
        for (int box = kCGPDFMediaBox; box <= kCGPDFArtBox; ++box)
            require(CGRectEqualToRect(CGPDFPageGetBoxRect(before, static_cast<CGPDFBox>(box)), CGPDFPageGetBoxRect(after, static_cast<CGPDFBox>(box))), "PDF page geometry changed");
        for (const auto* key : {"Contents", "Resources"}) {
            CanonicalPageObjects left, right;
            left.object(pageObject(CGPDFPageGetDictionary(before), key, std::strcmp(key, "Resources") == 0));
            right.object(pageObject(CGPDFPageGetDictionary(after), key, std::strcmp(key, "Resources") == 0));
            require(left.result == right.result, "Signed revision changed PDF page contents/resources");
        }
        CGPDFArrayRef oldAnnotations = nullptr, newAnnotations = nullptr;
        CGPDFDictionaryGetArray(CGPDFPageGetDictionary(before), "Annots", &oldAnnotations);
        CGPDFDictionaryGetArray(CGPDFPageGetDictionary(after), "Annots", &newAnnotations);
        const size_t oldCount = oldAnnotations ? CGPDFArrayGetCount(oldAnnotations) : 0;
        const size_t newCount = newAnnotations ? CGPDFArrayGetCount(newAnnotations) : 0;
        require(oldCount <= 1024 && newCount >= oldCount && newCount - oldCount <= 1, "Unexpected PDF annotation change");
        for (size_t i = 0; i < newCount; ++i) {
            CGPDFDictionaryRef annotation = nullptr;
            require(CGPDFArrayGetDictionary(newAnnotations, i, &annotation), "Invalid PDF annotation");
            if (i == oldCount) { added.push_back(annotation); continue; }
            CGPDFDictionaryRef previous = nullptr;
            require(CGPDFArrayGetDictionary(oldAnnotations, i, &previous), "Invalid original PDF annotation");
            std::map<std::string, CGPDFObjectRef> leftKeys, rightKeys;
            CGPDFDictionaryApplyFunction(previous, CanonicalPageObjects::collect, &leftKeys);
            CGPDFDictionaryApplyFunction(annotation, CanonicalPageObjects::collect, &rightKeys);
            // Back references to the page/field tree are structural, not visual.
            for (auto key : {"P", "Parent", "Kids"}) { leftKeys.erase(key); rightKeys.erase(key); }
            CanonicalPageObjects left, right;
            for (auto& item : leftKeys) { left.token(item.first); left.object(item.second); }
            for (auto& item : rightKeys) { right.token(item.first); right.object(item.second); }
            require(left.result == right.result, "An existing PDF annotation was changed");
        }
    }
    return added;
}
int nibble(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
bool whitespace(uint8_t c) { return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32; }
void verifyCMS(const Bytes& contents, const Bytes& signedBytes, const std::string* expected) {
    const auto* cursor = contents.data();
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms(
        d2i_CMS_ContentInfo(nullptr, &cursor, static_cast<long>(contents.size())), CMS_ContentInfo_free);
    require(cms != nullptr && CMS_is_detached(cms.get()) == 1, "Invalid detached CMS");
    require(std::all_of(cursor, contents.data() + contents.size(), [](uint8_t c) { return c == 0; }), "Nonzero CMS padding");
    auto infos = CMS_get0_SignerInfos(cms.get());
    require(infos && sk_CMS_SignerInfo_num(infos) == 1, "Expected exactly one CMS signer");
    auto info = sk_CMS_SignerInfo_value(infos, 0);
    X509_ALGOR* digest = nullptr;
    CMS_SignerInfo_get0_algs(info, nullptr, nullptr, &digest, nullptr);
    require(digest && OBJ_obj2nid(digest->algorithm) == NID_sha256, "Unsupported PDF digest algorithm");
    // CMS_verify checks signed attributes, content digest and cryptographic signature.
    for (int nid : {NID_pkcs9_contentType, NID_pkcs9_messageDigest}) {
        const int index = CMS_signed_get_attr_by_NID(info, nid, -1);
        require(index >= 0 && CMS_signed_get_attr_by_NID(info, nid, index) < 0, "Missing or duplicate signed attribute");
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(signedBytes.data(), static_cast<int>(signedBytes.size())), BIO_free);
    require(input != nullptr && CMS_verify(cms.get(), nullptr, nullptr, input.get(), nullptr,
            CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) == 1, "PDF CMS integrity verification failed");
    if (expected) {
        auto signers = CMS_get0_signers(cms.get());
        require(signers && sk_X509_num(signers) == 1, "CMS signer certificate missing");
        auto cert = sk_X509_value(signers, 0);
        unsigned char* encoded = nullptr;
        const int length = i2d_X509(cert, &encoded);
        const bool matches = length > 0 && static_cast<size_t>(length) == expected->size() &&
            std::memcmp(encoded, expected->data(), expected->size()) == 0;
        OPENSSL_free(encoded);
        sk_X509_free(signers);
        require(matches, "Unexpected PDF signer certificate");
    }
}
size_t verifySignature(CGPDFDictionaryRef signature, const Bytes& pdf, const std::string* expected) {
    require(nameIs(signature, "Type", "Sig") && nameIs(signature, "Filter", "Adobe.PPKLite") &&
            nameIs(signature, "SubFilter", "ETSI.CAdES.detached"), "Unsupported PDF signature dictionary");
    CGPDFArrayRef byteRange = nullptr;
    require(CGPDFDictionaryGetArray(signature, "ByteRange", &byteRange) && CGPDFArrayGetCount(byteRange) == 4, "Invalid ByteRange");
    std::array<size_t, 4> range{};
    for (size_t i = 0; i < range.size(); ++i) {
        CGPDFInteger value = -1;
        require(CGPDFArrayGetInteger(byteRange, i, &value) && value >= 0 && static_cast<uint64_t>(value) <= pdf.size(), "Invalid ByteRange number");
        range[i] = static_cast<size_t>(value);
    }
    const auto start = range[1], end = range[2];
    require(range[0] == 0 && start > 0 && end > start + 2 && end <= pdf.size() &&
            range[3] <= pdf.size() - end, "Invalid ByteRange coverage");
    const size_t revisionEnd = end + range[3];
    // The one excluded interval must be exactly this dictionary's hex Contents.
    require(pdf[start] == '<' && pdf[end - 1] == '>' && (end - start - 2) % 2 == 0, "ByteRange gap is not hex Contents");
    size_t token = start;
    while (token && whitespace(pdf[token - 1])) --token;
    const std::string key = "/Contents";
    require(token >= key.size() && std::equal(key.begin(), key.end(), pdf.begin() + token - key.size()), "ByteRange gap is not Contents");
    Bytes decoded;
    for (size_t i = start + 1; i < end - 1; i += 2) {
        const int hi = nibble(pdf[i]), lo = nibble(pdf[i + 1]);
        require(hi >= 0 && lo >= 0, "Malformed signature Contents");
        decoded.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    CGPDFStringRef contents = nullptr;
    require(CGPDFDictionaryGetString(signature, "Contents", &contents) && CGPDFStringGetLength(contents) == decoded.size() &&
            std::equal(decoded.begin(), decoded.end(), CGPDFStringGetBytePtr(contents)), "Contents/ByteRange mismatch");
    Bytes signedBytes(pdf.begin(), pdf.begin() + start);
    signedBytes.insert(signedBytes.end(), pdf.begin() + end, pdf.begin() + revisionEnd);
    verifyCMS(decoded, signedBytes, expected);
    return revisionEnd;
}
}

Inspection inspectPAdES(const Bytes& pdf) {
    Inspection report; report.format="pades"; report.state="unsigned";
    Document document(pdf);
    require(CGPDFDocumentGetNumberOfPages(document.value)>0 && CGPDFDocumentGetNumberOfPages(document.value)<=1000,"Unsupported PDF page count (1–1000)");
    const auto entries=signatures(document);
    if(!entries.empty())report.state="signed";
    for(auto dictionary:entries) {
        InspectedSignature result;
        try {
            CGPDFStringRef value=nullptr;
            require(CGPDFDictionaryGetString(dictionary,"Contents",&value),"Signature Contents missing");
            Bytes cms(CGPDFStringGetBytePtr(value),CGPDFStringGetBytePtr(value)+CGPDFStringGetLength(value));
            CGPDFArrayRef ranges=nullptr;
            require(CGPDFDictionaryGetArray(dictionary,"ByteRange",&ranges) && CGPDFArrayGetCount(ranges)==4,"Invalid ByteRange");
            std::array<size_t,4> r{};
            for(size_t i=0;i<4;++i) {CGPDFInteger n=-1;require(CGPDFArrayGetInteger(ranges,i,&n)&&n>=0&&uint64_t(n)<=pdf.size(),"Invalid ByteRange number");r[i]=size_t(n);}
            require(r[0]==0&&r[1]<r[2]&&r[3]<=pdf.size()-r[2],"Invalid ByteRange coverage");
            Bytes signedBytes(pdf.begin(),pdf.begin()+r[1]);
            signedBytes.insert(signedBytes.end(),pdf.begin()+r[2],pdf.begin()+r[2]+r[3]);
            auto signers=inspectCMS(cms,&signedBytes,nullptr);
            // The inspection scope deliberately matches SG-03: one CMS signer
            // per signature dictionary, SHA-256, Adobe.PPKLite/ETSI detached.
            require(signers.size()==1,"Unsupported multi-signer PDF CMS");
            result=std::move(signers.front());
            result.revisionEnd=r[2]+r[3]; result.laterChanges=result.revisionEnd<pdf.size();
            result.revisionEnd=verifySignature(dictionary,pdf,nullptr);
            require(result.integrity=="verified","PDF CMS could not be verified");
            result.laterChanges=result.revisionEnd<pdf.size();
        } catch(const std::exception& error) {
            const std::string message=error.what();
            if(result.integrity=="verified"||result.reason.empty()) {
                result.integrity=message.find("Unsupported")!=std::string::npos || message.find("CMS")!=std::string::npos ? "notVerifiable":"invalid";
                if(message=="PDF CMS integrity verification failed")result.integrity="invalid";
                result.reason=message;
            }
        }
        report.signatures.push_back(std::move(result));
    }
    std::stable_sort(report.signatures.begin(),report.signatures.end(),[](const auto& a,const auto& b){return a.revisionEnd<b.revisionEnd;});
    return report;
}

bool isPreviewablePDF(const Bytes& bytes) {
    try { Document document(bytes); const auto pages=CGPDFDocumentGetNumberOfPages(document.value);return pages>0&&pages<=1000; }
    catch(...) { return false; }
}

void requireExpectedCertificate(const std::string& certificate, const std::string& sha256) {
    require(sha256.size() == 64 && std::all_of(sha256.begin(), sha256.end(), [](char c) { return nibble(c) >= 0; }), "Invalid expected certificate fingerprint");
    std::array<unsigned char, 32> digest{};
    unsigned int length = 0;
    require(EVP_Digest(certificate.data(), certificate.size(), digest.data(), &length, EVP_sha256(), nullptr) == 1 && length == digest.size(), "Cannot hash expected certificate");
    for (size_t i = 0; i < digest.size(); ++i)
        require(digest[i] == static_cast<unsigned char>((nibble(sha256[2*i]) << 4) | nibble(sha256[2*i+1])), "Token certificate differs from selected certificate; reload selection before signing");
}

void requireExpectedDocument(const Bytes& document, const std::string& sha256) {
    require(sha256.size() == 64 && std::all_of(sha256.begin(), sha256.end(), [](char c) { return nibble(c) >= 0; }), "Invalid expected document SHA-256");
    std::array<unsigned char, 32> digest{}; unsigned int length = 0;
    require(EVP_Digest(document.data(), document.size(), digest.data(), &length, EVP_sha256(), nullptr) == 1 && length == digest.size(), "Cannot hash document snapshot");
    for (size_t i = 0; i < digest.size(); ++i)
        require(digest[i] == static_cast<unsigned char>((nibble(sha256[2*i]) << 4) | nibble(sha256[2*i+1])), "Document snapshot differs from approved SHA-256; no signing authorized");
}

Bytes readSource(const std::string& path) {
    const int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW_ANY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("Cannot open PDF source");
    struct Close { int fd; ~Close() { close(fd); } } closeSource{fd};
    struct stat info{};
    require(fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_size > 0 && static_cast<uint64_t>(info.st_size) <= maxInput, "Invalid PDF input size/type");
    Bytes bytes;
    std::array<uint8_t, 65536> chunk{};
    while (true) {
        const auto count = read(fd, chunk.data(), chunk.size());
        if (count < 0 && errno == EINTR) continue;
        require(count >= 0, "PDF source read error");
        if (count == 0) break;
        require(bytes.size() + static_cast<size_t>(count) <= maxInput, "PDF source grew beyond limit");
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + count);
    }
    struct stat after{};
    require(fstat(fd, &after) == 0 && info.st_dev == after.st_dev && info.st_ino == after.st_ino &&
            info.st_size == after.st_size && static_cast<uint64_t>(after.st_size) == bytes.size() &&
            info.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && info.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
            info.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && info.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
            "Document snapshot changed during read");
    require(bytes.size() >= 5 && std::memcmp(bytes.data(), "%PDF-", 5) == 0, "Input is not a PDF");
    return bytes;
}

void verifyPDF(const Bytes& pdf, const Bytes& source, const std::string& expectedCertificate) {
    require(!expectedCertificate.empty() && pdf.size() <= maxOutput && source.size() <= maxInput && !source.empty(), "Invalid verification input");
    require(pdf.size() > source.size() && std::equal(source.begin(), source.end(), pdf.begin()), "Signed PDF does not preserve source bytes");
    size_t eof = pdf.size();
    while (eof && whitespace(pdf[eof - 1])) --eof;
    require(eof >= 5 && std::memcmp(pdf.data() + eof - 5, "%%EOF", 5) == 0, "Truncated PDF or unexpected trailing data");
    Document original(source), result(pdf);
    require(CGPDFDocumentGetNumberOfPages(original.value) > 0 &&
            CGPDFDocumentGetNumberOfPages(original.value) == CGPDFDocumentGetNumberOfPages(result.value), "PDF page count changed");
    const auto addedWidgets = comparePages(original, result);
    // Certification transforms require a separate DocMDP/FieldMDP policy (SG-11).
    CGPDFDictionaryRef permissions = nullptr;
    require(!CGPDFDictionaryGetDictionary(CGPDFDocumentGetCatalog(original.value), "Perms", &permissions), "Certified PDFs are not supported");
    const auto before = signatures(original), after = signatures(result);
    require(after.size() == before.size() + 1, "Expected one additional PDF signature");
    size_t finalCount = 0;
    CGPDFDictionaryRef finalSignature = nullptr;
    for (auto signature : after) {
        CGPDFArrayRef ranges = nullptr;
        CGPDFInteger offset = -1, length = -1;
        require(CGPDFDictionaryGetArray(signature, "ByteRange", &ranges) && CGPDFArrayGetCount(ranges) == 4 &&
                CGPDFArrayGetInteger(ranges, 2, &offset) && CGPDFArrayGetInteger(ranges, 3, &length) &&
                offset >= 0 && length >= 0 && static_cast<uint64_t>(offset) <= pdf.size() &&
                static_cast<uint64_t>(length) <= pdf.size() - static_cast<size_t>(offset), "Invalid signature revision");
        const auto revisionEnd = static_cast<size_t>(offset + length);
        const bool isFinal = revisionEnd == pdf.size();
        if (isFinal) { ++finalCount; finalSignature = signature; }
        else require(revisionEnd <= source.size(), "Unexpected intermediate PDF revision");
        verifySignature(signature, pdf, isFinal ? &expectedCertificate : nullptr);
    }
    require(finalCount == 1, "Final PDF revision is not signed exactly once");
    CGPDFDictionaryRef widgetValue = nullptr;
    require(addedWidgets.size() == 1 && nameIs(addedWidgets.front(), "Subtype", "Widget") &&
            nameIs(addedWidgets.front(), "FT", "Sig") &&
            CGPDFDictionaryGetDictionary(addedWidgets.front(), "V", &widgetValue) && widgetValue == finalSignature,
            "Final signature is not bound to the added PDF widget");
}
}
