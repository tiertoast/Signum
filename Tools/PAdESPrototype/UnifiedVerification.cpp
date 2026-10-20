#include "UnifiedVerification.h"
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <memory>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <unistd.h>
#include <sys/resource.h>
#include <fcntl.h>
namespace signum {
namespace {
using CMS = std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)>;
CMS decode(const Bytes& bytes, bool padded) {
    auto cursor = bytes.data();
    CMS cms(d2i_CMS_ContentInfo(nullptr, &cursor, static_cast<long>(bytes.size())), CMS_ContentInfo_free);
    if (!cms ||
        (!padded && cursor != bytes.data()+bytes.size()) ||
        !std::all_of(cursor, bytes.data()+bytes.size(), [](uint8_t c){return c==0;}))
        throw std::runtime_error("Struttura CMS SignedData malformata");
    if (OBJ_obj2nid(CMS_get0_type(cms.get())) != NID_pkcs7_signed)
        throw std::runtime_error("Tipo CMS non supportato: richiesto SignedData");
    return cms;
}
std::string bioString(BIO* bio) {
    char* p=nullptr; auto n=BIO_get_mem_data(bio,&p);
    return n>0 ? std::string(p, std::min<long>(n,2048)) : std::string();
}
std::string name(X509_NAME* value) {
    std::unique_ptr<BIO,decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()),BIO_free);
    if (!bio || !value) return {};
    X509_NAME_print_ex(bio.get(),value,0,XN_FLAG_RFC2253); return bioString(bio.get());
}
std::string oid(const ASN1_OBJECT* object) {
    if (!object) return {};
    char text[128]{}; OBJ_obj2txt(text,sizeof(text),object,0);return text;
}
std::string quoted(const std::string& value) {
    std::ostringstream out; out << '"';
    // X509_NAME_print_ex escapes non-ASCII/control bytes. Fixed diagnostics and
    // OpenSSL algorithm/time labels are ASCII; preserve no unvalidated JSON.
    for (unsigned char c:value) {
        if(c=='"'||c=='\\') out << '\\' << c;
        else if(c<32) out << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << unsigned(c) << std::dec;
        else out << c;
    }
    out << '"';return out.str();
}
std::string json(const Inspection& r) {
    std::ostringstream out;
    out << "{\"version\":1,\"format\":" << quoted(r.format) << ",\"state\":" << quoted(r.state)
        << ",\"reason\":" << quoted(r.reason) << ",\"previewablePDF\":" << (r.previewablePDF?"true":"false") << ",\"signatures\":[";
    bool first=true;
    for(const auto& s:r.signatures) {
        if(!first) out << ','; first=false;
        out << "{\"integrity\":" << quoted(s.integrity) << ",\"reason\":" << quoted(s.reason)
            << ",\"subject\":" << quoted(s.subject) << ",\"issuer\":" << quoted(s.issuer)
            << ",\"fingerprint\":" << quoted(s.fingerprint) << ",\"algorithm\":" << quoted(s.algorithm)
            << ",\"declaredTime\":" << quoted(s.declaredTime) << ",\"revisionEnd\":" << s.revisionEnd
            << ",\"layer\":" << s.layer << ",\"laterChanges\":" << (s.laterChanges?"true":"false") << '}';
    }
    out << "]}";return out.str();
}
bool writeAll(const void* data,size_t n) {
    auto p=static_cast<const uint8_t*>(data);
    while(n) {auto count=write(STDOUT_FILENO,p,n);if(count<0&&errno==EINTR)continue;if(count<=0)return false;p+=count;n-=count;}return true;
}
bool writeCount(size_t n) {uint8_t b[4]={uint8_t(n>>24),uint8_t(n>>16),uint8_t(n>>8),uint8_t(n)};return writeAll(b,4);}
}

std::vector<InspectedSignature> inspectCMS(const Bytes& bytes,const Bytes* detached,Bytes* payload) {
    auto cms=decode(bytes,detached!=nullptr);
    auto infos=CMS_get0_SignerInfos(cms.get());
    int count=infos?sk_CMS_SignerInfo_num(infos):0;
    if(count<1||count>32) throw std::runtime_error("Numero firmatari CMS non supportato (1–32)");
    auto certs=CMS_get1_certs(cms.get());
    int certificates=certs?sk_X509_num(certs):0;
    if(certs)sk_X509_pop_free(certs,X509_free);
    if(certificates>64) throw std::runtime_error("Troppi certificati CMS");
    CMS_set1_signers_certs(cms.get(),nullptr,0);
    bool needsContent=CMS_is_detached(cms.get())==1 && !detached;
    bool supportedContent=OBJ_obj2nid(CMS_get0_eContentType(cms.get()))==NID_pkcs7_data;
    BIO* input=detached?BIO_new_mem_buf(detached->data(),static_cast<int>(detached->size())):nullptr;
    std::unique_ptr<BIO,decltype(&BIO_free_all)> chain(nullptr,BIO_free_all);
    bool contentRead=false;
    if(!needsContent && supportedContent) {
        chain.reset(CMS_dataInit(cms.get(),input));
        if(!chain && input) BIO_free(input);
        if(chain) {
            std::array<uint8_t,65536> chunk{};size_t total=0;int n;
            while((n=BIO_read(chain.get(),chunk.data(),chunk.size()))>0) {
                if(size_t(n)>maxOutput-total)throw std::runtime_error("Contenuto CMS oltre il limite");
                total+=n;if(payload)payload->insert(payload->end(),chunk.begin(),chunk.begin()+n);
            }
            contentRead=n==0;
        }
    } else if(input)BIO_free(input);
    std::vector<InspectedSignature> result;
    for(int i=0;i<count;++i) {
        auto info=sk_CMS_SignerInfo_value(infos,i);InspectedSignature s;
        X509* cert=nullptr;X509_ALGOR *digest=nullptr,*algorithm=nullptr;
        CMS_SignerInfo_get0_algs(info,nullptr,&cert,&digest,&algorithm);
        s.algorithm=oid(algorithm?algorithm->algorithm:nullptr)+" / "+oid(digest?digest->algorithm:nullptr);
        if(cert) {
            s.subject=name(X509_get_subject_name(cert));s.issuer=name(X509_get_issuer_name(cert));
            unsigned char hash[EVP_MAX_MD_SIZE];unsigned int length=0;
            if(X509_digest(cert,EVP_sha256(),hash,&length)) {std::ostringstream h;for(unsigned int j=0;j<length;++j)h<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(hash[j]);s.fingerprint=h.str();}
        }
        auto when=CMS_signed_get0_data_by_OBJ(info,OBJ_nid2obj(NID_pkcs9_signingTime),-3,V_ASN1_UTCTIME);
        if(!when)when=CMS_signed_get0_data_by_OBJ(info,OBJ_nid2obj(NID_pkcs9_signingTime),-3,V_ASN1_GENERALIZEDTIME);
        if(when) {std::unique_ptr<BIO,decltype(&BIO_free)> b(BIO_new(BIO_s_mem()),BIO_free);if(b){ASN1_TIME_print(b.get(),static_cast<ASN1_TIME*>(when));s.declaredTime=bioString(b.get());}}
        int hash=digest?OBJ_obj2nid(digest->algorithm):NID_undef;
        int signatureAlgorithm=algorithm?OBJ_obj2nid(algorithm->algorithm):NID_undef;
        EVP_PKEY* key=cert?X509_get0_pubkey(cert):nullptr;
        const bool rsaAlgorithm=signatureAlgorithm==NID_rsaEncryption || signatureAlgorithm==NID_rsassaPss ||
            (signatureAlgorithm==NID_sha256WithRSAEncryption&&hash==NID_sha256) ||
            (signatureAlgorithm==NID_sha384WithRSAEncryption&&hash==NID_sha384) ||
            (signatureAlgorithm==NID_sha512WithRSAEncryption&&hash==NID_sha512);
        const bool ecAlgorithm=(signatureAlgorithm==NID_ecdsa_with_SHA256&&hash==NID_sha256) ||
            (signatureAlgorithm==NID_ecdsa_with_SHA384&&hash==NID_sha384) ||
            (signatureAlgorithm==NID_ecdsa_with_SHA512&&hash==NID_sha512);
        bool algorithmSupported=key &&
            (((EVP_PKEY_is_a(key,"RSA")||EVP_PKEY_is_a(key,"RSA-PSS"))&&rsaAlgorithm) || (EVP_PKEY_is_a(key,"EC")&&ecAlgorithm)) &&
            (hash==NID_sha256||hash==NID_sha384||hash==NID_sha512);
        if(needsContent)s.reason="Firma detached: serve il contenuto esterno, non caricato automaticamente";
        else if(!supportedContent)s.reason="Tipo di contenuto CMS non supportato";
        else if(!cert)s.reason="Certificato del firmatario assente";
        else if(!algorithmSupported)s.reason="Algoritmo non supportato dalla policy di verifica locale";
        else if(!contentRead)s.reason="Impossibile elaborare il contenuto CMS";
        else {
            ERR_clear_error();
            // Same OpenSSL checks used by CMS_verify, evaluated per SignerInfo.
            const bool attributes=CMS_signed_get_attr_count(info)<0 || CMS_SignerInfo_verify(info)>0;
            const bool content=CMS_SignerInfo_verify_content(info,chain.get())>0;
            s.integrity=attributes&&content?"verified":"invalid";
            if(s.integrity=="invalid")s.reason="Digest del contenuto o firma crittografica non corrispondente";
        }
        result.push_back(std::move(s));
    }
    ERR_clear_error();return result;
}

int verificationMain() {
    // A read-only entry point, before any provider/PIN/signing argument handling.
    // macOS rejects finite RLIMIT_DATA/RLIMIT_AS. The parent samples RSS and
    // kills this disposable process at its configured memory threshold.
    rlimit cpu{25,25},files{0,0};
    if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_FSIZE,&files)||fcntl(STDIN_FILENO,F_SETFD,FD_CLOEXEC))return 2;
    int sink=open("/dev/null",O_WRONLY|O_CLOEXEC);if(sink<0||dup2(sink,STDERR_FILENO)<0)return 2;close(sink);
    Bytes bytes;std::array<uint8_t,65536> buffer{};
    while(true) {auto n=read(STDIN_FILENO,buffer.data(),buffer.size());if(n<0&&errno==EINTR)continue;if(n<0)return 2;if(!n)break;if(size_t(n)>maxOutput-bytes.size())return 2;bytes.insert(bytes.end(),buffer.begin(),buffer.begin()+n);}
    Inspection report;
    try {
        auto head=std::string(bytes.begin(),bytes.begin()+std::min<size_t>(bytes.size(),1024));
        if(!bytes.empty() && bytes[0]!=0x30 && head.find("%PDF-")!=std::string::npos) {report.format="pades";report=inspectPAdES(bytes);}
        else if(!bytes.empty()&&bytes[0]==0x30) {
            report.format="cades";report.state="signed";Bytes current=bytes;
            for(size_t layer=1;layer<=5;++layer) {
                Bytes payload;auto entries=inspectCMS(current,nullptr,&payload);
                if(entries.size()+report.signatures.size()>32)throw std::runtime_error("Troppi firmatari annidati");
                for(auto& s:entries){s.layer=layer;report.signatures.push_back(std::move(s));}
                const bool allVerified=std::all_of(report.signatures.begin(),report.signatures.end(),[](const auto& s){return s.integrity=="verified";});
                if(!allVerified)break;
                bool nested=false;try{auto inner=decode(payload,false);nested=true;}catch(...){}
                if(!nested){
                    // Only preview a PDF validated by the isolated parser.
                    // Other content can be exported after an explicit user
                    // request; never open/execute it or choose its destination.
                    report.previewablePDF=isPreviewablePDF(payload);
                    report.content=std::move(payload);
                    break;
                }
                if(layer==5)throw std::runtime_error("Superato il limite di cinque livelli CMS");
                current=std::move(payload);
            }
        } else if(head.find('<')!=std::string::npos) {report.format="xml";report.reason="XML/XAdES non supportato in questa versione";}
        else report.reason="Formato non riconosciuto";
    } catch(const std::exception& error) {
        report.reason=error.what();
        report.state=report.reason.find("Tipo CMS non supportato")==0 || report.reason.find("Encrypted PDFs")==0 || report.reason.find("Unsupported PDF page count")==0 ? "unsupported":"damaged";
        if(report.reason.find("Tipo CMS non supportato")==0)report.format="unknown";
        report.content.clear();
    }
    auto metadata=json(report);
    if(metadata.size()>256*1024)return 2;
    return writeCount(metadata.size())&&writeCount(report.content.size())&&writeAll(metadata.data(),metadata.size())&&writeAll(report.content.data(),report.content.size())?0:2;
}
}
