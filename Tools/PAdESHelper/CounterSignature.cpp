#include "UnifiedVerification.h"
#include <openssl/pkcs7.h>
#include <openssl/asn1t.h>
#include <openssl/ess.h>
#include <memory>
#include <set>
#include <stdexcept>
namespace signum {
namespace {
Bytes wrap(unsigned char tag,const Bytes& input) {
    if(input.size()>8*1024*1024)throw std::runtime_error("Metadati controfirma oltre il limite");
    Bytes out{tag};size_t n=input.size();
    if(n<128)out.push_back(n);else {Bytes length;while(n){length.insert(length.begin(),n&255);n>>=8;}out.push_back(0x80|length.size());out.insert(out.end(),length.begin(),length.end());}
    out.insert(out.end(),input.begin(),input.end());return out;
}
Bytes join(std::initializer_list<Bytes> values) {Bytes out;for(const auto& v:values)out.insert(out.end(),v.begin(),v.end());return out;}
}
Bytes counterEnvelope(const Bytes& signer,const Bytes& target,CMS_ContentInfo* source) {
    if(signer.empty()||signer.size()>1024*1024)throw std::runtime_error("Controfirma oltre il limite");
    auto p=signer.data();std::unique_ptr<PKCS7_SIGNER_INFO,decltype(&PKCS7_SIGNER_INFO_free)> si(d2i_PKCS7_SIGNER_INFO(nullptr,&p,signer.size()),PKCS7_SIGNER_INFO_free);
    if(!si||p!=signer.data()+signer.size())throw std::runtime_error("SignerInfo controfirma malformato");
    int length=si->digest_alg?i2d_X509_ALGOR(si->digest_alg,nullptr):0;
    if(length<1||length>1024)throw std::runtime_error("Algoritmo controfirma malformato");
    Bytes algorithm(length);auto a=algorithm.data();i2d_X509_ALGOR(si->digest_alg,&a);
    Bytes certificates;auto certs=CMS_get1_certs(source);
    if(certs) {
        try {for(int i=0;i<sk_X509_num(certs);++i){auto cert=sk_X509_value(certs,i);int n=i2d_X509(cert,nullptr);if(n<1||n>65536||i>=64)throw std::runtime_error("Limite certificati controfirma");Bytes b(n);auto q=b.data();i2d_X509(cert,&q);certificates.insert(certificates.end(),b.begin(),b.end());}}
        catch(...){sk_X509_pop_free(certs,X509_free);throw;}
        sk_X509_pop_free(certs,X509_free);
    }
    const Bytes dataOID{6,9,42,134,72,134,247,13,1,7,1},signedOID{6,9,42,134,72,134,247,13,1,7,2};
    auto content=wrap(0x30,join({dataOID,wrap(0xa0,wrap(4,target))}));
    auto signedData=wrap(0x30,join({Bytes{2,1,1},wrap(0x31,algorithm),content,wrap(0xa0,certificates),wrap(0x31,signer)}));
    return wrap(0x30,join({signedOID,wrap(0xa0,signedData)}));
}
int verifyCounterSignature(CMS_SignerInfo* si,X509* cert,const Bytes& target) {
    if(!cert)return 0;
    X509_ALGOR *digest=nullptr,*signature=nullptr;CMS_SignerInfo_get0_algs(si,nullptr,nullptr,&digest,&signature);
    EVP_PKEY* key=X509_get0_pubkey(cert);
    if(!digest||!signature||OBJ_obj2nid(digest->algorithm)!=NID_sha256||OBJ_obj2nid(signature->algorithm)!=NID_rsaEncryption||!key||!EVP_PKEY_is_a(key,"RSA")||EVP_PKEY_get_bits(key)<2048||EVP_PKEY_get_bits(key)>8192)return 0;
    int count=CMS_signed_get_attr_count(si);if(count<1||count>64)return 0;
    STACK_OF(X509_ATTRIBUTE)* attrs=sk_X509_ATTRIBUTE_new_null();if(!attrs)return 0;
    std::unique_ptr<STACK_OF(X509_ATTRIBUTE),void(*)(STACK_OF(X509_ATTRIBUTE)*)> owned(attrs,[](STACK_OF(X509_ATTRIBUTE)* p){sk_X509_ATTRIBUTE_free(p);});
    std::set<std::string> seen;
    size_t total=0;bool hasDigest=false,hasESS=false;
    for(int i=0;i<count;++i) {
        auto attr=CMS_signed_get_attr(si,i);char oid[128];int len=OBJ_obj2txt(oid,sizeof(oid),X509_ATTRIBUTE_get0_object(attr),1);
        if(len<=0||len>=int(sizeof(oid))||!seen.insert(oid).second)return -1;
        int size=i2d_X509_ATTRIBUTE(attr,nullptr);if(size<=0||size>1024*1024||size_t(size)>1024*1024-total)return 0;total+=size;
        if(!sk_X509_ATTRIBUTE_push(attrs,attr))return 0;
        int nid=OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr));
        if(nid==NID_pkcs9_contentType||nid==NID_pkcs9_countersignature)return -1;
        if(nid==NID_pkcs9_messageDigest) {
            if(X509_ATTRIBUTE_count(attr)!=1)return -1;auto v=X509_ATTRIBUTE_get0_type(attr,0);
            unsigned char hash[32];unsigned int n=0;
            if(!v||v->type!=V_ASN1_OCTET_STRING||ASN1_STRING_length(v->value.octet_string)!=32||EVP_Digest(target.data(),target.size(),hash,&n,EVP_sha256(),nullptr)!=1||CRYPTO_memcmp(hash,ASN1_STRING_get0_data(v->value.octet_string),32))return -1;
            hasDigest=true;
        }
        if(nid==NID_id_smime_aa_signingCertificateV2) {
            if(X509_ATTRIBUTE_count(attr)!=1)return -1;auto v=X509_ATTRIBUTE_get0_type(attr,0);if(!v||v->type!=V_ASN1_SEQUENCE)return -1;
            auto p=ASN1_STRING_get0_data(v->value.sequence);int n=ASN1_STRING_length(v->value.sequence);auto begin=p;
            std::unique_ptr<ESS_SIGNING_CERT_V2,decltype(&ESS_SIGNING_CERT_V2_free)> ess(d2i_ESS_SIGNING_CERT_V2(nullptr,&p,n),ESS_SIGNING_CERT_V2_free);
            STACK_OF(X509)* chain=sk_X509_new_null();if(!chain)return 0;
            if(!sk_X509_push(chain,cert)){sk_X509_free(chain);return 0;}
            int ok=ess&&p==begin+n?OSSL_ESS_check_signing_certs(nullptr,ess.get(),chain,1):0;sk_X509_free(chain);
            if(ok!=1)return -1;hasESS=true;
        }
    }
    if(!hasDigest)return -1;if(!hasESS)return 0;
    unsigned char* der=nullptr;int n=ASN1_item_i2d(reinterpret_cast<ASN1_VALUE*>(attrs),&der,ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));
    if(n<=0){OPENSSL_free(der);return 0;}
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    auto value=CMS_SignerInfo_get0_signature(si);
    int ok=ctx&&value&&EVP_DigestVerifyInit(ctx.get(),nullptr,EVP_sha256(),nullptr,key)==1?EVP_DigestVerify(ctx.get(),ASN1_STRING_get0_data(value),ASN1_STRING_length(value),der,n):0;
    OPENSSL_free(der);return ok==1?1:-1;
}
}
