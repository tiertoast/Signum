#include "EvidenceExtraction.h"
#include <openssl/asn1t.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <memory>
#include <iomanip>
#include <sstream>
DEFINE_STACK_OF(OCSP_BASICRESP)
namespace signum {
namespace {
// ETSI RevocationValues: only explicitly typed CRL and BasicOCSPResponse values.
typedef struct { STACK_OF(X509_CRL)* crls; STACK_OF(OCSP_BASICRESP)* ocsps; ASN1_TYPE* other; } RevocationValues;
ASN1_SEQUENCE(RevocationValues) = {
 ASN1_EXP_SEQUENCE_OF_OPT(RevocationValues, crls, X509_CRL, 0),
 ASN1_EXP_SEQUENCE_OF_OPT(RevocationValues, ocsps, OCSP_BASICRESP, 1),
 ASN1_EXP_OPT(RevocationValues, other, ASN1_ANY, 2)
} ASN1_SEQUENCE_END(RevocationValues)
RevocationValues* d2i_RevocationValues(RevocationValues**,const unsigned char** p,long n) {
 return reinterpret_cast<RevocationValues*>(ASN1_item_d2i(nullptr,p,n,ASN1_ITEM_rptr(RevocationValues)));
}
void RevocationValues_free(RevocationValues* value) { ASN1_item_free(reinterpret_cast<ASN1_VALUE*>(value),ASN1_ITEM_rptr(RevocationValues)); }
void bounded(int n) { if(n<1||n>1024*1024)throw std::runtime_error("Evidenza o attributo oltre 1 MiB"); }
template<typename T,typename Encoder> std::string encoded(T* value,Encoder encode) {
 int n=encode(value,nullptr);bounded(n);std::vector<unsigned char> bytes(n);auto p=bytes.data();
 if(encode(value,&p)!=n)throw std::runtime_error("Evidenza DER non codificabile");return evidenceBase64(bytes.data(),bytes.size());
}
void values(const ASN1_STRING* sequence,InspectedSignature& s) {
 const auto* begin=ASN1_STRING_get0_data(sequence);auto p=begin;int n=ASN1_STRING_length(sequence);bounded(n);
 std::unique_ptr<RevocationValues,decltype(&RevocationValues_free)> values(d2i_RevocationValues(nullptr,&p,n),RevocationValues_free);
 if(!values||p!=begin+n)throw std::runtime_error("revocationValues malformato");
 if(sk_X509_CRL_num(values->crls)>16||sk_OCSP_BASICRESP_num(values->ocsps)>16)throw std::runtime_error("Troppe evidenze incorporate");
 for(int i=0;i<sk_X509_CRL_num(values->crls);i++)s.evidence.push_back({"crl","cmsRevocationValues","signerInfo",encoded(sk_X509_CRL_value(values->crls,i),i2d_X509_CRL),s.signatureKey});
 for(int i=0;i<sk_OCSP_BASICRESP_num(values->ocsps);i++) {
  std::unique_ptr<OCSP_RESPONSE,decltype(&OCSP_RESPONSE_free)> r(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL,sk_OCSP_BASICRESP_value(values->ocsps,i)),OCSP_RESPONSE_free);
  if(!r)throw std::runtime_error("BasicOCSPResponse non convertibile");
  s.evidence.push_back({"ocsp","cmsRevocationValues","signerInfo",encoded(r.get(),i2d_OCSP_RESPONSE),s.signatureKey});
 }
 if(values->other)s.evidenceIssue="Altre evidenze revocationValues non supportate";
}
}
std::string evidenceBase64(const unsigned char* bytes,size_t n) {
 if(n>1024*1024)throw std::runtime_error("Evidenza oltre 1 MiB");
 std::string result(4*((n+2)/3)+1,'\0');int z=EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()),bytes,int(n));result.resize(z);return result;
}
std::string evidenceDigest(const unsigned char* bytes,size_t n,const EVP_MD* md) {
 unsigned char out[EVP_MAX_MD_SIZE];unsigned int count=0;
 if(EVP_Digest(bytes,n,out,&count,md,nullptr)!=1)throw std::runtime_error("Digest evidenza non disponibile");
 std::ostringstream s;for(unsigned int i=0;i<count;i++)s<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(out[i]);return s.str();
}
void inspectSignerEvidence(CMS_SignerInfo* info,InspectedSignature& s) {
 auto value=CMS_SignerInfo_get0_signature(info);int n=value?ASN1_STRING_length(value):0;
 if(n<=0||n>16384)throw std::runtime_error("SignatureValue fuori dai limiti");
 const auto* bytes=ASN1_STRING_get0_data(value);s.signatureValue=evidenceBase64(bytes,n);
 s.signatureKey=evidenceDigest(bytes,n,EVP_sha256());
 for(bool isSigned:{true,false}) {
  int count=isSigned?CMS_signed_get_attr_count(info):CMS_unsigned_get_attr_count(info);
  if(count>64)throw std::runtime_error("Troppi attributi SignerInfo");
  for(int i=0;i<count;i++) {
   auto attr=isSigned?CMS_signed_get_attr(info,i):CMS_unsigned_get_attr(info,i);
   char oid[128];OBJ_obj2txt(oid,sizeof(oid),X509_ATTRIBUTE_get0_object(attr),1);
   auto der=encoded(attr,i2d_X509_ATTRIBUTE);
   (isSigned?s.signedAttributes:s.unsignedAttributes).push_back({oid,der});
   if(isSigned)continue;
   bool timestamp=std::string(oid)=="1.2.840.113549.1.9.16.2.14", revocation=std::string(oid)=="1.2.840.113549.1.9.16.2.24";
   if(!timestamp&&!revocation)continue;
   int entries=X509_ATTRIBUTE_count(attr);if(entries>16)throw std::runtime_error("Troppi valori attributo");
   for(int j=0;j<entries;j++) {
    auto v=X509_ATTRIBUTE_get0_type(attr,j);
    if(!v||v->type!=V_ASN1_SEQUENCE)throw std::runtime_error("Attributo evidenza non SEQUENCE");
    if(timestamp) {
     if(s.timestampTokens.size()>=4)throw std::runtime_error("Troppe marche per SignerInfo");
     bounded(ASN1_STRING_length(v->value.sequence));s.timestampTokens.push_back(evidenceBase64(ASN1_STRING_get0_data(v->value.sequence),ASN1_STRING_length(v->value.sequence)));
    } else values(v->value.sequence,s);
   }
  }
 }
}
void inspectCMSEvidence(CMS_ContentInfo* cms,Inspection& report) {
 STACK_OF(X509_CRL)* crls=CMS_get1_crls(cms);
 if(!crls)return;
 try {
  if(sk_X509_CRL_num(crls)>16)throw std::runtime_error("Troppe CRL CMS globali");
  for(int i=0;i<sk_X509_CRL_num(crls);i++)report.unassociatedEvidence.push_back({"crl","cmsSignedData","unassociated",encoded(sk_X509_CRL_value(crls,i),i2d_X509_CRL),""});
 }catch(...){sk_X509_CRL_pop_free(crls,X509_CRL_free);throw;}
 sk_X509_CRL_pop_free(crls,X509_CRL_free);
}
}
