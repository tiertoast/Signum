// Development-only fixture composer. Never linked into the app/helper.
#include <openssl/cms.h>
#include <openssl/ocsp.h>
#include <openssl/evp.h>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <iomanip>
#include <sstream>
using Bytes=std::vector<unsigned char>;
Bytes read(const std::string& p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("read");return Bytes(std::istreambuf_iterator<char>(f),{});}
void write(const std::string&p,const Bytes&b){std::ofstream f(p,std::ios::binary);f.write((const char*)b.data(),b.size());if(!f)throw std::runtime_error("write");}
Bytes wrap(unsigned char tag,const Bytes&b){Bytes out{tag};if(b.size()<128)out.push_back(b.size());else{Bytes length;size_t n=b.size();while(n){length.insert(length.begin(),n&255);n>>=8;}out.push_back(0x80|length.size());out.insert(out.end(),length.begin(),length.end());}out.insert(out.end(),b.begin(),b.end());return out;}
int main(int argc,char**argv){try{
 if(argc<4)return 2;auto bytes=read(argv[2]);auto p=bytes.data();CMS_ContentInfo*cms=d2i_CMS_ContentInfo(nullptr,(const unsigned char**)&p,bytes.size());if(!cms)return 3;
 CMS_set1_signers_certs(cms,nullptr,0);auto infos=CMS_get0_SignerInfos(cms);
 for(int i=0;i<sk_CMS_SignerInfo_num(infos);i++){
  auto si=sk_CMS_SignerInfo_value(infos,i);X509*cert=nullptr;CMS_SignerInfo_get0_algs(si,nullptr,&cert,nullptr,nullptr);if(!cert)return 4;
  unsigned char hash[32];unsigned n=0;X509_digest(cert,EVP_sha256(),hash,&n);std::ostringstream h;for(unsigned j=0;j<n;j++)h<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(hash[j]);
  if(std::string(argv[1])=="extract") {auto value=CMS_SignerInfo_get0_signature(si);write(std::string(argv[3])+"/"+h.str()+".bin",Bytes(ASN1_STRING_get0_data(value),ASN1_STRING_get0_data(value)+ASN1_STRING_length(value)));continue;}
  if(argc<6||h.str()!=argv[4])continue;
  auto token=read(argv[5]);if(!CMS_unsigned_add1_attr_by_NID(si,NID_id_smime_aa_timeStampToken,V_ASN1_SEQUENCE,token.data(),int(token.size())))return 5;
  Bytes crls,ocsps;
  for(int a=6;a<argc;a++) {
   auto raw=read(argv[a]);const unsigned char*q=raw.data();
   if(std::string(argv[a]).find(".crl")!=std::string::npos) {crls.insert(crls.end(),raw.begin(),raw.end());continue;}
   OCSP_RESPONSE*r=d2i_OCSP_RESPONSE(nullptr,&q,raw.size());if(!r)return 6;OCSP_BASICRESP*b=OCSP_response_get1_basic(r);unsigned char*der=nullptr;int length=i2d_OCSP_BASICRESP(b,&der);if(length<=0)return 7;ocsps.insert(ocsps.end(),der,der+length);OPENSSL_free(der);OCSP_BASICRESP_free(b);OCSP_RESPONSE_free(r);
  }
  Bytes values;if(!crls.empty()){auto v=wrap(0xa0,wrap(0x30,crls));values.insert(values.end(),v.begin(),v.end());}if(!ocsps.empty()){auto v=wrap(0xa1,wrap(0x30,ocsps));values.insert(values.end(),v.begin(),v.end());}values=wrap(0x30,values);
  if(!CMS_unsigned_add1_attr_by_txt(si,"1.2.840.113549.1.9.16.2.24",V_ASN1_SEQUENCE,values.data(),int(values.size())))return 8;
 }
 if(std::string(argv[1])!="extract"){unsigned char*der=nullptr;int n=i2d_CMS_ContentInfo(cms,&der);if(n<=0)return 9;write(argv[3],Bytes(der,der+n));OPENSSL_free(der);}CMS_ContentInfo_free(cms);return 0;
}catch(...){return 10;}}
