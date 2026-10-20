#include "CRevocationEvidence.h"
#include "evidence_policy.h"
#include <openssl/ts.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
static X509* decode(const uint8_t* bytes,size_t size) {
 if(!bytes||!size||size>65536)return NULL;const unsigned char*p=bytes;X509*x=d2i_X509(NULL,&p,(long)size);
 if(x&&p!=bytes+size){X509_free(x);return NULL;}return x;
}
static int append(X509*x,uint8_t*out,size_t capacity,size_t*used) {
 int n=i2d_X509(x,NULL);if(n<=0||n>65536||*used>capacity||capacity-*used<(size_t)n+4)return 0;
 out[(*used)++]=(uint8_t)(n>>24);out[(*used)++]=(uint8_t)(n>>16);out[(*used)++]=(uint8_t)(n>>8);out[(*used)++]=(uint8_t)n;
 unsigned char*p=out+*used;if(i2d_X509(x,&p)!=n)return 0;*used+=(size_t)n;return 1;
}
int signum_timestamp_inspect(const uint8_t*bytes,size_t size,const uint8_t*value,size_t value_size,int64_t*at,int64_t*accuracy,uint8_t*out,size_t capacity,size_t*used) {
 int result=-1;PKCS7*token=NULL;TS_TST_INFO*info=NULL;STACK_OF(X509)*signers=NULL;
 if(!at||!accuracy||!used||!out)return -1;*at=0;*accuracy=0;*used=0;
 if(!bytes||!size||size>1024*1024||!value||!value_size||value_size>16384)return -1;
 const unsigned char*p=bytes;token=d2i_PKCS7(NULL,&p,(long)size);
 if(!token||p!=bytes+size||!PKCS7_type_is_signed(token)||!token->d.sign||sk_X509_num(token->d.sign->cert)>16)goto done;
 info=PKCS7_to_TS_TST_INFO(token);if(!info||TS_TST_INFO_get_version(info)!=1)goto done;
 TS_MSG_IMPRINT*imprint=TS_TST_INFO_get_msg_imprint(info);if(!imprint)goto done;
 int nid=OBJ_obj2nid(TS_MSG_IMPRINT_get_algo(imprint)->algorithm);
 const EVP_MD*md=nid==NID_sha256?EVP_sha256():nid==NID_sha384?EVP_sha384():nid==NID_sha512?EVP_sha512():NULL;
 if(!md){result=0;goto done;}
 unsigned char digest[EVP_MAX_MD_SIZE];unsigned int n=0;const ASN1_OCTET_STRING*claimed=TS_MSG_IMPRINT_get_msg(imprint);
 if(!EVP_Digest(value,value_size,digest,&n,md,NULL)||ASN1_STRING_length(claimed)!=(int)n||CRYPTO_memcmp(digest,ASN1_STRING_get0_data(claimed),n))goto done;
 const ASN1_GENERALIZEDTIME*time=TS_TST_INFO_get_time(info);struct tm t;memset(&t,0,sizeof(t));
 if(!time||ASN1_STRING_length(time)!=15||!ASN1_TIME_to_tm((const ASN1_TIME*)time,&t)){result=0;goto done;}
 TS_ACCURACY*a=TS_TST_INFO_get_accuracy(info);
 if(!a){result=0;goto done;}
 const ASN1_INTEGER*seconds=TS_ACCURACY_get_seconds(a),*millis=TS_ACCURACY_get_millis(a),*micros=TS_ACCURACY_get_micros(a);
 long sec=seconds?ASN1_INTEGER_get(seconds):0,ms=millis?ASN1_INTEGER_get(millis):0,us=micros?ASN1_INTEGER_get(micros):0;
 if(sec<0||sec>60||ms<0||ms>999||us<0||us>999||(millis&&ms==0)||(micros&&us==0)){result=0;goto done;}
 *accuracy=(int64_t)sec*1000000+ms*1000+us;
 *at=(int64_t)timegm(&t);if(*at<=0)goto done;
 signers=PKCS7_get0_signers(token,NULL,0);if(!signers||sk_X509_num(signers)!=1)goto done;
 X509*leaf=sk_X509_value(signers,0);if(!append(leaf,out,capacity,used))goto done;
 for(int i=0;i<sk_X509_num(token->d.sign->cert);i++) {
  X509*x=sk_X509_value(token->d.sign->cert,i);if(X509_cmp(leaf,x)&&!append(x,out,capacity,used))goto done;
 }
 result=1;
done:if(result!=1){*used=0;*at=0;}sk_X509_free(signers);TS_TST_INFO_free(info);PKCS7_free(token);ERR_clear_error();return result;
}
int signum_certificate_issued_by(const uint8_t*c,size_t n,const uint8_t*i,size_t z) {
 X509*cert=decode(c,n),*issuer=decode(i,z);int ok=cert&&issuer&&signum_evidence_key(X509_get0_pubkey(issuer))&&
 X509_check_issued(issuer,cert)==X509_V_OK&&X509_verify(cert,X509_get0_pubkey(issuer))==1;
 X509_free(cert);X509_free(issuer);ERR_clear_error();return ok;
}
int signum_ocsp_request(const uint8_t*c,size_t n,const uint8_t*i,size_t z,uint8_t*out,size_t capacity,size_t*used) {
 int ok=0;X509*cert=decode(c,n),*issuer=decode(i,z);OCSP_REQUEST*request=NULL;OCSP_CERTID*id=NULL;
 if(!used||!out)goto done;*used=0;if(!cert||!issuer)goto done;
 id=OCSP_cert_to_id(EVP_sha256(),cert,issuer);request=OCSP_REQUEST_new();
 if(!id||!request||!OCSP_request_add0_id(request,id))goto done;id=NULL;
 int length=i2d_OCSP_REQUEST(request,NULL);if(length<1||(size_t)length>capacity)goto done;
 unsigned char*p=out;if(i2d_OCSP_REQUEST(request,&p)!=length)goto done;*used=(size_t)length;ok=1;
done:OCSP_CERTID_free(id);OCSP_REQUEST_free(request);X509_free(cert);X509_free(issuer);ERR_clear_error();return ok;
}
static int location(char*out,size_t capacity,size_t*used,const char*kind,const ASN1_IA5STRING*url) {
 int n=ASN1_STRING_length(url);const unsigned char*p=ASN1_STRING_get0_data(url);
 if(n<1||n>2048)return 0;for(int i=0;i<n;i++)if(p[i]<33||p[i]>126)return 0;
 if(*used+(size_t)n+4>=capacity)return 0;out[(*used)++]=*kind;out[(*used)++]=' ';memcpy(out+*used,p,n);*used+=(size_t)n;out[(*used)++]='\n';out[*used]=0;return 1;
}
int signum_revocation_locations(const uint8_t*c,size_t n,char*out,size_t capacity) {
 X509*cert=decode(c,n);size_t used=0;int count=0,critical=-1;if(!out||!capacity)return 0;out[0]=0;if(!cert)return 0;
 AUTHORITY_INFO_ACCESS*aia=X509_get_ext_d2i(cert,NID_info_access,&critical,NULL);
 if(critical!=-2)for(int i=0;aia&&i<sk_ACCESS_DESCRIPTION_num(aia)&&count<8;i++) {
  ACCESS_DESCRIPTION*a=sk_ACCESS_DESCRIPTION_value(aia,i);if(OBJ_obj2nid(a->method)==NID_ad_OCSP&&a->location->type==GEN_URI)count+=location(out,capacity,&used,"O",a->location->d.uniformResourceIdentifier);
 }
 AUTHORITY_INFO_ACCESS_free(aia);
 CRL_DIST_POINTS*cdp=X509_get_ext_d2i(cert,NID_crl_distribution_points,&critical,NULL);
 if(critical!=-2)for(int i=0;cdp&&i<sk_DIST_POINT_num(cdp)&&count<8;i++) {
  DIST_POINT*d=sk_DIST_POINT_value(cdp,i);if(!d->distpoint||d->distpoint->type!=0||d->CRLissuer||d->reasons)continue;
  GENERAL_NAMES*names=d->distpoint->name.fullname;
  for(int j=0;j<sk_GENERAL_NAME_num(names)&&count<8;j++){GENERAL_NAME*g=sk_GENERAL_NAME_value(names,j);if(g->type==GEN_URI)count+=location(out,capacity,&used,"C",g->d.uniformResourceIdentifier);}
 }
 CRL_DIST_POINTS_free(cdp);X509_free(cert);return count;
}

int signum_revocation_targets(int kind,const uint8_t*bytes,size_t size,const uint8_t*c,size_t n,const uint8_t*i,size_t z) {
 int match=0;X509*cert=decode(c,n),*issuer=decode(i,z);OCSP_RESPONSE*response=NULL;OCSP_BASICRESP*basic=NULL;X509_CRL*crl=NULL;
 if(!bytes||!size||size>8*1024*1024||!cert||!issuer)goto done;const unsigned char*p=bytes;
 if(kind==1){
  response=d2i_OCSP_RESPONSE(NULL,&p,(long)size);if(!response||p!=bytes+size)goto done;
  basic=OCSP_response_get1_basic(response);if(!basic||OCSP_resp_count(basic)>128)goto done;
  for(int j=0;j<OCSP_resp_count(basic);j++){
   const OCSP_CERTID*id=OCSP_SINGLERESP_get0_id(OCSP_resp_get0(basic,j));ASN1_OBJECT*oid=NULL;
   if(!OCSP_id_get0_info(NULL,&oid,NULL,NULL,(OCSP_CERTID*)id))continue;
   int nid=OBJ_obj2nid(oid);const EVP_MD*md=nid==NID_sha1?EVP_sha1():nid==NID_sha256?EVP_sha256():NULL;if(!md)continue;
   OCSP_CERTID*expected=OCSP_cert_to_id(md,cert,issuer);if(expected&&!OCSP_id_cmp(expected,id))match++;OCSP_CERTID_free(expected);
  }
 }else if(kind==2){
  crl=d2i_X509_CRL(NULL,&p,(long)size);if(crl&&p==bytes+size&&!X509_NAME_cmp(X509_CRL_get_issuer(crl),X509_get_subject_name(issuer)))match=1;
 }
 done:X509_free(cert);X509_free(issuer);OCSP_RESPONSE_free(response);OCSP_BASICRESP_free(basic);X509_CRL_free(crl);ERR_clear_error();return match==1;
}
