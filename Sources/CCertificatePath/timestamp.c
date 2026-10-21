#include "CRevocationEvidence.h"
#include <openssl/ts.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "evidence_policy.h"
// The result intentionally exposes token authentication rather than a trusted
// signature time: TL authorization and TSA revocation are separate obligations.
int signum_timestamp_token(const uint8_t *bytes,size_t size,const uint8_t *data,size_t data_size,
    const uint8_t *anchor_bytes,size_t anchor_size,int64_t now,int64_t *generated,char *reason,size_t capacity) {
    const char *why="Marca temporale fuori dai limiti o non supportata";int result=0;
    PKCS7 *token=NULL;TS_TST_INFO *info=NULL;TS_VERIFY_CTX *ctx=NULL;X509_STORE *store=NULL;X509 *anchor=NULL;
    if(!generated||!reason||!capacity)return 0;*generated=0;
    if(!bytes||!size||size>1024*1024||!data||!data_size||data_size>16384||!anchor_bytes||!anchor_size||anchor_size>65536||now<=0||now>253402300799LL)goto done;
    const unsigned char *p=bytes;token=d2i_PKCS7(NULL,&p,(long)size);
    if(!token||p!=bytes+size){result=-1;why="Token RFC 3161 DER malformato";goto done;}
    if(!PKCS7_type_is_signed(token)||!token->d.sign||PKCS7_get_detached(token)||sk_X509_num(token->d.sign->cert)>16)goto done;
    STACK_OF(PKCS7_SIGNER_INFO) *signers=PKCS7_get_signer_info(token);
    if(!signers||sk_PKCS7_SIGNER_INFO_num(signers)!=1)goto done;
    PKCS7_SIGNER_INFO *signer=sk_PKCS7_SIGNER_INFO_value(signers,0);
    int md=OBJ_obj2nid(signer->digest_alg->algorithm);
    if(md!=NID_sha256&&md!=NID_sha384&&md!=NID_sha512)goto done;
    for(int i=0;i<sk_X509_num(token->d.sign->cert);i++) {
        EVP_PKEY *key=X509_get0_pubkey(sk_X509_value(token->d.sign->cert,i));
        if(!signum_evidence_key(key))goto done;
    }
    info=PKCS7_to_TS_TST_INFO(token);
    if(!info||TS_TST_INFO_get_version(info)!=1){result=-1;why="TSTInfo RFC 3161 malformato o versione errata";goto done;}
    if(TS_TST_INFO_get_ext_count(info)>0)goto done;
    TS_MSG_IMPRINT *imprint=TS_TST_INFO_get_msg_imprint(info);
    int hash=imprint?OBJ_obj2nid(TS_MSG_IMPRINT_get_algo(imprint)->algorithm):NID_undef;
    if(hash!=NID_sha256&&hash!=NID_sha384&&hash!=NID_sha512)goto done;
    struct tm tm;memset(&tm,0,sizeof(tm));
    const ASN1_GENERALIZEDTIME *time=TS_TST_INFO_get_time(info);
    if(!time||!ASN1_TIME_to_tm((const ASN1_TIME *)time,&tm)){result=-1;why="genTime RFC 3161 non valido";goto done;}
    int64_t at=(int64_t)timegm(&tm);
    // This subset handles whole seconds, avoiding silent loss of fractional
    // precision when assessing certificate/TL boundaries.
    if(at<=0||at>now||ASN1_STRING_length(time)!=15){result=0;why="genTime futuro o precisione temporale non supportata";goto done;}
    p=anchor_bytes;anchor=d2i_X509(NULL,&p,(long)anchor_size);
    if(!anchor||p!=anchor_bytes+anchor_size)goto done;
    EVP_PKEY *anchor_key=X509_get0_pubkey(anchor);
    if(!signum_evidence_key(anchor_key))goto done;
    store=X509_STORE_new();ctx=TS_VERIFY_CTX_new();
    if(!store||!ctx||!X509_STORE_add_cert(store,anchor))goto done;
    X509_VERIFY_PARAM *param=X509_STORE_get0_param(store);
    X509_VERIFY_PARAM_set_time(param,(time_t)at);X509_VERIFY_PARAM_set_auth_level(param,2);X509_VERIFY_PARAM_set_depth(param,12);
    X509_VERIFY_PARAM_set_flags(param,X509_V_FLAG_PARTIAL_CHAIN|X509_V_FLAG_X509_STRICT|X509_V_FLAG_CHECK_SS_SIGNATURE);
    if(!TS_VERIFY_CTX_set0_store(ctx,store))goto done;store=NULL; // ownership transferred
    TS_VERIFY_CTX_set_flags(ctx,TS_VFY_SIGNATURE|TS_VFY_VERSION|TS_VFY_DATA|TS_VFY_SIGNER);
    BIO *input=BIO_new_mem_buf(data,(int)data_size);
    if(!input)goto done;
    if(!TS_VERIFY_CTX_set0_data(ctx,input)){BIO_free(input);goto done;} // ownership transferred
    if(TS_RESP_verify_token(ctx,token)!=1){result=-1;why="Firma, ESSCertID, TSA o impronta della marca non verificati";goto done;}
    *generated=at;result=1;why="Token RFC 3161 autenticato rispetto all’identità TSA esplicita; revoca TSA e autorizzazione TL da verificare";
done:
    snprintf(reason,capacity,"%s",why);TS_VERIFY_CTX_free(ctx);X509_STORE_free(store);X509_free(anchor);
    TS_TST_INFO_free(info);PKCS7_free(token);ERR_clear_error();return result;
}
