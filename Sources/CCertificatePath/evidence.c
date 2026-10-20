#include "CRevocationEvidence.h"
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "evidence_policy.h"

static X509 *certificate(const uint8_t *bytes,size_t size) {
    if(!bytes||!size||size>65536)return NULL;
    const unsigned char *p=bytes;X509 *x=d2i_X509(NULL,&p,(long)size);
    if(x&&p!=bytes+size){X509_free(x);return NULL;}return x;
}
static int date(const ASN1_TIME *a,int64_t *out) {
    struct tm t;memset(&t,0,sizeof(t));
    if(!a||!ASN1_TIME_to_tm(a,&t))return 0;
    time_t n=timegm(&t);if(n<0)return 0;*out=(int64_t)n;return 1;
}
static int valid_at(X509 *x,int64_t now) {
    int64_t first=0,last=0;
    return date(X509_get0_notBefore(x),&first)&&date(X509_get0_notAfter(x),&last)&&first<=now&&last>=now;
}
static int strong_signature(const X509_ALGOR *alg,EVP_PKEY *key) {
    int md=NID_undef,pk=NID_undef;
    if(!alg||!signum_evidence_key(key))return 0;
    // PSS parameters require their own policy interpreter; never silently accept.
    if(!OBJ_find_sigid_algs(OBJ_obj2nid(alg->algorithm),&md,&pk))return 0;
    return md==NID_sha256||md==NID_sha384||md==NID_sha512||pk==NID_ED25519||pk==NID_ED448;
}
static int window(const ASN1_TIME *first,const ASN1_TIME *last,int64_t now,int64_t maximum_age,
                  int64_t *a,int64_t *b,const char **why) {
    if(!date(first,a)||!date(last,b)||*a>*b) {*why="Intervallo di aggiornamento assente o malformato";return 0;}
    if(*a>now||*b<now||now-*a>maximum_age) {*why="Evidenza non corrente: futura, scaduta o oltre il limite di età";return -2;}
    return 1;
}
static int ocsp(X509 *cert,X509 *issuer,const uint8_t *bytes,size_t size,int64_t now,
                int64_t *a,int64_t *b,int64_t *rev,const char **why) {
    const unsigned char *p=bytes;OCSP_RESPONSE *response=d2i_OCSP_RESPONSE(NULL,&p,(long)size);
    OCSP_BASICRESP *basic=NULL;X509_STORE *store=NULL;STACK_OF(X509) *extra=NULL;OCSP_CERTID *expected=NULL;
    int result=-1;
    *why="Risposta OCSP malformata o firma non valida";
    if(!response||p!=bytes+size)goto done;
    if(OCSP_response_status(response)!=OCSP_RESPONSE_STATUS_SUCCESSFUL) {result=0;*why="Responder OCSP senza esito utilizzabile";goto done;}
    basic=OCSP_response_get1_basic(response);if(!basic)goto done;
    if(OCSP_resp_count(basic)<1||OCSP_resp_count(basic)>128){result=0;*why="Numero di risposte OCSP oltre il profilo";goto done;}
    for(int i=0;i<OCSP_BASICRESP_get_ext_count(basic);i++)
        if(X509_EXTENSION_get_critical(OCSP_BASICRESP_get_ext(basic,i))){result=0;*why="Estensione critica OCSP non supportata";goto done;}
    const STACK_OF(X509) *embedded=OCSP_resp_get0_certs(basic);
    if(embedded&&sk_X509_num(embedded)>16){result=0;*why="Troppi certificati del responder OCSP";goto done;}
    for(int i=0;embedded&&i<sk_X509_num(embedded);i++) {
        if(!signum_evidence_key(X509_get0_pubkey(sk_X509_value(embedded,i)))) {
            result=0;*why="Chiave del responder fuori dal profilo supportato";goto done;
        }
    }
    extra=sk_X509_new_null();store=X509_STORE_new();
    if(!extra||!store||!sk_X509_push(extra,issuer)||!X509_STORE_add_cert(store,issuer)){result=0;goto done;}
    X509_VERIFY_PARAM *param=X509_STORE_get0_param(store);
    X509_VERIFY_PARAM_set_time(param,(time_t)now);X509_VERIFY_PARAM_set_auth_level(param,2);
    X509_VERIFY_PARAM_set_depth(param,3);
    X509_VERIFY_PARAM_set_flags(param,X509_V_FLAG_PARTIAL_CHAIN|X509_V_FLAG_X509_STRICT);
    if(OCSP_basic_verify(basic,extra,store,0)!=1)goto done;
    X509 *signer=NULL;
    if(OCSP_resp_get0_signer(basic,&signer,extra)!=1||!signer||!valid_at(signer,now))goto done;
    if(!strong_signature(OCSP_resp_get0_tbs_sigalg(basic),X509_get0_pubkey(signer))) {
        result=0;*why="Algoritmo di firma OCSP non supportato";goto done;
    }
    if(X509_cmp(signer,issuer)) {
        // Delegation is checked by OCSP_basic_verify. This initial profile also
        // requires no-check, otherwise responder revocation remains unresolved.
        int index=X509_get_ext_by_NID(signer,NID_id_pkix_OCSP_noCheck,-1);
        X509_EXTENSION *ext=index>=0?X509_get_ext(signer,index):NULL;
        const ASN1_OCTET_STRING *value=ext?X509_EXTENSION_get_data(ext):NULL;
        if(index<0||X509_get_ext_by_NID(signer,NID_id_pkix_OCSP_noCheck,index)>=0||
           X509_EXTENSION_get_critical(ext)||!value||ASN1_STRING_length(value)!=2||
           memcmp(ASN1_STRING_get0_data(value),"\x05\x00",2)) {
            result=0;*why="Revoca del responder delegato non risolta (OCSP no-check assente)";goto done;
        }
    }
    int64_t produced=0;
    if(!date((const ASN1_TIME *)OCSP_resp_get0_produced_at(basic),&produced)||produced>now) {
        result=-2;*why="Data producedAt OCSP assente, malformata o futura";goto done;
    }
    int found=-1;
    for(int i=0;i<OCSP_resp_count(basic);i++) {
        OCSP_SINGLERESP *single=OCSP_resp_get0(basic,i);
        const OCSP_CERTID *id=OCSP_SINGLERESP_get0_id(single);
        ASN1_OBJECT *digest=NULL;
        if(!OCSP_id_get0_info(NULL,&digest,NULL,NULL,(OCSP_CERTID *)id))goto done;
        int nid=OBJ_obj2nid(digest);
        // SHA-1 CertID hashes identify a certificate; they are not signatures.
        const EVP_MD *md=nid==NID_sha1?EVP_sha1():nid==NID_sha256?EVP_sha256():NULL;
        if(!md)continue;
        OCSP_CERTID_free(expected);expected=OCSP_cert_to_id(md,cert,issuer);
        if(expected&&!OCSP_id_cmp(id,expected)) {
            if(found>=0){*why="Risposte OCSP duplicate per lo stesso certificato";goto done;}found=i;
        }
    }
    if(found<0){result=0;*why="OCSP non riferito a questa coppia certificato/emittente";goto done;}
    OCSP_SINGLERESP *single=OCSP_resp_get0(basic,found);
    for(int i=0;i<OCSP_SINGLERESP_get_ext_count(single);i++)
        if(X509_EXTENSION_get_critical(OCSP_SINGLERESP_get_ext(single,i))){result=0;*why="Estensione critica SingleResponse non supportata";goto done;}
    ASN1_GENERALIZEDTIME *r=NULL,*first=NULL,*last=NULL;int reason=0;
    int status=OCSP_single_get0_status(single,&reason,&r,&first,&last);
    result=window((ASN1_TIME *)first,(ASN1_TIME *)last,now,7*86400,a,b,why);if(result!=1)goto done;
    if(produced<*a){result=-1;*why="Date OCSP incoerenti";goto done;}
    if(status==V_OCSP_CERTSTATUS_GOOD){result=1;*why="OCSP corrente autenticato: stato good per il certificato";}
    else if(status==V_OCSP_CERTSTATUS_REVOKED){
        if(!date((ASN1_TIME *)r,rev)||*rev>now){result=-1;*why="Data di revoca OCSP non valida";}
        else {result=2;*why="OCSP corrente autenticato: certificato revocato";}
    } else {result=0;*why="OCSP corrente autenticato: stato unknown";}
done:
    OCSP_CERTID_free(expected);sk_X509_free(extra);X509_STORE_free(store);OCSP_BASICRESP_free(basic);OCSP_RESPONSE_free(response);return result;
}
static int crl(X509 *cert,X509 *issuer,const uint8_t *bytes,size_t size,int64_t now,
               int64_t *a,int64_t *b,int64_t *rev,const char **why) {
    const unsigned char *p=bytes;X509_CRL *list=d2i_X509_CRL(NULL,&p,(long)size);int result=-1;
    *why="CRL malformata, emittente errato o firma non valida";
    if(!list||p!=bytes+size)goto done;
    if(X509_NAME_cmp(X509_CRL_get_issuer(list),X509_get_subject_name(issuer)))goto done;
    uint32_t usage=X509_get_key_usage(issuer);
    if(usage==UINT32_MAX||!(usage&KU_CRL_SIGN))goto done;
    const X509_ALGOR *alg=NULL;X509_CRL_get0_signature(list,NULL,&alg);
    if(!strong_signature(alg,X509_get0_pubkey(issuer))){result=0;*why="Algoritmo di firma CRL non supportato";goto done;}
    if(X509_CRL_verify(list,X509_get0_pubkey(issuer))!=1)goto done;
    // A partial/indirect/delta list cannot prove absence of revocation.
    if(X509_CRL_get_ext_by_NID(list,NID_delta_crl,-1)>=0||X509_CRL_get_ext_by_NID(list,NID_issuing_distribution_point,-1)>=0) {
        result=0;*why="CRL delta, indiretta o con ambito ristretto non supportata";goto done;
    }
    for(int i=0;i<X509_CRL_get_ext_count(list);i++)
        if(X509_EXTENSION_get_critical(X509_CRL_get_ext(list,i))) {result=0;*why="Estensione critica CRL non supportata";goto done;}
    int critical=-1;AUTHORITY_KEYID *akid=X509_CRL_get_ext_d2i(list,NID_authority_key_identifier,&critical,NULL);
    int akid_ok=critical!=-2&&(!akid||X509_check_akid(issuer,akid)==X509_V_OK);
    AUTHORITY_KEYID_free(akid);if(!akid_ok)goto done;
    result=window(X509_CRL_get0_lastUpdate(list),X509_CRL_get0_nextUpdate(list),now,31*86400,a,b,why);
    if(result!=1)goto done;
    STACK_OF(X509_REVOKED) *entries=X509_CRL_get_REVOKED(list);X509_REVOKED *match=NULL;
    if(entries&&sk_X509_REVOKED_num(entries)>100000){result=0;*why="CRL oltre il limite di voci";goto done;}
    for(int i=0;entries&&i<sk_X509_REVOKED_num(entries);i++) {
        X509_REVOKED *entry=sk_X509_REVOKED_value(entries,i);
        for(int j=0;j<X509_REVOKED_get_ext_count(entry);j++) {
            X509_EXTENSION *ext=X509_REVOKED_get_ext(entry,j);
            if(X509_EXTENSION_get_critical(ext)||OBJ_obj2nid(X509_EXTENSION_get_object(ext))==NID_certificate_issuer) {
                result=0;*why="Estensione di voce CRL fuori dal profilo diretto";goto done;
            }
        }
        if(!ASN1_INTEGER_cmp(X509_REVOKED_get0_serialNumber(entry),X509_get0_serialNumber(cert))) {
            if(match){result=-1;*why="Numero seriale duplicato nella CRL";goto done;}match=entry;
        }
    }
    if(match) {
        ASN1_ENUMERATED *code=X509_REVOKED_get_ext_d2i(match,NID_crl_reason,&critical,NULL);
        int unsupported=critical==-2||(code&&ASN1_ENUMERATED_get(code)==CRL_REASON_REMOVE_FROM_CRL);
        ASN1_ENUMERATED_free(code);
        if(unsupported){result=0;*why="Motivo CRL non supportato";goto done;}
        if(!date(X509_REVOKED_get0_revocationDate(match),rev)||*rev>now){result=-1;*why="Data di revoca CRL non valida";goto done;}
        result=2;*why="CRL completa corrente autenticata: certificato revocato";
    } else {result=1;*why="CRL completa corrente autenticata: certificato non elencato";}
done:X509_CRL_free(list);return result;
}
int signum_revocation_evidence(int kind,const uint8_t *cert_bytes,size_t cert_size,const uint8_t *issuer_bytes,size_t issuer_size,
    const uint8_t *evidence,size_t evidence_size,int64_t now,int64_t *a,int64_t *b,int64_t *rev,char *reason,size_t capacity) {
    int result=0;const char *why="Evidenza o limiti non supportati";X509 *cert=NULL,*issuer=NULL;
    if(!a||!b||!rev||!reason||!capacity)return 0;
    *a=*b=*rev=0;
    if(!evidence||!evidence_size||evidence_size>8*1024*1024||now<=0||now>253402300799LL)goto done;
    cert=certificate(cert_bytes,cert_size);issuer=certificate(issuer_bytes,issuer_size);
    if(!cert||!issuer){result=-1;why="Certificato o emittente DER malformato";goto done;}
    if(!signum_evidence_key(X509_get0_pubkey(cert))||!signum_evidence_key(X509_get0_pubkey(issuer))) {
        why="Chiave del certificato o emittente fuori dal profilo supportato";goto done;
    }
    if(X509_check_issued(issuer,cert)!=X509_V_OK||X509_check_ca(issuer)<=0||
       X509_verify(cert,X509_get0_pubkey(issuer))!=1){result=-1;why="Il certificato non è firmato dall’emittente indicato";goto done;}
    if(!valid_at(issuer,now)){why="Emittente non valido alla data corrente";goto done;}
    if(kind==1)result=ocsp(cert,issuer,evidence,evidence_size,now,a,b,rev,&why);
    else if(kind==2)result=crl(cert,issuer,evidence,evidence_size,now,a,b,rev,&why);
done:
    snprintf(reason,capacity,"%s",why);X509_free(cert);X509_free(issuer);ERR_clear_error();return result;
}
