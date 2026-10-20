#include "CCertificatePath.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define MAX_CERTS 65
#define MAX_DEPTH 12
#define MAX_VISITS 4096
static X509 *decode(const uint8_t *p, size_t n) {
    if(!p || !n || n>65536) return NULL;
    const unsigned char *q=p; X509 *x=d2i_X509(NULL,&q,(long)n);
    if(x && q!=p+n) { X509_free(x); return NULL; } return x;
}
static int policy(X509 *x, int leaf, time_t when, int tsa, const char **reason) {
    int before=X509_cmp_time(X509_get0_notBefore(x),&when), after=X509_cmp_time(X509_get0_notAfter(x),&when);
    if(!before||!after||before>0||after<0) { *reason="Certificato scaduto, non ancora valido o data malformata"; return -1; }
    for(int i=0;i<X509_get_ext_count(x);i++) {
        X509_EXTENSION *ext=X509_get_ext(x,i);
        if(X509_EXTENSION_get_critical(ext) && !X509_supported_extension(ext)) {
            *reason="Estensione critica non supportata";return -1;
        }
    }
    EVP_PKEY *key=X509_get0_pubkey(x);
    if(!key) { *reason="Chiave pubblica non decodificabile"; return -1; }
    int bits=EVP_PKEY_get_bits(key);
    int rsa=EVP_PKEY_is_a(key,"RSA")||EVP_PKEY_is_a(key,"RSA-PSS");
    int ec=EVP_PKEY_is_a(key,"EC"), ed=EVP_PKEY_is_a(key,"ED25519")||EVP_PKEY_is_a(key,"ED448");
    if(!rsa&&!ec&&!ed) { *reason="Tipo di chiave non supportato dalla policy"; return 0; }
    if((rsa&&bits<2048)||(ec&&bits<256)) { *reason="Chiave inferiore alla sicurezza minima"; return -1; }
    int md=0,pk=0,security=0;uint32_t flags=0;
    if(!X509_get_signature_info(x,&md,&pk,&security,&flags)) { *reason="Algoritmo del certificato non supportato"; return 0; }
    if(md==NID_sha1||md==NID_md5) { *reason="Algoritmo debole vietato dalla policy";return -1; }
    if(md!=NID_sha256&&md!=NID_sha384&&md!=NID_sha512&&pk!=NID_ED25519&&pk!=NID_ED448) {
        *reason="Algoritmo del certificato fuori dal profilo supportato";return 0;
    }
    int critical=-1;
    BASIC_CONSTRAINTS *bc=X509_get_ext_d2i(x,NID_basic_constraints,&critical,NULL);
    if(critical==-2) { *reason="Basic Constraints duplicati";return -1; }
    int ca=bc&&bc->ca; BASIC_CONSTRAINTS_free(bc);
    if((leaf&&ca)||(!leaf&&!ca)) { *reason="Basic Constraints incompatibili con il ruolo del certificato";return -1; }
    ASN1_BIT_STRING *ku=X509_get_ext_d2i(x,NID_key_usage,&critical,NULL);
    if(critical==-2) { *reason="Key Usage duplicato";return -1; }
    int permitted=leaf ? (!ku||ASN1_BIT_STRING_get_bit(ku,0)||ASN1_BIT_STRING_get_bit(ku,1)) : (ku&&ASN1_BIT_STRING_get_bit(ku,5));
    ASN1_BIT_STRING_free(ku);
    if(!permitted) { *reason="Key Usage incompatibile";return -1; }
    if(tsa)return 1; // Dedicated OpenSSL timestamp purpose checks EKU.
    EXTENDED_KEY_USAGE *eku=X509_get_ext_d2i(x,NID_ext_key_usage,&critical,NULL);
    if(critical==-2) { *reason="Extended Key Usage duplicato";return -1; }
    permitted=!eku;
    for(int i=0;eku&&i<sk_ASN1_OBJECT_num(eku);i++) {
        char oid[100];OBJ_obj2txt(oid,sizeof(oid),sk_ASN1_OBJECT_value(eku,i),1);
        if(!strcmp(oid,"2.5.29.37.0")||!strcmp(oid,"1.3.6.1.5.5.7.3.36")) permitted=1;
    }
    EXTENDED_KEY_USAGE_free(eku);
    if(!permitted) { *reason="Extended Key Usage non consente la firma di documenti";return -1; }
    return 1;
}
struct search {
    X509 *certs[MAX_CERTS], *anchor;
    int tsa;
    int count, chosen[MAX_DEPTH], used[MAX_CERTS], visits, paths, invalid, unsupported, success, exhausted;
    time_t when; char *hashes;size_t capacity;char message[256], invalid_message[256], invalid_hashes[1024];
};
static void check(struct search *s,int length) {
    if(++s->paths>128) {s->unsupported=1;s->exhausted=1;return;}
    STACK_OF(X509) *untrusted=sk_X509_new_null();
    X509_STORE *store=X509_STORE_new();X509_STORE_CTX *ctx=X509_STORE_CTX_new();
    if(!store||!ctx||!untrusted) {s->unsupported=1;goto cleanup;}
    for(int i=0;i<=length;i++) {
        X509 *certificate=i==length?s->anchor:s->certs[s->chosen[i]];
        int md=0,pk=0,security=0;uint32_t flags=0;
        if(!X509_get_signature_info(certificate,&md,&pk,&security,&flags)||
           (md!=NID_sha256&&md!=NID_sha384&&md!=NID_sha512&&md!=NID_sha1&&md!=NID_md5&&pk!=NID_ED25519&&pk!=NID_ED448)) {
            s->unsupported=1;snprintf(s->message,sizeof(s->message),"Algoritmo del certificato non supportato");goto cleanup;
        }
    }
    // Exactly one authenticated TL identity per attempt. Never load default paths.
    if(!X509_STORE_add_cert(store,s->anchor)) {s->unsupported=1;goto cleanup;}
    for(int i=1;i<length;i++) sk_X509_push(untrusted,s->certs[s->chosen[i]]);
    if(!X509_STORE_CTX_init(ctx,store,s->certs[0],untrusted)) {s->unsupported=1;goto cleanup;}
    X509_VERIFY_PARAM *param=X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_time(param,s->when); X509_VERIFY_PARAM_set_depth(param,MAX_DEPTH);
    X509_VERIFY_PARAM_set_auth_level(param,2);
    X509_VERIFY_PARAM_set_flags(param,X509_V_FLAG_PARTIAL_CHAIN|X509_V_FLAG_X509_STRICT|X509_V_FLAG_CHECK_SS_SIGNATURE|X509_V_FLAG_POLICY_CHECK);
    if(s->tsa)X509_STORE_CTX_set_purpose(ctx,X509_PURPOSE_TIMESTAMP_SIGN);
    int ok=X509_verify_cert(ctx);
    STACK_OF(X509) *attempt=X509_STORE_CTX_get0_chain(ctx);
    size_t used=0;
    for(int i=0;attempt&&i<sk_X509_num(attempt)&&i<MAX_DEPTH+1;i++) {
        unsigned char hash[32];unsigned int n=0;
        if(used+66>s->capacity||!X509_digest(sk_X509_value(attempt,i),EVP_sha256(),hash,&n)||n!=32)break;
        for(int j=0;j<32;j++) used+=(size_t)snprintf(s->hashes+used,s->capacity-used,"%02x",hash[j]);
        s->hashes[used++]='\n';s->hashes[used]=0;
    }

    if(ok==1) {
        STACK_OF(X509) *chain=X509_STORE_CTX_get0_chain(ctx);
        int n=sk_X509_num(chain);const char *why=NULL;int acceptable=1;
        if(n<(s->tsa?1:2)||n>MAX_DEPTH+1||X509_cmp(sk_X509_value(chain,n-1),s->anchor)) acceptable=0;
        for(int i=0;i<n&&acceptable;i++) {
            int p=policy(sk_X509_value(chain,i),i==0,s->when,s->tsa,&why);
            if(p!=1) {acceptable=0;if(p<0)s->invalid=1;else s->unsupported=1;snprintf(s->message,sizeof(s->message),"%s",why);}
        }
        if(acceptable) {
            size_t at=0;
            for(int i=0;i<n;i++) {
                unsigned char hash[32];unsigned int z=0;
                if(!X509_digest(sk_X509_value(chain,i),EVP_sha256(),hash,&z)||z!=32||at+66>s->capacity) {acceptable=0;break;}
                for(int j=0;j<32;j++) at+=(size_t)snprintf(s->hashes+at,s->capacity-at,"%02x",hash[j]);
                s->hashes[at++]='\n';s->hashes[at]=0;
            }
            if(acceptable)s->success=1;else s->unsupported=1;
        }
    } else {
        int error=X509_STORE_CTX_get_error(ctx);
        if(ok<0||error==X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM||error==X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE||error==X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX||error==X509_V_ERR_UNSUPPORTED_NAME_SYNTAX||error==X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE||error==X509_V_ERR_UNSPECIFIED||error==X509_V_ERR_OUT_OF_MEM||error==X509_V_ERR_INVALID_CALL||error==X509_V_ERR_STORE_LOOKUP||error==X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT||error==X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY||error==X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE||error==X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT||error==X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) s->unsupported=1;
        else s->invalid=1;
        snprintf(s->message,sizeof(s->message),"OpenSSL: %s (codice %d, profondità %d)",X509_verify_cert_error_string(error),error,X509_STORE_CTX_get_error_depth(ctx));
    }
cleanup:
    X509_STORE_CTX_free(ctx);X509_STORE_free(store);sk_X509_free(untrusted);ERR_clear_error();
}
static void walk(struct search *s,int length) {
    if(s->success)return;
    if(++s->visits>MAX_VISITS) {s->unsupported=1;s->exhausted=1;return;}
    X509 *last=s->certs[s->chosen[length-1]];
    if(s->tsa&&!X509_cmp(last,s->anchor)){check(s,length-1);return;}
    if(!X509_NAME_cmp(X509_get_issuer_name(last),X509_get_subject_name(s->anchor))) {
        int was_invalid=s->invalid;check(s,length);
        if(!was_invalid&&s->invalid) {
            snprintf(s->invalid_message,sizeof(s->invalid_message),"%s",s->message);
            snprintf(s->invalid_hashes,sizeof(s->invalid_hashes),"%s",s->hashes);
        }
    }
    if(length>=MAX_DEPTH||s->paths>128)return;
    for(int i=1;i<s->count&&!s->success&&s->visits<=MAX_VISITS;i++) {
        if(!s->used[i]&&!X509_NAME_cmp(X509_get_issuer_name(last),X509_get_subject_name(s->certs[i]))) {
            s->used[i]=1;s->chosen[length]=i;walk(s,length+1);s->used[i]=0;
        }
    }
}
int signum_path_validate_purpose(const uint8_t *packed,size_t size,const uint8_t *anchor,size_t anchor_size,int64_t when,int tsa,char *hashes,size_t capacity,char *reason,size_t reason_capacity) {
    struct search s;memset(&s,0,sizeof(s));s.when=(time_t)when;s.tsa=tsa==1;s.hashes=hashes;s.capacity=capacity;
    if(capacity)hashes[0]=0;
    const char *why="Percorso verso il servizio TL non ricostruibile con i certificati disponibili";
    int result=0;
    if(size>2*1024*1024||!capacity)goto done;
    int entries=0;
    while(size) {
        if(size<4||++entries>MAX_CERTS)goto done;
        size_t n=((size_t)packed[0]<<24)|((size_t)packed[1]<<16)|((size_t)packed[2]<<8)|packed[3];packed+=4;size-=4;
        if(n>size)goto done;
        X509 *x=decode(packed,n);
        if(!x&&entries==1){result=-1;why="Certificato DER del firmatario malformato";goto done;}
        if(x)s.certs[s.count++]=x;
        else {s.unsupported=1;snprintf(s.message,sizeof(s.message),"Intermedio DER malformato ignorato");}
        packed+=n;size-=n;
    }
    if(!s.count)goto done;
    result=0;
    s.anchor=decode(anchor,anchor_size);if(!s.anchor){why="Identità del servizio TL non supportata";goto done;}
    for(int i=0;i<=s.count;i++) {
        X509 *certificate=i==s.count?s.anchor:s.certs[i];
        EVP_PKEY *key=X509_get0_pubkey(certificate);
        int bits=key?EVP_PKEY_get_bits(key):0;
        if(bits>8192||(key&&EVP_PKEY_is_a(key,"EC")&&bits>521)) {why="Chiave oltre il limite di risorse supportato";goto done;}
        if(key&&(EVP_PKEY_is_a(key,"RSA")||EVP_PKEY_is_a(key,"RSA-PSS"))) {
            BIGNUM *exponent=NULL;
            int ok=EVP_PKEY_get_bn_param(key,OSSL_PKEY_PARAM_RSA_E,&exponent);
            int excessive=!ok||!exponent||BN_num_bits(exponent)>32;
            BN_free(exponent);
            if(excessive){why="Esponente RSA fuori dal profilo supportato";goto done;}
        }
    }
    s.used[0]=1;s.chosen[0]=0;walk(&s,1);
    if(s.success){result=1;why="Percorso X.509 verificato fino all’identità CA/QC autenticata";}
    else if(s.exhausted){result=0;why="Limite della ricerca dei percorsi raggiunto";}
    else if(s.invalid){result=-1;why=s.invalid_message[0]?s.invalid_message:"Vincoli del percorso incompatibili";snprintf(hashes,capacity,"%s",s.invalid_hashes);}
    else if(s.unsupported)why=s.message[0]?s.message:"Limite o condizione non supportata";
done:
    snprintf(reason,reason_capacity,"%s",why);
    for(int i=0;i<s.count;i++)X509_free(s.certs[i]);X509_free(s.anchor);ERR_clear_error();return result;
}

int signum_path_validate(const uint8_t *p,size_t n,const uint8_t *a,size_t z,int64_t when,char *h,size_t hc,char *r,size_t rc) {
 return signum_path_validate_purpose(p,n,a,z,when,0,h,hc,r,rc);
}
