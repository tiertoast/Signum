#ifndef SIGNUM_EVIDENCE_POLICY_H
#define SIGNUM_EVIDENCE_POLICY_H
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
static int signum_evidence_key(EVP_PKEY *key) {
    if(!key||EVP_PKEY_get_bits(key)>8192||EVP_PKEY_get_security_bits(key)<112)return 0;
    if(EVP_PKEY_is_a(key,"RSA")||EVP_PKEY_is_a(key,"RSA-PSS")) {
        BIGNUM *e=NULL;int ok=EVP_PKEY_get_bn_param(key,OSSL_PKEY_PARAM_RSA_E,&e);
        int permitted=ok&&e&&BN_num_bits(e)<=32;BN_free(e);return permitted;
    }
    return (EVP_PKEY_is_a(key,"EC")&&EVP_PKEY_get_bits(key)<=521)||EVP_PKEY_is_a(key,"ED25519")||EVP_PKEY_is_a(key,"ED448");
}
#endif
