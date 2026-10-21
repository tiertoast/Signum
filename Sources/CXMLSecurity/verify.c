#include "CXMLSecurity.h"
#include "CXAdES.h"
#include <pthread.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/valid.h>
#include <libxml/xmlschemas.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#define XMLSEC_CRYPTO_OPENSSL 1
#include <xmlsec/crypto.h>
#include <xmlsec/xmltree.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <stdio.h>
#include <string.h>

static pthread_once_t xml_once = PTHREAD_ONCE_INIT;
static int xml_initialized;
static void initialize_xml(void) {
    xml_initialized = xmlSecInit() >= 0 && xmlSecCryptoAppInit(NULL) >= 0 && xmlSecCryptoInit() >= 0;
}
int signum_xml_initialize(void) { pthread_once(&xml_once, initialize_xml); return xml_initialized; }

#define TL "http://uri.etsi.org/02231/v2#"
#define DS "http://www.w3.org/2000/09/xmldsig#"
#define XA "http://uri.etsi.org/01903/v1.3.2#"
#define EX "http://www.w3.org/2001/10/xml-exc-c14n#"
#define ENV DS "enveloped-signature"
#define CHECK(c, m) do { if(!(c)) { snprintf(error,error_size,"%s",m); goto done; } } while(0)
static xmlXPathObjectPtr query(xmlXPathContextPtr c, const char *s) {
    return xmlXPathEvalExpression(BAD_CAST s,c);
}
static int count(xmlXPathContextPtr c,const char *s) {
    xmlXPathObjectPtr o=query(c,s); int n=o && o->nodesetval ? o->nodesetval->nodeNr : 0;
    if(o) xmlXPathFreeObject(o); return n;
}
static xmlNodePtr one(xmlXPathContextPtr c,const char *s) {
    xmlXPathObjectPtr o=query(c,s); xmlNodePtr n=NULL;
    if(o && o->nodesetval && o->nodesetval->nodeNr==1) n=o->nodesetval->nodeTab[0];
    if(o) xmlXPathFreeObject(o); return n;
}
static int prop(xmlNodePtr n,const char *key,const char *value) {
    if(!n) return 0;
    xmlChar *v=xmlGetProp(n,BAD_CAST key); int ok=v && xmlStrEqual(v,BAD_CAST value);
    xmlFree(v); return ok;
}
static int alg(xmlNodePtr n,const char *value) { return prop(n,"Algorithm",value); }
/* URI registry: fixed-parameter RFC 9231 2.3.10 only. The existing global
 * no-child-parameters check rejects #rsa-pss and all explicit overrides.
 * xmlsec 1.3.12 fixes PSS salt length to digest size; OpenSSL verifies MGF1
 * with the signature digest for unrestricted RSA keys and the EMSA-PSS trailer.
 * RSA-PSS SPKI restrictions are checked against explicit XML profile parameters
 * below; embedded MGF constraints must not override the backend default. */
static int signatureAlgorithm(xmlNodePtr node) {
    static const char *const uris[] = {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
        "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1",
        "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"
    };
    for(size_t i=0;i<sizeof(uris)/sizeof(uris[0]);i++) if(alg(node,uris[i])) return i >= 6 ? 2 : 1;
    return 0;
}
/* Validate key constraints through the existing OpenSSL verification API. xmlsec
 * sets padding/salt itself, but does not explicitly set MGF1: a constrained SPKI
 * may change that default. All setters must accept this exact fixed profile. */
static int pssKeyCompatible(EVP_PKEY *key,xmlNodePtr method) {
    int type=EVP_PKEY_base_id(key);
    if(type!=EVP_PKEY_RSA && type!=EVP_PKEY_RSA_PSS) return 0;
    const EVP_MD *md=alg(method,"http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1") ? EVP_sha256() :
                     alg(method,"http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1") ? EVP_sha384() : EVP_sha512();
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new(key,NULL);
    int ok=ctx && EVP_PKEY_verify_init(ctx)>0 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PSS_PADDING)>0 &&
        EVP_PKEY_CTX_set_signature_md(ctx,md)>0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx,md)>0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx,EVP_MD_get_size(md))>0;
    EVP_PKEY_CTX_free(ctx); return ok;
}
static const EVP_MD *digest(xmlNodePtr n) {
    if(alg(n,"http://www.w3.org/2001/04/xmlenc#sha256")) return EVP_sha256();
    if(alg(n,"http://www.w3.org/2001/04/xmldsig-more#sha384")) return EVP_sha384();
    if(alg(n,"http://www.w3.org/2001/04/xmlenc#sha512")) return EVP_sha512();
    return NULL;
}
static int b64equal(xmlNodePtr n,const unsigned char *bytes,size_t len) {
    xmlChar *raw=n ? xmlNodeGetContent(n) : NULL;
    if(!raw) return 0;
    size_t l=xmlStrlen(raw); char *compact=xmlMalloc(l+1); size_t k=0;
    for(size_t i=0;i<l;i++) if(raw[i]!=' ' && raw[i]!='\t' && raw[i]!='\n' && raw[i]!='\r') compact[k++]=raw[i];
    compact[k]=0;
    unsigned char *decoded=xmlMalloc(k+1);
    int d= k%4==0 && k<131072 ? EVP_DecodeBlock(decoded,(unsigned char*)compact,(int)k) : -1;
    if(d>0 && k && compact[k-1]=='=') d--;
    if(d>0 && k>1 && compact[k-2]=='=') d--;
    int ok=d>=0 && (size_t)d==len && memcmp(decoded,bytes,len)==0;
    xmlFree(decoded); xmlFree(compact); xmlFree(raw); return ok;
}

/* RFC 5035 IssuerSerial DER used by XAdES IssuerSerialV2. */
typedef struct { GENERAL_NAMES *issuer; ASN1_INTEGER *serial; } SignumIssuerSerial;
ASN1_SEQUENCE(SignumIssuerSerial) = {
    ASN1_SEQUENCE_OF(SignumIssuerSerial, issuer, GENERAL_NAME),
    ASN1_SIMPLE(SignumIssuerSerial, serial, ASN1_INTEGER)
} ASN1_SEQUENCE_END(SignumIssuerSerial)
IMPLEMENT_ASN1_FUNCTIONS(SignumIssuerSerial)
static int issuerSerialMatches(xmlNodePtr node, X509 *cert) {
    SignumIssuerSerial *is=SignumIssuerSerial_new();
    if(!is) return 0;
    GENERAL_NAME *name=GENERAL_NAME_new();
    if(!name) { SignumIssuerSerial_free(is); return 0; }
    GENERAL_NAME_set0_value(name,GEN_DIRNAME,X509_NAME_dup(X509_get_issuer_name(cert)));
    sk_GENERAL_NAME_push(is->issuer,name);
    ASN1_INTEGER_free(is->serial); is->serial=ASN1_INTEGER_dup(X509_get0_serialNumber(cert));
    unsigned char *der=NULL; int len=i2d_SignumIssuerSerial(is,&der);
    int ok=len>0 && b64equal(node,der,len);
    OPENSSL_free(der); SignumIssuerSerial_free(is); return ok;
}

/* Register only globally unique, unqualified Id attributes; reject all aliases.
   This table is shared by preflight resolution and xmlsec verification. */
static int ids(xmlDocPtr doc,xmlNodePtr n,int depth,int *nodes) {
    for(;n;n=n->next) {
        if(++*nodes>500000 || depth>64) return 0;
        if(n->type==XML_ELEMENT_NODE) {
            for(xmlAttrPtr a=n->properties;a;a=a->next) {
                if(xmlStrcasecmp(a->name,BAD_CAST "id")==0) {
                    if(a->ns || !xmlStrEqual(a->name,BAD_CAST "Id")) return 0;
                    xmlChar *v=xmlNodeListGetString(doc,a->children,1);
                    if(!v || xmlValidateNCName(v,0)!=0 || xmlGetID(doc,v)) { xmlFree(v); return 0; }
                    if(!xmlAddID(NULL,doc,v,a)) { xmlFree(v); return 0; }
                    xmlFree(v);
                }
                if(a->ns && xmlStrEqual(a->ns->href,BAD_CAST "http://www.w3.org/XML/1998/namespace") && xmlStrEqual(a->name,BAD_CAST "base")) return 0;
            }
            if(!ids(doc,n->children,depth+1,nodes)) return 0;
        }
    }
    return 1;
}
int signum_xml_verify(const unsigned char *xml,size_t size,const unsigned char *cert,size_t cert_size,const char *schema_path,char *error,size_t error_size) {
    xmlSchemaParserCtxtPtr scp=NULL; xmlSchemaPtr schema=NULL; xmlSchemaValidCtxtPtr scv=NULL;
    int result=0, nodes=0; xmlDocPtr doc=NULL; xmlXPathContextPtr xp=NULL; xmlSecDSigCtxPtr ctx=NULL;
    xmlXPathObjectPtr refs=NULL; X509 *x509=NULL; EVP_PKEY *pub=NULL;
    CHECK(size>0 && size<=64*1024*1024 && cert_size>0 && cert_size<=96*1024,"input bounds");
    CHECK(signum_xml_initialize(),"xmlsec initialization");
    for(size_t i=0;i+9<size;i++) {
        CHECK(strncasecmp((const char*)xml+i,"<!DOCTYPE",9)!=0 && strncasecmp((const char*)xml+i,"<!ENTITY",8)!=0,"DTD/entities forbidden");
    }
    doc=xmlReadMemory((const char*)xml,(int)size,NULL,"UTF-8",XML_PARSE_NONET|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    CHECK(doc && !doc->intSubset && !doc->extSubset,"XML/DTD rejected");
    CHECK(ids(doc,xmlDocGetRootElement(doc),0,&nodes),"duplicate/ambiguous IDs or resource limits");
    scp=xmlSchemaNewParserCtxt(schema_path); CHECK(scp,"schema parser");
    schema=xmlSchemaParse(scp); CHECK(schema,"bundled schema compilation");
    scv=xmlSchemaNewValidCtxt(schema); CHECK(scv && xmlSchemaValidateDoc(scv,doc)==0,"ETSI/XAdES schema validation failed");
    xp=xmlXPathNewContext(doc); CHECK(xp,"XPath context");
    xmlXPathRegisterNs(xp,BAD_CAST "t",BAD_CAST TL); xmlXPathRegisterNs(xp,BAD_CAST "d",BAD_CAST DS); xmlXPathRegisterNs(xp,BAD_CAST "x",BAD_CAST XA);
    xmlXPathRegisterNs(xp,BAD_CAST "a",BAD_CAST "http://uri.etsi.org/02231/v2/additionaltypes#");
    xmlXPathRegisterNs(xp,BAD_CAST "s",BAD_CAST "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#");
    xmlNodePtr root=one(xp,"/t:TrustServiceStatusList");
    CHECK(root && count(xp,"//t:TrustServiceStatusList")==1 && count(xp,"/t:TrustServiceStatusList/t:SchemeInformation")==1,"ambiguous TL root/scheme");
    CHECK(count(xp,"//d:Signature")==1 && count(xp,"/t:TrustServiceStatusList/d:Signature")==1,"signature placement/count");
    xmlNodePtr sig=one(xp,"/t:TrustServiceStatusList/d:Signature");
    CHECK(count(xp,"//d:RetrievalMethod|//d:KeyInfoReference|//d:Manifest|//d:KeyValue|//d:X509SKI")==0,"indirect/ambiguous key or manifest");
    CHECK(count(xp,"//d:SignedInfo")==1 && count(xp,"//d:SignatureValue")==1 && count(xp,"//d:KeyInfo")==1,"ambiguous signature structure");
    CHECK(alg(one(xp,"//d:SignedInfo/d:CanonicalizationMethod"),EX),"unsupported SignedInfo canonicalization");
    xmlNodePtr sm=one(xp,"//d:SignedInfo/d:SignatureMethod");
    int signatureProfile=signatureAlgorithm(sm);
    CHECK(signatureProfile,"unsupported signature algorithm");
    CHECK(count(xp,"//x:QualifyingProperties")==1 && count(xp,"//x:SignedProperties")==1,"XAdES properties count");
    CHECK(count(xp,"//d:Object")==1 && count(xp,"//d:Object/*")==1,"unsigned signature objects/wrapping forbidden");
    xmlNodePtr qp=one(xp,"/t:TrustServiceStatusList/d:Signature/d:Object/x:QualifyingProperties");
    xmlNodePtr sp=one(xp,"/t:TrustServiceStatusList/d:Signature/d:Object/x:QualifyingProperties/x:SignedProperties");
    CHECK(count(xp,"//x:QualifyingProperties/*")==1,"unsigned XAdES properties unsupported in baseline PoC");
    xmlChar *sid=xmlGetProp(sig,BAD_CAST "Id");
    xmlChar *target=qp ? xmlGetProp(qp,BAD_CAST "Target") : NULL;
    int targetOK=sid && target && target[0]=='#' && xmlStrEqual(sid,target+1);
    xmlFree(sid); xmlFree(target); CHECK(targetOK && sp,"QualifyingProperties target");
    CHECK(count(xp,"//x:SignedSignatureProperties")==1 && count(xp,"//x:SigningTime")==1 && count(xp,"//x:SigningCertificateV2")==1 && count(xp,"//x:SigningCertificate")==0,"TLv6 requires baseline signed certificate V2/time");
    CHECK(count(xp,"//x:SignedDataObjectProperties/x:DataObjectFormat[x:MimeType='text/xml']")>=1,"missing signed data object format");
    CHECK(count(xp,"//d:KeyInfo/*")==1 && count(xp,"//d:KeyInfo/d:X509Data/*")==1,"ambiguous signer metadata");
    CHECK(count(xp,"//d:X509Certificate")==1,"PoC requires one explicit signer certificate");
    CHECK(b64equal(one(xp,"//d:KeyInfo/d:X509Data/d:X509Certificate"),cert,cert_size),"signer certificate is not the authorized certificate");
    const unsigned char *cp=cert; x509=d2i_X509(NULL,&cp,cert_size); CHECK(x509 && cp==cert+cert_size,"invalid signer DER");
    pub=X509_get_pubkey(x509); CHECK(pub && EVP_PKEY_get_security_bits(pub)>=112,"weak signing key");
    CHECK(signatureProfile!=2 || pssKeyCompatible(pub,sm),
          "RSA key constraints incompatible with fixed XML PSS parameters");
    xmlNodePtr cd=one(xp,"//x:SignedProperties/x:SignedSignatureProperties/x:SigningCertificateV2/x:Cert/x:CertDigest");
    CHECK(cd && count(xp,"//x:SigningCertificateV2/x:Cert")==1,"ambiguous signed certificate binding");
    xp->node=cd;
    const EVP_MD *md=digest(one(xp,"./d:DigestMethod")); unsigned char hash[EVP_MAX_MD_SIZE]; unsigned int hl=0;
    CHECK(md && EVP_Digest(cert,cert_size,hash,&hl,md,NULL)==1 && b64equal(one(xp,"./d:DigestValue"),hash,hl),"SigningCertificateV2 digest mismatch");
    xmlNodePtr issuer=one(xp,"//x:SigningCertificateV2/x:Cert/x:IssuerSerialV2");
    CHECK(!issuer || issuerSerialMatches(issuer,x509),"IssuerSerialV2 mismatch");
    refs=query(xp,"//d:SignedInfo/d:Reference");
    CHECK(refs && refs->nodesetval && refs->nodesetval->nodeNr==2,"PoC requires exactly root and SignedProperties references");
    int rootRefs=0,spRefs=0; xmlNodePtr rootRef=NULL;
    for(int i=0;i<refs->nodesetval->nodeNr;i++) {
        xmlNodePtr ref=refs->nodesetval->nodeTab[i]; xp->node=ref;
        xmlChar *uri=xmlGetProp(ref,BAD_CAST "URI"); xmlNodePtr dest=NULL;
        if(uri && !uri[0]) dest=root;
        else if(uri && uri[0]=='#' && xmlValidateNCName(uri+1,0)==0) { xmlAttrPtr id=xmlGetID(doc,uri+1); if(id) dest=id->parent; }
        xmlFree(uri);
        CHECK(dest==root || dest==sp,"external/unknown reference or wrapping");
        CHECK(digest(one(xp,"./d:DigestMethod")) && one(xp,"./d:DigestValue"),"unsupported reference digest");
        CHECK(count(xp,"./d:Transforms")==1,"transforms count");
        if(dest==root) {
            rootRefs++; rootRef=ref;
            CHECK(count(xp,"./d:Transforms/d:Transform")==2 && alg(one(xp,"./d:Transforms/d:Transform[1]"),ENV) && alg(one(xp,"./d:Transforms/d:Transform[2]"),EX),"root transforms must be enveloped + exclusive c14n");
        } else {
            spRefs++;
            CHECK(prop(ref,"Type","http://uri.etsi.org/01903#SignedProperties") && count(xp,"./d:Transforms/d:Transform")==1 && alg(one(xp,"./d:Transforms/d:Transform"),EX),"SignedProperties reference profile");
        }
        CHECK(count(xp,"./d:Transforms/d:Transform/*")==0,"transform parameters unsupported");
    }
    CHECK(rootRefs==1 && spRefs==1,"reference coverage");
    xmlNodePtr format=one(xp,"//x:SignedProperties/x:SignedDataObjectProperties/x:DataObjectFormat");
    xmlChar *refID=xmlGetProp(rootRef,BAD_CAST "Id");
    xmlChar *objectRef=format ? xmlGetProp(format,BAD_CAST "ObjectReference") : NULL;
    int formatOK=refID && objectRef && objectRef[0]=='#' && xmlStrEqual(refID,objectRef+1);
    xmlFree(refID); xmlFree(objectRef);
    CHECK(formatOK && count(xp,"//x:DataObjectFormat")==1,"DataObjectFormat must identify the signed root reference");
    CHECK(count(xp,"//d:CanonicalizationMethod/*|//d:SignatureMethod/*|//d:DigestMethod/*")==0,"algorithm parameters unsupported");
    ctx=xmlSecDSigCtxCreate(NULL); CHECK(ctx,"xmlsec context");
    ctx->enabledReferenceUris=xmlSecTransformUriTypeEmpty|xmlSecTransformUriTypeSameDocument;
    ctx->keyInfoReadCtx.retrievalMethodCtx.enabledUris=xmlSecTransformUriTypeNone;
    ctx->signKey=xmlSecCryptoAppKeyLoadMemory(cert,cert_size,xmlSecKeyDataFormatCertDer,NULL,NULL,NULL);
    CHECK(ctx->signKey,"authorized public key load");
    CHECK(xmlSecDSigCtxVerify(ctx,sig)>=0 && ctx->status==xmlSecDSigStatusSucceeded,"XML signature/reference verification failed");
    result=1;
done:
    if(scv) xmlSchemaFreeValidCtxt(scv); if(schema) xmlSchemaFree(schema); if(scp) xmlSchemaFreeParserCtxt(scp);
    if(pub) EVP_PKEY_free(pub); if(x509) X509_free(x509);
    if(refs) xmlXPathFreeObject(refs); if(ctx) xmlSecDSigCtxDestroy(ctx);
    if(xp) xmlXPathFreeContext(xp); if(doc) xmlFreeDoc(doc);
    return result;
}
