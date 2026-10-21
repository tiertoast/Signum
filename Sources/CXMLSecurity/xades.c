#include "CXAdES.h"
#include <libxml/parser.h>
#include <libxml/c14n.h>
#include <libxml/xpath.h>
#include <libxml/valid.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#define XMLSEC_CRYPTO_OPENSSL 1
#include <xmlsec/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define DS "http://www.w3.org/2000/09/xmldsig#"
#define XA "http://uri.etsi.org/01903/v1.3.2#"
#define EX "http://www.w3.org/2001/10/xml-exc-c14n#"
#define SHA "http://www.w3.org/2001/04/xmlenc#sha256"
#define RSA "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
#define ENV DS "enveloped-signature"
#define SPT "http://uri.etsi.org/01903#SignedProperties"
#define LIMIT (8*1024*1024)
#define REQUIRE(c,m) do { if(!(c)) { snprintf(r->error,sizeof(r->error),"%s",m); goto done; } } while(0)
#define ASIC "http://uri.etsi.org/02918/v1.2.1#"
typedef struct { char uri[301],mime[64]; const unsigned char *bytes;size_t size; } detached_object;
static int number(const unsigned char *p,size_t size,size_t *offset,size_t *value) {
    if(*offset>size||size-*offset<4)return 0;
    const unsigned char *v=p+*offset;*value=((size_t)v[0]<<24)|((size_t)v[1]<<16)|((size_t)v[2]<<8)|v[3];*offset+=4;return 1;
}
static int unpack(const unsigned char *p,size_t size,detached_object objects[5],size_t *count) {
    size_t at=0,n=0,total=0;if(!p||size>17*1024*1024||!number(p,size,&at,count)||!*count||*count>5)return 0;
    for(size_t i=0;i<*count;i++) {
        if(!number(p,size,&at,&n)||!n||n>300||n>size-at||memchr(p+at,0,n))return 0;
        memcpy(objects[i].uri,p+at,n);objects[i].uri[n]=0;at+=n;
        const char *uri=objects[i].uri;
        if(uri[0]=='/'||uri[0]=='#'||strstr(uri,"..")||strchr(uri,':')||strchr(uri,'?')||strchr(uri,'#')||strchr(uri,'\\')||
           (strchr(uri,'/')&&strcmp(uri,"META-INF/manifest.xml")))return 0;
        for(const unsigned char *c=(const unsigned char*)uri;*c;c++)if(*c<=32||*c>=127)return 0;
        for(size_t j=0;j<i;j++)if(!strcmp(objects[j].uri,uri))return 0;
        if(!number(p,size,&at,&n)||!n||n>=64||n>size-at||memchr(p+at,0,n))return 0;
        memcpy(objects[i].mime,p+at,n);objects[i].mime[n]=0;at+=n;
        if(strcmp(objects[i].mime,"application/octet-stream")&&strcmp(objects[i].mime,"application/xml"))return 0;
        if(!number(p,size,&at,&n)||!n||n>8*1024*1024||n>size-at)return 0;
        objects[i].bytes=p+at;objects[i].size=n;at+=n;total+=n;
    }
    return at==size&&total<=16*1024*1024+16384;
}
static int named(xmlNodePtr n,const char *name,const char *ns) {
    return n && n->type==XML_ELEMENT_NODE && xmlStrEqual(n->name,BAD_CAST name) && n->ns && xmlStrEqual(n->ns->href,BAD_CAST ns);
}
static xmlNodePtr child(xmlNodePtr n,const char *name,const char *ns) {
    if(!n) return NULL; xmlNodePtr found=NULL;
    for(xmlNodePtr c=n->children;c;c=c->next) if(named(c,name,ns)) { if(found) return NULL; found=c; }
    return found;
}
static int property(xmlNodePtr n,const char *key,const char *value) {
    xmlChar *v=n?xmlGetProp(n,BAD_CAST key):NULL; int ok=v && !strcmp((char*)v,value); xmlFree(v); return ok;
}
static int shape(xmlNodePtr n,const char *pattern) {
    if(!n) return 0;
    const char *p=pattern;
    for(xmlNodePtr c=n->children;c;c=c->next) {
        if(c->type==XML_TEXT_NODE) { for(xmlChar *v=c->content;v&&*v;v++) if(!isspace(*v)) return 0; continue; }
        if(c->type!=XML_ELEMENT_NODE || !*p) return 0;
        const char *end=strchr(p,' '); size_t len=end?(size_t)(end-p):strlen(p);
        if(len<3 || xmlStrlen(c->name)!=(int)len-2 || strncmp((char*)c->name,p+2,len-2) ||
           !c->ns || !xmlStrEqual(c->ns->href,BAD_CAST (*p=='d'?DS:XA))) return 0;
        p=end?end+1:p+len;
    }
    return !*p;
}
static int attributes(xmlNodePtr n,const char *allowed) {
    if(!n) return 0;
    for(xmlAttrPtr a=n->properties;a;a=a->next) {
        if(a->ns) return 0;
        const char *p=allowed; int found=0;
        while(*p) { const char *end=strchr(p,' '); size_t l=end?(size_t)(end-p):strlen(p);
            if(xmlStrlen(a->name)==(int)l && !strncmp((char*)a->name,p,l)) found=1;
            p=end?end+1:p+l;
        }
        if(!found) return 0;
    }
    return 1;
}
static int leaf(xmlNodePtr n) {
    if(!n) return 0;
    for(xmlNodePtr c=n->children;c;c=c->next) if(c->type!=XML_TEXT_NODE) return 0;
    return 1;
}
static int algorithm(xmlNodePtr n,const char *uri) { return n && attributes(n,"Algorithm") && shape(n,"") && property(n,"Algorithm",uri); }
static int scan(xmlDocPtr doc,xmlNodePtr n,int depth,int *nodes,xmlNodePtr signature) {
    for(;n;n=n->next) {
        if(++*nodes>100000 || depth>64) return 0;
        if(n->type==XML_TEXT_NODE) continue;
        if(n->type!=XML_ELEMENT_NODE) return 0; // No DTD, entity nodes, PI, comments or XInclude processing.
        if(n->ns && xmlStrEqual(n->ns->href,BAD_CAST "http://www.w3.org/2001/XInclude")) return 0;
        if(n->ns && (xmlStrEqual(n->ns->href,BAD_CAST DS)||xmlStrEqual(n->ns->href,BAD_CAST XA))) {
            xmlNodePtr p=n; while(p && p!=signature) p=p->parent;
            if(!p) return 0; // Signature namespaces cannot be hidden in application payload.
        }
        int ids=0, attrs=0;
        for(xmlAttrPtr a=n->properties;a;a=a->next) {
            if(++attrs>128) return 0;
            if(a->ns && xmlStrEqual(a->ns->href,BAD_CAST "http://www.w3.org/XML/1998/namespace") && xmlStrEqual(a->name,BAD_CAST "base")) return 0;
            if(!xmlStrcasecmp(a->name,BAD_CAST "id")) {
                if(++ids>1 || (a->ns && !(xmlStrEqual(a->ns->href,BAD_CAST "http://www.w3.org/XML/1998/namespace") && xmlStrEqual(a->name,BAD_CAST "id")))) return 0;
                xmlChar *v=xmlNodeListGetString(doc,a->children,1);
                if(!v || xmlStrlen(v)>256 || xmlValidateNCName(v,0)!=0) { xmlFree(v); return 0; }
                xmlAttrPtr old=xmlGetID(doc,v);
                if((old && old!=a) || (!old && !xmlAddID(NULL,doc,v,a))) { xmlFree(v); return 0; }
                xmlFree(v);
            }
        }
        if(!scan(doc,n->children,depth+1,nodes,signature)) return 0;
    }
    return 1;
}
static xmlDocPtr parse(const unsigned char *data,size_t size) {
    if(!data || !size || size>LIMIT || memchr(data,0,size)) return NULL;
    for(size_t i=0;i+8<size;i++) if(!strncasecmp((const char*)data+i,"<!DOCTYPE",9)||!strncasecmp((const char*)data+i,"<!ENTITY",8)) return NULL;
    unsigned char *utf=malloc(size+1); if(!utf) return NULL; memcpy(utf,data,size);utf[size]=0;
    int valid=xmlCheckUTF8(utf); free(utf); if(!valid) return NULL;
    int options=XML_PARSE_NONET|XML_PARSE_NOERROR|XML_PARSE_NOWARNING;
#if LIBXML_VERSION >= 21300
    options|=XML_PARSE_NO_XXE;
#endif
    xmlDocPtr doc=xmlReadMemory((const char*)data,(int)size,NULL,NULL,options);
    if(doc && (doc->intSubset || doc->extSubset || !xmlStrEqual(doc->version,BAD_CAST "1.0") ||
               (doc->encoding && xmlStrcasecmp(doc->encoding,BAD_CAST "UTF-8") && xmlStrcasecmp(doc->encoding,BAD_CAST "UTF8")))) { xmlFreeDoc(doc);return NULL; }
    return doc;
}
static int copy(unsigned char **out,size_t *size,const unsigned char *bytes,size_t len) {
    if(!bytes || !len || len>LIMIT) return 0;
    *out=malloc(len); if(!*out) return 0; memcpy(*out,bytes,len); *size=len; return 1;
}
static int canonical(xmlDocPtr doc,xmlNodePtr node,unsigned char **out,size_t *size) {
    xmlXPathContextPtr xp=NULL;xmlXPathObjectPtr obj=NULL;xmlChar *buf=NULL;int len=-1,ok=0;
    if(node) {
        xp=xmlXPathNewContext(doc); if(!xp) goto done;xp->node=node;
        obj=xmlXPathEvalExpression(BAD_CAST "(.//. | .//@* | .//namespace::*)",xp);
        if(!obj || !obj->nodesetval) goto done;
    }
    len=xmlC14NDocDumpMemory(doc,obj?obj->nodesetval:NULL,XML_C14N_EXCLUSIVE_1_0,NULL,0,&buf);
    ok=len>0 && copy(out,size,buf,(size_t)len);
 done: xmlFree(buf);if(obj)xmlXPathFreeObject(obj);if(xp)xmlXPathFreeContext(xp);return ok;
}
static int serialize(xmlDocPtr doc,signum_xades_result *r) {
    xmlChar *buf=NULL;int len=0;xmlDocDumpMemoryEnc(doc,&buf,&len,"UTF-8");
    int ok=len>0 && copy(&r->document,&r->document_size,buf,(size_t)len);xmlFree(buf);return ok;
}
static void base64(xmlNodePtr n,const unsigned char *bytes,size_t len) {
    unsigned char *buf=malloc(4*((len+2)/3)+1);if(!buf)return;
    EVP_EncodeBlock(buf,bytes,(int)len);xmlNodeSetContent(n,buf);free(buf);
}
static unsigned char *decode(xmlNodePtr n,size_t *size) {
    if(!leaf(n))return NULL;xmlChar *text=xmlNodeGetContent(n);if(!text)return NULL;
    size_t len=xmlStrlen(text),k=0;unsigned char *b=malloc(len+1),*out=malloc(len+1);
    if(!b||!out){free(b);free(out);xmlFree(text);return NULL;}
    for(size_t i=0;i<len;i++)if(!isspace(text[i]))b[k++]=text[i];b[k]=0;xmlFree(text);
    int got=k && k%4==0 && k<=131072?EVP_DecodeBlock(out,b,(int)k):-1;
    if(got>0 && b[k-1]=='=')got--;if(got>0 && k>1 && b[k-2]=='=')got--;
    unsigned char *back=malloc(k+1);int valid=got>0 && back && EVP_EncodeBlock(back,out,got)==(int)k && !memcmp(back,b,k);
    free(back);free(b);if(!valid){free(out);return NULL;}*size=(size_t)got;return out;
}
static int digest_node(xmlDocPtr doc,xmlNodePtr n,xmlNodePtr value) {
    unsigned char *bytes=NULL,hash[32];size_t len=0;unsigned int hl=0;
    int ok=canonical(doc,n,&bytes,&len) && EVP_Digest(bytes,len,hash,&hl,EVP_sha256(),NULL)==1;
    if(ok)base64(value,hash,hl);free(bytes);return ok;
}
static int rsa_certificate(const unsigned char *der,size_t size) {
    if(!der || !size || size>65536)return 0;
    const unsigned char *p=der; X509 *c=d2i_X509(NULL,&p,size);EVP_PKEY *key=c?X509_get_pubkey(c):NULL;
    int ok=c&&p==der+size&&key&&EVP_PKEY_base_id(key)==EVP_PKEY_RSA&&EVP_PKEY_get_bits(key)>=2048&&EVP_PKEY_get_bits(key)<=8192;
    EVP_PKEY_free(key);X509_free(c);return ok;
}
static xmlNodePtr add(xmlNodePtr p,xmlNsPtr ns,const char *name,const char *text) { return xmlNewChild(p,ns,BAD_CAST name,text?BAD_CAST text:NULL); }
static void attr(xmlNodePtr n,const char *name,const char *v) { xmlNewProp(n,BAD_CAST name,BAD_CAST v); }
static xmlNodePtr method(xmlNodePtr p,xmlNsPtr ns,const char *name,const char *uri) { xmlNodePtr n=add(p,ns,name,NULL);attr(n,"Algorithm",uri);return n; }
static xmlNodePtr reference(xmlNodePtr si,xmlNsPtr ds,const char *uri,const char *id,int root) {
    xmlNodePtr ref=add(si,ds,"Reference",NULL);attr(ref,"URI",uri);
    if(root)attr(ref,"Id",id);else attr(ref,"Type",SPT);
    if(root!=2) { xmlNodePtr ts=add(ref,ds,"Transforms",NULL);if(root)method(ts,ds,"Transform",ENV);method(ts,ds,"Transform",EX); }
    method(ref,ds,"DigestMethod",SHA);return add(ref,ds,"DigestValue",NULL);
}
void signum_xades_dispose(signum_xades_result *r) {
    free(r->document);free(r->signed_info);free(r->certificate);free(r->signature);memset(r,0,sizeof(*r));
}
int signum_xades_input(const unsigned char *data,size_t size,signum_xades_result *r) {
    memset(r,0,sizeof(*r));xmlDocPtr doc=parse(data,size);int nodes=0;
    int ok=doc && scan(doc,doc->children,0,&nodes,NULL);
    if(!ok)snprintf(r->error,sizeof(r->error),"XML fuori profilo: UTF-8, nessuna firma preesistente/DTD/entità/PI/commento, ID univoci e limiti richiesti.");
    if(doc)xmlFreeDoc(doc);return ok;
}
static int prepare(const unsigned char *data,size_t size,const unsigned char *cert,size_t cert_size,const char *time,signum_xades_result *r,const detached_object *objects,size_t count) {
    memset(r,0,sizeof(*r));int ok=0,nodes=0;xmlDocPtr doc=NULL;unsigned char root_hash[32],nonce[16];unsigned int hl=0;
    unsigned char *root_bytes=NULL;size_t root_size=0;
    REQUIRE(signum_xml_initialize(),"xmlsec initialization");
    if(objects) {
        doc=xmlNewDoc(BAD_CAST "1.0");REQUIRE(doc,"XML allocation");
        xmlNodePtr root=xmlNewNode(NULL,BAD_CAST "XAdESSignatures");xmlDocSetRootElement(doc,root);
        xmlSetNs(root,xmlNewNs(root,BAD_CAST ASIC,BAD_CAST "asic"));
    } else {
        doc=parse(data,size);REQUIRE(doc && scan(doc,doc->children,0,&nodes,NULL),"Unsigned XML rejected: structure/IDs/resource limits");
    }
    REQUIRE(rsa_certificate(cert,cert_size),"RSA 2048..8192 signer certificate required");
    REQUIRE(time && strlen(time)==20 && time[19]=='Z',"UTC declared SigningTime required");
    if(!objects)REQUIRE(canonical(doc,NULL,&root_bytes,&root_size) && EVP_Digest(root_bytes,root_size,root_hash,&hl,EVP_sha256(),NULL)==1,"root canonicalization");
    REQUIRE(RAND_bytes(nonce,sizeof(nonce))==1,"signature identifier generation");
    char id[40]="Signum-",spid[64],refid[64],target[64],spuri[80],refuri[80];
    for(int i=0;i<16;i++)snprintf(id+7+2*i,3,"%02x",nonce[i]);
    snprintf(spid,sizeof(spid),"%s-properties",id);snprintf(refid,sizeof(refid),"%s-data",id);
    snprintf(target,sizeof(target),"#%s",id);snprintf(spuri,sizeof(spuri),"#%s",spid);snprintf(refuri,sizeof(refuri),"#%s",refid);
    REQUIRE(!xmlGetID(doc,BAD_CAST id)&&!xmlGetID(doc,BAD_CAST spid)&&!xmlGetID(doc,BAD_CAST refid),"identifier collision");
    xmlNodePtr sig=add(xmlDocGetRootElement(doc),NULL,"Signature",NULL);REQUIRE(sig,"signature allocation");
    xmlNsPtr ds=xmlNewNs(sig,BAD_CAST DS,BAD_CAST "ds");xmlSetNs(sig,ds);attr(sig,"Id",id);
    xmlNodePtr si=add(sig,ds,"SignedInfo",NULL);method(si,ds,"CanonicalizationMethod",EX);method(si,ds,"SignatureMethod",RSA);
    xmlNodePtr root_value=NULL;
    if(objects) {
        for(size_t i=0;i<count;i++) {
            char rid[80];snprintf(rid,sizeof(rid),"%s-%zu",refid,i);
            xmlNodePtr v=reference(si,ds,objects[i].uri,rid,2);unsigned char h[32];
            REQUIRE(EVP_Digest(objects[i].bytes,objects[i].size,h,&hl,EVP_sha256(),NULL)==1,"detached digest");base64(v,h,32);
        }
    } else { root_value=reference(si,ds,"",refid,1);base64(root_value,root_hash,32); }
    xmlNodePtr sp_value=reference(si,ds,spuri,NULL,0);
    add(sig,ds,"SignatureValue",NULL);
    xmlNodePtr ki=add(sig,ds,"KeyInfo",NULL);base64(add(add(ki,ds,"X509Data",NULL),ds,"X509Certificate",NULL),cert,cert_size);
    xmlNodePtr qp=add(add(sig,ds,"Object",NULL),NULL,"QualifyingProperties",NULL);
    xmlNsPtr xa=xmlNewNs(qp,BAD_CAST XA,BAD_CAST "xades");xmlSetNs(qp,xa);attr(qp,"Target",target);
    xmlNodePtr sp=add(qp,xa,"SignedProperties",NULL);attr(sp,"Id",spid);
    xmlNodePtr ssp=add(sp,xa,"SignedSignatureProperties",NULL);add(ssp,xa,"SigningTime",time);
    xmlNodePtr cd=add(add(add(ssp,xa,"SigningCertificateV2",NULL),xa,"Cert",NULL),xa,"CertDigest",NULL);
    method(cd,ds,"DigestMethod",SHA);unsigned char hash[32];REQUIRE(EVP_Digest(cert,cert_size,hash,&hl,EVP_sha256(),NULL)==1,"certificate digest");base64(add(cd,ds,"DigestValue",NULL),hash,32);
    xmlNodePtr sdp=add(sp,xa,"SignedDataObjectProperties",NULL);
    for(size_t i=0;i<(objects?count:1);i++) {
        char uri[100];snprintf(uri,sizeof(uri),objects?"#%s-%zu":"#%s",refid,i);
        xmlNodePtr fmt=add(sdp,xa,"DataObjectFormat",NULL);attr(fmt,"ObjectReference",uri);add(fmt,xa,"MimeType",objects?objects[i].mime:"application/xml");
    }
    REQUIRE(digest_node(doc,sp,sp_value)&&canonical(doc,si,&r->signed_info,&r->signed_info_size)&&r->signed_info_size<=4096&&serialize(doc,r),"preparation/canonicalization limits");
    ok=1;
 done:free(root_bytes);if(doc)xmlFreeDoc(doc);return ok;
}
static int signing_time(xmlNodePtr n,char out[32]) {
    if(!leaf(n)||!attributes(n,""))return 0;
    xmlChar *s=xmlNodeGetContent(n);int ok=s&&xmlStrlen(s)==20;
    if(ok) {
        for(int i=0;i<20;i++) {
            char expected=i==4||i==7?'-':i==10?'T':i==13||i==16?':':i==19?'Z':0;
            if(expected ? s[i]!=expected : !isdigit(s[i]))ok=0;
        }
        int y=0,m=0,d=0,h=0,minute=0,sec=0;
        if(sscanf((char*)s,"%4d-%2d-%2dT%2d:%2d:%2dZ",&y,&m,&d,&h,&minute,&sec)!=6)ok=0;
        const int days[]={31,28,31,30,31,30,31,31,30,31,30,31};
        if(y<1970||m<1||m>12||d<1||h>23||minute>59||sec>59)ok=0;
        else if(d>days[m-1]+(m==2&&y%4==0&&(y%100!=0||y%400==0)))ok=0;
        if(ok)memcpy(out,s,21);
    }
    xmlFree(s);return ok;
}
static int process(const unsigned char *data,size_t size,const unsigned char *signature,size_t signature_size,signum_xades_result *r,const detached_object *objects,size_t count) {
    memset(r,0,sizeof(*r));int ok=0,nodes=0;xmlDocPtr doc=NULL;xmlSecDSigCtxPtr ctx=NULL;
    unsigned char *certificate=NULL,*binding=NULL;size_t certificate_size=0,binding_size=0;
    xmlChar *sid=NULL,*spid=NULL,*refid=NULL;
    REQUIRE(signum_xml_initialize(),"xmlsec initialization");doc=parse(data,size);REQUIRE(doc,"Malformed/unsafe XML");
    xmlNodePtr root=xmlDocGetRootElement(doc),sig=child(root,"Signature",DS);
    REQUIRE(sig && scan(doc,doc->children,0,&nodes,sig),"Signature placement, duplicate IDs or unsafe XML");
    if(objects)REQUIRE(named(root,"XAdESSignatures",ASIC)&&shape(root,"d:Signature")&&attributes(root,""),"ASiC signatures root");
    for(xmlNodePtr n=sig->next;n;n=n->next)REQUIRE(n->type==XML_TEXT_NODE,"Signature must be the last root element");
    REQUIRE(shape(sig,"d:SignedInfo d:SignatureValue d:KeyInfo d:Object")&&attributes(sig,"Id"),"Signature structure outside profile");
    sid=xmlGetProp(sig,BAD_CAST "Id");REQUIRE(sid&&xmlGetID(doc,sid)&&xmlGetID(doc,sid)->parent==sig,"Signature Id");
    xmlNodePtr si=child(sig,"SignedInfo",DS),sv=child(sig,"SignatureValue",DS),ki=child(sig,"KeyInfo",DS),object=child(sig,"Object",DS);
    char si_shape[256]="d:CanonicalizationMethod d:SignatureMethod",sdp_shape[200]="";
    for(size_t i=0;i<(objects?count+1:2);i++)strcat(si_shape," d:Reference");
    for(size_t i=0;i<(objects?count:1);i++)strcat(sdp_shape,i?" x:DataObjectFormat":"x:DataObjectFormat");
    REQUIRE(shape(si,si_shape)&&attributes(si,"")&&attributes(sv,"")&&leaf(sv),"SignedInfo structure");
    REQUIRE(algorithm(child(si,"CanonicalizationMethod",DS),EX)&&algorithm(child(si,"SignatureMethod",DS),RSA),"Only exclusive c14n and RSA-SHA256 supported");
    REQUIRE(shape(ki,"d:X509Data")&&attributes(ki,"")&&shape(object,"x:QualifyingProperties")&&attributes(object,""),"KeyInfo/Object structure");
    xmlNodePtr xd=child(ki,"X509Data",DS),xc=child(xd,"X509Certificate",DS),qp=child(object,"QualifyingProperties",XA);
    REQUIRE(shape(xd,"d:X509Certificate")&&attributes(xd,"")&&attributes(xc,"")&&shape(qp,"x:SignedProperties")&&attributes(qp,"Target"),"Ambiguous signer or QualifyingProperties");
    char target[300];snprintf(target,sizeof(target),"#%s",sid);REQUIRE(property(qp,"Target",target),"QualifyingProperties Target mismatch");
    xmlNodePtr sp=child(qp,"SignedProperties",XA),ssp=child(sp,"SignedSignatureProperties",XA),sdp=child(sp,"SignedDataObjectProperties",XA);
    REQUIRE(shape(sp,"x:SignedSignatureProperties x:SignedDataObjectProperties")&&attributes(sp,"Id")&&
            shape(ssp,"x:SigningTime x:SigningCertificateV2")&&attributes(ssp,"")&&shape(sdp,sdp_shape)&&attributes(sdp,""),"SignedProperties structure");
    spid=xmlGetProp(sp,BAD_CAST "Id");REQUIRE(spid&&xmlGetID(doc,spid)&&xmlGetID(doc,spid)->parent==sp,"SignedProperties Id");
    xmlNodePtr sc=child(ssp,"SigningCertificateV2",XA),cert=child(sc,"Cert",XA),cd=child(cert,"CertDigest",XA);
    REQUIRE(shape(sc,"x:Cert")&&attributes(sc,"")&&shape(cert,"x:CertDigest")&&attributes(cert,"")&&shape(cd,"d:DigestMethod d:DigestValue")&&attributes(cd,"")&&
            algorithm(child(cd,"DigestMethod",DS),SHA)&&attributes(child(cd,"DigestValue",DS),""),"SigningCertificateV2 profile");
    REQUIRE(signing_time(child(ssp,"SigningTime",XA),r->signing_time),"Declared SigningTime invalid");
    certificate=decode(xc,&certificate_size);REQUIRE(rsa_certificate(certificate,certificate_size),"Signer certificate invalid or unsupported RSA key");
    binding=decode(child(cd,"DigestValue",DS),&binding_size);unsigned char hash[32];unsigned int hl=0;
    if(!(binding&&binding_size==32&&EVP_Digest(certificate,certificate_size,hash,&hl,EVP_sha256(),NULL)==1&&!memcmp(hash,binding,32))) {
        snprintf(r->error,sizeof(r->error),"Signer certificate digest mismatch");ok=-1;goto done;
    }
    xmlNodePtr refs[6]={0};size_t index=0;
    for(xmlNodePtr n=si->children;n;n=n->next)if(named(n,"Reference",DS))refs[index++]=n;
    size_t data_count=objects?count:1;
    REQUIRE(index==data_count+1,"Reference count");
    char spuri[300];snprintf(spuri,sizeof(spuri),"#%s",spid);
    xmlNodePtr spref=refs[data_count];
    REQUIRE(attributes(spref,"URI Type")&&property(spref,"URI",spuri)&&property(spref,"Type",SPT),"SignedProperties reference binding");
    for(size_t i=0;i<index;i++) {
        xmlNodePtr ref=refs[i];int detached=objects&&i<data_count;
        REQUIRE(shape(ref,detached?"d:DigestMethod d:DigestValue":"d:Transforms d:DigestMethod d:DigestValue")&&
                algorithm(child(ref,"DigestMethod",DS),SHA)&&attributes(child(ref,"DigestValue",DS),"")&&leaf(child(ref,"DigestValue",DS)),"Reference digest/structure");
        if(detached) {
            REQUIRE(attributes(ref,"URI Id")&&property(ref,"URI",objects[i].uri),"Unknown, reordered, external or uncovered detached reference");
            size_t len=0;unsigned char *value=decode(child(ref,"DigestValue",DS),&len);unsigned char hash[32];unsigned int hlen=0;
            int valid=value&&len==32&&EVP_Digest(objects[i].bytes,objects[i].size,hash,&hlen,EVP_sha256(),NULL)==1&&!memcmp(hash,value,32);free(value);
            if(!valid){snprintf(r->error,sizeof(r->error),"Detached content digest mismatch");ok=-1;goto done;}
        } else {
            if(i==0)REQUIRE(attributes(ref,"URI Id")&&property(ref,"URI",""),"Reference coverage/external URI forbidden");
            xmlNodePtr ts=child(ref,"Transforms",DS);
            REQUIRE(attributes(ts,"")&&shape(ts,!objects&&i==0?"d:Transform d:Transform":"d:Transform"),"Reference transform count");
            int j=0;for(xmlNodePtr n=ts->children;n;n=n->next)if(n->type==XML_ELEMENT_NODE){REQUIRE(algorithm(n,!objects&&i==0&&j==0?ENV:EX),"Transform not allowed");j++;}
        }
    }
    xmlNodePtr fmt=sdp->children;
    for(size_t i=0;i<data_count;i++) {
        while(fmt&&fmt->type!=XML_ELEMENT_NODE)fmt=fmt->next;
        xmlChar *rid=xmlGetProp(refs[i],BAD_CAST "Id");
        int identified=rid&&xmlGetID(doc,rid)&&xmlGetID(doc,rid)->parent==refs[i];
        char refuri[300];snprintf(refuri,sizeof(refuri),"#%s",rid?rid:BAD_CAST "");xmlFree(rid);
        xmlNodePtr mime=child(fmt,"MimeType",XA);
        REQUIRE(identified&&shape(fmt,"x:MimeType")&&attributes(fmt,"ObjectReference")&&property(fmt,"ObjectReference",refuri)&&leaf(mime)&&attributes(mime,""),"DataObjectFormat binding/profile");
        xmlChar *mt=xmlNodeGetContent(mime);int valid=mt&&!strcmp((char*)mt,objects?objects[i].mime:"application/xml");xmlFree(mt);REQUIRE(valid,"DataObjectFormat MIME mismatch");
        fmt=fmt->next;
    }
    if(signature) { REQUIRE(signature_size>=256&&signature_size<=1024,"RSA signature length");base64(sv,signature,signature_size); }
    r->signature=decode(sv,&r->signature_size);REQUIRE(r->signature&&r->signature_size>=256&&r->signature_size<=1024,"SignatureValue malformed");
    if(objects) {
        size_t len=0;unsigned char *value=decode(child(spref,"DigestValue",DS),&len),*canon=NULL;size_t canon_size=0;
        unsigned char hash[32];unsigned int hlen=0;
        int valid=value&&len==32&&canonical(doc,sp,&canon,&canon_size)&&EVP_Digest(canon,canon_size,hash,&hlen,EVP_sha256(),NULL)==1&&!memcmp(hash,value,32);
        free(value);free(canon);
        if(!valid){snprintf(r->error,sizeof(r->error),"SignedProperties digest mismatch");ok=-1;goto done;}
        unsigned char *signed_bytes=NULL;size_t signed_size=0;
        REQUIRE(canonical(doc,si,&signed_bytes,&signed_size),"SignedInfo canonicalization");
        const unsigned char *cp=certificate;X509 *x509=d2i_X509(NULL,&cp,certificate_size);EVP_PKEY *key=x509?X509_get_pubkey(x509):NULL;
        EVP_MD_CTX *md=EVP_MD_CTX_new();EVP_PKEY_CTX *pkey=NULL;
        valid=signed_size<=4096&&key&&md&&EVP_DigestVerifyInit(md,&pkey,EVP_sha256(),NULL,key)==1&&
            EVP_PKEY_CTX_set_rsa_padding(pkey,RSA_PKCS1_PADDING)>0&&EVP_DigestVerify(md,r->signature,r->signature_size,signed_bytes,signed_size)==1;
        free(signed_bytes);EVP_MD_CTX_free(md);EVP_PKEY_free(key);X509_free(x509);
        if(!valid){snprintf(r->error,sizeof(r->error),"Detached XMLDSig signature invalid");ok=-1;goto done;}
    } else {
    ctx=xmlSecDSigCtxCreate(NULL);REQUIRE(ctx,"xmlsec context");
    ctx->enabledReferenceUris=xmlSecTransformUriTypeEmpty|xmlSecTransformUriTypeSameDocument;
    ctx->keyInfoReadCtx.retrievalMethodCtx.enabledUris=xmlSecTransformUriTypeNone;
    REQUIRE(xmlSecDSigCtxEnableReferenceTransform(ctx,xmlSecTransformEnvelopedId)>=0&&
            xmlSecDSigCtxEnableReferenceTransform(ctx,xmlSecTransformExclC14NId)>=0&&
            xmlSecDSigCtxEnableReferenceTransform(ctx,xmlSecTransformSha256Id)>=0,"Reference transform whitelist");
    ctx->signKey=xmlSecCryptoAppKeyLoadMemory(certificate,certificate_size,xmlSecKeyDataFormatCertDer,NULL,NULL,NULL);
    REQUIRE(ctx->signKey,"Signer public key unavailable");
    if(xmlSecDSigCtxVerify(ctx,sig)<0||ctx->status!=xmlSecDSigStatusSucceeded) {
        snprintf(r->error,sizeof(r->error),"XMLDSig signature or reference integrity invalid");ok=-1;goto done;
    }
    }
    REQUIRE(canonical(doc,si,&r->signed_info,&r->signed_info_size)&&r->signed_info_size<=4096&&copy(&r->certificate,&r->certificate_size,certificate,certificate_size),"Verified result bounds");
    if(signature)REQUIRE(serialize(doc,r),"Signed XML serialization");ok=1;
 done:free(certificate);free(binding);xmlFree(sid);xmlFree(spid);xmlFree(refid);if(ctx)xmlSecDSigCtxDestroy(ctx);if(doc)xmlFreeDoc(doc);return ok;
}
int signum_xades_verify(const unsigned char *data,size_t size,signum_xades_result *r) { return process(data,size,NULL,0,r,NULL,0); }
int signum_xades_finish(const unsigned char *data,size_t size,const unsigned char *sig,size_t sig_size,signum_xades_result *r) { return process(data,size,sig,sig_size,r,NULL,0); }

int signum_xades_prepare(const unsigned char *data,size_t size,const unsigned char *cert,size_t cert_size,const char *time,signum_xades_result *r) {
    return prepare(data,size,cert,cert_size,time,r,NULL,0);
}
int signum_xades_detached_prepare(const unsigned char *packed,size_t size,const unsigned char *cert,size_t cert_size,const char *time,signum_xades_result *r) {
    detached_object objects[5];size_t count=0;
    if(!unpack(packed,size,objects,&count)){memset(r,0,sizeof(*r));snprintf(r->error,sizeof(r->error),"Detached objects rejected");return 0;}
    return prepare(NULL,0,cert,cert_size,time,r,objects,count);
}
int signum_xades_detached_verify(const unsigned char *data,size_t size,const unsigned char *packed,size_t packed_size,signum_xades_result *r) {
    detached_object objects[5];size_t count=0;
    if(!unpack(packed,packed_size,objects,&count)){memset(r,0,sizeof(*r));snprintf(r->error,sizeof(r->error),"Detached objects rejected");return 0;}
    return process(data,size,NULL,0,r,objects,count);
}
int signum_xades_detached_finish(const unsigned char *data,size_t size,const unsigned char *packed,size_t packed_size,const unsigned char *sig,size_t sig_size,signum_xades_result *r) {
    detached_object objects[5];size_t count=0;
    if(!unpack(packed,packed_size,objects,&count)){memset(r,0,sizeof(*r));snprintf(r->error,sizeof(r->error),"Detached objects rejected");return 0;}
    return process(data,size,sig,sig_size,r,objects,count);
}

static xmlChar *manifest_uri(const xmlChar *path) {
    size_t len=xmlStrlen(path);xmlChar *out=xmlMalloc(3*len+1);if(!out)return NULL;
    static const char hex[]="0123456789ABCDEF";size_t at=0;
    for(size_t i=0;i<len;i++) {
        unsigned char c=path[i];
        if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||strchr("-._~",c))out[at++]=c;
        else {out[at++]='%';out[at++]=hex[c>>4];out[at++]=hex[c&15];}
    }
    out[at]=0;return out;
}
/* ODF manifest is interpreted by namespace/fields, not by serializer spelling.
 * Its exact bytes are separately covered by the detached signature. */
int signum_asic_manifest(const unsigned char *data,size_t size,const unsigned char *packed,size_t packed_size) {
    static const char *ns="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
    detached_object objects[5];size_t count=0;int nodes=0,valid=0,roots=0;unsigned int seen=0;
    if(size>16384||!unpack(packed,packed_size,objects,&count)||count<3||strcmp(objects[count-1].uri,"META-INF/manifest.xml"))return 0;
    xmlDocPtr doc=parse(data,size);if(!doc) return 0;
    xmlNodePtr root=xmlDocGetRootElement(doc);
    if(!named(root,"manifest",ns)||!scan(doc,doc->children,0,&nodes,NULL))goto done;
    for(xmlAttrPtr a=root->properties;a;a=a->next)if(!a->ns||!xmlStrEqual(a->ns->href,BAD_CAST ns)||!xmlStrEqual(a->name,BAD_CAST "version"))goto done;
    xmlChar *version=xmlGetNsProp(root,BAD_CAST "version",BAD_CAST ns);int version_ok=version&&xmlStrEqual(version,BAD_CAST "1.2");xmlFree(version);if(!version_ok)goto done;
    for(xmlNodePtr n=root->children;n;n=n->next) {
        if(n->type==XML_TEXT_NODE){for(xmlChar *c=n->content;c&&*c;c++)if(!isspace(*c))goto done;continue;}
        if(!named(n,"file-entry",ns)||!shape(n,""))goto done;
        for(xmlAttrPtr a=n->properties;a;a=a->next)if(!a->ns||!xmlStrEqual(a->ns->href,BAD_CAST ns)||(!xmlStrEqual(a->name,BAD_CAST "full-path")&&!xmlStrEqual(a->name,BAD_CAST "media-type")))goto done;
        xmlChar *path=xmlGetNsProp(n,BAD_CAST "full-path",BAD_CAST ns),*mime=xmlGetNsProp(n,BAD_CAST "media-type",BAD_CAST ns);
        int matched=0;
        if(path&&mime&&xmlStrEqual(path,BAD_CAST "/")) { matched=++roots==1&&xmlStrEqual(mime,BAD_CAST "application/vnd.etsi.asic-e+zip"); }
        else if(path&&mime&&xmlStrEqual(mime,BAD_CAST "application/octet-stream")) {
            xmlChar *uri=manifest_uri(path);
            if(uri)for(size_t i=0;i<count-1;i++)if(xmlStrEqual(uri,BAD_CAST objects[i].uri)&&!(seen&(1U<<i))) {seen|=1U<<i;matched=1;break;}
            xmlFree(uri);
        }
        xmlFree(path);xmlFree(mime);if(!matched)goto done;
    }
    valid=roots==1&&seen==((1U<<(count-1))-1);
 done:xmlFreeDoc(doc);return valid;
}
