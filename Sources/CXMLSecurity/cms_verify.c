#include "CXMLSecurity.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/objects.h>

/* In-process equivalent of `openssl cms -verify -inform DER -binary -noverify`,
 * using the bundled OpenSSL instead of the system LibreSSL command line tool. */
int signum_cms_verify_attached(const unsigned char *der, size_t length, size_t maximum_content,
                               unsigned char **content, size_t *content_length) {
    if (content) *content = NULL;
    if (content_length) *content_length = 0;
    if (!der || !length || length > LONG_MAX || !content || !content_length) return -1;
    const unsigned char *cursor = der;
    CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)length);
    int status = -1;
    BIO *out = NULL;
    /* Exactly one DER object, attached SignedData only. */
    if (!cms || cursor != der + length || OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_signed ||
        CMS_is_detached(cms) == 1) goto done;
    out = BIO_new(BIO_s_mem());
    if (!out) goto done;
    /* Signed attributes, content digest and signature of every SignerInfo are
     * checked; the signer certificate chain deliberately is not (no trust). */
    if (CMS_verify(cms, NULL, NULL, NULL, out, CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) != 1) { status = 0; goto done; }
    char *data = NULL;
    long produced = BIO_get_mem_data(out, &data);
    if (produced < 0 || (size_t)produced > maximum_content) goto done;
    unsigned char *copy = malloc(produced ? (size_t)produced : 1);
    if (!copy) goto done;
    if (produced) memcpy(copy, data, (size_t)produced);
    *content = copy; *content_length = (size_t)produced; status = 1;
done:
    BIO_free(out);
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return status;
}

void signum_cms_free(unsigned char *content, size_t length) {
    if (!content) return;
    volatile unsigned char *p = content;
    for (size_t i = 0; i < length; ++i) p[i] = 0;
    free(content);
}
