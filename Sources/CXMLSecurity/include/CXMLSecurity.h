#ifndef SIGNUM_XML_SECURITY_H
#define SIGNUM_XML_SECURITY_H
#include <stddef.h>
#include "CXAdES.h"
/* No network, PKI path building, revocation, or qualification. Serialized by Swift. */
int signum_xml_verify(const unsigned char *xml, size_t size,
                      const unsigned char *certificate, size_t cert_size,
                      const char *schema_path, char *error, size_t error_size);
/* Attached CMS SignedData integrity only (signer chain NOT verified). Returns 1
 * and the encapsulated content (free with signum_cms_free), 0 if a signature or
 * digest is invalid, -1 if malformed, detached, oversized or out of memory. */
int signum_cms_verify_attached(const unsigned char *der, size_t length, size_t maximum_content,
                               unsigned char **content, size_t *content_length);
void signum_cms_free(unsigned char *content, size_t length);
#endif
