#ifndef SIGNUM_XML_SECURITY_H
#define SIGNUM_XML_SECURITY_H
#include <stddef.h>
/* No network, PKI path building, revocation, or qualification. Serialized by Swift. */
int signum_xml_verify(const unsigned char *xml, size_t size,
                      const unsigned char *certificate, size_t cert_size,
                      const char *schema_path, char *error, size_t error_size);
#endif
