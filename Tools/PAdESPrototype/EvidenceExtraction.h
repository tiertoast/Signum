#pragma once
#include "UnifiedVerification.h"
#include <openssl/cms.h>
namespace signum {
std::string evidenceBase64(const unsigned char*, size_t);
std::string evidenceDigest(const unsigned char*, size_t, const EVP_MD*);
void inspectSignerEvidence(CMS_SignerInfo*, InspectedSignature&);
void inspectCMSEvidence(CMS_ContentInfo*, Inspection&);
}
