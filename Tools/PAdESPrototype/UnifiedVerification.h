#pragma once
#include "PAdESVerification.h"
#include <openssl/cms.h>
namespace signum {
struct InspectedAttribute { std::string oid, der; };
struct InspectedEvidence {
    std::string kind, source, association = "unassociated", der, signatureKey;
    size_t signatureRevisionEnd = 0, sourceRevisionEnd = 0;
};
struct InspectedSignature {
    std::string integrity = "notVerifiable", reason, subject, issuer, fingerprint, algorithm, declaredTime;
    std::string signerDER, signatureValue, signatureKey, contentsSHA1;
    std::string parentSignatureKey, signerPath;
    size_t signerIndex = 0;
    std::vector<InspectedAttribute> signedAttributes, unsignedAttributes;
    std::vector<std::string> timestampTokens;
    std::vector<InspectedEvidence> evidence;
    std::string evidenceIssue;
    std::vector<std::string> certificateDERs;
    size_t revisionEnd = 0, layer = 1;
    bool laterChanges = false;
};
struct Inspection {
    std::string format = "unknown", state = "unsupported", reason;
    std::vector<InspectedSignature> signatures;
    std::vector<InspectedEvidence> unassociatedEvidence;
    Bytes content;
    bool previewablePDF = false;
};
std::vector<InspectedSignature> inspectCMS(const Bytes& bytes, const Bytes* detached, Bytes* payload, const Bytes* counterTarget = nullptr, size_t depth = 0, const std::string& pathPrefix = "");
int verifyCounterSignature(CMS_SignerInfo*, X509*, const Bytes&);
Bytes counterEnvelope(const Bytes&, const Bytes&, CMS_ContentInfo*);
Inspection inspectPAdES(const Bytes& bytes);
bool isPreviewablePDF(const Bytes& bytes);
int verificationMain(bool external = false);
}
