#pragma once
#include "PAdESVerification.h"
namespace signum {
struct InspectedSignature {
    std::string integrity = "notVerifiable", reason, subject, issuer, fingerprint, algorithm, declaredTime;
    size_t revisionEnd = 0, layer = 1;
    bool laterChanges = false;
};
struct Inspection {
    std::string format = "unknown", state = "unsupported", reason;
    std::vector<InspectedSignature> signatures;
    Bytes content;
    bool previewablePDF = false;
};
std::vector<InspectedSignature> inspectCMS(const Bytes& bytes, const Bytes* detached, Bytes* payload);
Inspection inspectPAdES(const Bytes& bytes);
bool isPreviewablePDF(const Bytes& bytes);
int verificationMain();
}
