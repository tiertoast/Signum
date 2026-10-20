#if os(macOS)
import Foundation
import SignumCore

struct LoadedCertificates {
    var certificates: [SignumCertificate] = []
    var identities: [String: SignumCertificateIdentity] = [:]
    var assessments: [String: CertificateEligibility.Assessment] = [:]
    var derByID: [String: Data] = [:]
}

/// One value replaced on provider edits. The accepted canonical provider is
/// bound to the exact visible path and discovery generation that produced it.
/// No filesystem resolution or vendor calls occur on the UI thread.
struct ProviderSelection {
    private(set) var path = "/Library/bit4id/pkcs11/libbit4xpki.dylib"
    private(set) var activeModulePath: String?
    private var loadedInputPath: String?
    private(set) var requestID = UUID()
    private(set) var tokens: [SignumToken] = []
    var selectedSlot: UInt?
    var selectedCertificateID: String?
    var certificates: [SignumCertificate] = []
    var certificateIdentities: [String: SignumCertificateIdentity] = [:]
    var certificateAssessments: [String: CertificateEligibility.Assessment] = [:]
    var certificateDERs: [String: Data] = [:]
    var pin = ""

    var signingProvider: String? { loadedInputPath == path ? activeModulePath : nil }

    mutating func changePath(_ next: String) {
        guard next != path else { return }
        self = ProviderSelection(path: next)
    }
    private init(path: String) { self.path = path }
    init() {}

    @discardableResult mutating func beginDiscovery() -> UUID {
        self = ProviderSelection(path: path)
        return requestID
    }
    @discardableResult mutating func acceptDiscovery(request: UUID, inputPath: String, canonicalPath: String,
                                                     tokens: [SignumToken], slot: UInt?, certificates: LoadedCertificates) -> Bool {
        guard request == requestID, inputPath == path, canonicalPath.hasPrefix("/") else { return false }
        loadedInputPath = inputPath; activeModulePath = canonicalPath
        self.tokens = tokens; selectedSlot = slot
        applyCertificates(certificates)
        return true
    }
    mutating func applyCertificates(_ loaded: LoadedCertificates) {
        certificates = loaded.certificates; certificateIdentities = loaded.identities
        certificateDERs = loaded.derByID; certificateAssessments = loaded.assessments
        let eligible = loaded.certificates.filter { loaded.assessments[$0.id]?.permitsSigning == true }
        selectedCertificateID = eligible.count == 1 ? eligible[0].id : nil
    }
    mutating func beginCertificateLoad() -> UUID {
        applyCertificates(LoadedCertificates()); pin = ""; requestID = UUID()
        return requestID
    }

    mutating func select(route: DeviceCertificateRoute) {
        changePath(route.providerPath)
        let request = beginDiscovery()
        var loaded = LoadedCertificates()
        loaded.certificates = [route.certificate]
        loaded.derByID[route.certificate.id] = route.der
        loaded.assessments[route.certificate.id] = route.assessment
        loaded.identities[route.certificate.id] = route.identity
        _ = acceptDiscovery(request: request, inputPath: path, canonicalPath: route.providerPath,
            tokens: [route.token], slot: route.token.slot, certificates: loaded)
        // Inspecting an ineligible certificate is allowed; approval is blocked.
        selectedCertificateID = route.certificate.id
    }
}
#endif
