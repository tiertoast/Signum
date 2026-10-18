#if os(macOS)
import Foundation

/// Presentation only. This never changes SG-04 or grants permission to sign.
public struct CertificateVisibility: Sendable {
    public let eligible: [DeviceCertificate]
    public let ineligible: [DeviceCertificate]
    public let indeterminate: [DeviceCertificate]
    public init(_ certificates: [DeviceCertificate]) {
        eligible = certificates.filter { $0.routes.first?.assessment.status == .eligible }
        ineligible = certificates.filter { $0.routes.first?.assessment.status == .ineligible }
        indeterminate = certificates.filter { $0.routes.first?.assessment.status == .indeterminate || $0.routes.isEmpty }
    }
    public func visible(showExcluded: Bool) -> [DeviceCertificate] {
        showExcluded ? eligible + ineligible + indeterminate : eligible
    }
    public func includes(route: DeviceCertificateRoute, showExcluded: Bool) -> Bool {
        visible(showExcluded: showExcluded).contains { $0.routes.contains { $0.id == route.id } }
    }
}
#endif
