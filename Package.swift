// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Signum",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SignumCore", targets: ["SignumCore"]),
        .library(name: "SignumTrustCore", targets: ["SignumTrustCore"]),
        .library(name: "SignumTrustAuthentication", targets: ["SignumTrustAuthentication"]),
        .executable(name: "SignumTrustProbe", targets: ["SignumTrustProbe"]),
        .executable(name: "SignumPKCS11Worker", targets: ["SignumPKCS11Worker"]),
        .executable(name: "SignumCLI", targets: ["SignumCLI"]),
        .executable(name: "SignumApp", targets: ["SignumApp"])
    ],
    targets: [
        .target(name: "CCertificatePolicy", publicHeadersPath: "include",
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("CoreFoundation")]),
        .target(name: "COutputPermissions", publicHeadersPath: "include"),
        .target(name: "CProcessCoordination", dependencies: ["COutputPermissions"], publicHeadersPath: "include"),
        .target(name: "CSecurePIN", publicHeadersPath: "include"),
        .target(name: "CPKCS11", dependencies: ["CCertificatePolicy"], publicHeadersPath: "include"),
        .target(name: "SignumTrustCore"),
        .target(name: "CCertificatePath", dependencies: ["CXMLSec"], publicHeadersPath: "include"),
        .target(name: "SignumCertificateValidation", dependencies: ["CCertificatePath", "SignumTrustAuthentication"]),
        .testTarget(name: "SignumCertificateValidationTests", dependencies: ["SignumCertificateValidation", "SignumCore", "SignumApp", "SignumTrustIntegration"], resources: [.copy("Fixtures")]),
        .systemLibrary(name: "CXMLSec", pkgConfig: "xmlsec1-openssl", providers: [.brew(["libxmlsec1"])]),
        .target(name: "CXMLSecurity", dependencies: ["CXMLSec"], publicHeadersPath: "include"),
        .target(name: "SignumTrustAuthentication", dependencies: ["SignumTrustCore", "CXMLSecurity"], resources: [.copy("Schemas")]),
        .executableTarget(name: "SignumTrustProbe", dependencies: ["SignumTrustAuthentication", "SignumCertificateValidation", "SignumCore"]),
        .testTarget(name: "SignumTrustAuthenticationTests", dependencies: ["SignumTrustAuthentication"], resources: [.copy("Fixtures")]),
        .testTarget(name: "SignumTrustCoreTests", dependencies: ["SignumTrustCore"]),
        .target(name: "SignumCore", dependencies: ["CPKCS11", "CCertificatePolicy", "COutputPermissions", "CProcessCoordination", "CSecurePIN"]),
        .executableTarget(name: "SignumPKCS11Worker", dependencies: ["SignumCore"]),
        .executableTarget(name: "SignumCLI", dependencies: ["SignumCore"]),
        .target(name: "SignumTrustIntegration", dependencies: ["SignumTrustAuthentication"]),
        .testTarget(name: "SignumTrustIntegrationTests", dependencies: ["SignumTrustIntegration", "SignumTrustAuthentication", "SignumApp"], resources: [.copy("Fixtures")]),
        .executableTarget(name: "SignumApp", dependencies: ["SignumCore", "SignumTrustIntegration", "SignumCertificateValidation"]),
        .executableTarget(name: "SignumOutputCrashProbe", dependencies: ["SignumCore"],
                          path: "Tests/SignumOutputCrashProbe"),
        .target(name: "SignumPlacementReference", dependencies: ["SignumCore"],
                path: "Tools/PlacementPrototype/Reference"),
        .testTarget(name: "SignumCoreTests", dependencies: ["SignumPlacementReference", "SignumCore", "SignumOutputCrashProbe", "SignumCLI", "SignumApp", "SignumPKCS11Worker"])
    ]
)
