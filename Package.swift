// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Signum",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SignumCore", targets: ["SignumCore"]),
        .executable(name: "SignumCLI", targets: ["SignumCLI"]),
        .executable(name: "SignumApp", targets: ["SignumApp"])
    ],
    targets: [
        .target(name: "CPKCS11", publicHeadersPath: "include"),
        .target(name: "SignumCore", dependencies: ["CPKCS11"]),
        .executableTarget(name: "SignumCLI", dependencies: ["SignumCore"]),
        .executableTarget(name: "SignumApp", dependencies: ["SignumCore"]),
        .executableTarget(name: "SignumOutputCrashProbe", dependencies: ["SignumCore"],
                          path: "Tests/SignumOutputCrashProbe"),
        .testTarget(name: "SignumCoreTests", dependencies: ["SignumCore", "SignumOutputCrashProbe"])
    ]
)
