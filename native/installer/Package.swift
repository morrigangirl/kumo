// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "KumoInstaller",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "KumoSetup", targets: ["KumoSetup"])],
    dependencies: [.package(path: "../malware")],
    targets: [.executableTarget(name: "KumoSetup", dependencies: [
        .product(name: "KumoMalwareCore", package: "malware"),
        .product(name: "KumoMalwareSetupSupport", package: "malware"),
    ], linkerSettings: [.linkedFramework("AppKit"), .linkedFramework("Security")]),
    .testTarget(name: "KumoSetupTests", dependencies: ["KumoSetup"])]
)
