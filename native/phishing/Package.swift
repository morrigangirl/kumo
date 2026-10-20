// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "KumoPhishing",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "KumoPhishingHost", targets: ["KumoPhishingHost"]),
        .executable(name: "KumoPhishLangSetup", targets: ["KumoPhishLangSetup"]),
    ],
    targets: [
        .target(name: "KumoPhishingCore", linkerSettings: [.linkedFramework("CoreML")]),
        .executableTarget(name: "KumoPhishingHost", dependencies: ["KumoPhishingCore"]),
        .testTarget(name: "KumoPhishingCoreTests", dependencies: ["KumoPhishingCore"]),
        .target(name: "KumoPhishLangSetupSupport", linkerSettings: [.linkedFramework("Security")]),
        .executableTarget(name: "KumoPhishLangSetup", dependencies: ["KumoPhishLangSetupSupport"]),
        .testTarget(name: "KumoPhishLangSetupTests", dependencies: ["KumoPhishLangSetupSupport"]),
    ]
)
