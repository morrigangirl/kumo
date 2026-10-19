// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "KumoApplePasswords",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "KumoApplePasswords", targets: ["KumoApplePasswords"]),
        .executable(name: "kumo-apple-passwords", targets: ["KumoApplePasswordsProbe"]),
        .executable(name: "kumo-autofill-probe", targets: ["KumoAutoFillProbe"]),
    ],
    targets: [
        .target(name: "KumoApplePasswords"),
        .executableTarget(name: "KumoApplePasswordsProbe", dependencies: ["KumoApplePasswords"]),
        .executableTarget(name: "KumoAutoFillProbe"),
    ]
)
