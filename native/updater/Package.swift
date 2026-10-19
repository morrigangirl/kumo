// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "KumoUpdaterPolicy", platforms: [.macOS(.v13)], products: [
    .library(name: "KumoUpdaterPolicy", targets: ["KumoUpdaterPolicy"]),
], targets: [
    .target(name: "KumoUpdaterPolicy", path: "Sources", exclude: ["main.swift"], linkerSettings: [.linkedFramework("Security")]),
    .testTarget(name: "KumoUpdaterPolicyTests", dependencies: ["KumoUpdaterPolicy"], path: "Tests/KumoUpdaterPolicyTests"),
])
