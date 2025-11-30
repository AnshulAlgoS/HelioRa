// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "HelioRaMonitor",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .executable(
            name: "HelioRaMonitor",
            targets: ["HelioRaMonitor"])
    ],
    dependencies: [
        .package(url: "https://github.com/httpswift/swifter.git", from: "1.5.0")
    ],
    targets: [
        .executableTarget(
            name: "HelioRaMonitor",
            dependencies: [
                .product(name: "Swifter", package: "swifter")
            ],
            path: "HelioRaMonitor"
        )
    ]
)
