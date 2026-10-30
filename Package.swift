// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ZapretBar",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "ZapretBar",
            path: "Sources/ZapretBar"
        )
    ]
)
