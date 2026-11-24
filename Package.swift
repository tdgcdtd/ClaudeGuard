// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ClaudeGuard",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "ClaudeGuard",
            targets: ["ClaudeGuard"]
        )
    ],
    targets: [
        .executableTarget(
            name: "ClaudeGuard",
            path: "Sources/ClaudeGuard"
        ),
        .testTarget(
            name: "ClaudeGuardTests",
            dependencies: ["ClaudeGuard"],
            path: "Tests/ClaudeGuardTests"
        )
    ]
)
