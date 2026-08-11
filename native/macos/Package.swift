// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AgentPassNative",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AgentPassNativeCore", targets: ["AgentPassNativeCore"]),
        .executable(name: "agentpass-native-service", targets: ["AgentPassNativeService"]),
        .executable(name: "agentpass-native-client", targets: ["AgentPassNativeClient"])
    ],
    targets: [
        .target(
            name: "AgentPassNativeCore",
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("LocalAuthentication")]
        ),
        .executableTarget(
            name: "AgentPassNativeService",
            dependencies: ["AgentPassNativeCore"]
        ),
        .executableTarget(
            name: "AgentPassNativeClient",
            dependencies: ["AgentPassNativeCore"]
        ),
        .testTarget(
            name: "AgentPassNativeCoreTests",
            dependencies: ["AgentPassNativeCore"]
        )
    ]
)
