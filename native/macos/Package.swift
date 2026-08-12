// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AgentPassNative",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AgentPassNativeCore", targets: ["AgentPassNativeCore"]),
        .library(name: "AgentPassApp", targets: ["AgentPassApp"]),
        .executable(name: "agentpass-native-service", targets: ["AgentPassNativeService"]),
        .executable(name: "agentpass-native-client", targets: ["AgentPassNativeClient"]),
        .executable(name: "agentpass-native-manager", targets: ["AgentPassNativeManager"]),
        .executable(name: "agentpass-legacy-service-migration", targets: ["AgentPassLegacyServiceMigration"]),
        .executable(name: "agentpass-legacy-approval-migration", targets: ["AgentPassLegacyApprovalMigration"]),
        .executable(name: "agentpass-atomic-rename", targets: ["AgentPassAtomicRename"])
    ],
    targets: [
        .target(name: "AgentPassApp"),
        .target(
            name: "AgentPassNativeCore",
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("LocalAuthentication")]
        ),
        .target(name: "AgentPassNativeServiceSupport", dependencies: ["AgentPassNativeCore"]),
        .executableTarget(
            name: "AgentPassNativeService",
            dependencies: ["AgentPassNativeCore", "AgentPassNativeServiceSupport"]
        ),
        .executableTarget(
            name: "AgentPassNativeClient",
            dependencies: ["AgentPassNativeCore"]
        ),
        .executableTarget(
            name: "AgentPassNativeManager",
            linkerSettings: [.linkedFramework("ServiceManagement")]
        ),
        .executableTarget(
            name: "AgentPassLegacyServiceMigration",
            dependencies: ["AgentPassNativeCore"]
        ),
        .executableTarget(
            name: "AgentPassLegacyApprovalMigration",
            dependencies: ["AgentPassNativeCore"]
        ),
        .executableTarget(name: "AgentPassAtomicRename"),
        .testTarget(
            name: "AgentPassNativeCoreTests",
            dependencies: ["AgentPassNativeCore"]
        ),
        .testTarget(
            name: "AgentPassAppTests",
            dependencies: ["AgentPassApp"]
        ),
        .testTarget(
            name: "AgentPassNativeServiceSupportTests",
            dependencies: ["AgentPassNativeServiceSupport", "AgentPassNativeCore"]
        )
    ]
)
