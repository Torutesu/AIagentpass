// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AgentPassNative",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AgentPassNativeCore", targets: ["AgentPassNativeCore"]),
        .library(name: "AgentPassApp", targets: ["AgentPassApp"]),
        .library(name: "AgentPassOnboardingUI", targets: ["AgentPassOnboardingUI"]),
        .executable(name: "agentpass-onboarding", targets: ["AgentPassOnboardingApp"]),
        .executable(name: "agentpass-native-service", targets: ["AgentPassNativeService"]),
        .executable(name: "agentpass-native-client", targets: ["AgentPassNativeClient"]),
        .executable(name: "agentpass-native-agent-host", targets: ["AgentPassNativeAgentHost"]),
        .executable(name: "agentpass-git-sign", targets: ["AgentPassGitSigningHelper"]),
        .executable(name: "agentpass-git-session-sign", targets: ["AgentPassGitSessionSigningHelper"]),
        .executable(name: "agentpass-git-sign-xpc", targets: ["AgentPassGitSigningXPCHelper"]),
        .executable(name: "agentpass-native-manager", targets: ["AgentPassNativeManager"]),
        .executable(name: "agentpass-legacy-service-migration", targets: ["AgentPassLegacyServiceMigration"]),
        .executable(name: "agentpass-legacy-approval-migration", targets: ["AgentPassLegacyApprovalMigration"]),
        .executable(name: "agentpass-atomic-rename", targets: ["AgentPassAtomicRename"]),
        .executable(name: "agentpass-negative-xpc-probe", targets: ["AgentPassNegativeXPCProbe"]),
        .executable(
            name: "agentpass-qualification-grant-client",
            targets: ["AgentPassQualificationGrantClient"]
        ),
        .executable(
            name: "agentpass-qualification-controller",
            targets: ["AgentPassQualificationController"]
        )
    ],
    targets: [
        .target(name: "AgentPassApp"),
        .target(
            name: "AgentPassOnboardingUI",
            dependencies: ["AgentPassApp"]
        ),
        .executableTarget(
            name: "AgentPassOnboardingApp",
            dependencies: ["AgentPassOnboardingUI"]
        ),
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
            name: "AgentPassNativeAgentHost",
            dependencies: ["AgentPassNativeCore"]
        ),
        .executableTarget(
            name: "AgentPassGitSigningHelper",
            dependencies: ["AgentPassNativeCore"]
        ),
        .executableTarget(
            name: "AgentPassGitSessionSigningHelper",
            dependencies: ["AgentPassNativeCore"]
        ),
        .executableTarget(
            name: "AgentPassGitSigningXPCHelper",
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
        .executableTarget(
            name: "AgentPassNegativeXPCProbe",
            dependencies: ["AgentPassNativeCore"]
        ),
        .executableTarget(
            name: "AgentPassQualificationGrantClient",
            dependencies: ["AgentPassNativeCore"]
        ),
        .executableTarget(
            name: "AgentPassQualificationController",
            dependencies: ["AgentPassNativeCore"]
        ),
        .testTarget(
            name: "AgentPassNativeCoreTests",
            dependencies: ["AgentPassNativeCore"]
        ),
        .testTarget(
            name: "AgentPassAppTests",
            dependencies: ["AgentPassApp"]
        ),
        .testTarget(
            name: "AgentPassOnboardingUITests",
            dependencies: ["AgentPassOnboardingUI", "AgentPassApp"]
        ),
        .testTarget(
            name: "AgentPassNativeServiceSupportTests",
            dependencies: ["AgentPassNativeServiceSupport", "AgentPassNativeCore"]
        ),
        .testTarget(
            name: "AgentPassNativeServiceTests",
            dependencies: ["AgentPassNativeService", "AgentPassNativeCore"]
        ),
        .testTarget(
            name: "AgentPassQualificationGrantClientTests",
            dependencies: ["AgentPassQualificationGrantClient", "AgentPassNativeCore"]
        )
    ]
)
