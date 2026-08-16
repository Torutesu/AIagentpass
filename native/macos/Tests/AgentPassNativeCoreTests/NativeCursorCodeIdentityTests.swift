@testable import AgentPassNativeCore
import Security
import Testing

private func runtimeEntry(
    _ relativePath: String,
    digest: String = String(repeating: "a", count: 64),
    size: UInt64 = 1,
    executable: Bool = false
) throws -> NativeCursorAgentRuntimeManifestEntry {
    try NativeCursorAgentRuntimeManifestEntry(
        relativePath: relativePath,
        sha256: digest,
        size: size,
        isExecutable: executable
    )
}

@Test func cursorAgentRuntimeSpecHasNoBundleOrHomeLauncherPath() throws {
    #expect(NativeCursorAgentRuntimeSpec.runtimeRoot == "/Library/Application Support/AgentPass/CursorAgent/runtime")
    #expect(NativeCursorAgentRuntimeSpec.nodePath == NativeCursorAgentRuntimeSpec.runtimeRoot + "/node")
    #expect(NativeCursorAgentRuntimeSpec.indexPath == NativeCursorAgentRuntimeSpec.runtimeRoot + "/index.js")
    #expect(NativeCursorAgentRuntimeSpec.fixedArguments == [
        "--use-system-ca",
        NativeCursorAgentRuntimeSpec.indexPath
    ])
    #expect(NativeCursorAgentRuntimeSpec.fixedEnvironment == [
        NativeCursorAgentRuntimeSpec.invokedAsEnvironmentKey:
            NativeCursorAgentRuntimeSpec.invokedAsEnvironmentValue
    ])
    #expect(NativeCursorAgentRuntimeSpec.requiredPaths.allSatisfy {
        !$0.contains("/Applications/Cursor.app/") && !$0.contains("/.local/")
    })
}

@Test func cursorRuntimeManifestIsAClosedSortedInventory() throws {
    let manifest = try NativeCursorAgentRuntimeManifest(entries: [
        try runtimeEntry("chunks/one.index.js", digest: String(repeating: "c", count: 64), size: 3),
        try runtimeEntry("index.js", digest: String(repeating: "b", count: 64), size: 2),
        try runtimeEntry("node", digest: String(repeating: "a", count: 64), size: 1, executable: true)
    ])

    #expect(manifest.entries.map(\.relativePath) == ["chunks/one.index.js", "index.js", "node"])
    #expect(manifest.entries.allSatisfy { $0.isRegularFile })
    #expect(manifest.entry(for: "node")?.isExecutable == true)
}

@Test func cursorRuntimeManifestRejectsTraversalAndDuplicateEntries() throws {
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try runtimeEntry("../escape")
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try runtimeEntry("nested/../../escape")
    }

    let node = try runtimeEntry("node", executable: true)
    let index = try runtimeEntry("index.js")
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifest(entries: [node, index, node])
    }
}

@Test func cursorRuntimeManifestRejectsBoundedCountAndSizeViolations() throws {
    var tooMany = [
        try runtimeEntry("node", executable: true),
        try runtimeEntry("index.js")
    ]
    for index in 0..<NativeCursorAgentRuntimePolicy.maximumFileCount {
        tooMany.append(try runtimeEntry("chunks/file-\(index).js"))
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifest(entries: tooMany)
    }

    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try runtimeEntry(
            "large.bin",
            size: NativeCursorAgentRuntimePolicy.maximumFileSize + 1
        )
    }

    let twoHundredMiB: UInt64 = 200 * 1024 * 1024
    let tooLargeInTotal = [
        try runtimeEntry("node", size: twoHundredMiB, executable: true),
        try runtimeEntry("index.js", size: twoHundredMiB),
        try runtimeEntry("native/addon.node", size: twoHundredMiB)
    ]
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifest(entries: tooLargeInTotal)
    }
}

@Test func cursorRuntimeIdentityClaimUsesSecurityFrameworkWhenProvisioned() throws {
    let requirementText = "anchor apple generic and identifier \"com.example.cursor-agent\""
    let claim = NativeCursorAgentRuntimeCodeIdentityClaim(
        identifier: "com.example.cursor-agent",
        teamIdentifier: "ABCDE12345",
        designatedRequirement: requirementText
    )
    var requirement: SecRequirement?
    #expect(
        SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess
    )
    #expect(requirement != nil)
    #expect(claim.teamIdentifier == "ABCDE12345")
}

@Test func cursorRuntimeSystemManifestProviderFailsClosedUntilMaterialized() throws {
    #expect(throws: NativeCursorAgentRuntimeTrustError.manifestUnavailable) {
        try NativeAgentHostExecutableTrustHooks.system.loadRuntimeManifest()
    }
    #expect(throws: NativeAgentHostExecutableTrustError.noTrustedCandidate) {
        try NativeAgentHostExecutableTrust.resolveCursorExecutable()
    }
}
