@testable import AgentPassNativeCore
import CryptoKit
import Foundation
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

private let testCursorManifestSPKIPrefix = Data([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
])

private func testBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private struct SignedCursorManifestFixture {
    let manifestData: Data
    let trustConfigData: Data
    let signingKey: Curve25519.Signing.PrivateKey
}

private func signedCursorManifestFixture(
    signingKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey(),
    coreOverride: [String: Any]? = nil
) throws -> SignedCursorManifestFixture {
    let core = coreOverride ?? [
        "schema_version": 1,
        "runtime_id": "cursor-agent",
        "runtime_version": "1.2.3",
        "release_digest": "sha256:" + String(repeating: "d", count: 64),
        "materialization_epoch": NSNumber(value: UInt64(1)),
        "files": [
            [
                "relative_path": "index.js",
                "sha256": String(repeating: "b", count: 64),
                "size": NSNumber(value: UInt64(2)),
                "executable": false
            ],
            [
                "relative_path": "node",
                "sha256": String(repeating: "a", count: 64),
                "size": NSNumber(value: UInt64(1)),
                "executable": true
            ]
        ]
    ]
    let coreData = try NativeStrictJSON.data(core)
    let signature = try signingKey.signature(
        for: Data(NativeCursorAgentRuntimeManifestLoader.signatureDomain.utf8) + coreData
    )
    let signatureObject: [String: Any] = [
        "algorithm": "ed25519",
        "domain": NativeCursorAgentRuntimeManifestLoader.signatureDomain,
        "key_id": "cursor-runtime-v1",
        "signature_base64url": testBase64URL(signature)
    ]
    let manifest: [String: Any] = [
        "core": core,
        "signature": signatureObject
    ]
    let der = testCursorManifestSPKIPrefix + signingKey.publicKey.rawRepresentation
    let trust = [
        "schema_version": 1,
        "key_id": "cursor-runtime-v1",
        "public_key_der_base64url": testBase64URL(der)
    ] as [String: Any]
    return SignedCursorManifestFixture(
        manifestData: try NativeStrictJSON.data(manifest) + Data([0x0a]),
        trustConfigData: try NativeStrictJSON.data(trust),
        signingKey: signingKey
    )
}

private func mutatedManifest(
    _ fixture: SignedCursorManifestFixture,
    _ mutate: (inout [String: Any]) -> Void
) throws -> Data {
    var object = try NativeStrictJSON.object(
        from: Data(fixture.manifestData.dropLast()),
        maxBytes: NativeCursorAgentRuntimeManifestLoader.maximumManifestBytes,
        maxDepth: 8
    )
    mutate(&object)
    return try NativeStrictJSON.data(object) + Data([0x0a])
}

private func mutatedCoreManifest(
    _ fixture: SignedCursorManifestFixture,
    _ mutate: (inout [String: Any]) -> Void
) throws -> Data {
    try mutatedManifest(fixture) { object in
        var core = object["core"] as! [String: Any]
        mutate(&core)
        object["core"] = core
    }
}

private enum CursorRuntimeVectorTestError: Error {
    case repositoryRootNotFound
    case invalidBase64URL
}

private func repositoryRoot(from filePath: String) throws -> URL {
    var candidate = URL(fileURLWithPath: filePath).deletingLastPathComponent()
    for _ in 0..<8 {
        let vector = candidate
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("vectors", isDirectory: true)
            .appendingPathComponent("cursor-agent-runtime-manifest-v1.json")
        if FileManager.default.isReadableFile(atPath: vector.path) {
            return candidate
        }
        let parent = candidate.deletingLastPathComponent()
        guard parent.path != candidate.path else { break }
        candidate = parent
    }
    throw CursorRuntimeVectorTestError.repositoryRootNotFound
}

private func decodeTestBase64URL(_ value: String) throws -> Data {
    guard value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else {
        throw CursorRuntimeVectorTestError.invalidBase64URL
    }
    var standard = value
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    standard += String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
    guard let data = Data(base64Encoded: standard),
          testBase64URL(data) == value else {
        throw CursorRuntimeVectorTestError.invalidBase64URL
    }
    return data
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
    ], runtimeVersion: "test-1", releaseDigest: "sha256:" + String(repeating: "a", count: 64), materializationEpoch: 1)

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
        try NativeCursorAgentRuntimeManifest(
            entries: [node, index, node],
            runtimeVersion: "test-1",
            releaseDigest: "sha256:" + String(repeating: "a", count: 64),
            materializationEpoch: 1
        )
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
        try NativeCursorAgentRuntimeManifest(
            entries: tooMany,
            runtimeVersion: "test-1",
            releaseDigest: "sha256:" + String(repeating: "a", count: 64),
            materializationEpoch: 1
        )
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
        try NativeCursorAgentRuntimeManifest(
            entries: tooLargeInTotal,
            runtimeVersion: "test-1",
            releaseDigest: "sha256:" + String(repeating: "a", count: 64),
            materializationEpoch: 1
        )
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

@Test func signedCursorRuntimeManifestLoadsOnlyWithIndependentTrustRoot() throws {
    let fixture = try signedCursorManifestFixture()
    let manifest = try NativeCursorAgentRuntimeManifestLoader.verify(
        manifestData: fixture.manifestData,
        trustConfigData: fixture.trustConfigData
    )
    #expect(manifest.entries.map(\.relativePath) == ["index.js", "node"])
    #expect(manifest.entry(for: "node")?.isExecutable == true)
    #expect(manifest.runtimeVersion == "1.2.3")
    #expect(manifest.releaseDigest == "sha256:" + String(repeating: "d", count: 64))
    #expect(manifest.materializationEpoch == 1)
}

@Test func cursorRuntimeSharedNodeVectorIsAcceptedBySwift() throws {
    let root = try repositoryRoot(from: #filePath)
    let vectorURL = root
        .appendingPathComponent("contracts", isDirectory: true)
        .appendingPathComponent("vectors", isDirectory: true)
        .appendingPathComponent("cursor-agent-runtime-manifest-v1.json")
    let vector = try NativeStrictJSON.object(
        from: Data(contentsOf: vectorURL),
        maxBytes: NativeCursorAgentRuntimeManifestLoader.maximumManifestBytes,
        maxDepth: 4
    )
    let encodedManifest = try #require(vector["canonical_manifest_base64url"] as? String)
    let keyID = try #require(vector["key_id"] as? String)
    let publicKeyDER = try #require(vector["public_key_der_base64url"] as? String)
    let manifestData = try decodeTestBase64URL(encodedManifest)
    let trustConfigData = try NativeStrictJSON.data([
        "schema_version": 1,
        "key_id": keyID,
        "public_key_der_base64url": publicKeyDER
    ])

    let manifest = try NativeCursorAgentRuntimeManifestLoader.verify(
        manifestData: manifestData,
        trustConfigData: trustConfigData
    )
    #expect(manifest.runtimeVersion == "2026.08.17")
    #expect(manifest.releaseDigest == "sha256:" + String(repeating: "a", count: 64))
    #expect(manifest.materializationEpoch == 1)
}

@Test func signedCursorRuntimeManifestRejectsSelfSignedOrSubstitutedTrustKey() throws {
    let fixture = try signedCursorManifestFixture()
    let substituted = try signedCursorManifestFixture(
        signingKey: Curve25519.Signing.PrivateKey()
    )
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: fixture.manifestData,
            trustConfigData: substituted.trustConfigData
        )
    }

    var embeddedOnly = try NativeStrictJSON.object(
        from: fixture.trustConfigData,
        maxBytes: NativeCursorAgentRuntimeManifestLoader.maximumTrustConfigBytes,
        maxDepth: 8
    )
    embeddedOnly["key_id"] = "different-key"
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: fixture.manifestData,
            trustConfigData: try NativeStrictJSON.data(embeddedOnly)
        )
    }
}

@Test func signedCursorRuntimeManifestRejectsUnknownAndNonCanonicalJSON() throws {
    let fixture = try signedCursorManifestFixture()
    let unknown = try mutatedCoreManifest(fixture) { core in
        core["unexpected"] = true
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: unknown,
            trustConfigData: fixture.trustConfigData
        )
    }

    let missingEnvelopeMember = try mutatedManifest(fixture) { object in
        object.removeValue(forKey: "signature")
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: missingEnvelopeMember,
            trustConfigData: fixture.trustConfigData
        )
    }

    let extraEnvelope = try mutatedManifest(fixture) { object in
        object["unexpected"] = true
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: extraEnvelope,
            trustConfigData: fixture.trustConfigData
        )
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(manifestData: Data(fixture.manifestData.dropLast()), trustConfigData: fixture.trustConfigData)
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(manifestData: fixture.manifestData + Data([0x0a]), trustConfigData: fixture.trustConfigData)
    }

    let trustUnknown = try NativeStrictJSON.object(
        from: fixture.trustConfigData,
        maxBytes: NativeCursorAgentRuntimeManifestLoader.maximumTrustConfigBytes,
        maxDepth: 8
    )
    var changedTrust = trustUnknown
    changedTrust["extra"] = "denied"
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: fixture.manifestData,
            trustConfigData: try NativeStrictJSON.data(changedTrust)
        )
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: fixture.manifestData,
            trustConfigData: fixture.trustConfigData + Data([0x20])
        )
    }
}

@Test func signedCursorRuntimeManifestRejectsMalformedEpochAndReleaseMetadata() throws {
    let fixture = try signedCursorManifestFixture()
    for epoch: Any in [
        NSNumber(value: UInt64(0)),
        "1",
        NSNumber(value: NativeCursorAgentRuntimePolicy.maximumSafeInteger + 1)
    ] {
        let malformed = try mutatedCoreManifest(fixture) { core in
            core["materialization_epoch"] = epoch
        }
        #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
            try NativeCursorAgentRuntimeManifestLoader.verify(
                manifestData: malformed,
                trustConfigData: fixture.trustConfigData
            )
        }
    }

    for version in ["bad version", "1+2", "1:2"] {
        let invalidVersion = try mutatedCoreManifest(fixture) { core in
            core["runtime_version"] = version
        }
        #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
            try NativeCursorAgentRuntimeManifestLoader.verify(
                manifestData: invalidVersion,
                trustConfigData: fixture.trustConfigData
            )
        }
    }
    let invalidDigest = try mutatedCoreManifest(fixture) { core in
        core["release_digest"] = "sha256:" + String(repeating: "A", count: 64)
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: invalidDigest,
            trustConfigData: fixture.trustConfigData
        )
    }
}

@Test func signedCursorRuntimeManifestRejectsOrderingDuplicatesAndTraversal() throws {
    let fixture = try signedCursorManifestFixture()
    let reordered = try mutatedCoreManifest(fixture) { core in
        core["files"] = [
            [
                "relative_path": "node",
                "sha256": String(repeating: "a", count: 64),
                "size": NSNumber(value: UInt64(1)),
                "executable": true
            ],
            [
                "relative_path": "index.js",
                "sha256": String(repeating: "b", count: 64),
                "size": NSNumber(value: UInt64(2)),
                "executable": false
            ]
        ]
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: reordered,
            trustConfigData: fixture.trustConfigData
        )
    }

    let duplicate = try mutatedCoreManifest(fixture) { core in
        core["files"] = [
            [
                "relative_path": "index.js",
                "sha256": String(repeating: "b", count: 64),
                "size": NSNumber(value: UInt64(2)),
                "executable": false
            ],
            [
                "relative_path": "index.js",
                "sha256": String(repeating: "b", count: 64),
                "size": NSNumber(value: UInt64(2)),
                "executable": false
            ]
        ]
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: duplicate,
            trustConfigData: fixture.trustConfigData
        )
    }

    let traversal = try mutatedCoreManifest(fixture) { core in
        core["files"] = [[
            "relative_path": "../node",
            "sha256": String(repeating: "a", count: 64),
            "size": NSNumber(value: UInt64(1)),
            "executable": true
        ], [
            "relative_path": "index.js",
            "sha256": String(repeating: "b", count: 64),
            "size": NSNumber(value: UInt64(2)),
            "executable": false
        ]]
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: traversal,
            trustConfigData: fixture.trustConfigData
        )
    }
}

@Test func signedCursorRuntimeManifestRejectsTamperedSignatureAndUnsafeFiles() throws {
    let fixture = try signedCursorManifestFixture()
    let tampered = try mutatedManifest(fixture) { object in
        var signature = object["signature"] as! [String: Any]
        let old = signature["signature_base64url"] as! String
        signature["signature_base64url"] = (old.first == "A" ? "B" : "A") + String(old.dropFirst())
        object["signature"] = signature
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: tampered,
            trustConfigData: fixture.trustConfigData
        )
    }

    let unsafe = try mutatedCoreManifest(fixture) { core in
        core["files"] = [[
            "relative_path": "index.js",
            "sha256": String(repeating: "G", count: 64),
            "size": NSNumber(value: UInt64(2)),
            "executable": "yes"
        ], [
            "relative_path": "node",
            "sha256": String(repeating: "a", count: 64),
            "size": NSNumber(value: UInt64(1)),
            "executable": true
        ]]
    }
    #expect(throws: NativeCursorAgentRuntimeTrustError.invalidManifest) {
        try NativeCursorAgentRuntimeManifestLoader.verify(
            manifestData: unsafe,
            trustConfigData: fixture.trustConfigData
        )
    }
}
