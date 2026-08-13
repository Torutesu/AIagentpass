import Foundation
import Testing
@testable import AgentPassNativeCore

private let processHash = String(repeating: "a", count: 64)
private let changedHash = String(repeating: "b", count: 64)

private func executable(
    deviceID: UInt64 = 1,
    inode: UInt64 = 100,
    fileSize: UInt64 = 10,
    modificationTimeNanoseconds: Int64 = 20
) throws -> NativeExecutableFileIdentity {
    try NativeExecutableFileIdentity(
        deviceID: deviceID,
        inode: inode,
        fileSize: fileSize,
        modificationTimeNanoseconds: modificationTimeNanoseconds
    )
}

private func facts(
    uid: UInt32 = 501,
    pid: Int32 = 900,
    pidVersion: UInt64 = 1,
    bootIdentity: String = "boot-a",
    executableFileIdentity: NativeExecutableFileIdentity? = nil,
    codeDirectoryHash: String = processHash,
    bundleIdentifier: String? = "dev.example.agent",
    teamIdentifier: String? = "TEAM123456",
    signatureKind: NativeCodeSignatureKind = .developerID,
    entitlements: [String: NativeEntitlementValue] = ["com.example.agent": .boolean(true)]
) throws -> NativeObservedProcessFacts {
    try NativeObservedProcessFacts(
        uid: uid,
        pid: pid,
        pidVersion: pidVersion,
        bootIdentity: bootIdentity,
        executableFileIdentity: executableFileIdentity ?? executable(),
        codeDirectoryHash: codeDirectoryHash,
        bundleIdentifier: bundleIdentifier,
        teamIdentifier: teamIdentifier,
        signatureKind: signatureKind,
        entitlements: entitlements
    )
}

private func identity(
    process: NativeObservedProcessFacts? = nil,
    ancestry: [NativeProcessAncestryEntry] = []
) throws -> NativeProcessIdentity {
    let observation = try NativeProcessObservation(
        process: process ?? facts(),
        ancestry: ancestry
    )
    return NativeProcessIdentity(observation: observation)
}

private struct FixtureObservationSource: NativeProcessObservationSource {
    let observation: NativeProcessObservation

    func observe() throws -> NativeProcessObservation { observation }
}

@Test func nativeProcessIdentityCanonicalBindingIsDeterministicAndPrivate() throws {
    let entitlementsA: [String: NativeEntitlementValue] = [
        "z.last": .object(["nested": .string("value")]),
        "a.first": .array([.unsignedInteger(7), .boolean(true)])
    ]
    let entitlementsB: [String: NativeEntitlementValue] = [
        "a.first": .array([.unsignedInteger(7), .boolean(true)]),
        "z.last": .object(["nested": .string("value")])
    ]
    let first = try identity(process: facts(entitlements: entitlementsA))
    let second = try identity(process: facts(entitlements: entitlementsB))
    #expect(first.canonicalRepresentation == second.canonicalRepresentation)
    #expect(first.canonicalBindingHash == second.canonicalBindingHash)
    #expect(first.canonicalAncestryBindingHash == second.canonicalAncestryBindingHash)
    #expect(first.canonicalBindingData == Data(first.canonicalRepresentation.utf8))
    #expect(!first.canonicalRepresentation.localizedCaseInsensitiveContains("audit"))
    #expect(!first.canonicalRepresentation.localizedCaseInsensitiveContains("argv"))
    #expect(!first.canonicalRepresentation.localizedCaseInsensitiveContains("environment"))
    let exposedLabels = Mirror(reflecting: first).children.compactMap(\.label)
        + Mirror(reflecting: first.process).children.compactMap(\.label)
    #expect(!exposedLabels.contains("auditToken"))
    #expect(!exposedLabels.contains("argv"))
    #expect(!exposedLabels.contains("environment"))

    let changed = try identity(process: facts(codeDirectoryHash: changedHash))
    #expect(first.canonicalBindingHash != changed.canonicalBindingHash)
}

@Test func nativeProcessIdentityCaptureUsesOnlyObservationBoundary() throws {
    let observed = try NativeProcessObservation(process: facts(pid: 901), ancestry: [])
    let captured = try NativeProcessIdentity.capture(from: FixtureObservationSource(observation: observed))
    #expect(captured.pid == 901)
    #expect(captured.pidVersion == 1)
}

@Test func nativeProcessIdentityPolicyMatchesAndRejectsSecurityAttributes() throws {
    let expected = try identity()
    let policy = try NativeProcessIdentityPolicy(
        expectedUID: 501,
        expectedBootIdentity: "boot-a",
        expectedExecutableFileIdentity: executable(),
        expectedCodeDirectoryHash: processHash,
        expectedBundleIdentifier: "dev.example.agent",
        expectedTeamIdentifier: "TEAM123456",
        expectedSignatureKind: .developerID,
        requiredEntitlements: ["com.example.agent": .boolean(true)]
    )
    #expect(expected.evaluate(policy: policy).isAllowed)

    let teamMismatch = try identity(process: facts(teamIdentifier: "OTHERTEAM"))
    #expect(teamMismatch.evaluate(policy: policy).denialReasons == [.teamIdentifierMismatch])

    let bundleMismatch = try identity(process: facts(bundleIdentifier: "dev.attacker.agent"))
    #expect(bundleMismatch.evaluate(policy: policy).denialReasons == [.bundleIdentifierMismatch])

    let entitlementMismatch = try identity(process: facts(entitlements: ["com.example.agent": .boolean(false)]))
    #expect(entitlementMismatch.evaluate(policy: policy).denialReasons == [.entitlementMismatch])

    let adhoc = try identity(process: facts(teamIdentifier: nil, signatureKind: .adhoc))
    let securePolicy = try NativeProcessIdentityPolicy(
        expectedBundleIdentifier: "dev.example.agent",
        expectedTeamIdentifier: "TEAM123456",
        expectedSignatureKind: .developerID,
        allowedSignatureKinds: [.developerID],
        rejectAdHocSignature: true
    )
    let adhocReasons = adhoc.evaluate(policy: securePolicy).denialReasons
    #expect(adhocReasons.contains(NativeProcessIdentityReasonCode.adHocSignature))
    #expect(adhocReasons.contains(NativeProcessIdentityReasonCode.signatureKindMismatch))
    #expect(adhocReasons.contains(NativeProcessIdentityReasonCode.teamIdentifierMismatch))
}

@Test func nativeProcessIdentityRevalidationDetectsPIDReuse() throws {
    let baseline = try identity(process: facts(pid: 42, pidVersion: 10))
    let reused = try identity(process: facts(pid: 42, pidVersion: 11))
    let result = baseline.revalidate(against: reused)
    #expect(!result.isValid)
    #expect(result.denialReasons == [.pidReused])
    #expect(NativeProcessIdentityReasonCode.pidReused.rawValue == "pid_reused")
}

@Test func nativeProcessIdentityRevalidationDetectsExecutableAndHashDrift() throws {
    let baseline = try identity(process: facts())
    let drifted = try identity(process: facts(
        executableFileIdentity: try executable(inode: 101, fileSize: 11, modificationTimeNanoseconds: 21),
        codeDirectoryHash: changedHash
    ))
    let reasons = baseline.revalidationDenialReasons(against: drifted)
    #expect(reasons.contains(.executableFileIdentityChanged))
    #expect(reasons.contains(.codeDirectoryHashChanged))
}

@Test func nativeProcessIdentityRevalidationDetectsParentDeathAndChainSubstitution() throws {
    let parent = try facts(pid: 901, pidVersion: 4, codeDirectoryHash: processHash)
    let grandparent = try facts(pid: 902, pidVersion: 8, executableFileIdentity: try executable(inode: 102))
    let baseline = try identity(ancestry: [.observed(parent), .observed(grandparent)])

    let parentDied = try identity(ancestry: [])
    #expect(baseline.revalidationDenialReasons(against: parentDied) == [.parentDied])

    let substitutedParent = try facts(pid: 999, pidVersion: 1, executableFileIdentity: try executable(inode: 999))
    let substituted = try identity(ancestry: [.observed(substitutedParent), .observed(grandparent)])
    #expect(baseline.revalidationDenialReasons(against: substituted).contains(.ancestorChainSubstitution))
}

@Test func nativeProcessIdentityRevalidationDetectsUnknownAncestor() throws {
    let baseline = try identity(ancestry: [.observed(try facts(pid: 901))])
    let current = try identity(ancestry: [.unknown(pid: 901, pidVersion: 1)])
    let reasons = baseline.revalidationDenialReasons(against: current)
    #expect(reasons == [.unknownAncestor])

    let policy = try NativeProcessIdentityPolicy(expectedAncestry: current.ancestry)
    #expect(!baseline.matches(policy: policy))
}

@Test func nativeProcessIdentityRevalidationDetectsBootChangeAndStableReasonOrdering() throws {
    let baseline = try identity(process: facts(bootIdentity: "boot-a"))
    let current = try identity(process: facts(
        pid: 900,
        pidVersion: 2,
        bootIdentity: "boot-b",
        executableFileIdentity: try executable(inode: 101),
        codeDirectoryHash: changedHash,
        teamIdentifier: "OTHERTEAM"
    ))
    let reasons = baseline.revalidationDenialReasons(against: current)
    #expect(reasons == [
        .pidReused,
        .bootIdentityChanged,
        .executableFileIdentityChanged,
        .codeDirectoryHashChanged,
        .teamIdentifierMismatch
    ])
}

@Test func nativeProcessIdentityExactPolicyCanBindOrderedAncestry() throws {
    let parent = try facts(pid: 901)
    let expected = try identity(ancestry: [.observed(parent)])
    let policy = try NativeProcessIdentityPolicy.exact(expected)
    #expect(expected.matches(policy: policy))

    let reordered = try identity(ancestry: [.observed(try facts(pid: 902))])
    #expect(reordered.evaluate(policy: policy).denialReasons.contains(.ancestorChainSubstitution))
}

@Test func nativeProcessIdentityRejectsUnboundedOrCrossBootObservations() throws {
    #expect(throws: NativeProcessIdentityError.self) {
        _ = try NativeProcessObservation(
            process: facts(),
            ancestry: try (0...16).map { index in .observed(try facts(pid: Int32(1_000 + index))) }
        )
    }
    #expect(throws: NativeProcessIdentityError.self) {
        _ = try NativeProcessObservation(
            process: facts(bootIdentity: "boot-a"),
            ancestry: [.observed(try facts(pid: 901, bootIdentity: "boot-b"))]
        )
    }
    #expect(throws: NativeProcessIdentityError.self) {
        _ = try facts(entitlements: Dictionary(uniqueKeysWithValues: (0...32).map { ("entitlement.\($0)", .boolean(true)) }))
    }
    #expect(throws: NativeProcessIdentityError.self) {
        _ = try facts(entitlements: ["large": .string(String(repeating: "x", count: 4097))])
    }
}
