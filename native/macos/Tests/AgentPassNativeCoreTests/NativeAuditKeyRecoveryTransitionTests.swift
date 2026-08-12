import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct RecoveryP256Signer: P256MessageSigner {
    let privateKey: P256.Signing.PrivateKey
    init(_ byte: UInt8) throws { privateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32)) }
    var publicKeyX963: Data { privateKey.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message).rawRepresentation }
}

private struct RecoveryTransitionFixture {
    let authorities: [(id: String, key: Curve25519.Signing.PrivateKey)]
    let policy: NativeAuditKeyRecoveryPolicy
    let old: RecoveryP256Signer
    let replacement: RecoveryP256Signer
    let authorization: NativeAuditKeyRecoveryAuthorization
    let transition: NativeAuditKeyRecoveryTransition
}

private func recoveryFixture(
    generation: Int = 1,
    previousTransitionHash: String = String(repeating: "0", count: 64),
    previousReceiptHash: String = String(repeating: "0", count: 64),
    previousEventIndex: Int = 10,
    previousEventHash: String = String(repeating: "a", count: 64),
    checkpointIndex: Int = 7,
    createdAt: String = "2030-01-01T00:00:01.000Z",
    expiresAt: String = "2030-01-01T00:15:01.000Z",
    old: RecoveryP256Signer? = nil,
    replacement: RecoveryP256Signer? = nil
) throws -> RecoveryTransitionFixture {
    let authorities = [
        (id: "alpha", key: try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x11, count: 32))),
        (id: "bravo", key: try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x22, count: 32)))
    ]
    let policy = try NativeAuditKeyRecoveryPolicy(
        policyID: "offline-main", threshold: 2,
        keys: authorities.reversed().map { try NativeAuditKeyRecoveryPolicyKey(id: $0.id, publicKey: $0.key.publicKey) }
    )
    let retiring = try old ?? RecoveryP256Signer(UInt8(generation))
    let next = try replacement ?? RecoveryP256Signer(UInt8(generation + 1))
    let authorization = try NativeAuditKeyRecoveryAuthorization(
        tenant: "native-host", installationID: "installation-001", operationID: "recovery-op-\(generation)",
        recoveryRequestID: "recovery-request-\(generation)", policy: policy, fromGeneration: generation,
        oldPublicKeyX963: retiring.publicKeyX963, newPublicKeyX963: next.publicKeyX963,
        lifecycleHeadHash: String(repeating: "b", count: 64), createdAt: createdAt, expiresAt: expiresAt,
        previousTransitionHash: previousTransitionHash, previousTransitionReceiptHash: previousReceiptHash,
        lastCheckpointIndex: checkpointIndex, lastCheckpointHash: String(repeating: "c", count: 64),
        lastCheckpointReceiptHash: String(repeating: "d", count: 64),
        previousAnchorEventIndex: previousEventIndex, previousAnchorEventHash: previousEventHash
    )
    let transition = try NativeAuditKeyRecoveryTransition(
        authorization: authorization, policy: policy,
        approvalSigners: authorities.reversed(), replacementSigner: next
    )
    return RecoveryTransitionFixture(authorities: authorities, policy: policy, old: retiring, replacement: next, authorization: authorization, transition: transition)
}

private func recoveryAnchorPEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func recoveryAnchorFingerprint(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func recoveryReceipt(
    transition: NativeAuditKeyRecoveryTransition,
    index: Int,
    anchor: Curve25519.Signing.PrivateKey,
    receivedAt: String = "2030-01-01T00:00:02.000Z"
) throws -> Data {
    var statement: [String: Any] = [
        "version": 2, "tenant": transition.tenant, "index": index,
        "transition_hash": transition.transitionHash, "received_at": receivedAt,
        "previous_receipt_hash": transition.previousTransitionReceiptHash,
        "event_index": transition.previousAnchorEventIndex + 1,
        "previous_event_hash": transition.previousAnchorEventHash,
        "last_checkpoint_index": transition.lastCheckpointIndex,
        "last_checkpoint_hash": transition.lastCheckpointHash,
        "last_checkpoint_receipt_hash": transition.lastCheckpointReceiptHash
    ]
    statement["signature"] = try anchor.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
    statement["anchor_key_fingerprint"] = recoveryAnchorFingerprint(anchor.publicKey)
    statement["receipt_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(statement))
    return try NativeAuditLog.canonical(statement)
}

private func mutateRecoveryJSON(_ data: Data, _ mutation: (inout [String: Any]) throws -> Void) throws -> Data {
    var object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    try mutation(&object)
    return try NativeAuditLog.canonical(object)
}

private func decodeRecovery(
    _ data: Data,
    fixture: RecoveryTransitionFixture,
    nowMilliseconds: Int64? = nil
) throws -> NativeAuditKeyRecoveryTransition {
    try NativeAuditKeyRecoveryTransition.decodeCanonical(
        data,
        pinnedPolicy: fixture.policy,
        expectedInstallationID: "installation-001",
        nowMilliseconds: nowMilliseconds
    )
}

private func protectedRecoveryStoreDirectory() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-v3-transition-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    guard chmod(root.path, 0o700) == 0, let resolved = Darwin.realpath(root.path, nil) else { throw POSIXError(.EIO) }
    defer { free(resolved) }
    return URL(fileURLWithPath: String(cString: resolved))
}

@Test func auditKeyRecoveryPolicyMatchesNodeCanonicalHashAndOrdering() throws {
    let fixture = try recoveryFixture()
    #expect(fixture.policy.keys.map(\.id) == ["alpha", "bravo"])
    #expect(fixture.policy.policyHash == "1350932512c559adc0f92844877e5925a58b9d9cd535f0899c11a4aceba4598b")
    #expect(try NativeAuditKeyRecoveryPolicy.decodeCanonical(fixture.policy.canonicalData()) == fixture.policy)
    #expect(fixture.policy.keys[0].fingerprint == "SHA256:UD2O5G1YHGSZZlaa4JXicEHegzIujgSA5VOeANLV2HQ")
    #expect(fixture.policy.keys[1].fingerprint == "SHA256:dE82zKZ-sZEssoLgjoa9L-DQkASijPbnxr1Wzda_Zao")
}

@Test func auditKeyRecoveryConvertsAuthoritiesPolicyAtExplicitHashBoundary() throws {
    let fixture = try recoveryFixture()
    let authoritiesObject: [String: Any] = [
        "version": 1, "policy_id": "offline-main", "threshold": 2,
        "authorities": fixture.authorities.reversed().map { authority in
            ["id": authority.id, "public_key": recoveryAnchorPEM(authority.key.publicKey)]
        }
    ]
    let authoritiesData = try NativeAuditLog.canonical(authoritiesObject)
    let conversion = try NativeAuditKeyRecoveryPolicy.convertingAuthoritiesPolicy(authoritiesData)
    let sourceHash = try NativeRecoveryVerifier.policyHash(authoritiesData)
    #expect(conversion.authoritiesPolicyHash == sourceHash)
    #expect(conversion.anchorPolicy == fixture.policy)
    #expect(conversion.authoritiesPolicyHash != conversion.anchorPolicy.policyHash)
    let anchorObject = try #require(JSONSerialization.jsonObject(with: conversion.anchorPolicy.canonicalData()) as? [String: Any])
    #expect(anchorObject["authorities"] == nil)
    #expect((anchorObject["keys"] as? [[String: Any]])?.map { $0["id"] as! String } == ["alpha", "bravo"])

    var wrongSchema = authoritiesObject
    wrongSchema["keys"] = wrongSchema.removeValue(forKey: "authorities")
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryPolicy.convertingAuthoritiesPolicy(NativeAuditLog.canonical(wrongSchema))
    }
}

@Test func auditKeyRecoveryTransitionRoundTripsExactNodeV3Schema() throws {
    let fixture = try recoveryFixture()
    let data = try fixture.transition.canonicalData()
    let decoded = try NativeAuditKeyRecoveryTransition.decodeCanonical(
        data, pinnedPolicy: fixture.policy, expectedInstallationID: "installation-001",
        nowMilliseconds: 1_893_456_002_000
    )
    #expect(decoded == fixture.transition)
    let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    #expect(object["version"] as? Int == 3)
    #expect(object["old_signature"] == nil)
    #expect(Set(object.keys) == Set(NativeAuditKeyRecoveryTransition.CodingKeys.allCases.map(\.stringValue)))
    let evidence = try #require(object["recovery_evidence"] as? [String: Any])
    let embedded = try NativeAuditLog.canonical(try #require(evidence["authorization"] as? [String: Any]))
    let authorizationData = try fixture.authorization.canonicalData()
    #expect(embedded == authorizationData)
}

@Test func auditKeyRecoveryProductionFactoryConsumesSignaturesWithoutOfflinePrivateKeys() throws {
    let fixture = try recoveryFixture()
    let message = try fixture.authorization.canonicalData()
    let approvals = try fixture.authorities.map {
        try NativeAuditKeyRecoveryApproval(keyID: $0.id, signature: $0.key.signature(for: message))
    }
    let replacementSignature = try fixture.replacement.sign(message: message)
    let transition = try NativeAuditKeyRecoveryTransition(
        authorization: fixture.authorization, policy: fixture.policy,
        approvals: approvals, replacementSignature: replacementSignature
    )
    #expect(try decodeRecovery(transition.canonicalData(), fixture: fixture) == transition)

    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryTransition(
            authorization: fixture.authorization, policy: fixture.policy,
            approvals: Array(approvals.reversed()), replacementSignature: replacementSignature
        )
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryTransition(
            authorization: fixture.authorization, policy: fixture.policy,
            approvals: approvals, replacementSignature: Data(repeating: 0, count: 64)
        )
    }
}

@Test func auditKeyRecoveryEvidenceDecoderRejectsSubstitutionReplayAndNoncanonicalApprovals() throws {
    let fixture = try recoveryFixture()
    let evidence = fixture.transition.recoveryEvidence
    let data = try evidence.canonicalData()
    let now: Int64 = 1_893_456_002_000
    #expect(try NativeAuditKeyRecoveryEvidence.decodeCanonical(
        data, pinnedPolicy: fixture.policy, expectedAuthorization: fixture.authorization,
        expectedInstallationID: "installation-001", nowMilliseconds: now
    ) == evidence)

    let wrongAuthorization = try recoveryFixture(generation: 2).authorization
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryEvidence.decodeCanonical(
            data, pinnedPolicy: fixture.policy, expectedAuthorization: wrongAuthorization,
            expectedInstallationID: "installation-001", nowMilliseconds: now
        )
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryEvidence.decodeCanonical(
            data, pinnedPolicy: fixture.policy, expectedAuthorization: fixture.authorization,
            expectedInstallationID: "substituted-installation", nowMilliseconds: now
        )
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryEvidence.decodeCanonical(
            data, pinnedPolicy: fixture.policy, expectedAuthorization: fixture.authorization,
            expectedInstallationID: "installation-001", nowMilliseconds: 1_893_456_902_000
        )
    }

    let reversed = try mutateRecoveryJSON(data) { object in
        object["approvals"] = Array((object["approvals"] as! [[String: Any]]).reversed())
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryEvidence.decodeCanonical(
            reversed, pinnedPolicy: fixture.policy, expectedAuthorization: fixture.authorization,
            expectedInstallationID: "installation-001", nowMilliseconds: now
        )
    }
    let duplicate = try mutateRecoveryJSON(data) { object in
        let approvals = object["approvals"] as! [[String: Any]]
        object["approvals"] = [approvals[0], approvals[0]]
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryEvidence.decodeCanonical(
            duplicate, pinnedPolicy: fixture.policy, expectedAuthorization: fixture.authorization,
            expectedInstallationID: "installation-001", nowMilliseconds: now
        )
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryEvidence.decodeCanonical(
            data + Data([0x0a]), pinnedPolicy: fixture.policy,
            expectedAuthorization: fixture.authorization,
            expectedInstallationID: "installation-001", nowMilliseconds: now
        )
    }
}

@Test func auditKeyRecoveryRejectsPolicyAuthorizationApprovalAndPossessionTampering() throws {
    let fixture = try recoveryFixture()
    let valid = try fixture.transition.canonicalData()

    let policyHash = try mutateRecoveryJSON(valid) { object in
        var evidence = object["recovery_evidence"] as! [String: Any]
        var policy = evidence["policy"] as! [String: Any]
        policy["policy_hash"] = String(repeating: "0", count: 64)
        evidence["policy"] = policy; object["recovery_evidence"] = evidence
    }
    #expect(throws: AgentPassNativeError.self) { try decodeRecovery(policyHash, fixture: fixture) }

    let duplicatedAuthorization = try mutateRecoveryJSON(valid) { object in
        var evidence = object["recovery_evidence"] as! [String: Any]
        var authorization = evidence["authorization"] as! [String: Any]
        authorization["operation_id"] = "different-operation"
        evidence["authorization"] = authorization; object["recovery_evidence"] = evidence
    }
    #expect(throws: AgentPassNativeError.self) { try decodeRecovery(duplicatedAuthorization, fixture: fixture) }

    let reversed = try mutateRecoveryJSON(valid) { object in
        var evidence = object["recovery_evidence"] as! [String: Any]
        evidence["approvals"] = Array((evidence["approvals"] as! [[String: Any]]).reversed())
        object["recovery_evidence"] = evidence
    }
    #expect(throws: AgentPassNativeError.self) { try decodeRecovery(reversed, fixture: fixture) }

    let duplicate = try mutateRecoveryJSON(valid) { object in
        var evidence = object["recovery_evidence"] as! [String: Any]
        let approvals = evidence["approvals"] as! [[String: Any]]
        evidence["approvals"] = [approvals[0], approvals[0]]
        object["recovery_evidence"] = evidence
    }
    #expect(throws: AgentPassNativeError.self) { try decodeRecovery(duplicate, fixture: fixture) }

    let replacementProof = try mutateRecoveryJSON(valid) { object in object["new_signature"] = Data(repeating: 0, count: 64).base64EncodedString() }
    #expect(throws: AgentPassNativeError.self) { try decodeRecovery(replacementProof, fixture: fixture) }

    let unknown = try mutateRecoveryJSON(valid) { object in object["unexpected"] = true }
    #expect(throws: AgentPassNativeError.self) { try decodeRecovery(unknown, fixture: fixture) }
    #expect(throws: AgentPassNativeError.self) { try decodeRecovery(valid + Data([0x0a]), fixture: fixture) }
}

@Test func auditKeyRecoveryEnforcesPinnedTrustThresholdReplayAndClockWindow() throws {
    let fixture = try recoveryFixture()
    let data = try fixture.transition.canonicalData()
    #expect(throws: AgentPassNativeError.self) {
        try decodeRecovery(data, fixture: fixture, nowMilliseconds: 1_893_455_990_000)
    }
    #expect(throws: AgentPassNativeError.self) {
        try decodeRecovery(data, fixture: fixture, nowMilliseconds: 1_893_456_902_000)
    }

    let foreign = Curve25519.Signing.PrivateKey()
    let swapped = try NativeAuditKeyRecoveryPolicy(policyID: "offline-main", threshold: 1, keys: [
        try NativeAuditKeyRecoveryPolicyKey(id: "alpha", publicKey: foreign.publicKey)
    ])
    #expect(throws: AgentPassNativeError.self) {
        try fixture.transition.verify(pinnedPolicy: swapped, expectedInstallationID: "installation-001")
    }
    #expect(throws: AgentPassNativeError.self) {
        try fixture.transition.verify(pinnedPolicy: fixture.policy, expectedInstallationID: "installation-other")
    }

    // A fully self-consistent transition under an attacker-selected embedded
    // policy must still fail at the public decode boundary.
    let foreignAuthorization = try NativeAuditKeyRecoveryAuthorization(
        tenant: "native-host", installationID: "installation-001", operationID: "foreign-policy-op",
        recoveryRequestID: "foreign-policy-request", policy: swapped, fromGeneration: 1,
        oldPublicKeyX963: fixture.old.publicKeyX963, newPublicKeyX963: fixture.replacement.publicKeyX963,
        lifecycleHeadHash: String(repeating: "b", count: 64), createdAt: "2030-01-01T00:00:01.000Z",
        expiresAt: "2030-01-01T00:15:01.000Z", previousTransitionHash: String(repeating: "0", count: 64),
        previousTransitionReceiptHash: String(repeating: "0", count: 64), lastCheckpointIndex: 7,
        lastCheckpointHash: String(repeating: "c", count: 64), lastCheckpointReceiptHash: String(repeating: "d", count: 64),
        previousAnchorEventIndex: 10, previousAnchorEventHash: String(repeating: "a", count: 64)
    )
    let foreignTransition = try NativeAuditKeyRecoveryTransition(
        authorization: foreignAuthorization, policy: swapped,
        approvalSigners: [(id: "alpha", key: foreign)], replacementSigner: fixture.replacement
    )
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyRecoveryTransition.decodeCanonical(
            foreignTransition.canonicalData(), pinnedPolicy: fixture.policy,
            expectedInstallationID: "installation-001"
        )
    }
}

@Test func auditKeyRecoveryReceiptIsV2AndCannotPostdateAuthorization() throws {
    let fixture = try recoveryFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let verifier = try NativeAuditKeyRecoveryTransitionReceiptVerifier(tenant: "native-host", anchorPublicKeyPEM: recoveryAnchorPEM(anchor.publicKey))
    let receiptData = try recoveryReceipt(transition: fixture.transition, index: 1, anchor: anchor)
    let receipt = try verifier.verify(receiptData: receiptData, transition: fixture.transition, expectedTransitionIndex: 1)
    #expect(receipt.version == 2)
    #expect(receipt.transitionHash == fixture.transition.transitionHash)
    let late = try recoveryReceipt(transition: fixture.transition, index: 1, anchor: anchor, receivedAt: "2030-01-01T00:15:02.000Z")
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(receiptData: late, transition: fixture.transition, expectedTransitionIndex: 1)
    }
}

private func ordinaryTransition(
    old: RecoveryP256Signer, replacement: RecoveryP256Signer, generation: Int,
    operationID: String, previousTransitionHash: String, previousReceiptHash: String,
    previousEventIndex: Int, previousEventHash: String, checkpointIndex: Int, createdAt: String
) throws -> NativeAuditKeyTransition {
    let statement = try NativeAuditKeyTransitionStatement(
        tenant: "native-host", operationID: operationID, fromGeneration: generation,
        oldPublicKeyX963: old.publicKeyX963, newPublicKeyX963: replacement.publicKeyX963,
        lifecycleHeadHash: String(repeating: "b", count: 64), lastCheckpointIndex: checkpointIndex,
        lastCheckpointHash: String(repeating: "c", count: 64), lastCheckpointReceiptHash: String(repeating: "d", count: 64),
        previousTransitionHash: previousTransitionHash, previousTransitionReceiptHash: previousReceiptHash,
        previousAnchorEventIndex: previousEventIndex, previousAnchorEventHash: previousEventHash, createdAt: createdAt
    )
    return try NativeAuditKeyTransition(statement: statement, retiringSigner: old, replacementSigner: replacement)
}

private func ordinaryReceipt(_ transition: NativeAuditKeyTransition, index: Int, anchor: Curve25519.Signing.PrivateKey, receivedAt: String) throws -> Data {
    var statement: [String: Any] = [
        "version": 2, "tenant": transition.tenant, "index": index, "transition_hash": transition.transitionHash,
        "received_at": receivedAt, "previous_receipt_hash": transition.previousTransitionReceiptHash,
        "event_index": transition.previousAnchorEventIndex + 1, "previous_event_hash": transition.previousAnchorEventHash,
        "last_checkpoint_index": transition.lastCheckpointIndex, "last_checkpoint_hash": transition.lastCheckpointHash,
        "last_checkpoint_receipt_hash": transition.lastCheckpointReceiptHash
    ]
    statement["signature"] = try anchor.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
    statement["anchor_key_fingerprint"] = recoveryAnchorFingerprint(anchor.publicKey)
    statement["receipt_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(statement))
    return try NativeAuditLog.canonical(statement)
}

@Test func auditKeyTransitionStoreVerifiesV2V3V2MixedHistoryAndRecoveryReplay() throws {
    let root = try protectedRecoveryStoreDirectory(); defer { try? FileManager.default.removeItem(at: root) }
    let anchor = Curve25519.Signing.PrivateKey()
    let key1 = try RecoveryP256Signer(1), key2 = try RecoveryP256Signer(2), key3 = try RecoveryP256Signer(3), key4 = try RecoveryP256Signer(4)
    let first = try ordinaryTransition(
        old: key1, replacement: key2, generation: 1, operationID: "rotation-1",
        previousTransitionHash: String(repeating: "0", count: 64), previousReceiptHash: String(repeating: "0", count: 64),
        previousEventIndex: 10, previousEventHash: String(repeating: "a", count: 64), checkpointIndex: 7,
        createdAt: "2030-01-01T00:00:01.000Z"
    )
    let firstReceiptData = try ordinaryReceipt(first, index: 1, anchor: anchor, receivedAt: "2030-01-01T00:00:02.000Z")
    let firstReceipt = try NativeAuditKeyTransitionReceiptVerifier(tenant: "native-host", anchorPublicKeyPEM: recoveryAnchorPEM(anchor.publicKey))
        .verify(receiptData: firstReceiptData, transition: first, expectedTransitionIndex: 1)
    let recovery = try recoveryFixture(
        generation: 2, previousTransitionHash: first.transitionHash, previousReceiptHash: firstReceipt.receiptHash,
        previousEventIndex: 12, previousEventHash: String(repeating: "e", count: 64), checkpointIndex: 8,
        createdAt: "2030-01-01T00:00:03.000Z", expiresAt: "2030-01-01T00:15:03.000Z", old: key2, replacement: key3
    )
    let recoveryReceiptData = try recoveryReceipt(transition: recovery.transition, index: 2, anchor: anchor, receivedAt: "2030-01-01T00:00:04.000Z")
    let recoveryReceipt = try NativeAuditKeyRecoveryTransitionReceiptVerifier(tenant: "native-host", anchorPublicKeyPEM: recoveryAnchorPEM(anchor.publicKey))
        .verify(receiptData: recoveryReceiptData, transition: recovery.transition, expectedTransitionIndex: 2)
    let third = try ordinaryTransition(
        old: key3, replacement: key4, generation: 3, operationID: "rotation-3",
        previousTransitionHash: recovery.transition.transitionHash, previousReceiptHash: recoveryReceipt.receiptHash,
        previousEventIndex: 14, previousEventHash: String(repeating: "f", count: 64), checkpointIndex: 9,
        createdAt: "2030-01-01T00:00:05.000Z"
    )
    let thirdReceiptData = try ordinaryReceipt(third, index: 3, anchor: anchor, receivedAt: "2030-01-01T00:00:06.000Z")

    let policyData = try recovery.policy.canonicalData()
    let path = root.appendingPathComponent("transitions.jsonl").path
    let store = try NativeAuditKeyTransitionStore(path: path, tenant: "native-host", anchorPublicKeyPEM: recoveryAnchorPEM(anchor.publicKey), recoveryPolicyData: policyData, installationID: "installation-001")
    _ = try store.accept(transitionData: first.canonicalData(), receiptData: firstReceiptData, retiringPublicKeyX963: key1.publicKeyX963)
    let recovered = try store.accept(transitionData: recovery.transition.canonicalData(), receiptData: recoveryReceiptData)
    #expect(recovered.count == 2)
    #expect(recovered.latestTransition == nil)
    #expect(recovered.latestRecoveryTransition == recovery.transition)
    let final = try store.accept(transitionData: third.canonicalData(), receiptData: thirdReceiptData)
    #expect(final.count == 3)
    #expect(final.latestTransition == third)
    #expect(final.latestRecoveryTransition == nil)

    let restarted = try NativeAuditKeyTransitionStore(path: path, tenant: "native-host", anchorPublicKeyPEM: recoveryAnchorPEM(anchor.publicKey), recoveryPolicyData: policyData, installationID: "installation-001")
    #expect(try restarted.status() == final)
    #expect(try restarted.accept(transitionData: recovery.transition.canonicalData(), receiptData: recoveryReceiptData) == final)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransitionStore(path: path, tenant: "native-host", anchorPublicKeyPEM: recoveryAnchorPEM(anchor.publicKey))
    }
}
