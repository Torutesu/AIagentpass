import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct TransitionSoftwareSigner: P256MessageSigner {
    let privateKey: P256.Signing.PrivateKey
    init(byte: UInt8) throws {
        privateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
    }
    var publicKeyX963: Data { privateKey.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try privateKey.signature(for: message).rawRepresentation }
}

private struct TransitionFixture {
    let old: TransitionSoftwareSigner
    let replacement: TransitionSoftwareSigner
    let statement: NativeAuditKeyTransitionStatement
    let transition: NativeAuditKeyTransition

    init() throws {
        old = try TransitionSoftwareSigner(byte: 1)
        replacement = try TransitionSoftwareSigner(byte: 2)
        statement = try NativeAuditKeyTransitionStatement(
            tenant: "native-host",
            operationID: "audit-key-rotation-0001",
            fromGeneration: 1,
            oldPublicKeyX963: old.publicKeyX963,
            newPublicKeyX963: replacement.publicKeyX963,
            lifecycleHeadHash: String(repeating: "a", count: 64),
            lastCheckpointIndex: 7,
            lastCheckpointHash: String(repeating: "b", count: 64),
            lastCheckpointReceiptHash: String(repeating: "c", count: 64),
            previousTransitionHash: String(repeating: "d", count: 64),
            previousTransitionReceiptHash: String(repeating: "e", count: 64),
            previousAnchorEventIndex: 9,
            previousAnchorEventHash: String(repeating: "f", count: 64),
            createdAt: "2030-01-01T00:00:01.000Z"
        )
        transition = try NativeAuditKeyTransition(statement: statement, retiringSigner: old, replacementSigner: replacement)
    }
}

private func transitionAnchorPEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func transitionAnchorFingerprint(_ key: Curve25519.Signing.PublicKey) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.rawRepresentation
    return "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func transitionReceiptData(
    transition: NativeAuditKeyTransition,
    key: Curve25519.Signing.PrivateKey,
    index: Int = 1,
    eventIndex: Int? = nil,
    previousEventHash: String? = nil,
    previousReceiptHash: String? = nil,
    receivedAt: String = "2030-01-01T00:00:02.000Z",
    lastCheckpointHash: String? = nil
) throws -> Data {
    var statement: [String: Any] = [
        "version": 2, "tenant": transition.tenant, "index": index,
        "transition_hash": transition.transitionHash, "received_at": receivedAt,
        "previous_receipt_hash": previousReceiptHash ?? transition.previousTransitionReceiptHash,
        "event_index": eventIndex ?? transition.previousAnchorEventIndex + 1,
        "previous_event_hash": previousEventHash ?? transition.previousAnchorEventHash,
        "last_checkpoint_index": transition.lastCheckpointIndex,
        "last_checkpoint_hash": lastCheckpointHash ?? transition.lastCheckpointHash,
        "last_checkpoint_receipt_hash": transition.lastCheckpointReceiptHash
    ]
    let signature = try key.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
    statement["anchor_key_fingerprint"] = transitionAnchorFingerprint(key.publicKey)
    statement["signature"] = signature
    statement["receipt_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(statement))
    return try NativeAuditLog.canonical(statement)
}

private func mutateTransition(_ data: Data, _ mutation: (inout [String: Any]) -> Void) throws -> Data {
    var object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    mutation(&object)
    return try NativeAuditLog.canonical(object)
}

@Test func auditKeyTransitionUsesExactNodeV2CanonicalSchemaAndDualRawP256Proofs() throws {
    let fixture = try TransitionFixture()
    let statementData = try fixture.statement.canonicalData()
    let statementObject = try #require(JSONSerialization.jsonObject(with: statementData) as? [String: Any])
    #expect(Set(statementObject.keys) == [
        "version", "tenant", "operation_id", "from_generation", "to_generation",
        "old_key_fingerprint", "new_key_fingerprint", "new_public_key", "lifecycle_head_hash",
        "created_at", "previous_transition_hash", "previous_transition_receipt_hash",
        "last_checkpoint_index", "last_checkpoint_hash", "last_checkpoint_receipt_hash",
        "previous_anchor_event_index", "previous_anchor_event_hash",
        "retiring_generation_pending_checkpoint_count"
    ])
    #expect(fixture.statement.version == 2)
    #expect(fixture.statement.toGeneration == 2)
    #expect(fixture.statement.retiringGenerationPendingCheckpointCount == 0)
    #expect(fixture.statement.newPublicKey == (try SSHSIG.authorizedKey(publicKeyX963: fixture.replacement.publicKeyX963)))
    #expect(fixture.statement.oldKeyFingerprint == NativeAuditCheckpoints.fingerprint(fixture.old.publicKeyX963))
    #expect(fixture.statement.newKeyFingerprint == NativeAuditCheckpoints.fingerprint(fixture.replacement.publicKeyX963))

    let encoded = try fixture.transition.canonicalData()
    let decoded = try NativeAuditKeyTransition.decodeCanonical(encoded)
    #expect(decoded == fixture.transition)
    try decoded.verify(retiringPublicKeyX963: fixture.old.publicKeyX963)
    #expect(try NativeAuditKeyTransition.decodeCanonical(encoded, retiringPublicKeyX963: fixture.old.publicKeyX963) == fixture.transition)
    #expect(Data(base64Encoded: decoded.oldSignature)?.count == 64)
    #expect(Data(base64Encoded: decoded.newSignature)?.count == 64)
    var unhashed = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    unhashed.removeValue(forKey: "transition_hash")
    #expect(decoded.transitionHash == NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)))
}

@Test func auditKeyTransitionDeterministicStatementVectorMatchesNodeCanonicalJSON() throws {
    let fixture = try TransitionFixture()
    let expected = #"{"created_at":"2030-01-01T00:00:01.000Z","from_generation":1,"last_checkpoint_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","last_checkpoint_index":7,"last_checkpoint_receipt_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","lifecycle_head_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","new_key_fingerprint":"SHA256:_gCrDzQZAfhjpJFgz1VFiNaSgoLVMbeZrdxBI_Rc6Fo","new_public_key":"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFUPRxAD89+Xw99QaseX9nIfsaH7e49vg9IkSYplyI4kE2CT1wEuUJpzcVy9CwCjzA/0tcAbP/oZarH7MnA2uOY=","old_key_fingerprint":"SHA256:JWsb4ydF0dHJ1JEhzIe8RRxPLfp1bYm0yRCvrrYliuA","operation_id":"audit-key-rotation-0001","previous_anchor_event_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","previous_anchor_event_index":9,"previous_transition_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","previous_transition_receipt_hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","retiring_generation_pending_checkpoint_count":0,"tenant":"native-host","to_generation":2,"version":2}"#
    #expect(String(decoding: try fixture.statement.canonicalData(), as: UTF8.self) == expected)
    #expect(NativeAuditLog.hash(Data(expected.utf8)) == "217a8009a8288b7f3448d79756b1b0e24093ccf7e7311b2f80cef1a12573b9d8")
}

@Test func auditKeyTransitionRejectsNonCanonicalUnknownAndOversizedEncodings() throws {
    let fixture = try TransitionFixture()
    let canonical = try fixture.transition.canonicalData()
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransition.decodeCanonical(Data(" \(String(decoding: canonical, as: UTF8.self))".utf8))
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransition.decodeCanonical(try mutateTransition(canonical) { $0["unexpected"] = true })
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransition.decodeCanonical(Data(repeating: 0x20, count: NativeAuditKeyTransitionStatement.maximumEncodedBytes + 1))
    }
}

@Test func auditKeyTransitionRejectsGenerationBoundaryKeySignatureAndHashMutations() throws {
    let fixture = try TransitionFixture()
    let canonical = try fixture.transition.canonicalData()
    let mutations: [(inout [String: Any]) -> Void] = [
        { $0["version"] = 1 },
        { $0["to_generation"] = 3 },
        { $0["retiring_generation_pending_checkpoint_count"] = 1 },
        { $0["previous_anchor_event_index"] = 0 },
        { $0["last_checkpoint_hash"] = String(repeating: "A", count: 64) },
        { $0["new_public_key"] = "ecdsa-sha2-nistp256 AAAA" },
        { $0["new_key_fingerprint"] = $0["old_key_fingerprint"] },
        { $0["old_signature"] = Data(repeating: 0, count: 64).base64EncodedString() },
        { $0["new_signature"] = Data(repeating: 0, count: 64).base64EncodedString() },
        { $0["transition_hash"] = String(repeating: "0", count: 64) }
    ]
    for mutation in mutations {
        #expect(throws: AgentPassNativeError.self) {
            try NativeAuditKeyTransition.decodeCanonical(try mutateTransition(canonical, mutation))
        }
    }
    let unrelated = try TransitionSoftwareSigner(byte: 3)
    #expect(throws: AgentPassNativeError.self) {
        try fixture.transition.verify(retiringPublicKeyX963: unrelated.publicKeyX963)
    }

    // A parser cannot discover the retiring key from the v2 wire artifact. Prove
    // that the context-taking decoder, used by the service, rejects a
    // hash-consistent forged retiring-key proof even when the replacement proof
    // remains valid.
    var forgedObject = try #require(JSONSerialization.jsonObject(with: canonical) as? [String: Any])
    forgedObject["old_signature"] = Data(repeating: 0, count: 64).base64EncodedString()
    forgedObject.removeValue(forKey: "transition_hash")
    forgedObject["transition_hash"] = NativeAuditLog.hash(try NativeAuditLog.canonical(forgedObject))
    let forged = try NativeAuditLog.canonical(forgedObject)
    _ = try NativeAuditKeyTransition.decodeCanonical(forged)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransition.decodeCanonical(forged, retiringPublicKeyX963: fixture.old.publicKeyX963)
    }
}

@Test func auditKeyTransitionReceiptVerifierAcceptsExactEd25519V2EventBoundary() throws {
    let fixture = try TransitionFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let verifier = try NativeAuditKeyTransitionReceiptVerifier(tenant: fixture.transition.tenant, anchorPublicKeyPEM: transitionAnchorPEM(anchor.publicKey))
    let data = try transitionReceiptData(transition: fixture.transition, key: anchor)
    let receipt = try verifier.verify(receiptData: data, transition: fixture.transition, expectedTransitionIndex: 1)
    #expect(receipt.eventIndex == fixture.transition.previousAnchorEventIndex + 1)
    #expect(receipt.previousEventHash == fixture.transition.previousAnchorEventHash)
    #expect(receipt.previousReceiptHash == fixture.transition.previousTransitionReceiptHash)
    #expect(receipt.lastCheckpointHash == fixture.transition.lastCheckpointHash)
}

@Test func auditKeyTransitionReceiptRejectsSignedBoundaryRollbackAndMutationCases() throws {
    let fixture = try TransitionFixture()
    let anchor = Curve25519.Signing.PrivateKey()
    let verifier = try NativeAuditKeyTransitionReceiptVerifier(tenant: fixture.transition.tenant, anchorPublicKeyPEM: transitionAnchorPEM(anchor.publicKey))
    let wrongEvent = try transitionReceiptData(transition: fixture.transition, key: anchor, eventIndex: fixture.transition.previousAnchorEventIndex + 2)
    let wrongEventHead = try transitionReceiptData(transition: fixture.transition, key: anchor, previousEventHash: String(repeating: "0", count: 64))
    let wrongTransitionReceipt = try transitionReceiptData(transition: fixture.transition, key: anchor, previousReceiptHash: String(repeating: "0", count: 64))
    let wrongCheckpoint = try transitionReceiptData(transition: fixture.transition, key: anchor, lastCheckpointHash: String(repeating: "0", count: 64))
    let timestampRollback = try transitionReceiptData(transition: fixture.transition, key: anchor, receivedAt: "2029-12-31T23:59:59.000Z")
    for data in [wrongEvent, wrongEventHead, wrongTransitionReceipt, wrongCheckpoint, timestampRollback] {
        #expect(throws: AgentPassNativeError.self) {
            try verifier.verify(receiptData: data, transition: fixture.transition, expectedTransitionIndex: 1)
        }
    }

    let valid = try transitionReceiptData(transition: fixture.transition, key: anchor)
    #expect(throws: AgentPassNativeError.self) {
        try verifier.verify(receiptData: valid, transition: fixture.transition, expectedTransitionIndex: 2)
    }
    #expect(throws: AgentPassNativeError.self) {
        let unknown = try mutateTransition(valid) { $0["extra"] = "field" }
        _ = try verifier.verify(receiptData: unknown, transition: fixture.transition, expectedTransitionIndex: 1)
    }
    #expect(throws: AgentPassNativeError.self) {
        let changed = try mutateTransition(valid) { $0["signature"] = Data(repeating: 0, count: 64).base64EncodedString() }
        _ = try verifier.verify(receiptData: changed, transition: fixture.transition, expectedTransitionIndex: 1)
    }
    #expect(throws: AgentPassNativeError.self) {
        let changed = try mutateTransition(valid) { $0["receipt_hash"] = String(repeating: "0", count: 64) }
        _ = try verifier.verify(receiptData: changed, transition: fixture.transition, expectedTransitionIndex: 1)
    }
}

@Test func auditKeyTransitionConstructorsRejectUnsafeLimitsAndMismatchedReplacementSigner() throws {
    let fixture = try TransitionFixture()
    let unrelated = try TransitionSoftwareSigner(byte: 3)
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransition(statement: fixture.statement, retiringSigner: fixture.old, replacementSigner: unrelated)
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeAuditKeyTransitionStatement(
            tenant: String(repeating: "t", count: 65), operationID: "operation", fromGeneration: 1,
            oldPublicKeyX963: fixture.old.publicKeyX963, newPublicKeyX963: fixture.replacement.publicKeyX963,
            lifecycleHeadHash: String(repeating: "a", count: 64), lastCheckpointIndex: 1,
            lastCheckpointHash: String(repeating: "b", count: 64), lastCheckpointReceiptHash: String(repeating: "c", count: 64),
            previousAnchorEventIndex: 1, previousAnchorEventHash: String(repeating: "d", count: 64),
            createdAt: "2030-01-01T00:00:00.000Z"
        )
    }
}
