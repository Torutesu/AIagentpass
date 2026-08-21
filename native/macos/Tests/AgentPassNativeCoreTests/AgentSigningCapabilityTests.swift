import Foundation
import CryptoKit
import Testing
@testable import AgentPassNativeCore

private let agentSigningFixtureIDs = [
    "organization": "11111111-1111-4111-8111-111111111111",
    "device": "22222222-2222-4222-8222-222222222222",
    "agent": "33333333-3333-4333-8333-333333333333",
    "session": "44444444-4444-4444-8444-444444444444",
    "capability": "55555555-5555-4555-8555-555555555555",
    "request": "66666666-6666-4666-8666-666666666666"
]

private func agentSigningFixture() throws -> [String: Any] {
    let source = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // AgentPassNativeCoreTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // macos
        .deletingLastPathComponent() // native
        .deletingLastPathComponent() // repository
        .appendingPathComponent("test/fixtures/agent-signing-capability-v1.json")
    return try #require(JSONSerialization.jsonObject(with: Data(contentsOf: source)) as? [String: Any])
}

private func agentSigningFixtureEnvelopeData() throws -> Data {
    let fixture = try agentSigningFixture()
    let envelope = try #require(fixture["envelope"] as? [String: Any])
    return try NativeStrictJSON.data(envelope)
}

private func agentSigningEnvelopeObject() throws -> [String: Any] {
    let fixture = try agentSigningFixture()
    return try #require(fixture["envelope"] as? [String: Any])
}

private func agentSigningStatementObject() throws -> [String: Any] {
    let envelope = try agentSigningEnvelopeObject()
    return try #require(envelope["statement"] as? [String: Any])
}

private func agentSigningEpochMilliseconds(_ value: String) throws -> Int64 {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    let date = try #require(formatter.date(from: value))
    return Int64((date.timeIntervalSince1970 * 1_000).rounded())
}

private func agentSigningBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func agentSigningContext(
    now: String = "2026-08-16T00:00:10.000Z",
    skew: Int64 = 0,
    maximumTTL: Int64 = 60_000,
    organizationID: String = agentSigningFixtureIDs["organization"]!,
    keyID: String = "git-commit-signing-v1",
    sequence: Int64 = 13,
    controlSequence: Int64 = 12,
    authorityGeneration: Int64 = 7
) throws -> NativeAgentSigningCapabilityVerificationContext {
    try NativeAgentSigningCapabilityVerificationContext(
        nowMilliseconds: try agentSigningEpochMilliseconds(now),
        allowedClockSkewMilliseconds: skew,
        maximumTTLMilliseconds: maximumTTL,
        organizationID: organizationID,
        sessionID: agentSigningFixtureIDs["session"]!,
        deviceID: agentSigningFixtureIDs["device"]!,
        agentID: agentSigningFixtureIDs["agent"]!,
        keyID: keyID,
        sequence: sequence,
        controlSequence: controlSequence,
        authorityGeneration: authorityGeneration
    )
}

private func agentSigningSignedData(
    _ capability: NativeAgentSigningCapabilityEnvelope,
    privateKey: Curve25519.Signing.PrivateKey
) throws -> Data {
    let signature = try privateKey.signature(for: NativeAgentSigningCapabilityCodec.signedStatementBytes(capability))
    let signedEnvelope = try NativeAgentSigningCapabilityEnvelope(
        statement: capability.statement,
        signature: agentSigningBase64URL(signature)
    )
    return try NativeAgentSigningCapabilityCodec.canonicalJSON(signedEnvelope)
}

@Test func agentSigningCapabilityFixtureUsesTheSharedCanonicalStatementAndDomain() throws {
    let fixture = try agentSigningFixture()
    let envelope = try NativeAgentSigningCapabilityCodec.decode(try agentSigningFixtureEnvelopeData())
    let canonicalStatement = try String(decoding: NativeAgentSigningCapabilityCodec.canonicalStatementJSON(envelope.statement), as: UTF8.self)
    let signed = try NativeAgentSigningCapabilityCodec.signedStatementBytes(envelope)

    #expect(canonicalStatement == fixture["canonical_statement"] as? String)
    #expect(envelope.statementHash == fixture["statement_hash"] as? String)
    #expect(NativeAgentSigningCapabilityCodec.signatureDomain == "AgentPass-Agent-Signing-Capability-v1\0")
    #expect(signed.base64EncodedString() == fixture["signed_statement_bytes_base64"] as? String)
    #expect(envelope.statement.organizationID == agentSigningFixtureIDs["organization"])
    #expect(envelope.statement.issuedAt == "2026-08-16T00:00:00.000Z")
    #expect(envelope.statement.issuedAt == envelope.statement.notBefore)
    #expect(envelope.statement.maxSignatures == 1)
}

@Test func agentSigningCapabilityCodecRetainsExactPublicFieldsAndCanonicalBytes() throws {
    let data = try agentSigningFixtureEnvelopeData()
    let envelope = try NativeAgentSigningCapabilityCodec.decode(data)

    #expect(envelope.version == 1)
    #expect(envelope.type == "agentpass.agent-signing-capability")
    #expect(envelope.statement.sessionID == agentSigningFixtureIDs["session"])
    #expect(envelope.statement.deviceID == agentSigningFixtureIDs["device"])
    #expect(envelope.statement.agentID == agentSigningFixtureIDs["agent"])
    #expect(envelope.statement.scope.repositories == ["/work/project"])
    #expect(envelope.statement.scope.branches.allow == ["feature/*"])
    #expect(envelope.statement.scope.branches.deny == ["main"])
    #expect(envelope.statement.scope.tags == nil)
    #expect(try NativeAgentSigningCapabilityCodec.canonicalJSON(envelope) == data)
    #expect(try NativeAgentSigningCapabilityCodec.statementHash(envelope.statement) == envelope.statementHash)
}

@Test func agentSigningCapabilityCodecRejectsDuplicateUnknownAndNonCanonicalBytes() throws {
    #expect(throws: NativeAgentSigningCapabilityCodecError.duplicateField) {
        _ = try NativeAgentSigningCapabilityCodec.decode(Data(#"{"version":1,"version":1}"#.utf8))
    }

    var unknownEnvelope = try agentSigningEnvelopeObject()
    unknownEnvelope["unexpected"] = true
    #expect(throws: NativeAgentSigningCapabilityCodecError.unknownField) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(unknownEnvelope))
    }

    var unknownStatement = try agentSigningStatementObject()
    unknownStatement["ttl_seconds"] = 30
    var envelope = try agentSigningEnvelopeObject()
    envelope["statement"] = unknownStatement
    #expect(throws: NativeAgentSigningCapabilityCodecError.unknownField) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
    }

    #expect(throws: NativeAgentSigningCapabilityCodecError.nonCanonicalJSON) {
        _ = try NativeAgentSigningCapabilityCodec.decode(Data((" " + String(decoding: try agentSigningFixtureEnvelopeData(), as: UTF8.self)).utf8))
    }
}

@Test func agentSigningCapabilityCodecRejectsDowngradeCrossProtocolAndTampering() throws {
    var envelope = try agentSigningEnvelopeObject()
    envelope["version"] = 0
    #expect(throws: NativeAgentSigningCapabilityCodecError.unsupportedVersion) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
    }

    envelope = try agentSigningEnvelopeObject()
    envelope["type"] = "agentpass.agent-session-grant"
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidType) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
    }

    envelope = try agentSigningEnvelopeObject()
    envelope["statement_hash"] = String(repeating: "a", count: 64)
    #expect(throws: NativeAgentSigningCapabilityCodecError.statementHashMismatch) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
    }

    envelope = try agentSigningEnvelopeObject()
    envelope["signature"] = String(repeating: "!", count: 86)
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidSignatureEncoding) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
    }
}

@Test func agentSigningCapabilityCodecRejectsAuthoritySubstitutionsAndBounds() throws {
    var statement = try agentSigningStatementObject()
    statement["organization_id"] = "99999999-9999-4999-8999-999999999999"
    var envelope = try agentSigningEnvelopeObject()
    envelope["statement"] = statement
    #expect(throws: NativeAgentSigningCapabilityCodecError.statementHashMismatch) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
    }

    statement = try agentSigningStatementObject()
    statement["one_use"] = false
    envelope["statement"] = statement
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidBoolean) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
    }

    statement = try agentSigningStatementObject()
    statement["max_signatures"] = 2
    envelope["statement"] = statement
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidBudget) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
    }

    statement = try agentSigningStatementObject()
    statement["issued_at"] = "2026-08-16T00:00:01.000Z"
    envelope["statement"] = statement
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidTimestamp) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
    }
}

@Test func agentSigningCapabilityVerifierRequiresPinnedKeyDomainAndExplicitAuthority() throws {
    let shape = try NativeAgentSigningCapabilityCodec.decode(try agentSigningFixtureEnvelopeData())
    let privateKey = Curve25519.Signing.PrivateKey()
    let signedData = try agentSigningSignedData(shape, privateKey: privateKey)
    let verifier = try NativeAgentSigningCapabilityVerifier(
        trustedPublicKey: privateKey.publicKey,
        expectedIssuer: NativeAgentSigningCapabilityCodec.issuer,
        expectedKeyPurpose: NativeAgentSigningCapabilityCodec.operation,
        expectedKeyID: "git-commit-signing-v1",
        expectedDomain: NativeAgentSigningCapabilityCodec.signatureDomain
    )

    let verified = try verifier.verify(signedData, context: try agentSigningContext())
    #expect(verified.statement == shape.statement)

    let wrongKey = Curve25519.Signing.PrivateKey()
    let wrongVerifier = try NativeAgentSigningCapabilityVerifier(
        trustedPublicKey: wrongKey.publicKey,
        expectedIssuer: NativeAgentSigningCapabilityCodec.issuer,
        expectedKeyPurpose: NativeAgentSigningCapabilityCodec.operation,
        expectedKeyID: "git-commit-signing-v1",
        expectedDomain: NativeAgentSigningCapabilityCodec.signatureDomain
    )
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidSignature) {
        _ = try wrongVerifier.verify(signedData, context: try agentSigningContext())
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidDomain) {
        _ = try NativeAgentSigningCapabilityVerifier(
            trustedPublicKey: privateKey.publicKey,
            expectedIssuer: NativeAgentSigningCapabilityCodec.issuer,
            expectedKeyPurpose: NativeAgentSigningCapabilityCodec.operation,
            expectedKeyID: "git-commit-signing-v1",
            expectedDomain: "AgentPass-Wrong-Domain-v1\0"
        )
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidKeyPurpose) {
        _ = try NativeAgentSigningCapabilityVerifier(
            trustedPublicKey: privateKey.publicKey,
            expectedIssuer: NativeAgentSigningCapabilityCodec.issuer,
            expectedKeyPurpose: "git.push.sign",
            expectedKeyID: "git-commit-signing-v1",
            expectedDomain: NativeAgentSigningCapabilityCodec.signatureDomain
        )
    }
}

@Test func agentSigningCapabilityVerifierRejectsTenantBindingAndTimeViolations() throws {
    let shape = try NativeAgentSigningCapabilityCodec.decode(try agentSigningFixtureEnvelopeData())
    let privateKey = Curve25519.Signing.PrivateKey()
    let signedData = try agentSigningSignedData(shape, privateKey: privateKey)
    let verifier = try NativeAgentSigningCapabilityVerifier(
        trustedPublicKey: privateKey.publicKey,
        expectedIssuer: NativeAgentSigningCapabilityCodec.issuer,
        expectedKeyPurpose: NativeAgentSigningCapabilityCodec.operation,
        expectedKeyID: "git-commit-signing-v1",
        expectedDomain: NativeAgentSigningCapabilityCodec.signatureDomain
    )

    #expect(throws: NativeAgentSigningCapabilityCodecError.authorityMismatch) {
        _ = try verifier.verify(
            signedData,
            context: try agentSigningContext(organizationID: "99999999-9999-4999-8999-999999999999")
        )
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.authorityMismatch) {
        _ = try verifier.verify(signedData, context: try agentSigningContext(sequence: 14))
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.authorityMismatch) {
        _ = try verifier.verify(signedData, context: try agentSigningContext(keyID: "git-commit-signing-v2"))
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.authorityMismatch) {
        _ = try verifier.verify(signedData, context: try agentSigningContext(controlSequence: 13))
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.authorityMismatch) {
        _ = try verifier.verify(signedData, context: try agentSigningContext(authorityGeneration: 8))
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.notYetValid) {
        _ = try verifier.verify(signedData, context: try agentSigningContext(now: "2026-08-15T23:59:59.000Z"))
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.expired) {
        _ = try verifier.verify(signedData, context: try agentSigningContext(now: "2026-08-16T00:01:00.000Z"))
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.expired) {
        _ = try verifier.verify(signedData, context: try agentSigningContext(now: "2026-08-16T00:00:30.000Z"))
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.ttlExceeded) {
        _ = try verifier.verify(signedData, context: try agentSigningContext(maximumTTL: 1_000))
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidVerificationContext) {
        _ = try agentSigningContext(now: "1970-01-01T00:00:00.000Z")
    }
}

@Test func agentSigningCapabilityVerificationContextCanBindAnObservedSession() throws {
    let binding = try NativeAgentSessionBinding(
        agentID: agentSigningFixtureIDs["agent"]!,
        deviceID: agentSigningFixtureIDs["device"]!,
        processBindingDigest: Data(repeating: 0x11, count: NativeAgentSessionBinding.digestByteCount),
        ancestryBindingDigest: Data(repeating: 0x22, count: NativeAgentSessionBinding.digestByteCount),
        worktreeBindingDigest: Data(repeating: 0x33, count: NativeAgentSessionBinding.digestByteCount),
        controlSequence: 12,
        authorityGeneration: 7,
        keyGeneration: 99
    )
    let context = try NativeAgentSigningCapabilityVerificationContext(
        nowMilliseconds: try agentSigningEpochMilliseconds("2026-08-16T00:00:10.000Z"),
        allowedClockSkewMilliseconds: 0,
        maximumTTLMilliseconds: 60_000,
        organizationID: agentSigningFixtureIDs["organization"]!,
        sessionID: agentSigningFixtureIDs["session"]!,
        binding: binding,
        keyID: "git-commit-signing-v1",
        sequence: 13
    )

    #expect(context.agentID == binding.agentID)
    #expect(context.deviceID == binding.deviceID)
    #expect(context.controlSequence == binding.controlSequence)
    #expect(context.authorityGeneration == binding.authorityGeneration)
    #expect(context.sequence == 13)
    #expect(context.keyID == "git-commit-signing-v1")
}

@Test func agentSigningCapabilityCodecRejectsEpochAndAllowsIssuedAtBeforeNotBefore() throws {
    var issuedEpochStatement = try agentSigningStatementObject()
    issuedEpochStatement["issued_at"] = "1970-01-01T00:00:00.000Z"
    var issuedEpochEnvelope = try agentSigningEnvelopeObject()
    issuedEpochEnvelope["statement"] = issuedEpochStatement
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidTimestamp) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(issuedEpochEnvelope))
    }

    var epochStatement = try agentSigningStatementObject()
    epochStatement["not_before"] = "1970-01-01T00:00:00.000Z"
    var epochEnvelope = try agentSigningEnvelopeObject()
    epochEnvelope["statement"] = epochStatement
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidTimestamp) {
        _ = try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(epochEnvelope))
    }

    let shape = try NativeAgentSigningCapabilityCodec.decode(try agentSigningFixtureEnvelopeData())
    let earlierIssuedAt = try NativeAgentSigningCapabilityStatement(
        capabilityID: shape.statement.capabilityID,
        sessionID: shape.statement.sessionID,
        organizationID: shape.statement.organizationID,
        deviceID: shape.statement.deviceID,
        agentID: shape.statement.agentID,
        scope: shape.statement.scope,
        keyID: shape.statement.keyID,
        issuedAt: "2026-08-16T00:00:00.000Z",
        notBefore: "2026-08-16T00:00:01.000Z",
        expiresAt: "2026-08-16T00:00:30.000Z",
        sequence: shape.statement.sequence,
        controlSequence: shape.statement.controlSequence,
        authorityGeneration: shape.statement.authorityGeneration
    )
    #expect(earlierIssuedAt.issuedAt < earlierIssuedAt.notBefore)
    #expect(try NativeAgentSigningCapabilityCodec.statementHash(earlierIssuedAt).count == 64)
}

@Test func agentSigningCapabilityRequestContainsNoCallerAuthorityFields() throws {
    let request = try NativeAgentSigningCapabilityRequest(requestID: agentSigningFixtureIDs["request"]!)
    let data = try NativeAgentSigningCapabilityCodec.encodeRequest(request)
    #expect(String(decoding: data, as: UTF8.self) == #"{"request_id":"66666666-6666-4666-8666-666666666666"}"#)
    #expect(try NativeAgentSigningCapabilityCodec.decodeRequest(data) == request)

    #expect(throws: NativeAgentSigningCapabilityCodecError.unknownField) {
        _ = try NativeAgentSigningCapabilityCodec.decodeRequest(Data(#"{"request_id":"66666666-6666-4666-8666-666666666666","operation":"git.commit.sign"}"#.utf8))
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.duplicateField) {
        _ = try NativeAgentSigningCapabilityCodec.decodeRequest(Data(#"{"request_id":"66666666-6666-4666-8666-666666666666","request_id":"77777777-7777-4777-8777-777777777777"}"#.utf8))
    }
}

@Test func agentSigningCapabilityResponseCapsRemainingBudgetAtOne() throws {
    let capability = try NativeAgentSigningCapabilityCodec.decode(try agentSigningFixtureEnvelopeData())
    let metadata: [String: Any] = [
        "operation": "git.commit.sign",
        "key_purpose": "git.commit.sign",
        "issued_at": capability.statement.issuedAt,
        "expires_at": capability.statement.expiresAt,
        "sequence": capability.statement.sequence,
        "remaining_session_signatures": 1,
        "replayed": false
    ]
    var response: [String: Any] = [
        "capability": try NativeStrictJSON.object(from: try NativeAgentSigningCapabilityCodec.canonicalJSON(capability), maxBytes: 16 * 1024, maxDepth: 8),
        "metadata": metadata,
        "request_id": agentSigningFixtureIDs["request"]!
    ]
    let decoded = try NativeAgentSigningCapabilityCodec.decodeResponse(try NativeStrictJSON.data(response))
    #expect(decoded.metadata.remainingSessionSignatures == 1)
    #expect(decoded.metadata.sequence == capability.statement.sequence)

    response["metadata"] = [
        "operation": "git.commit.sign",
        "key_purpose": "git.commit.sign",
        "issued_at": capability.statement.issuedAt,
        "expires_at": capability.statement.expiresAt,
        "sequence": capability.statement.sequence,
        "remaining_session_signatures": 2,
        "replayed": false
    ]
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidBudget) {
        _ = try NativeAgentSigningCapabilityCodec.decodeResponse(try NativeStrictJSON.data(response))
    }
}
