import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore
@testable import AgentPassNativeService

private let issuerOrganization = "11111111-1111-4111-8111-111111111111"
private let issuerDevice = "22222222-2222-4222-8222-222222222222"
private let issuerAgent = "33333333-3333-4333-8333-333333333333"
private let issuerSession = "44444444-4444-4444-8444-444444444444"
private let issuerCapability = "55555555-5555-4555-8555-555555555555"
private let issuerRequest = "66666666-6666-4666-8666-666666666666"

private struct IssuerUnusedSigner: P256MessageSigner {
    let publicKeyX963 = Data([0x04] + Array(repeating: 0x01, count: 64))
    func sign(message: Data) throws -> Data { Data(repeating: 0x02, count: 64) }
}

private final class IssuerUnusedTransport: NativeAgentHTTPTransporting, @unchecked Sendable {
    func send(url: URL, method: String, headers: [String: String], body: Data, timeoutSeconds: Int) throws -> NativeAgentHTTPResponse {
        NativeAgentHTTPResponse(statusCode: 503, body: Data())
    }
}

private struct IssuerClock: NativeAgentWallClock {
    func sample() throws -> NativeAgentWallClockValue {
        NativeAgentWallClockValue(millisecondsSinceUnixEpoch: 1_786_838_410_000)
    }
}

private struct IssuerRandom: NativeAgentRandomBytesGenerating {
    let value: UInt8
    func randomBytes(count: Int) throws -> Data { Data(repeating: value, count: count) }
}

private func issuerFixtureEnvelope() throws -> NativeAgentSigningCapabilityEnvelope {
    let path = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("test/fixtures/agent-signing-capability-v1.json")
    let root = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any])
    let envelope = try #require(root["envelope"] as? [String: Any])
    return try NativeAgentSigningCapabilityCodec.decode(try NativeStrictJSON.data(envelope))
}

private func issuerSignedResponse(
    privateKey: Curve25519.Signing.PrivateKey,
    replayed: Bool = false
) throws -> NativeAgentSigningCapabilityResponse {
    let shape = try issuerFixtureEnvelope()
    let signature = try privateKey.signature(for: NativeAgentSigningCapabilityCodec.signedStatementBytes(shape))
    let capability = try NativeAgentSigningCapabilityEnvelope(
        statement: shape.statement,
        signature: signature.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    )
    let metadata = try NativeAgentSigningCapabilityResponseMetadata(
        issuedAt: capability.statement.issuedAt,
        expiresAt: capability.statement.expiresAt,
        sequence: capability.statement.sequence,
        remainingSessionSignatures: replayed ? 0 : 1,
        replayed: replayed
    )
    return try NativeAgentSigningCapabilityResponse(
        capability: capability,
        metadata: metadata,
        requestID: issuerRequest
    )
}

private func issuerContext() throws -> NativeAgentSigningCapabilityVerificationContext {
    try NativeAgentSigningCapabilityVerificationContext(
        nowMilliseconds: 1_786_838_410_000,
        allowedClockSkewMilliseconds: 0,
        maximumTTLMilliseconds: 60_000,
        organizationID: issuerOrganization,
        sessionID: issuerSession,
        deviceID: issuerDevice,
        agentID: issuerAgent,
        keyID: "git-commit-signing-v1",
        sequence: 13,
        controlSequence: 12,
        authorityGeneration: 7
    )
}

private func issuer() throws -> (NativeAgentDedicatedSigningCapabilityIssuer, Curve25519.Signing.PrivateKey) {
    let privateKey = Curve25519.Signing.PrivateKey()
    let verifier = try NativeAgentSigningCapabilityVerifier(
        trustedPublicKey: privateKey.publicKey,
        expectedIssuer: NativeAgentSigningCapabilityCodec.issuer,
        expectedKeyPurpose: NativeAgentSigningCapabilityCodec.operation,
        expectedKeyID: "git-commit-signing-v1",
        expectedDomain: NativeAgentSigningCapabilityCodec.signatureDomain
    )
    let consumer = try NativeAgentSigningCapabilityHTTPConsumer(
        baseURL: URL(string: "https://api.agentpass.test")!,
        organizationID: issuerOrganization,
        deviceID: issuerDevice,
        sessionID: issuerSession,
        transport: IssuerUnusedTransport(),
        signer: IssuerUnusedSigner(),
        wallClock: IssuerClock()
    )
    return (NativeAgentDedicatedSigningCapabilityIssuer(
        consumer: consumer,
        verifier: verifier,
        random: IssuerRandom(value: 0xa5),
        wallClock: IssuerClock()
    ), privateKey)
}

@Test func dedicatedIssuerVerifiesBeforeCreatingServiceOwnedRequest() throws {
    let (issuer, privateKey) = try issuer()
    let response = try issuerSignedResponse(privateKey: privateKey)
    let request = try issuer.issue(
        response: response,
        context: try issuerContext(),
        commitPayload: Data("tree abc\n\nmessage\n".utf8)
    )

    #expect(request.requestID == issuerRequest)
    #expect(request.sessionID == issuerSession)
    #expect(request.capabilityID == issuerCapability)
    #expect(request.requestNonce == Data(repeating: 0xa5, count: 16))
    #expect(request.createdAtMilliseconds == 1_786_838_410_000)
    #expect(try request.canonicalCapabilityData() == NativeAgentSigningCapabilityCodec.canonicalJSON(response.capability))
}

@Test func dedicatedIssuerRejectsInvalidSignatureAndAuthoritySubstitution() throws {
    let (issuer, privateKey) = try issuer()
    var response = try issuerSignedResponse(privateKey: privateKey)
    let wrongKey = Curve25519.Signing.PrivateKey()
    let shape = try issuerFixtureEnvelope()
    let wrongSignature = try wrongKey.signature(for: NativeAgentSigningCapabilityCodec.signedStatementBytes(shape))
    response = try NativeAgentSigningCapabilityResponse(
        capability: try NativeAgentSigningCapabilityEnvelope(
            statement: shape.statement,
            signature: wrongSignature.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        ),
        metadata: response.metadata,
        requestID: response.requestID
    )
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidSignature) {
        _ = try issuer.issue(
            response: response,
            context: try issuerContext(),
            commitPayload: Data([1])
        )
    }

    let valid = try issuerSignedResponse(privateKey: privateKey)
    #expect(throws: NativeAgentSigningCapabilityCodecError.authorityMismatch) {
        _ = try issuer.issue(
            response: valid,
            context: try NativeAgentSigningCapabilityVerificationContext(
                nowMilliseconds: 1_786_838_410_000,
                allowedClockSkewMilliseconds: 0,
                maximumTTLMilliseconds: 60_000,
                organizationID: issuerOrganization,
                sessionID: issuerSession,
                deviceID: issuerDevice,
                agentID: issuerAgent,
                keyID: "git-commit-signing-v1",
                sequence: 14,
                controlSequence: 12,
                authorityGeneration: 7
            ),
            commitPayload: Data([1])
        )
    }
}

@Test func dedicatedIssuerRejectsReplayAndMalformedServiceInputs() throws {
    let (issuer, privateKey) = try issuer()
    let replayed = try issuerSignedResponse(privateKey: privateKey, replayed: true)
    #expect(throws: NativeAgentPassSignRequestError.replayedCapability) {
        _ = try issuer.issue(
            response: replayed,
            context: try issuerContext(),
            commitPayload: Data([1])
        )
    }
    let valid = try issuerSignedResponse(privateKey: privateKey)
    #expect(throws: NativeAgentPassSignRequestError.invalidRequest) {
        _ = try issuer.issue(
            response: valid,
            context: try issuerContext(),
            commitPayload: Data()
        )
    }
}

@Test func dedicatedIssuerRequiresResponseRequestIDMatch() throws {
    let (issuer, privateKey) = try issuer()
    let response = try issuerSignedResponse(privateKey: privateKey)
    let request = try NativeAgentSigningCapabilityRequest(
        requestID: "77777777-7777-4777-8777-777777777777"
    )
    #expect(throws: NativeAgentDedicatedSigningCapabilityIssuerError.requestMismatch) {
        _ = try issuer.issue(
            request: request,
            response: response,
            context: try issuerContext(),
            commitPayload: Data([1])
        )
    }
}

@Test func signingCapabilityResponseBindsMetadataToTheCapability() throws {
    let privateKey = Curve25519.Signing.PrivateKey()
    let response = try issuerSignedResponse(privateKey: privateKey)
    let capability = response.capability

    let wrongSequence = try NativeAgentSigningCapabilityResponseMetadata(
        issuedAt: capability.statement.issuedAt,
        expiresAt: capability.statement.expiresAt,
        sequence: capability.statement.sequence + 1,
        remainingSessionSignatures: 1,
        replayed: false
    )
    #expect(throws: NativeAgentSigningCapabilityCodecError.authorityMismatch) {
        _ = try NativeAgentSigningCapabilityResponse(
            capability: capability,
            metadata: wrongSequence,
            requestID: issuerRequest
        )
    }

    let wrongIssuedAt = try NativeAgentSigningCapabilityResponseMetadata(
        issuedAt: "2026-08-16T00:00:01.000Z",
        expiresAt: capability.statement.expiresAt,
        sequence: capability.statement.sequence,
        remainingSessionSignatures: 1,
        replayed: false
    )
    #expect(throws: NativeAgentSigningCapabilityCodecError.authorityMismatch) {
        _ = try NativeAgentSigningCapabilityResponse(
            capability: capability,
            metadata: wrongIssuedAt,
            requestID: issuerRequest
        )
    }

    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidOperation) {
        _ = try NativeAgentSigningCapabilityResponseMetadata(
            issuedAt: capability.statement.issuedAt,
            expiresAt: capability.statement.expiresAt,
            sequence: capability.statement.sequence,
            remainingSessionSignatures: 1,
            replayed: false,
            operation: "git.push.sign"
        )
    }
    #expect(throws: NativeAgentSigningCapabilityCodecError.invalidKeyPurpose) {
        _ = try NativeAgentSigningCapabilityResponseMetadata(
            issuedAt: capability.statement.issuedAt,
            expiresAt: capability.statement.expiresAt,
            sequence: capability.statement.sequence,
            remainingSessionSignatures: 1,
            replayed: false,
            keyPurpose: "git.push.sign"
        )
    }
}
