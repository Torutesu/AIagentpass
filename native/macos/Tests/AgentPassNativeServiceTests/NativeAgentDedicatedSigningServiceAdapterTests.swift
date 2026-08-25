import Foundation
import Testing
@testable import AgentPassNativeCore
@testable import AgentPassNativeService

@Test("Dedicated signer returns the fixed armored SSHSIG bytes, not base64url text")
func dedicatedSignerSignatureCodecUsesHostChildDataContract() throws {
    let armored = "-----BEGIN SSH SIGNATURE-----\nabc\n-----END SSH SIGNATURE-----\n"
    #expect(
        try NativeAgentDedicatedSigningServiceSignatureCodec.data(from: armored)
            == Data(armored.utf8)
    )

    #expect(throws: NativeAgentDedicatedSigningServiceAdapterError.signingFailed) {
        _ = try NativeAgentDedicatedSigningServiceSignatureCodec.data(
            from: "YWJjLWRvZXMtbm90LW1hdGNoLXNzaHNpZw"
        )
    }
}

@Test("Dedicated signer fails closed when service context is unavailable")
func dedicatedSignerDoesNotInvokeIssuerOrProviderWithoutServiceContext() throws {
    let payload = try dedicatedAuthorizedPayload()
    let issuer = DedicatedAdapterIssuerSpy { _ in
        throw IssueTrap.unexpectedIssuerCall
    }
    let provider = DedicatedAdapterContextProvider {
        throw NativeAgentDedicatedSigningServiceAdapterError.contextUnavailable
    }
    let adapter = NativeAgentDedicatedSigningServiceSignerAdapter(
        capabilityIssuer: issuer,
        contextProvider: provider,
        makeHandoffAdapter: { _ in throw IssueTrap.unexpectedHandoffCall },
        provider: { _ in throw IssueTrap.unexpectedProviderCall }
    )

    #expect(throws: NativeAgentDedicatedSigningServiceAdapterError.contextUnavailable) {
        _ = try adapter.signAuthorizedPayload(payload)
    }
    #expect(issuer.calls == 0)
}

@Test("Dedicated signer seam does not add Cloud fields to Host or Child DTOs")
func dedicatedSignerSeamKeepsTransportDTOsOpaque() throws {
    let sourceURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        .appendingPathComponent(
            "Sources/AgentPassNativeService/NativeAgentDedicatedSigningServiceAdapter.swift"
        )
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("AgentPassHostSignRequest") == false)
    #expect(source.contains("AgentPassChildGitSignRequest") == false)
    #expect(source.contains("gitCommitSigner") == false)
    #expect(source.contains("NativeAgentDedicatedSigningHandoffBroker"))
}

private enum IssueTrap: Error {
    case unexpectedIssuerCall
    case unexpectedHandoffCall
    case unexpectedProviderCall
}

private final class DedicatedAdapterIssuerSpy:
    NativeAgentDedicatedSigningCapabilityIssuing, @unchecked Sendable {
    private let operation: @Sendable (NativeAgentSigningCapabilityRequest) throws
        -> NativeAgentPassSignRequest
    private(set) var calls = 0

    init(
        _ operation: @escaping @Sendable (NativeAgentSigningCapabilityRequest) throws
            -> NativeAgentPassSignRequest
    ) {
        self.operation = operation
    }

    func issue(
        _ request: NativeAgentSigningCapabilityRequest,
        context: NativeAgentSigningCapabilityVerificationContext,
        commitPayload: Data
    ) throws -> NativeAgentPassSignRequest {
        calls += 1
        return try operation(request)
    }
}

private struct DedicatedAdapterContextProvider:
    NativeAgentDedicatedSigningContextProviding {
    let operation: @Sendable () throws -> NativeAgentDedicatedSigningServiceContext

    init(
        _ operation: @escaping @Sendable () throws -> NativeAgentDedicatedSigningServiceContext
    ) {
        self.operation = operation
    }

    func context(
        for payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload
    ) throws -> NativeAgentDedicatedSigningServiceContext {
        try operation()
    }
}

private func dedicatedAuthorizedPayload()
    throws -> NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload
{
    let observation = try NativeProcessObservation(
        process: NativeObservedProcessFacts(
            uid: 501,
            pid: 42,
            pidVersion: 9,
            bootIdentity: "dedicated-adapter-test-boot",
            executableFileIdentity: NativeExecutableFileIdentity(
                deviceID: 1,
                inode: 2,
                fileSize: 3,
                modificationTimeNanoseconds: 4
            ),
            codeDirectoryHash: String(repeating: "a", count: 64),
            bundleIdentifier: "dev.agentpass.agent-host",
            teamIdentifier: "ABCDE12345",
            signatureKind: .developerID,
            entitlements: [NativeAgentCodeRequirement.clientEntitlement: .boolean(true)]
        ),
        ancestry: []
    )
    let context = try NativeConnectionContext(
        osProcessID: observation.process.pid,
        effectiveUserID: observation.process.uid,
        auditSessionID: 7,
        pidVersion: observation.process.pidVersion
    )
    let peer = try NativeAgentAuthenticatedGitBridgePeerBinding(
        connectionContext: context,
        observation: observation,
        processPolicy: try NativeProcessIdentityPolicy.exact(
            NativeProcessIdentity(observation: observation)
        )
    )
    let session = try NativeAgentAuthenticatedGitBridgeSession(
        sessionID: "11111111-1111-4111-8111-111111111111",
        peer: peer,
        childPolicy: try NativeProcessIdentityPolicy.exact(peer.processIdentity),
        signatureBudget: NativeAgentSignatureBudgetLedger(
            try NativeAgentSignatureBudget(maxSignatures: 2, usedSignatures: 0)
        ),
        authenticator: try #require(
            NativeAgentAuthenticatedGitBridgeRequestAuthenticator(
                keyData: Data(repeating: 0x5a, count: 32)
            )
        )
    )
    _ = try session.prepare(launchNonce: Data(repeating: 1, count: 16))
    _ = try session.attach(childIdentity: peer.processIdentity)
    let request = try #require(
        session.makeRequest(requestSequence: 1, payload: Data("commit".utf8))
    )
    return try session.authorizeAndConsume(
        request,
        reobservedConnectionContext: context,
        reobservedObservation: observation
    )
}
