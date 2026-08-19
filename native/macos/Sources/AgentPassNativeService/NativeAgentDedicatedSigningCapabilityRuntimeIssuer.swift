import Foundation
import AgentPassNativeCore

/// Service-owned factory boundary for Dedicated signing capability issuance.
///
/// The HTTP consumer is intentionally session-bound.  A native service may
/// have several authenticated Dedicated sessions at once, so the runtime
/// issuer creates a consumer only after the Service has selected the exact
/// session-owned verification context.  The session ID is never taken from a
/// Host/Child DTO.
public final class NativeAgentDedicatedSigningCapabilityRuntimeIssuer:
    NativeAgentDedicatedSigningCapabilityIssuing, @unchecked Sendable {
    public typealias ConsumerFactory = @Sendable
        (_ sessionID: String) throws -> NativeAgentSigningCapabilityHTTPConsumer
    public typealias SequenceAuthorityFactory = @Sendable
        (_ context: NativeAgentSigningCapabilityVerificationContext) throws
        -> NativeAgentDedicatedSigningCapabilitySequenceAuthority

    private let makeConsumer: ConsumerFactory
    private let verifier: NativeAgentSigningCapabilityVerifier
    private let sequenceAuthority: SequenceAuthorityFactory
    private let random: any NativeAgentRandomBytesGenerating
    private let wallClock: any NativeAgentWallClock

    public init(
        makeConsumer: @escaping ConsumerFactory,
        verifier: NativeAgentSigningCapabilityVerifier,
        sequenceAuthority: @escaping SequenceAuthorityFactory,
        random: any NativeAgentRandomBytesGenerating = NativeAgentSystemRandomBytesGenerator(),
        wallClock: any NativeAgentWallClock = NativeAgentSystemWallClock()
    ) {
        self.makeConsumer = makeConsumer
        self.verifier = verifier
        self.sequenceAuthority = sequenceAuthority
        self.random = random
        self.wallClock = wallClock
    }

    public func issue(
        _ request: NativeAgentSigningCapabilityRequest,
        context: NativeAgentSigningCapabilityVerificationContext,
        commitPayload: Data
    ) throws -> NativeAgentPassSignRequest {
        let consumer = try makeConsumer(context.sessionID)
        let response = try consumer.issue(request)
        guard !response.metadata.replayed else {
            throw NativeAgentPassSignRequestError.replayedCapability
        }
        let canonicalCapability = try NativeAgentSigningCapabilityCodec.canonicalJSON(response.capability)
        let sequence = response.capability.statement.sequence
        let verificationContext = try NativeAgentSigningCapabilityVerificationContext(
            nowMilliseconds: context.nowMilliseconds,
            allowedClockSkewMilliseconds: context.allowedClockSkewMilliseconds,
            maximumTTLMilliseconds: context.maximumTTLMilliseconds,
            organizationID: context.organizationID,
            sessionID: context.sessionID,
            deviceID: context.deviceID,
            agentID: context.agentID,
            keyID: context.keyID,
            sequence: sequence,
            controlSequence: context.controlSequence,
            authorityGeneration: context.authorityGeneration
        )
        _ = try verifier.verify(canonicalCapability, context: verificationContext)
        let authority = try sequenceAuthority(context)
        let preparation = try authority.prepare(
            sequence: UInt64(exactly: sequence) ?? 0,
            statementHash: try NativeAgentSigningCapabilityCodec.statementHash(response.capability.statement)
        )
        let bootstrap: NativeAgentDedicatedSigningCapabilityTrustedBootstrap?
        if authority.snapshot().isInitialized {
            bootstrap = nil
        } else {
            bootstrap = NativeAgentDedicatedSigningCapabilityTrustedBootstrap()
        }
        _ = try authority.accept(preparation, trustedBootstrap: bootstrap)
        let materializer = NativeAgentDedicatedSigningCapabilityIssuer(
            consumer: consumer,
            verifier: verifier,
            random: random,
            wallClock: wallClock
        )
        return try materializer.issue(
            request: request,
            response: response,
            context: verificationContext,
            commitPayload: commitPayload
        )
    }
}
