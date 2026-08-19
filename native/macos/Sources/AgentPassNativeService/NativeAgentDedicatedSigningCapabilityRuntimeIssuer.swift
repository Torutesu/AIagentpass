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

    private let makeConsumer: ConsumerFactory
    private let verifier: NativeAgentSigningCapabilityVerifier
    private let random: any NativeAgentRandomBytesGenerating
    private let wallClock: any NativeAgentWallClock

    public init(
        makeConsumer: @escaping ConsumerFactory,
        verifier: NativeAgentSigningCapabilityVerifier,
        random: any NativeAgentRandomBytesGenerating = NativeAgentSystemRandomBytesGenerator(),
        wallClock: any NativeAgentWallClock = NativeAgentSystemWallClock()
    ) {
        self.makeConsumer = makeConsumer
        self.verifier = verifier
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
        let materializer = NativeAgentDedicatedSigningCapabilityIssuer(
            consumer: consumer,
            verifier: verifier,
            random: random,
            wallClock: wallClock
        )
        return try materializer.issue(
            request: request,
            response: response,
            context: context,
            commitPayload: commitPayload
        )
    }
}
