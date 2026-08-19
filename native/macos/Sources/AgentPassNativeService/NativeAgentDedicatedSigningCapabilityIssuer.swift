import Foundation
import AgentPassNativeCore

public enum NativeAgentDedicatedSigningCapabilityIssuerError: String, Error, Equatable, Sendable {
    case requestMismatch = "request_mismatch"
    case randomUnavailable = "random_unavailable"
    case clockUnavailable = "clock_unavailable"
}

/// Converts a device-authenticated Cloud capability response into the
/// service-owned request consumed by the future dedicated signing route.
/// Verification is mandatory and happens before request construction.
public final class NativeAgentDedicatedSigningCapabilityIssuer: @unchecked Sendable {
    private let consumer: NativeAgentSigningCapabilityHTTPConsumer
    private let verifier: NativeAgentSigningCapabilityVerifier
    private let random: any NativeAgentRandomBytesGenerating
    private let wallClock: any NativeAgentWallClock

    public init(
        consumer: NativeAgentSigningCapabilityHTTPConsumer,
        verifier: NativeAgentSigningCapabilityVerifier,
        random: any NativeAgentRandomBytesGenerating = NativeAgentSystemRandomBytesGenerator(),
        wallClock: any NativeAgentWallClock = NativeAgentSystemWallClock()
    ) {
        self.consumer = consumer
        self.verifier = verifier
        self.random = random
        self.wallClock = wallClock
    }

    /// Obtains a capability from Cloud and materializes one service-owned
    /// request only after the pinned verifier accepts its canonical bytes.
    public func issue(
        _ request: NativeAgentSigningCapabilityRequest,
        context: NativeAgentSigningCapabilityVerificationContext,
        commitPayload: Data
    ) throws -> NativeAgentPassSignRequest {
        let response = try consumer.issue(request)
        return try issue(
            request: request,
            response: response,
            context: context,
            commitPayload: commitPayload
        )
    }

    /// Materializes a request only when the Cloud response belongs to the
    /// exact request issued by this service boundary.
    public func issue(
        request: NativeAgentSigningCapabilityRequest,
        response: NativeAgentSigningCapabilityResponse,
        context: NativeAgentSigningCapabilityVerificationContext,
        commitPayload: Data
    ) throws -> NativeAgentPassSignRequest {
        guard response.requestID == request.requestID else {
            throw NativeAgentDedicatedSigningCapabilityIssuerError.requestMismatch
        }
        return try issue(
            response: response,
            context: context,
            commitPayload: commitPayload
        )
    }

    /// Materializes a request from an already shape-checked response.  This
    /// overload keeps the cryptographic boundary independently unit-testable
    /// without changing the HTTP consumer API.
    public func issue(
        response: NativeAgentSigningCapabilityResponse,
        context: NativeAgentSigningCapabilityVerificationContext,
        commitPayload: Data
    ) throws -> NativeAgentPassSignRequest {
        let canonicalCapability = try NativeAgentSigningCapabilityCodec.canonicalJSON(response.capability)
        let verifiedCapability = try verifier.verify(canonicalCapability, context: context)

        guard !response.metadata.replayed else {
            throw NativeAgentPassSignRequestError.replayedCapability
        }
        guard !commitPayload.isEmpty,
              commitPayload.count <= NativeAgentPassSignRequest.maximumCommitPayloadBytes else {
            throw NativeAgentPassSignRequestError.invalidRequest
        }
        let requestNonce: Data
        do {
            requestNonce = try random.randomBytes(count: NativeAgentPassSignRequest.nonceBytes)
        } catch {
            throw NativeAgentDedicatedSigningCapabilityIssuerError.randomUnavailable
        }
        guard requestNonce.count == NativeAgentPassSignRequest.nonceBytes else {
            throw NativeAgentDedicatedSigningCapabilityIssuerError.randomUnavailable
        }
        let createdAtMilliseconds: Int64
        do {
            createdAtMilliseconds = try wallClock.sample().millisecondsSinceUnixEpoch
        } catch {
            throw NativeAgentDedicatedSigningCapabilityIssuerError.clockUnavailable
        }
        guard createdAtMilliseconds >= 0 else {
            throw NativeAgentDedicatedSigningCapabilityIssuerError.clockUnavailable
        }
        return try NativeAgentPassSignRequest(
            response: response,
            verifiedCapability: verifiedCapability,
            commitPayload: commitPayload,
            requestNonce: requestNonce,
            createdAtMilliseconds: createdAtMilliseconds
        )
    }
}
