import Foundation
import AgentPassNativeCore

/// Failures while materializing a service-owned signing request.
public enum NativeAgentPassSignRequestError: String, Error, Equatable, Sendable {
    case invalidRequest = "invalid_request"
    case replayedCapability = "replayed_capability"
    case capabilityMismatch = "capability_mismatch"
}

/// A signing request owned by the native service after Cloud capability
/// verification.  This is deliberately not an XPC DTO and has no public
/// initializer: only the issuer in this target can create one.
public struct NativeAgentPassSignRequest: Equatable, Sendable {
    public static let minimumNonceBytes = 16
    public static let maximumNonceBytes = 64
    public static let maximumCommitPayloadBytes = 1 * 1024 * 1024

    public let requestID: String
    public let sessionID: String
    public let capabilityID: String
    public let capability: NativeAgentSigningCapabilityEnvelope
    public let commitPayload: Data
    public let requestNonce: Data
    public let createdAtMilliseconds: Int64

    internal init(
        response: NativeAgentSigningCapabilityResponse,
        verifiedCapability: NativeAgentSigningCapabilityEnvelope,
        commitPayload: Data,
        requestNonce: Data,
        createdAtMilliseconds: Int64
    ) throws {
        guard response.capability == verifiedCapability else {
            throw NativeAgentPassSignRequestError.capabilityMismatch
        }
        guard !response.metadata.replayed else {
            throw NativeAgentPassSignRequestError.replayedCapability
        }
        guard !commitPayload.isEmpty,
              commitPayload.count <= Self.maximumCommitPayloadBytes,
              (Self.minimumNonceBytes...Self.maximumNonceBytes).contains(requestNonce.count),
              createdAtMilliseconds >= 0 else {
            throw NativeAgentPassSignRequestError.invalidRequest
        }

        self.requestID = response.requestID
        self.sessionID = verifiedCapability.statement.sessionID
        self.capabilityID = verifiedCapability.statement.capabilityID
        self.capability = verifiedCapability
        self.commitPayload = commitPayload
        self.requestNonce = requestNonce
        self.createdAtMilliseconds = createdAtMilliseconds
    }

    /// Canonical Cloud capability bytes for service-internal handoff.  The
    /// request cannot be constructed from arbitrary bytes, and this method
    /// never exposes a caller-controlled envelope.
    public func canonicalCapabilityData() throws -> Data {
        try NativeAgentSigningCapabilityCodec.canonicalJSON(capability)
    }
}
