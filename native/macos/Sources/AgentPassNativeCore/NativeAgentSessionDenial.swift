import Foundation

/// The only denial reasons that may cross the Agent XPC boundary.
///
/// The raw values, numeric codes, and messages are protocol data. Keep this
/// enum closed and do not add associated values: callers must never receive
/// paths, tokens, code-signing material, Security.framework errors, or other
/// diagnostics from the Agent service.
@frozen public enum NativeAgentSessionDenialReason: String, CaseIterable, Codable, Equatable, Sendable {
    case malformedRequest = "malformed_request"
    case unavailable = "unavailable"
    case peerDenied = "peer_denied"
    case processDenied = "process_denied"
    case worktreeDenied = "worktree_denied"
    case controlDenied = "control_denied"
    case keyUnavailable = "key_unavailable"
    case leaseUnavailable = "lease_unavailable"
    case grantDenied = "grant_denied"
    case challengeDenied = "challenge_denied"
    case replayDetected = "replay_detected"
    case budgetExceeded = "budget_exceeded"
    case expired = "expired"
    case revoked = "revoked"
    case signingOutcomeUnknown = "signing_outcome_unknown"
    case internalFailure = "internal_failure"
}

public extension NativeAgentSessionDenialReason {
    /// The fixed NSError domain used by every public Agent XPC denial.
    static let errorDomain = "dev.agentpass.agent-session"

    /// The sole non-description userInfo key in the bounded NSError form.
    static let reasonCodeUserInfoKey = "AgentPassReasonCode"

    /// The numeric code is deliberately assigned explicitly so adding or
    /// reordering enum cases cannot change an existing wire-level code.
    var errorCode: Int {
        switch self {
        case .malformedRequest: return 1001
        case .unavailable: return 1002
        case .peerDenied: return 1003
        case .processDenied: return 1004
        case .worktreeDenied: return 1005
        case .controlDenied: return 1006
        case .keyUnavailable: return 1007
        case .leaseUnavailable: return 1008
        case .grantDenied: return 1009
        case .challengeDenied: return 1010
        case .replayDetected: return 1011
        case .budgetExceeded: return 1012
        case .expired: return 1013
        case .revoked: return 1014
        case .signingOutcomeUnknown: return 1015
        case .internalFailure: return 1099
        }
    }

    /// A short, generic message safe to display at the Agent XPC boundary.
    var message: String {
        switch self {
        case .malformedRequest: return "The agent request is invalid."
        case .unavailable: return "The agent service is unavailable."
        case .peerDenied: return "The agent peer is not authorized."
        case .processDenied: return "The agent process is not authorized."
        case .worktreeDenied: return "The worktree is not authorized."
        case .controlDenied: return "Control policy denies this operation."
        case .keyUnavailable: return "The signing key is unavailable."
        case .leaseUnavailable: return "The session lease is unavailable."
        case .grantDenied: return "The session grant is not authorized."
        case .challengeDenied: return "The session challenge is invalid."
        case .replayDetected: return "The request has already been used."
        case .budgetExceeded: return "The session signing budget is exhausted."
        case .expired: return "The session has expired."
        case .revoked: return "The session has been revoked."
        case .signingOutcomeUnknown: return "The signing outcome is unknown."
        case .internalFailure: return "The agent service encountered an internal error."
        }
    }

    /// A bounded NSError projection. The userInfo contains exactly the
    /// localized description and the stable numeric reason code.
    var nsError: NSError {
        NSError(
            domain: Self.errorDomain,
            code: errorCode,
            userInfo: [
                NSLocalizedDescriptionKey: message,
                Self.reasonCodeUserInfoKey: errorCode
            ]
        )
    }

    /// Alias kept next to `nsError` for XPC reply sites that use `error` as
    /// their local spelling. It still returns the same bounded projection.
    var error: NSError { nsError }

    /// Recovers a reason only from the exact bounded projection. Arbitrary
    /// NSError domains, Security errors, and user-supplied diagnostics do not
    /// enter the Agent denial taxonomy.
    static func reason(from error: NSError) -> Self? {
        let expectedKeys: Set<String> = [NSLocalizedDescriptionKey, reasonCodeUserInfoKey]
        guard error.domain == errorDomain,
              Set(error.userInfo.keys) == expectedKeys,
              let description = error.userInfo[NSLocalizedDescriptionKey] as? String,
              let reasonCode = error.userInfo[reasonCodeUserInfoKey] as? NSNumber,
              reasonCode.intValue == error.code,
              let reason = allCases.first(where: { $0.errorCode == error.code }),
              description == reason.message,
              reasonCode == NSNumber(value: reason.errorCode) else {
            return nil
        }
        return reason
    }
}

/// Names the stable userInfo key without exposing any additional projection
/// fields. This is useful to callers that need to inspect a denial safely.
public enum NativeAgentSessionDenialNSError {
    public static let domain = NativeAgentSessionDenialReason.errorDomain
    public static let reasonCodeKey = NativeAgentSessionDenialReason.reasonCodeUserInfoKey

    public static func make(_ reason: NativeAgentSessionDenialReason) -> NSError {
        reason.nsError
    }

    public static func reason(from error: NSError) -> NativeAgentSessionDenialReason? {
        NativeAgentSessionDenialReason.reason(from: error)
    }
}
