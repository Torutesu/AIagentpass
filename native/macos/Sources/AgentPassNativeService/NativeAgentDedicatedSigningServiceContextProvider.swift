import Foundation
import AgentPassNativeCore

/// Stable failures for resolving a Dedicated request to Service-owned Agent
/// authority.  No caller value is reflected in these errors.
public enum NativeAgentDedicatedSigningServiceContextProviderError: String, Error, Equatable, Sendable {
    case observationUnavailable = "observation_unavailable"
    case processBindingMismatch = "process_binding_mismatch"
    case associationMissing = "association_missing"
    case associationInvalid = "association_invalid"
    case capabilitySequenceUnavailable = "capability_sequence_unavailable"
    case requestIDUnavailable = "request_id_unavailable"
    case contextInvalid = "context_invalid"
}

/// The complete state projection that must be produced by fresh Service/OS
/// observers.  It is deliberately not Codable and cannot be built from an
/// XPC request alone.
public struct NativeAgentDedicatedSigningObservedState: Sendable {
    public let binding: NativeAgentSessionBinding
    public let worktree: NativeAgentWorktreeBinding

    public init(binding: NativeAgentSessionBinding, worktree: NativeAgentWorktreeBinding) throws {
        guard binding.worktreeBindingDigest == worktree.digest else {
            throw NativeAgentDedicatedSigningServiceContextProviderError.observationUnavailable
        }
        self.binding = binding
        self.worktree = worktree
    }
}

/// Resolves an authenticated Dedicated payload to the exact Generic Agent
/// Coordinator association. The sequence provider is intentionally injected:
/// it must read the Service's durable Cloud reservation state and must never
/// derive a sequence from the capability envelope being verified.
public final class NativeAgentDedicatedSigningServiceContextProvider:
    NativeAgentDedicatedSigningContextProviding, @unchecked Sendable {
    public typealias StateObserver = @Sendable
        (_ payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload)
        throws -> NativeAgentDedicatedSigningObservedState
    typealias SequenceProvider = @Sendable
        (_ association: NativeAgentCoordinatorSessionAssociation) throws -> Int64
    typealias AuthorityProvider = @Sendable
        (_ binding: NativeAgentSessionBinding) throws -> NativeSigningTransactionAuthority
    public typealias RequestIDFactory = @Sendable () -> String
    public typealias MillisecondClock = @Sendable () throws -> Int64

    private let organizationID: String
    private let capabilityKeyID: String
    private let registry: NativeAgentCoordinatorSessionAssociationRegistry
    private let observeState: StateObserver
    private let sequence: SequenceProvider
    private let authority: AuthorityProvider
    private let requestIDFactory: RequestIDFactory
    private let clock: MillisecondClock
    private let allowedClockSkewMilliseconds: Int64
    private let maximumTTLMilliseconds: Int64

    init(
        organizationID: String,
        capabilityKeyID: String,
        registry: NativeAgentCoordinatorSessionAssociationRegistry,
        observeState: @escaping StateObserver,
        sequence: @escaping SequenceProvider,
        authority: @escaping AuthorityProvider,
        requestIDFactory: @escaping RequestIDFactory = { UUID().uuidString.lowercased() },
        clock: @escaping MillisecondClock = {
            let value = Date().timeIntervalSince1970 * 1_000
            guard value.isFinite, value > 0, value <= Double(Int64.max) else {
                throw NativeAgentDedicatedSigningServiceContextProviderError.contextInvalid
            }
            return Int64(value.rounded())
        },
        allowedClockSkewMilliseconds: Int64 = 5_000,
        maximumTTLMilliseconds: Int64 = 60_000
    ) throws {
        guard UUID(uuidString: organizationID)?.uuidString.lowercased() == organizationID,
              capabilityKeyID.range(of: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$", options: .regularExpression) != nil,
              allowedClockSkewMilliseconds >= 0,
              maximumTTLMilliseconds > 0 else {
            throw NativeAgentDedicatedSigningServiceContextProviderError.contextInvalid
        }
        self.organizationID = organizationID
        self.capabilityKeyID = capabilityKeyID
        self.registry = registry
        self.observeState = observeState
        self.sequence = sequence
        self.authority = authority
        self.requestIDFactory = requestIDFactory
        self.clock = clock
        self.allowedClockSkewMilliseconds = allowedClockSkewMilliseconds
        self.maximumTTLMilliseconds = maximumTTLMilliseconds
    }

    public func context(
        for payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload
    ) throws -> NativeAgentDedicatedSigningServiceContext {
        let observed: NativeAgentDedicatedSigningObservedState
        do {
            observed = try observeState(payload)
        } catch let error as NativeAgentDedicatedSigningServiceContextProviderError {
            throw error
        } catch {
            throw NativeAgentDedicatedSigningServiceContextProviderError.observationUnavailable
        }
        guard hex(observed.binding.processBindingDigest) == payload.peerProcessBindingHash.lowercased() else {
            throw NativeAgentDedicatedSigningServiceContextProviderError.processBindingMismatch
        }

        guard let association = registry.lookup(
            processBindingDigest: observed.binding.processBindingDigest,
            ancestryBindingDigest: observed.binding.ancestryBindingDigest,
            worktreeBindingDigest: observed.binding.worktreeBindingDigest),
              association.isActive,
              association.binding == observed.binding,
              association.dedicatedSigningAssociation != nil else {
            throw NativeAgentDedicatedSigningServiceContextProviderError.associationMissing
        }

        let sequenceValue: Int64
        do {
            sequenceValue = try sequence(association)
        } catch {
            throw NativeAgentDedicatedSigningServiceContextProviderError.capabilitySequenceUnavailable
        }
        guard sequenceValue > 0 else {
            throw NativeAgentDedicatedSigningServiceContextProviderError.capabilitySequenceUnavailable
        }
        let requestID = requestIDFactory().lowercased()
        guard UUID(uuidString: requestID)?.uuidString.lowercased() == requestID else {
            throw NativeAgentDedicatedSigningServiceContextProviderError.requestIDUnavailable
        }
        let request: NativeAgentSigningCapabilityRequest
        let now: Int64
        let verification: NativeAgentSigningCapabilityVerificationContext
        do {
            request = try NativeAgentSigningCapabilityRequest(requestID: requestID)
            now = try clock()
            verification = try NativeAgentSigningCapabilityVerificationContext(
                nowMilliseconds: now,
                allowedClockSkewMilliseconds: allowedClockSkewMilliseconds,
                maximumTTLMilliseconds: maximumTTLMilliseconds,
                organizationID: organizationID,
                sessionID: association.sessionID,
                binding: observed.binding,
                keyID: capabilityKeyID,
                sequence: sequenceValue)
        } catch {
            throw NativeAgentDedicatedSigningServiceContextProviderError.contextInvalid
        }

        guard let dedicatedAssociation = association.dedicatedSigningAssociation else {
            throw NativeAgentDedicatedSigningServiceContextProviderError.associationInvalid
        }
        return try NativeAgentDedicatedSigningServiceContext(
            dedicatedSessionID: payload.sessionID,
            coordinatorSessionID: association.sessionID,
            binding: observed.binding,
            worktree: observed.worktree,
            capabilityRequest: request,
            verificationContext: verification,
            association: dedicatedAssociation,
            authorityProvider: { binding in
                guard binding == observed.binding else {
                    throw NativeAgentDedicatedSigningServiceContextProviderError.associationInvalid
                }
                return try self.authority(binding)
            })
    }

    private func hex(_ value: Data) -> String {
        value.map { String(format: "%02x", $0) }.joined()
    }
}
