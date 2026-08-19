import CryptoKit
import Foundation
import AgentPassNativeCore

/// Stable failures for the not-yet-wired Dedicated Host/Child signing seam.
/// No Cloud, process, or transaction detail is reflected to an XPC peer.
public enum NativeAgentDedicatedSigningServiceAdapterError: String, Error, Equatable, Sendable {
    case invalidAuthorizedPayload = "invalid_authorized_payload"
    case contextUnavailable = "context_unavailable"
    case contextMismatch = "context_mismatch"
    case capabilityIssuanceFailed = "capability_issuance_failed"
    case requestMaterializationFailed = "request_materialization_failed"
    case handoffUnavailable = "handoff_unavailable"
    case signingFailed = "signing_failed"
    case outcomeUnknown = "outcome_unknown"
}

/// The service-owned capability operation used by the adapter. Keeping this
/// narrow protocol separate from the concrete issuer makes the seam testable
/// without adding a fake Cloud response to the Host/Child transport contract.
public protocol NativeAgentDedicatedSigningCapabilityIssuing: Sendable {
    func issue(
        _ request: NativeAgentSigningCapabilityRequest,
        context: NativeAgentSigningCapabilityVerificationContext,
        commitPayload: Data
    ) throws -> NativeAgentPassSignRequest
}

extension NativeAgentDedicatedSigningCapabilityIssuer:
    NativeAgentDedicatedSigningCapabilityIssuing {}

/// Complete service-owned inputs for one authorized Dedicated signing.
///
/// The context is created by Service state, never decoded from a Host/Child
/// DTO. In particular, the association and authority factory remain private
/// to this typed value and cannot be selected by the authorized payload.
public struct NativeAgentDedicatedSigningServiceContext: @unchecked Sendable {
    /// Session ID owned by the authenticated Host/Child transport.
    public let dedicatedSessionID: String
    /// Session ID owned by the Generic Agent Coordinator and Cloud authority.
    /// These IDs are intentionally distinct: the Dedicated transport must not
    /// be able to select or masquerade as a Coordinator session.
    public let coordinatorSessionID: String
    public let binding: NativeAgentSessionBinding
    public let worktree: NativeAgentWorktreeBinding
    public let capabilityRequest: NativeAgentSigningCapabilityRequest
    public let verificationContext: NativeAgentSigningCapabilityVerificationContext

    fileprivate let association: NativeAgentDedicatedSigningAssociation
    fileprivate let authorityProvider: @Sendable
        (NativeAgentSessionBinding) throws -> NativeSigningTransactionAuthority

    public init(
        dedicatedSessionID: String,
        coordinatorSessionID: String,
        binding: NativeAgentSessionBinding,
        worktree: NativeAgentWorktreeBinding,
        capabilityRequest: NativeAgentSigningCapabilityRequest,
        verificationContext: NativeAgentSigningCapabilityVerificationContext,
        association: NativeAgentDedicatedSigningAssociation,
        authorityProvider: @escaping @Sendable
            (NativeAgentSessionBinding) throws -> NativeSigningTransactionAuthority
    ) throws {
        guard UUID(uuidString: dedicatedSessionID)?.uuidString.lowercased() == dedicatedSessionID,
              UUID(uuidString: coordinatorSessionID)?.uuidString.lowercased() == coordinatorSessionID,
              verificationContext.sessionID == coordinatorSessionID else {
            throw NativeAgentDedicatedSigningServiceAdapterError.contextMismatch
        }
        self.dedicatedSessionID = dedicatedSessionID
        self.coordinatorSessionID = coordinatorSessionID
        self.binding = binding
        self.worktree = worktree
        self.capabilityRequest = capabilityRequest
        self.verificationContext = verificationContext
        self.association = association
        self.authorityProvider = authorityProvider
    }
}

/// Service-owned lookup for the binding and capability verification context.
/// The authorized payload is only a lookup correlation and payload source; it
/// is not allowed to supply the binding, tenant, sequence, or authority.
public protocol NativeAgentDedicatedSigningContextProviding: Sendable {
    func context(
        for payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload
    ) throws -> NativeAgentDedicatedSigningServiceContext
}

public struct NativeAgentDedicatedSigningClosureContextProvider:
    NativeAgentDedicatedSigningContextProviding {
    private let operation: @Sendable
        (NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload) throws
        -> NativeAgentDedicatedSigningServiceContext

    public init(
        operation: @escaping @Sendable
            (NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload) throws
            -> NativeAgentDedicatedSigningServiceContext
    ) {
        self.operation = operation
    }

    public func context(
        for payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload
    ) throws -> NativeAgentDedicatedSigningServiceContext {
        try operation(payload)
    }
}

/// The transaction ledger stores the fixed Git SSHSIG as text so recovery can
/// replay the exact armored value. It is not the capability's base64url
/// encoding and must not be decoded as such. Host/Child XPC expects the same
/// armored SSHSIG bytes returned by `NativeAgentGitCommitSigner`.
enum NativeAgentDedicatedSigningServiceSignatureCodec {
    static func data(from transactionSignature: String) throws -> Data {
        guard transactionSignature.hasPrefix("-----BEGIN SSH SIGNATURE-----\n"),
              transactionSignature.hasSuffix("-----END SSH SIGNATURE-----\n"),
              let data = transactionSignature.data(using: .utf8),
              data.count <= AgentPassHostXPCContract.maximumSignatureBytes,
              String(data: data, encoding: .utf8) == transactionSignature else {
            throw NativeAgentDedicatedSigningServiceAdapterError.signingFailed
        }
        return data
    }
}

/// A small Service-owned adapter for the future Dedicated Host/Child route.
///
/// It deliberately stops at the existing Core handoff/transaction adapter:
/// Host/Child DTOs remain payload-only, and `main.swift` is not changed to
/// replace the legacy signer until a production context provider and complete
/// Coordinator wiring exist. There is no legacy signer fallback in this type.
public protocol NativeAgentDedicatedSigning: Sendable {
    func signAuthorizedPayload(
        _ payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload
    ) throws -> Data
}

public final class NativeAgentDedicatedSigningServiceSignerAdapter:
    NativeAgentDedicatedSigning, @unchecked Sendable {
    public typealias Provider = @Sendable (Data) throws -> Data

    typealias HandoffAdapterFactory = @Sendable
        (NativeAgentDedicatedSigningHandoffInputs?) throws
        -> NativeAgentSessionCoordinatorSigningAdapter

    private let capabilityIssuer: any NativeAgentDedicatedSigningCapabilityIssuing
    private let contextProvider: any NativeAgentDedicatedSigningContextProviding
    private let makeHandoffAdapter: HandoffAdapterFactory
    private let provider: Provider

    public init(
        capabilityIssuer: any NativeAgentDedicatedSigningCapabilityIssuing,
        handoffBroker: NativeAgentDedicatedSigningHandoffBroker,
        contextProvider: any NativeAgentDedicatedSigningContextProviding,
        provider: @escaping Provider
    ) {
        self.capabilityIssuer = capabilityIssuer
        self.contextProvider = contextProvider
        self.makeHandoffAdapter = { input in
            try handoffBroker.makeAdapter(for: input)
        }
        self.provider = provider
    }

    /// Internal factory used by focused tests to observe the handoff boundary
    /// without constructing a second Coordinator fixture or invoking a key.
    init(
        capabilityIssuer: any NativeAgentDedicatedSigningCapabilityIssuing,
        contextProvider: any NativeAgentDedicatedSigningContextProviding,
        makeHandoffAdapter: @escaping HandoffAdapterFactory,
        provider: @escaping Provider
    ) {
        self.capabilityIssuer = capabilityIssuer
        self.contextProvider = contextProvider
        self.makeHandoffAdapter = makeHandoffAdapter
        self.provider = provider
    }

    public func signAuthorizedPayload(
        _ payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload
    ) throws -> Data {
        guard !payload.payload.isEmpty,
              payload.payload.count <= NativeAgentPassSignRequest.maximumCommitPayloadBytes,
              payload.payloadDigest == Data(SHA256.hash(data: payload.payload)),
              Self.isDigest(payload.peerProcessBindingHash) else {
            throw NativeAgentDedicatedSigningServiceAdapterError.invalidAuthorizedPayload
        }

        let context: NativeAgentDedicatedSigningServiceContext
        do {
            context = try contextProvider.context(for: payload)
        } catch let error as NativeAgentDedicatedSigningServiceAdapterError {
            throw error
        } catch {
            throw NativeAgentDedicatedSigningServiceAdapterError.contextUnavailable
        }

        guard context.dedicatedSessionID == payload.sessionID,
              Self.hex(context.binding.processBindingDigest)
                  == payload.peerProcessBindingHash.lowercased(),
              context.verificationContext.sessionID == context.coordinatorSessionID else {
            throw NativeAgentDedicatedSigningServiceAdapterError.contextMismatch
        }

        let serviceRequest: NativeAgentPassSignRequest
        do {
            serviceRequest = try capabilityIssuer.issue(
                context.capabilityRequest,
                context: context.verificationContext,
                commitPayload: payload.payload
            )
        } catch {
            throw NativeAgentDedicatedSigningServiceAdapterError.capabilityIssuanceFailed
        }

        guard serviceRequest.sessionID == context.coordinatorSessionID,
              serviceRequest.commitPayload == payload.payload,
              serviceRequest.capabilityID == serviceRequest.capability.statement.capabilityID else {
            throw NativeAgentDedicatedSigningServiceAdapterError.requestMaterializationFailed
        }

        do {
            try NativeAgentDedicatedSigningScopeEvaluator.evaluate(
                capability: serviceRequest.capability.statement,
                worktree: context.worktree
            )
        } catch {
            throw NativeAgentDedicatedSigningServiceAdapterError.requestMaterializationFailed
        }

        let capabilityData: Data
        do {
            capabilityData = try serviceRequest.canonicalCapabilityData()
        } catch {
            throw NativeAgentDedicatedSigningServiceAdapterError.requestMaterializationFailed
        }

        // This is an in-process projection into the existing Core handoff
        // shape. It is never encoded into Host/Child XPC and does not change
        // either transport DTO.
        guard let agentRequest = AgentPassAgentSignRequest(
            sessionID: serviceRequest.sessionID,
            requestID: serviceRequest.requestID,
            capabilityID: serviceRequest.capabilityID,
            capability: capabilityData,
            commitPayload: serviceRequest.commitPayload,
            requestNonce: serviceRequest.requestNonce,
            createdAtMilliseconds: serviceRequest.createdAtMilliseconds
        ) else {
            throw NativeAgentDedicatedSigningServiceAdapterError.requestMaterializationFailed
        }

        let handoffInputs = context.association.makeHandoffInputs(
            request: agentRequest,
            authorityProvider: { observedBinding in
                guard observedBinding == context.binding else {
                    throw NativeAgentDedicatedSigningServiceAdapterError.contextMismatch
                }
                return try context.authorityProvider(observedBinding)
            }
        )

        let adapter: NativeAgentSessionCoordinatorSigningAdapter
        do {
            adapter = try makeHandoffAdapter(handoffInputs)
        } catch {
            throw NativeAgentDedicatedSigningServiceAdapterError.handoffUnavailable
        }

        do {
            let completed = try adapter.execute(provider: provider)
            guard let signature = completed.signature else {
                throw NativeAgentDedicatedSigningServiceAdapterError.signingFailed
            }
            return try NativeAgentDedicatedSigningServiceSignatureCodec.data(
                from: signature
            )
        } catch let error as NativeAgentSessionCoordinatorSigningAdapterError
            where error == .outcomeUnknown {
            throw NativeAgentDedicatedSigningServiceAdapterError.outcomeUnknown
        } catch let error as NativeAgentDedicatedSigningServiceAdapterError {
            throw error
        } catch {
            throw NativeAgentDedicatedSigningServiceAdapterError.signingFailed
        }
    }

    private static func isDigest(_ value: String) -> Bool {
        value.count == 64 && value.range(of: "^[0-9a-fA-F]{64}$", options: .regularExpression) != nil
    }

    private static func hex(_ value: Data) -> String {
        value.map { String(format: "%02x", $0) }.joined()
    }
}

extension NativeAgentDedicatedSigningServiceSignerAdapter:
    NativeAgentAuthenticatedHostSigning {
    public func sign(
        _ payload: NativeAgentAuthenticatedGitBridgeSession.AuthorizedPayload
    ) throws -> Data {
        try signAuthorizedPayload(payload)
    }
}
