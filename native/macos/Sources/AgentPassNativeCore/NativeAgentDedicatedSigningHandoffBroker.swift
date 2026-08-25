import Foundation

/// Secret-free failures for the Core boundary that connects a dedicated
/// Host/Child session to the authenticated Agent session coordinator.
public enum NativeAgentDedicatedSigningHandoffBrokerError: String, Error, Equatable, Sendable {
    /// The service has not associated this dedicated connection with an Agent
    /// coordinator. No handoff or provider may be created in this state.
    case associationMissing = "association_missing"
    /// A service-owned association was supplied, but its binding no longer
    /// matches the coordinator's live binding observation.
    case invalidAssociation = "invalid_association"
    /// The service did not provide a request/handoff input.
    case handoffMissing = "handoff_missing"
    /// The request could not be turned into the fixed Core transaction shape.
    case invalidRequest = "invalid_request"
}

/// The only request input accepted by the dedicated broker.
///
/// This is deliberately a small wrapper around the generic Core
/// `AgentPassAgentSignRequest`. It has no Host/Child DTO fields, key selector,
/// repository path, signer, budget, lease, or authority projection. The
/// service supplies the request and typed authority factory; the Coordinator
/// supplies the live binding and verified lease.
public final class NativeAgentDedicatedSigningHandoffInputs: @unchecked Sendable {
    fileprivate let token: NativeAgentDedicatedSigningAssociationToken
    fileprivate let agentRequest: AgentPassAgentSignRequest
    fileprivate let authorityProvider: @Sendable
        (NativeAgentSessionBinding) throws -> NativeSigningTransactionAuthority

    fileprivate init(
        token: NativeAgentDedicatedSigningAssociationToken,
        request: AgentPassAgentSignRequest,
        authorityProvider: @escaping @Sendable
            (NativeAgentSessionBinding) throws -> NativeSigningTransactionAuthority
    ) {
        self.token = token
        self.agentRequest = request
        self.authorityProvider = authorityProvider
    }
}

/// Service-owned association between one authenticated Agent coordinator and
/// one dedicated signing connection.
///
/// The association captures the coordinator, durable transaction store, and
/// an unforgeable issuance token. A caller cannot move inputs issued by one
/// association to another. The coordinator still re-observes its live
/// binding and active verified lease for every handoff.
public final class NativeAgentDedicatedSigningAssociation: @unchecked Sendable {
    fileprivate let coordinator: NativeAgentSessionCoordinator
    fileprivate let transactionStore: NativeSigningTransactionStore
    fileprivate let token = NativeAgentDedicatedSigningAssociationToken()

    public init(
        coordinator: NativeAgentSessionCoordinator,
        transactionStore: NativeSigningTransactionStore
    ) {
        self.coordinator = coordinator
        self.transactionStore = transactionStore
    }

    /// Issues service-owned handoff inputs. The authority projection is a
    /// typed Core value factory; Host/Child transport DTOs are not accepted.
    public func makeHandoffInputs(
        request: AgentPassAgentSignRequest,
        authorityProvider: @escaping @Sendable
            (NativeAgentSessionBinding) throws -> NativeSigningTransactionAuthority
    ) -> NativeAgentDedicatedSigningHandoffInputs {
        NativeAgentDedicatedSigningHandoffInputs(
            token: token,
            request: request, authorityProvider: authorityProvider)
    }
}

fileprivate final class NativeAgentDedicatedSigningAssociationToken: @unchecked Sendable {}

/// Bounded Core-only broker for dedicated signing.
///
/// `makeAdapter(for:)` is intentionally the only operation. It creates a
/// fresh `NativeAgentSessionCoordinatorSigningAdapter` for each request after
/// the existing Coordinator has issued a complete opaque handoff. It never
/// accepts Host/Child authority fields and it never invokes a provider itself.
/// Callers execute the returned adapter; provider-called-once and
/// post-provider `outcome_unknown` semantics therefore remain owned by the
/// existing adapter implementation.
public final class NativeAgentDedicatedSigningHandoffBroker: @unchecked Sendable {
    private let association: NativeAgentDedicatedSigningAssociation?

    /// A nil association is allowed only so the failure is explicit and
    /// testable. Production service wiring must supply the association created
    /// after Agent session activation and independent identity observation.
    public init(association: NativeAgentDedicatedSigningAssociation?) {
        self.association = association
    }

    /// Creates one fresh coordinator signing adapter for the supplied
    /// service-translated request.
    public func makeAdapter(
        for input: NativeAgentDedicatedSigningHandoffInputs?
    ) throws -> NativeAgentSessionCoordinatorSigningAdapter {
        guard let association else {
            throw NativeAgentDedicatedSigningHandoffBrokerError.associationMissing
        }
        guard let input else {
            throw NativeAgentDedicatedSigningHandoffBrokerError.handoffMissing
        }
        guard input.token === association.token else {
            throw NativeAgentDedicatedSigningHandoffBrokerError.invalidAssociation
        }

        do {
            let identity = try NativeSigningTransactionRequest(input.agentRequest)
            if try association.transactionStore.lookup(request: identity) != nil {
                // A transaction record, including an uncertain provider
                // outcome, is a durable one-shot tombstone. Do not create a
                // second adapter that could cause a retry after the provider
                // boundary has already been crossed.
                throw NativeAgentDedicatedSigningHandoffBrokerError.handoffMissing
            }
        } catch let error as NativeAgentDedicatedSigningHandoffBrokerError {
            throw error
        } catch {
            throw NativeAgentDedicatedSigningHandoffBrokerError.invalidRequest
        }

        let handoff: NativeAgentSessionCoordinatorSigningHandoff
        do {
            handoff = try association.coordinator.makeSigningHandoff(
                request: input.agentRequest
            ) { observedBinding in
                try input.authorityProvider(observedBinding)
            }
        } catch let error as NativeAgentDedicatedSigningHandoffBrokerError {
            throw error
        } catch let error as NativeAgentSessionCoordinatorError {
            switch error {
            case .bindingDenied:
                throw NativeAgentDedicatedSigningHandoffBrokerError.invalidAssociation
            case .sessionDenied, .leaseDenied, .connectionDenied, .invalidated:
                throw NativeAgentDedicatedSigningHandoffBrokerError.handoffMissing
            case .invalidInput, .challengeDenied, .grantDenied, .activationDenied,
                 .auditUnavailable, .invalidConfiguration:
                throw NativeAgentDedicatedSigningHandoffBrokerError.invalidRequest
            }
        } catch {
            throw NativeAgentDedicatedSigningHandoffBrokerError.invalidRequest
        }

        do {
            // This initializer is the only place a dedicated request obtains
            // an adapter. A new handoff and a new adapter are made on every
            // call; no adapter is cached or shared across requests.
            return try NativeAgentSessionCoordinatorSigningAdapter(
                handoff: handoff,
                coordinator: association.coordinator,
                transactionStore: association.transactionStore)
        } catch {
            throw NativeAgentDedicatedSigningHandoffBrokerError.handoffMissing
        }
    }
}
