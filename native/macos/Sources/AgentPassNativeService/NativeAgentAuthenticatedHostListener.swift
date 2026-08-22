import Foundation
import CryptoKit
import AgentPassNativeCore

/// Stable failures for the service-owned complete audit-token boundary.
///
/// No token words or OS error are included in a failure returned from this
/// boundary.  The listener must reject a connection when a trusted complete
/// token source is unavailable; the public NSXPC projection is not a fallback.
public enum NativeAgentAuthenticatedHostAuditTokenError: String, Error, Equatable, Sendable, LocalizedError {
    case invalidAuditToken = "invalid_audit_token"
    case auditTokenUnavailable = "audit_token_unavailable"

    public var errorDescription: String? { rawValue }
}

/// A complete, OS-owned Darwin `audit_token_t` captured at the XPC boundary.
///
/// The eight words are deliberately private to this module.  Callers can
/// inject a token source for deterministic tests, but the token cannot be
/// projected into a caller-controlled DTO or reconstructed from PID/EUID/ASID
/// attributes.  The word order is the Darwin `audit_token_t.val` order:
/// auid, euid, egid, ruid, rgid, pid, asid, pidversion.
public struct NativeAgentAuthenticatedHostCompleteAuditToken: Equatable, Sendable {
    private static let wordCount = 8
    private let words: [UInt32]

    public init(words: [UInt32]) throws {
        guard words.count == Self.wordCount else {
            throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
        }
        // `auid` may legitimately be AU_DEFAUDITID (`UINT32_MAX`), but the
        // live credential fields and the process-generation fields may not be
        // their invalid/sentinel values.  Keep this validation here as well
        // as in the OS adapter so injected sources cannot weaken the boundary.
        guard words[1] < UInt32.max,
              words[2] < UInt32.max,
              words[3] < UInt32.max,
              words[4] < UInt32.max,
              words[5] > 0,
              words[5] <= UInt32(Int32.max),
              words[6] > 0,
              words[6] <= UInt32(Int32.max),
              words[7] > 0,
              words[7] <= UInt32(Int32.max),
              words.contains(where: { $0 != 0 }) else {
            throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
        }
        self.words = words
    }

    /// Constructs the Core context from every complete-token word and the
    /// independently observed process generation.  The observation must
    /// agree with the token's PID, EUID, and PID-generation before the context
    /// can be used for authorization.
    public func context(matching observation: NativeProcessObservation) throws -> NativeConnectionContext {
        guard observation.process.pid == pid,
              observation.process.uid == effectiveUserID,
              observation.process.pidVersion == pidVersion else {
            throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
        }

        let contextPayload = NativeAgentAuthenticatedHostContextPayload(
            peerIdentity: NativeAgentAuthenticatedHostPeerIdentityPayload(
                pid: pid,
                effectiveUserID: effectiveUserID,
                auditSessionID: auditSessionID,
                pidVersion: pidVersion,
                tokenIdentity: tokenIdentity
            )
        )
        do {
            let encoded = try JSONEncoder().encode(contextPayload)
            return try JSONDecoder().decode(NativeConnectionContext.self, from: encoded)
        } catch {
            throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
        }
    }

    var pid: Int32 { Int32(words[5]) }
    var effectiveUserID: UInt32 { words[1] }
    var auditSessionID: UInt32 { words[6] }
    var pidVersion: UInt64 { UInt64(words[7]) }

    private var tokenIdentity: String {
        var data = Data(capacity: words.count * MemoryLayout<UInt32>.size)
        for word in words {
            var bigEndian = word.bigEndian
            withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
        }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

private struct NativeAgentAuthenticatedHostContextPayload: Encodable {
    let version = "native_connection_context/v1"
    let peerIdentity: NativeAgentAuthenticatedHostPeerIdentityPayload

    enum CodingKeys: String, CodingKey {
        case version
        case peerIdentity = "peer_identity"
    }
}

private struct NativeAgentAuthenticatedHostPeerIdentityPayload: Encodable {
    let version = "native_connection_peer_identity/v1"
    let pid: Int32
    let effectiveUserID: UInt32
    let auditSessionID: UInt32
    let pidVersion: UInt64
    let tokenIdentity: String

    enum CodingKeys: String, CodingKey {
        case version
        case pid
        case effectiveUserID = "effective_user_id"
        case auditSessionID = "audit_session_id"
        case pidVersion = "pid_version"
        case tokenIdentity = "token_identity"
    }
}

/// The only source accepted by the Host listener.  A production
/// implementation must return the complete live `audit_token_t` supplied by
/// the lower-level OS/Mach boundary; a public NSXPC attribute projection does
/// not satisfy this protocol.
public protocol NativeAgentAuthenticatedHostAuditTokenSource: Sendable {
    func completeAuditToken(for connection: NSXPCConnection) throws -> NativeAgentAuthenticatedHostCompleteAuditToken
}

/// Safe default while no trusted complete-token OS adapter is installed.
/// This intentionally makes the Host listener unavailable instead of falling
/// back to PID/EUID/ASID or a synthetic context.
public struct NativeAgentAuthenticatedHostUnavailableAuditTokenSource: NativeAgentAuthenticatedHostAuditTokenSource {
    public init() {}

    public func completeAuditToken(for connection: NSXPCConnection) throws -> NativeAgentAuthenticatedHostCompleteAuditToken {
        throw NativeAgentAuthenticatedHostAuditTokenError.auditTokenUnavailable
    }
}

/// Closure adapter used only at the OS boundary and by injection tests.
public struct NativeAgentAuthenticatedHostClosureAuditTokenSource: NativeAgentAuthenticatedHostAuditTokenSource {
    public typealias Operation = @Sendable (NSXPCConnection) throws -> NativeAgentAuthenticatedHostCompleteAuditToken

    private let operation: Operation

    public init(operation: @escaping Operation) {
        self.operation = operation
    }

    public func completeAuditToken(for connection: NSXPCConnection) throws -> NativeAgentAuthenticatedHostCompleteAuditToken {
        try operation(connection)
    }
}

/// `NSXPCConnection` owns its own serialized message queue, but Foundation's
/// Swift overlay does not mark the object `Sendable`. The endpoint observers
/// are `@Sendable` closures, so this narrow box keeps the existing XPC object
/// at the OS boundary without capturing the listener delegate itself.
private final class NativeAgentAuthenticatedHostConnectionBox: @unchecked Sendable {
    let connection: NSXPCConnection

    init(_ connection: NSXPCConnection) {
        self.connection = connection
    }
}

/// Service-side adapter for the dedicated Host Mach service.
///
/// This type deliberately keeps the OS boundary explicit: the caller must
/// provide independently observed child facts and a worktree binding digest.
/// If either dependency is unavailable, attach fails closed instead of using
/// request-supplied identity data.
public final class NativeAgentAuthenticatedHostListenerDelegate: NSObject, NSXPCListenerDelegate {
    public typealias SignatureBudgetProvider = NativeAgentAuthenticatedHostEndpoint.SignatureBudgetProvider

    public typealias ChildObservationFactory = @Sendable (Int32, UInt64) throws -> (NativeProcessObservation, Data)

    private let allowedClientUID: UInt32
    private let codeSigningRequirement: String
    private let peerPolicyFactory: @Sendable (NativeProcessObservation) throws -> NativeProcessIdentityPolicy
    private let childPolicy: NativeProcessIdentityPolicy?
    private let auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource
    private let childFactory: ChildObservationFactory?
    private let signer: any NativeAgentAuthenticatedHostSigning
    private let dedicatedSigner: (any NativeAgentAuthenticatedHostSigning)?
    private let childRegistrar: NativeAgentAuthenticatedHostEndpoint.ChildRegistrar?
    private let dedicatedChildRegistrar: NativeAgentAuthenticatedHostEndpoint.DedicatedChildRegistrar?
    private let childUnregistrar: NativeAgentAuthenticatedHostEndpoint.ChildUnregistrar?
    private let signatureBudgetProvider: SignatureBudgetProvider?
    private let nowMilliseconds: NativeAgentAuthenticatedHostEndpoint.MillisecondClock
    private let controlRegistry: NativeAgentHostControlRegistry
    private let endpointLock = NSLock()
    private var endpoints: [ObjectIdentifier: NativeAgentAuthenticatedHostEndpoint] = [:]

    init(
        allowedClientUID: UInt32,
        codeSigningRequirement: String,
        peerPolicyFactory: @escaping @Sendable (NativeProcessObservation) throws -> NativeProcessIdentityPolicy,
        childPolicy: NativeProcessIdentityPolicy?,
        auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource = NativeAgentAuthenticatedHostUnavailableAuditTokenSource(),
        childFactory: ChildObservationFactory?,
        signer: any NativeAgentAuthenticatedHostSigning,
        dedicatedSigner: (any NativeAgentAuthenticatedHostSigning)? = nil,
        childRegistrar: NativeAgentAuthenticatedHostEndpoint.ChildRegistrar? = nil,
        dedicatedChildRegistrar: NativeAgentAuthenticatedHostEndpoint.DedicatedChildRegistrar? = nil,
        childUnregistrar: NativeAgentAuthenticatedHostEndpoint.ChildUnregistrar? = nil,
        signatureBudgetProvider: SignatureBudgetProvider? = nil,
        controlRegistry: NativeAgentHostControlRegistry = NativeAgentHostControlRegistry(),
        nowMilliseconds: @escaping NativeAgentAuthenticatedHostEndpoint.MillisecondClock = {
            Int64(Date().timeIntervalSince1970 * 1_000)
        }
    ) {
        self.allowedClientUID = allowedClientUID
        self.codeSigningRequirement = codeSigningRequirement
        self.peerPolicyFactory = peerPolicyFactory
        self.childPolicy = childPolicy
        self.auditTokenSource = auditTokenSource
        self.childFactory = childFactory
        self.signer = signer
        self.dedicatedSigner = dedicatedSigner
        self.childRegistrar = childRegistrar
        self.dedicatedChildRegistrar = dedicatedChildRegistrar
        self.childUnregistrar = childUnregistrar
        self.signatureBudgetProvider = signatureBudgetProvider
        self.controlRegistry = controlRegistry
        self.nowMilliseconds = nowMilliseconds
        super.init()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let tokenSource = auditTokenSource
        let initialToken: NativeAgentAuthenticatedHostCompleteAuditToken
        do {
            initialToken = try tokenSource.completeAuditToken(for: connection)
        } catch {
            return false
        }
        guard initialToken.effectiveUserID == allowedClientUID else { return false }
        connection.setCodeSigningRequirement(codeSigningRequirement)

        let observer = NativeDarwinProcessObservationSource()
        do {
            let peerPID = initialToken.pid
            let peerUID = initialToken.effectiveUserID
            let connectionBox = NativeAgentAuthenticatedHostConnectionBox(connection)
            let initialObservation = try observer.observe(pid: peerPID, expectedUserID: peerUID)
            let context = try initialToken.context(matching: initialObservation)
            let peerPolicy = try peerPolicyFactory(initialObservation)
            guard let childFactory, let childPolicy else {
                // The Host surface is not usable until child provenance and
                // worktree binding are configured. Never expose a weak mode.
                return false
            }
            let expectedChildUID = allowedClientUID
            let endpoint = try NativeAgentAuthenticatedHostEndpoint(
                connectionContext: context,
                initialPeerObservation: initialObservation,
                peerProcessPolicy: peerPolicy,
                childProcessPolicy: childPolicy,
                observeConnectionContext: {
                    let currentToken = try tokenSource.completeAuditToken(for: connectionBox.connection)
                    guard currentToken.pid == peerPID,
                          currentToken.effectiveUserID == peerUID else {
                        throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
                    }
                    let current = try observer.observe(
                        pid: currentToken.pid,
                        expectedUserID: currentToken.effectiveUserID
                    )
                    return try currentToken.context(matching: current)
                },
                observePeerProcess: {
                    let currentToken = try tokenSource.completeAuditToken(for: connectionBox.connection)
                    guard currentToken.pid == peerPID,
                          currentToken.effectiveUserID == peerUID else {
                        throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
                    }
                    return try observer.observe(
                        pid: currentToken.pid,
                        expectedUserID: currentToken.effectiveUserID
                    )
                },
                observeChild: { pid, pidVersion in
                    let (childObservation, worktreeDigest) = try childFactory(pid, pidVersion)
                    guard childObservation.process.pid == pid,
                          childObservation.process.pidVersion == pidVersion,
                          childObservation.process.uid == expectedChildUID else {
                        throw NativeAgentAuthenticatedHostEndpointError.childIdentityMismatch
                    }
                    struct FixedSource: NativeProcessObservationSource {
                        let observation: NativeProcessObservation
                        func observe() throws -> NativeProcessObservation { observation }
                    }
                    return try NativeAgentAuthenticatedHostChildObservation(
                        observationSource: FixedSource(observation: childObservation),
                        worktreeBindingDigest: worktreeDigest
                    )
                },
                signer: signer,
                dedicatedSigner: dedicatedSigner,
                nowMilliseconds: nowMilliseconds,
                childRegistrar: childRegistrar,
                dedicatedChildRegistrar: dedicatedChildRegistrar,
                childUnregistrar: childUnregistrar,
                signatureBudgetProvider: signatureBudgetProvider,
                sessionRegistrar: { [controlRegistry] sessionID, endpoint, ownerIdentity in
                    try controlRegistry.register(
                        sessionID: sessionID,
                        endpoint: endpoint,
                        ownerIdentity: ownerIdentity
                    )
                },
                sessionUnregistrar: { [controlRegistry] endpoint in
                    controlRegistry.unregister(endpoint: endpoint)
                }
            )
            connection.exportedInterface = AgentPassHostXPCInterface.make()
            connection.exportedObject = endpoint
            let key = ObjectIdentifier(connection)
            endpointLock.lock()
            endpoints[key] = endpoint
            endpointLock.unlock()
            connection.invalidationHandler = { [weak self, weak endpoint, weak connection] in
                endpoint?.invalidateConnection()
                guard let self, let connection else { return }
                self.endpointLock.lock()
                self.endpoints.removeValue(forKey: ObjectIdentifier(connection))
                self.endpointLock.unlock()
            }
            connection.resume()
            return true
        } catch {
            return false
        }
    }
}

/// A control-only endpoint for a process that is separate from the Host that
/// owns the session. It has no Host signing methods and revalidates its own
/// complete peer identity before every registry operation.
public final class NativeAgentAuthenticatedHostControlEndpoint: NSObject, AgentPassHostControlXPCProtocol {
    public typealias ContextObserver = @Sendable () throws -> NativeConnectionContext
    public typealias ProcessObserver = @Sendable () throws -> NativeProcessObservation

    private static let errorDomain = "com.agentpass.native-authenticated-host-control"
    private let peerBinding: NativeAgentAuthenticatedGitBridgePeerBinding
    private let peerContextObserver: ContextObserver
    private let peerProcessObserver: ProcessObserver
    private let registry: NativeAgentHostControlRegistry
    private let stateLock = NSLock()
    private var invalidated = false

    init(
        connectionContext: NativeConnectionContext,
        initialPeerObservation: NativeProcessObservation,
        peerProcessPolicy: NativeProcessIdentityPolicy,
        observeConnectionContext: @escaping ContextObserver,
        observePeerProcess: @escaping ProcessObserver,
        registry: NativeAgentHostControlRegistry
    ) throws {
        self.peerBinding = try NativeAgentAuthenticatedGitBridgePeerBinding(
            connectionContext: connectionContext,
            observation: initialPeerObservation,
            processPolicy: peerProcessPolicy
        )
        self.peerContextObserver = observeConnectionContext
        self.peerProcessObserver = observePeerProcess
        self.registry = registry
        super.init()
    }

    public func closeHostSessionFromControl(
        _ request: AgentPassHostControlCloseRequest,
        withReply reply: @escaping (AgentPassHostControlCloseResponse?, NSError?) -> Void
    ) {
        do {
            let controllerIdentity = try revalidatePeer()
            reply(try registry.close(request: request, controllerIdentity: controllerIdentity), nil)
        } catch {
            reply(nil, makeError(error))
        }
    }

    public func invalidateConnection() {
        stateLock.withLock { invalidated = true }
    }

    private func revalidatePeer() throws -> NativeProcessIdentity {
        stateLock.lock()
        guard !invalidated else {
            stateLock.unlock()
            throw NativeAgentHostControlRegistryError.controlUnavailable
        }
        do {
            let context = try peerContextObserver()
            let observation = try peerProcessObserver()
            try peerBinding.revalidate(connectionContext: context, observation: observation)
            stateLock.unlock()
            return peerBinding.processIdentity
        } catch NativeAgentAuthenticatedGitBridgeError.peerIdentityMismatch {
            invalidated = true
            stateLock.unlock()
            throw NativeAgentHostControlRegistryError.controlPeerMismatch
        } catch NativeAgentAuthenticatedGitBridgeError.codeIdentityDenied {
            invalidated = true
            stateLock.unlock()
            throw NativeAgentHostControlRegistryError.controlPeerMismatch
        } catch NativeAgentAuthenticatedGitBridgeError.processIdentityChanged {
            invalidated = true
            stateLock.unlock()
            throw NativeAgentHostControlRegistryError.controlPeerMismatch
        } catch {
            invalidated = true
            stateLock.unlock()
            throw NativeAgentHostControlRegistryError.controlUnavailable
        }
    }

    private func makeError(_ error: Error) -> NSError {
        let stable: NativeAgentHostControlRegistryError
        if let error = error as? NativeAgentHostControlRegistryError {
            stable = error
        } else {
            stable = .controlUnavailable
        }
        let code: Int
        switch stable {
        case .controlUnavailable: code = 1
        case .controlPeerMismatch: code = 2
        case .controlReplay: code = 3
        case .controlInProgress: code = 4
        case .controlSessionMissing: code = 5
        }
        return NSError(
            domain: Self.errorDomain,
            code: code,
            userInfo: [NSLocalizedDescriptionKey: stable.rawValue]
        )
    }
}

/// Listener delegate for the dedicated Host control Mach service. The code
/// signing requirement is supplied independently of the normal Host listener
/// instance, and the complete audit token is captured again for this peer.
public final class NativeAgentAuthenticatedHostControlListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let allowedClientUID: UInt32
    private let codeSigningRequirement: String
    private let peerPolicyFactory: @Sendable (NativeProcessObservation) throws -> NativeProcessIdentityPolicy
    private let auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource
    private let registry: NativeAgentHostControlRegistry
    private let endpointLock = NSLock()
    private var endpoints: [ObjectIdentifier: NativeAgentAuthenticatedHostControlEndpoint] = [:]

    init(
        allowedClientUID: UInt32,
        codeSigningRequirement: String,
        peerPolicyFactory: @escaping @Sendable (NativeProcessObservation) throws -> NativeProcessIdentityPolicy,
        auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource,
        registry: NativeAgentHostControlRegistry
    ) {
        self.allowedClientUID = allowedClientUID
        self.codeSigningRequirement = codeSigningRequirement
        self.peerPolicyFactory = peerPolicyFactory
        self.auditTokenSource = auditTokenSource
        self.registry = registry
        super.init()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let tokenSource = auditTokenSource
        let token: NativeAgentAuthenticatedHostCompleteAuditToken
        do {
            token = try auditTokenSource.completeAuditToken(for: connection)
        } catch {
            return false
        }
        guard token.effectiveUserID == allowedClientUID else { return false }
        connection.setCodeSigningRequirement(codeSigningRequirement)

        let observer = NativeDarwinProcessObservationSource()
        do {
            let peerPID = token.pid
            let peerUID = token.effectiveUserID
            let connectionBox = NativeAgentAuthenticatedHostConnectionBox(connection)
            let initialObservation = try observer.observe(pid: peerPID, expectedUserID: peerUID)
            let context = try token.context(matching: initialObservation)
            let peerPolicy = try peerPolicyFactory(initialObservation)
            let endpoint = try NativeAgentAuthenticatedHostControlEndpoint(
                connectionContext: context,
                initialPeerObservation: initialObservation,
                peerProcessPolicy: peerPolicy,
                observeConnectionContext: {
                    let currentToken = try tokenSource.completeAuditToken(for: connectionBox.connection)
                    guard currentToken.pid == peerPID,
                          currentToken.effectiveUserID == peerUID else {
                        throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
                    }
                    let current = try observer.observe(pid: currentToken.pid, expectedUserID: currentToken.effectiveUserID)
                    return try currentToken.context(matching: current)
                },
                observePeerProcess: {
                    let currentToken = try tokenSource.completeAuditToken(for: connectionBox.connection)
                    guard currentToken.pid == peerPID,
                          currentToken.effectiveUserID == peerUID else {
                        throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
                    }
                    return try observer.observe(pid: currentToken.pid, expectedUserID: currentToken.effectiveUserID)
                },
                registry: registry
            )
            connection.exportedInterface = AgentPassHostControlXPCInterface.make()
            connection.exportedObject = endpoint
            let key = ObjectIdentifier(connection)
            endpointLock.withLock { endpoints[key] = endpoint }
            connection.invalidationHandler = { [weak self, weak endpoint, weak connection] in
                endpoint?.invalidateConnection()
                guard let self, let connection else { return }
                _ = self.endpointLock.withLock { self.endpoints.removeValue(forKey: ObjectIdentifier(connection)) }
            }
            connection.resume()
            return true
        } catch {
            return false
        }
    }
}
