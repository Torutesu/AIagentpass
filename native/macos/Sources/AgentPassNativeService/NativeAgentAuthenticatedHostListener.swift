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
        guard words[1] < UInt32.max,
              words[5] > 0,
              words[5] <= UInt32(Int32.max),
              words[6] > 0,
              words[6] < UInt32.max,
              words[7] > 0,
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
    public typealias ChildObservationFactory = @Sendable (Int32, UInt64) throws -> (NativeProcessObservation, Data)

    private let allowedClientUID: UInt32
    private let codeSigningRequirement: String
    private let peerPolicyFactory: @Sendable (NativeProcessObservation) throws -> NativeProcessIdentityPolicy
    private let childPolicy: NativeProcessIdentityPolicy?
    private let auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource
    private let childFactory: ChildObservationFactory?
    private let signer: any NativeAgentAuthenticatedHostSigning
    private let childRegistrar: NativeAgentAuthenticatedHostEndpoint.ChildRegistrar?
    private let childUnregistrar: NativeAgentAuthenticatedHostEndpoint.ChildUnregistrar?
    private let nowMilliseconds: NativeAgentAuthenticatedHostEndpoint.MillisecondClock
    private let endpointLock = NSLock()
    private var endpoints: [ObjectIdentifier: NativeAgentAuthenticatedHostEndpoint] = [:]

    public init(
        allowedClientUID: UInt32,
        codeSigningRequirement: String,
        peerPolicyFactory: @escaping @Sendable (NativeProcessObservation) throws -> NativeProcessIdentityPolicy,
        childPolicy: NativeProcessIdentityPolicy?,
        auditTokenSource: any NativeAgentAuthenticatedHostAuditTokenSource = NativeAgentAuthenticatedHostUnavailableAuditTokenSource(),
        childFactory: ChildObservationFactory?,
        signer: any NativeAgentAuthenticatedHostSigning,
        childRegistrar: NativeAgentAuthenticatedHostEndpoint.ChildRegistrar? = nil,
        childUnregistrar: NativeAgentAuthenticatedHostEndpoint.ChildUnregistrar? = nil,
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
        self.childRegistrar = childRegistrar
        self.childUnregistrar = childUnregistrar
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
                nowMilliseconds: nowMilliseconds,
                childRegistrar: childRegistrar,
                childUnregistrar: childUnregistrar
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
