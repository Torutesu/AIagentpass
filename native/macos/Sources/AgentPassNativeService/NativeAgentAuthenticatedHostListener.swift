import Foundation
import AgentPassNativeCore

/// Stable failures for the service-owned connection attribute boundary.
///
/// The public NSXPC API exposes selected peer attributes, not a raw
/// `audit_token_t`.  No OS error or raw token bytes are included here.
public enum NativeAgentAuthenticatedHostConnectionAttributeError: String, Error, Equatable, Sendable, LocalizedError {
    case invalidConnectionAttributes = "invalid_connection_attributes"

    public var errorDescription: String? { rawValue }
}

/// The security attributes read from an accepted `NSXPCConnection`.
///
/// This is intentionally a value type so the Core-facing context factory can
/// be injected without making Core import Foundation's XPC types.  It is not
/// a raw audit-token projection: Apple's public `NSXPCConnection` API exposes
/// PID, EUID, and BSM audit-session ID, but no `audit_token_t` accessor.
public struct NativeAgentAuthenticatedHostConnectionAttributes: Equatable, Sendable {
    public let processIdentifier: Int32
    public let effectiveUserID: UInt32
    public let auditSessionIdentifier: UInt32

    public init(
        processIdentifier: Int32,
        effectiveUserID: UInt32,
        auditSessionIdentifier: UInt64
    ) throws {
        guard processIdentifier > 0,
              effectiveUserID < UInt32.max,
              auditSessionIdentifier > 0,
              auditSessionIdentifier < UInt64(UInt32.max) else {
            throw NativeAgentAuthenticatedHostConnectionAttributeError.invalidConnectionAttributes
        }
        self.processIdentifier = processIdentifier
        self.effectiveUserID = effectiveUserID
        self.auditSessionIdentifier = UInt32(auditSessionIdentifier)
    }
}

/// The injectable boundary around the Foundation/macOS connection API.
public protocol NativeAgentAuthenticatedHostConnectionAttributeSource: Sendable {
    func attributes(for connection: NSXPCConnection) throws -> NativeAgentAuthenticatedHostConnectionAttributes
}

/// Production adapter for the public `NSXPCConnection` security attributes.
///
/// `not_proven`: this adapter has not and cannot, through the public NSXPC
/// API alone, prove possession of the complete live `audit_token_t`. A raw
/// audit-token source would require a transport/API boundary that actually
/// supplies that token (for example, a lower-level XPC integration). Until
/// such a source is wired, the Core's full-token adapter remains covered by
/// injected tests only and is not claimed as live production evidence.
public struct NativeAgentAuthenticatedHostNSXPCConnectionAttributeSource: NativeAgentAuthenticatedHostConnectionAttributeSource {
    public init() {}

    public func attributes(for connection: NSXPCConnection) throws -> NativeAgentAuthenticatedHostConnectionAttributes {
        guard let effectiveUserID = UInt32(exactly: connection.effectiveUserIdentifier),
              let auditSessionIdentifier = UInt64(exactly: connection.auditSessionIdentifier) else {
            throw NativeAgentAuthenticatedHostConnectionAttributeError.invalidConnectionAttributes
        }
        return try NativeAgentAuthenticatedHostConnectionAttributes(
            processIdentifier: connection.processIdentifier,
            effectiveUserID: effectiveUserID,
            auditSessionIdentifier: auditSessionIdentifier
        )
    }
}

/// Closure adapter used by injection tests and small service wiring seams.
public struct NativeAgentAuthenticatedHostClosureConnectionAttributeSource: NativeAgentAuthenticatedHostConnectionAttributeSource {
    public typealias Operation = @Sendable (NSXPCConnection) throws -> NativeAgentAuthenticatedHostConnectionAttributes

    private let operation: Operation

    public init(operation: @escaping Operation) {
        self.operation = operation
    }

    public func attributes(for connection: NSXPCConnection) throws -> NativeAgentAuthenticatedHostConnectionAttributes {
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
    public typealias PeerContextFactory = @Sendable (NativeAgentAuthenticatedHostConnectionAttributes, NativeProcessObservation) throws -> NativeConnectionContext
    public typealias ChildObservationFactory = @Sendable (Int32, UInt64) throws -> (NativeProcessObservation, Data)

    private let allowedClientUID: UInt32
    private let codeSigningRequirement: String
    private let peerPolicyFactory: @Sendable (NativeProcessObservation) throws -> NativeProcessIdentityPolicy
    private let childPolicy: NativeProcessIdentityPolicy?
    private let contextFactory: PeerContextFactory
    private let connectionAttributeSource: any NativeAgentAuthenticatedHostConnectionAttributeSource
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
        contextFactory: @escaping PeerContextFactory = { attributes, observation in
            try NativeConnectionContext(
                osProcessID: attributes.processIdentifier,
                effectiveUserID: attributes.effectiveUserID,
                auditSessionID: attributes.auditSessionIdentifier,
                pidVersion: observation.process.pidVersion
            )
        },
        connectionAttributeSource: any NativeAgentAuthenticatedHostConnectionAttributeSource = NativeAgentAuthenticatedHostNSXPCConnectionAttributeSource(),
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
        self.contextFactory = contextFactory
        self.connectionAttributeSource = connectionAttributeSource
        self.childFactory = childFactory
        self.signer = signer
        self.childRegistrar = childRegistrar
        self.childUnregistrar = childUnregistrar
        self.nowMilliseconds = nowMilliseconds
        super.init()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let attributeSource = connectionAttributeSource
        let initialAttributes: NativeAgentAuthenticatedHostConnectionAttributes
        do {
            initialAttributes = try attributeSource.attributes(for: connection)
        } catch {
            return false
        }
        guard initialAttributes.effectiveUserID == allowedClientUID else { return false }
        connection.setCodeSigningRequirement(codeSigningRequirement)

        let observer = NativeDarwinProcessObservationSource()
        do {
            let peerPID = initialAttributes.processIdentifier
            let peerUID = initialAttributes.effectiveUserID
            let connectionBox = NativeAgentAuthenticatedHostConnectionBox(connection)
            let contextFactory = self.contextFactory
            let initialObservation = try observer.observe(pid: peerPID, expectedUserID: peerUID)
            let context = try contextFactory(initialAttributes, initialObservation)
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
                    let currentAttributes = try attributeSource.attributes(for: connectionBox.connection)
                    guard currentAttributes.processIdentifier == peerPID,
                          currentAttributes.effectiveUserID == peerUID else {
                        throw NativeAgentAuthenticatedHostConnectionAttributeError.invalidConnectionAttributes
                    }
                    let current = try observer.observe(
                        pid: currentAttributes.processIdentifier,
                        expectedUserID: currentAttributes.effectiveUserID
                    )
                    return try contextFactory(currentAttributes, current)
                },
                observePeerProcess: {
                    let currentAttributes = try attributeSource.attributes(for: connectionBox.connection)
                    guard currentAttributes.processIdentifier == peerPID,
                          currentAttributes.effectiveUserID == peerUID else {
                        throw NativeAgentAuthenticatedHostConnectionAttributeError.invalidConnectionAttributes
                    }
                    return try observer.observe(
                        pid: currentAttributes.processIdentifier,
                        expectedUserID: currentAttributes.effectiveUserID
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
