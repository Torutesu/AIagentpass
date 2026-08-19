import Foundation
import AgentPassNativeCore

/// Service-side adapter for the dedicated Host Mach service.
///
/// This type deliberately keeps the OS boundary explicit: the caller must
/// provide independently observed child facts and a worktree binding digest.
/// If either dependency is unavailable, attach fails closed instead of using
/// request-supplied identity data.
public final class NativeAgentAuthenticatedHostListenerDelegate: NSObject, NSXPCListenerDelegate {
    public typealias PeerContextFactory = @Sendable (NSXPCConnection, NativeProcessObservation) throws -> NativeConnectionContext
    public typealias ChildObservationFactory = @Sendable (Int32, UInt64) throws -> (NativeProcessObservation, Data)

    private let allowedClientUID: UInt32
    private let codeSigningRequirement: String
    private let peerPolicyFactory: @Sendable (NativeProcessObservation) throws -> NativeProcessIdentityPolicy
    private let childPolicy: NativeProcessIdentityPolicy?
    private let contextFactory: PeerContextFactory
    private let childFactory: ChildObservationFactory?
    private let signer: any NativeAgentAuthenticatedHostSigning
    private let nowMilliseconds: NativeAgentAuthenticatedHostEndpoint.MillisecondClock
    private let endpointLock = NSLock()
    private var endpoints: [ObjectIdentifier: NativeAgentAuthenticatedHostEndpoint] = [:]

    public init(
        allowedClientUID: UInt32,
        codeSigningRequirement: String,
        peerPolicyFactory: @escaping @Sendable (NativeProcessObservation) throws -> NativeProcessIdentityPolicy,
        childPolicy: NativeProcessIdentityPolicy?,
        contextFactory: @escaping PeerContextFactory = { connection, observation in
            try NativeConnectionContext(
                osProcessID: connection.processIdentifier,
                effectiveUserID: connection.effectiveUserIdentifier,
                auditSessionID: UInt32(exactly: connection.auditSessionIdentifier) ?? 0,
                pidVersion: observation.process.pidVersion
            )
        },
        childFactory: ChildObservationFactory?,
        signer: any NativeAgentAuthenticatedHostSigning,
        nowMilliseconds: @escaping NativeAgentAuthenticatedHostEndpoint.MillisecondClock = {
            Int64(Date().timeIntervalSince1970 * 1_000)
        }
    ) {
        self.allowedClientUID = allowedClientUID
        self.codeSigningRequirement = codeSigningRequirement
        self.peerPolicyFactory = peerPolicyFactory
        self.childPolicy = childPolicy
        self.contextFactory = contextFactory
        self.childFactory = childFactory
        self.signer = signer
        self.nowMilliseconds = nowMilliseconds
        super.init()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier == allowedClientUID,
              connection.processIdentifier > 0,
              connection.auditSessionIdentifier > 0 else { return false }
        connection.setCodeSigningRequirement(codeSigningRequirement)

        let observer = NativeDarwinProcessObservationSource()
        do {
            let peerPID = connection.processIdentifier
            let peerUID = allowedClientUID
            let peerAuditSession = UInt32(exactly: connection.auditSessionIdentifier) ?? 0
            let initialObservation = try observer.observe(pid: peerPID, expectedUserID: peerUID)
            let context = try contextFactory(connection, initialObservation)
            let peerPolicy = try peerPolicyFactory(initialObservation)
            guard let childFactory, let childPolicy else {
                // The Host surface is not usable until child provenance and
                // worktree binding are configured. Never expose a weak mode.
                return false
            }
            let endpoint = try NativeAgentAuthenticatedHostEndpoint(
                connectionContext: context,
                initialPeerObservation: initialObservation,
                peerProcessPolicy: peerPolicy,
                childProcessPolicy: childPolicy,
                observeConnectionContext: {
                    let current = try observer.observe(pid: peerPID, expectedUserID: peerUID)
                    return try NativeConnectionContext(
                        osProcessID: peerPID,
                        effectiveUserID: peerUID,
                        auditSessionID: peerAuditSession,
                        pidVersion: current.process.pidVersion
                    )
                },
                observePeerProcess: {
                    try observer.observe(pid: peerPID, expectedUserID: peerUID)
                },
                observeChild: { pid, pidVersion in
                    let (childObservation, worktreeDigest) = try childFactory(pid, pidVersion)
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
                nowMilliseconds: nowMilliseconds
            )
            connection.exportedInterface = AgentPassHostXPCInterface.make()
            connection.exportedObject = endpoint
            let key = ObjectIdentifier(connection)
            endpointLock.lock()
            endpoints[key] = endpoint
            endpointLock.unlock()
            connection.invalidationHandler = { [weak self, weak endpoint, weak connection] in
                _ = endpoint?.closeHostSession(AgentPassHostCloseRequest(reason: .clientShutdown)!, withReply: { _, _ in })
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
