import CryptoKit
import Foundation
import AgentPassNativeCore

public enum NativeAgentAuthenticatedChildGitError: String, Error, Equatable, Sendable, LocalizedError {
    case invalidRequest = "invalid_request"
    case childNotRegistered = "child_not_registered"
    case childIdentityChanged = "child_identity_changed"
    case worktreeChanged = "worktree_changed"
    case replay = "replay"
    case sequenceMismatch = "sequence_mismatch"
    case signerFailed = "signer_failed"
    case closed = "closed"

    public var errorDescription: String? { rawValue }
}

public protocol NativeAgentAuthenticatedChildSigning: Sendable {
    func signChildPayload(_ payload: Data) throws -> Data
}

public struct NativeAgentAuthenticatedChildClosureSigner: NativeAgentAuthenticatedChildSigning {
    private let operation: @Sendable (Data) throws -> Data

    public init(operation: @escaping @Sendable (Data) throws -> Data) {
        self.operation = operation
    }

    public func signChildPayload(_ payload: Data) throws -> Data {
        try operation(payload)
    }
}

/// Service-local, memory-only registration created by the authenticated Host
/// attach operation. The child must later connect with the same OS-observed
/// process binding and worktree digest; request DTOs cannot create entries.
public final class NativeAgentAuthenticatedChildGitSessionRegistry: @unchecked Sendable {
    private struct Entry {
        let sessionID: String
        let processBindingHash: String
        let ancestryBindingHash: String
        let pid: Int32
        let pidVersion: UInt64
        let worktreeBindingDigest: Data
        let signer: any NativeAgentAuthenticatedChildSigning
        let signatureBudget: NativeAgentSignatureBudgetLedger
        var consumedPayloadDigests: Set<Data>
        var closed: Bool
    }

    private let lock = NSLock()
    private var entries: [String: Entry] = [:]

    public init() {}

    public func register(
        sessionID: String,
        identity: NativeProcessIdentity,
        worktreeBindingDigest: Data,
        signer: any NativeAgentAuthenticatedChildSigning,
        signatureBudget: NativeAgentSignatureBudgetLedger
    ) throws {
        guard AgentPassHostXPCContract.isDigest(worktreeBindingDigest),
              signatureBudget.snapshot().remainingSignatures > 0,
              !sessionID.isEmpty else {
            throw NativeAgentAuthenticatedChildGitError.invalidRequest
        }
        let key = identity.canonicalBindingHash
        lock.lock()
        defer { lock.unlock() }
        guard entries[key] == nil else {
            throw NativeAgentAuthenticatedChildGitError.childNotRegistered
        }
        entries[key] = Entry(
            sessionID: sessionID,
            processBindingHash: key,
            ancestryBindingHash: identity.canonicalAncestryBindingHash,
            pid: identity.pid,
            pidVersion: identity.pidVersion,
            worktreeBindingDigest: worktreeBindingDigest,
            signer: signer,
            signatureBudget: signatureBudget,
            consumedPayloadDigests: [],
            closed: false
        )
    }

    public func unregister(identityBindingHash: String) {
        lock.lock()
        entries.removeValue(forKey: identityBindingHash)
        lock.unlock()
    }

    public func sign(
        identity: NativeProcessIdentity,
        worktreeBindingDigest: Data,
        request: AgentPassChildGitSignRequest
    ) throws -> (signature: Data, budget: NativeAgentSignatureBudgetLedger.Snapshot) {
        let key = identity.canonicalBindingHash
        let signer: any NativeAgentAuthenticatedChildSigning
        let signatureBudget: NativeAgentSignatureBudgetLedger
        lock.lock()
        guard var entry = entries[key] else {
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.childNotRegistered
        }
        guard !entry.closed else {
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.closed
        }
        guard entry.pid == identity.pid, entry.pidVersion == identity.pidVersion,
              entry.processBindingHash == identity.canonicalBindingHash,
              entry.ancestryBindingHash == identity.canonicalAncestryBindingHash else {
            entry.closed = true
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.childIdentityChanged
        }
        guard entry.worktreeBindingDigest == worktreeBindingDigest else {
            entry.closed = true
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.worktreeChanged
        }
        guard request.requestSequence == 1 else {
            entry.closed = true
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.sequenceMismatch
        }
        let payloadDigest = Data(SHA256.hash(data: request.commitPayload))
        guard !entry.consumedPayloadDigests.contains(payloadDigest) else {
            entry.closed = true
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.replay
        }
        signer = entry.signer
        signatureBudget = entry.signatureBudget
        let budget: NativeAgentSignatureBudgetLedger.Snapshot
        do {
            budget = try entry.signatureBudget.reserve()
        } catch NativeAgentSignatureBudgetError.exhausted {
            entry.closed = true
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.closed
        } catch {
            entry.closed = true
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.invalidRequest
        }
        entry.consumedPayloadDigests.insert(payloadDigest)
        if budget.remainingSignatures == 0 { entry.closed = true }
        entries[key] = entry
        lock.unlock()

        do {
            let signature = try signer.signChildPayload(request.commitPayload)
            guard !signature.isEmpty, signature.count <= AgentPassChildGitXPCContract.maximumSignatureBytes else {
                throw NativeAgentAuthenticatedChildGitError.signerFailed
            }
            return (signature, signatureBudget.snapshot())
        } catch let error as NativeAgentAuthenticatedChildGitError {
            closeEntry(for: key)
            throw error
        } catch {
            closeEntry(for: key)
            throw NativeAgentAuthenticatedChildGitError.signerFailed
        }
    }

    private func closeEntry(for bindingHash: String) {
        lock.lock()
        if var entry = entries[bindingHash] {
            entry.closed = true
            entries[bindingHash] = entry
        }
        lock.unlock()
    }
}

public final class NativeAgentAuthenticatedChildGitEndpoint: NSObject, AgentPassChildGitXPCProtocol {
    public typealias IdentityObserver = @Sendable () throws -> NativeProcessIdentity
    public typealias WorktreeDigestObserver = @Sendable () throws -> Data

    private let registry: NativeAgentAuthenticatedChildGitSessionRegistry
    private let identityObserver: IdentityObserver
    private let worktreeDigestObserver: WorktreeDigestObserver
    private let stateLock = NSLock()
    private var used = false

    public init(
        registry: NativeAgentAuthenticatedChildGitSessionRegistry,
        identityObserver: @escaping IdentityObserver,
        worktreeDigestObserver: @escaping WorktreeDigestObserver
    ) {
        self.registry = registry
        self.identityObserver = identityObserver
        self.worktreeDigestObserver = worktreeDigestObserver
        super.init()
    }

    public func signChildGitCommit(
        _ request: AgentPassChildGitSignRequest,
        withReply reply: @escaping (AgentPassChildGitSignResponse?, NSError?) -> Void
    ) {
        do {
            stateLock.lock()
            guard !used else {
                stateLock.unlock()
                throw NativeAgentAuthenticatedChildGitError.replay
            }
            used = true
            stateLock.unlock()
            let result = try registry.sign(
                identity: identityObserver(),
                worktreeBindingDigest: worktreeDigestObserver(),
                request: request
            )
            guard let response = AgentPassChildGitSignResponse(
                responseSequence: request.requestSequence,
                signature: result.signature,
                maxSignatures: result.budget.maxSignatures,
                usedSignatures: result.budget.usedSignatures,
                remainingSignatures: result.budget.remainingSignatures
            ) else { throw NativeAgentAuthenticatedChildGitError.signerFailed }
            reply(response, nil)
        } catch {
            reply(nil, NSError(
                domain: "com.agentpass.native-authenticated-child-git",
                code: Self.errorCode(error),
                userInfo: [NSLocalizedDescriptionKey: Self.stableCode(error)]
            ))
        }
    }

    private static func stableCode(_ error: Error) -> String {
        (error as? NativeAgentAuthenticatedChildGitError)?.rawValue ?? NativeAgentAuthenticatedChildGitError.invalidRequest.rawValue
    }

    private static func errorCode(_ error: Error) -> Int {
        switch error as? NativeAgentAuthenticatedChildGitError {
        case .childNotRegistered: return 2
        case .childIdentityChanged: return 3
        case .worktreeChanged: return 4
        case .replay: return 5
        case .sequenceMismatch: return 6
        case .signerFailed: return 7
        case .closed: return 8
        default: return 1
        }
    }
}

public final class NativeAgentAuthenticatedChildGitListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let allowedClientUID: UInt32
    private let codeSigningRequirement: String
    private let registry: NativeAgentAuthenticatedChildGitSessionRegistry
    private let worktreeObserver: NativeDarwinGitWorktreeObserver

    public init(
        allowedClientUID: UInt32,
        codeSigningRequirement: String,
        registry: NativeAgentAuthenticatedChildGitSessionRegistry,
        worktreeObserver: NativeDarwinGitWorktreeObserver = .init()
    ) {
        self.allowedClientUID = allowedClientUID
        self.codeSigningRequirement = codeSigningRequirement
        self.registry = registry
        self.worktreeObserver = worktreeObserver
        super.init()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier == allowedClientUID,
              connection.processIdentifier > 0 else { return false }
        connection.setCodeSigningRequirement(codeSigningRequirement)
        let peerPID = connection.processIdentifier
        let peerUID = allowedClientUID
        let processObserver = NativeDarwinProcessObservationSource()
        let worktreeObserver = self.worktreeObserver
        do {
            _ = try processObserver.observe(pid: peerPID, expectedUserID: peerUID)
            let endpoint = NativeAgentAuthenticatedChildGitEndpoint(
                registry: registry,
                identityObserver: {
                    try NativeProcessIdentity.capture(from: NativeDarwinProcessObservationSourceForPID(
                        pid: peerPID,
                        uid: peerUID
                    ))
                },
                worktreeDigestObserver: {
                    try worktreeObserver.observe(pid: peerPID, expectedUserID: peerUID).binding.digest
                }
            )
            connection.exportedInterface = AgentPassChildGitXPCInterface.make()
            connection.exportedObject = endpoint
            connection.invalidationHandler = { [weak endpoint] in _ = endpoint }
            connection.resume()
            return true
        } catch {
            return false
        }
    }
}

private struct NativeDarwinProcessObservationSourceForPID: NativeProcessObservationSource {
    let pid: Int32
    let uid: UInt32
    func observe() throws -> NativeProcessObservation {
        try NativeDarwinProcessObservationSource().observe(pid: pid, expectedUserID: uid)
    }
}
