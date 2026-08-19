import CryptoKit
import Foundation
import AgentPassNativeCore

public enum NativeAgentAuthenticatedChildGitError: String, Error, Equatable, Sendable, LocalizedError {
    case invalidRequest = "invalid_request"
    case childNotRegistered = "child_not_registered"
    case attachTicketMissing = "attach_ticket_missing"
    case attachTicketMismatch = "attach_ticket_mismatch"
    case attachTicketExpired = "attach_ticket_expired"
    case attachTicketReplay = "attach_ticket_replay"
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
    public struct AttachTicket: Equatable, Sendable {
        public let value: Data
        public let expiresAtMilliseconds: Int64

        fileprivate init(value: Data, expiresAtMilliseconds: Int64) {
            self.value = value
            self.expiresAtMilliseconds = expiresAtMilliseconds
        }
    }

    private struct Entry {
        let sessionID: String
        let processBindingHash: String
        let processFactsBindingHash: String
        let ancestryBindingHash: String
        let uid: UInt32
        let bootIdentity: String
        let pid: Int32
        let pidVersion: UInt64
        let worktreeBindingDigest: Data
        let sessionExpiresAtMilliseconds: Int64?
        let signer: any NativeAgentAuthenticatedChildSigning
        let signatureBudget: NativeAgentSignatureBudgetLedger
        var consumedPayloadDigests: Set<Data>
        var activeAttachTicketDigest: Data?
        var activeAttachTicketExpiresAtMilliseconds: Int64?
        var consumedAttachTicketDigests: Set<Data>
        var closed: Bool
    }

    public static let defaultAttachTicketLifetimeMilliseconds: Int64 = 30 * 1_000

    private let lock = NSLock()
    private let ticketFactory: @Sendable () -> Data
    private var entries: [String: Entry] = [:]

    public init(ticketFactory: @escaping @Sendable () -> Data = {
        Data(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })
    }) {
        self.ticketFactory = ticketFactory
    }

    public func register(
        sessionID: String,
        identity: NativeProcessIdentity,
        worktreeBindingDigest: Data,
        signer: any NativeAgentAuthenticatedChildSigning,
        signatureBudget: NativeAgentSignatureBudgetLedger,
        expiresAtMilliseconds: Int64? = nil,
        nowMilliseconds: Int64? = nil
    ) throws {
        guard AgentPassHostXPCContract.isDigest(worktreeBindingDigest),
              signatureBudget.snapshot().remainingSignatures > 0,
              !sessionID.isEmpty else {
            throw NativeAgentAuthenticatedChildGitError.invalidRequest
        }
        let now = nowMilliseconds ?? Self.currentMilliseconds()
        guard AgentPassHostXPCContract.isTimestamp(now) else {
            throw NativeAgentAuthenticatedChildGitError.invalidRequest
        }
        if let expiresAtMilliseconds {
            guard AgentPassHostXPCContract.isTimestamp(expiresAtMilliseconds), expiresAtMilliseconds > now else {
                throw NativeAgentAuthenticatedChildGitError.invalidRequest
            }
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
            processFactsBindingHash: identity.process.canonicalProcessBindingHash,
            ancestryBindingHash: identity.canonicalAncestryBindingHash,
            uid: identity.uid,
            bootIdentity: identity.bootIdentity,
            pid: identity.pid,
            pidVersion: identity.pidVersion,
            worktreeBindingDigest: worktreeBindingDigest,
            sessionExpiresAtMilliseconds: expiresAtMilliseconds,
            signer: signer,
            signatureBudget: signatureBudget,
            consumedPayloadDigests: [],
            activeAttachTicketDigest: nil,
            activeAttachTicketExpiresAtMilliseconds: nil,
            consumedAttachTicketDigests: [],
            closed: false
        )
    }

    public func unregister(identityBindingHash: String) {
        lock.lock()
        entries.removeValue(forKey: identityBindingHash)
        lock.unlock()
    }

    /// Issues one opaque ticket for a Git helper whose observed ancestry
    /// contains the exact supervised child process. The helper PID is never
    /// used as the registry key or as the authority identity.
    public func issueAttachTicket(
        helperIdentity: NativeProcessIdentity,
        worktreeBindingDigest: Data,
        nowMilliseconds: Int64
    ) throws -> AttachTicket {
        guard AgentPassHostXPCContract.isDigest(worktreeBindingDigest),
              AgentPassHostXPCContract.isTimestamp(nowMilliseconds) else {
            throw NativeAgentAuthenticatedChildGitError.invalidRequest
        }
        lock.lock()
        defer { lock.unlock() }

        let candidates = entries.keys.compactMap { key -> (String, Entry)? in
            guard let entry = entries[key],
                  entry.worktreeBindingDigest == worktreeBindingDigest,
                  Self.helperBelongsTo(entry: entry, helperIdentity: helperIdentity) else {
                return nil
            }
            return (key, entry)
        }
        guard candidates.count == 1 else {
            throw NativeAgentAuthenticatedChildGitError.childNotRegistered
        }
        let key = candidates[0].0
        var entry = candidates[0].1
        guard !entry.closed else {
            throw NativeAgentAuthenticatedChildGitError.closed
        }
        if let sessionExpiry = entry.sessionExpiresAtMilliseconds, nowMilliseconds >= sessionExpiry {
            entry.closed = true
            entries[key] = entry
            throw NativeAgentAuthenticatedChildGitError.attachTicketExpired
        }
        guard entry.activeAttachTicketDigest == nil else {
            throw NativeAgentAuthenticatedChildGitError.attachTicketReplay
        }
        let ticket = ticketFactory()
        guard ticket.count == AgentPassChildGitXPCContract.attachTicketBytes,
              ticket.contains(where: { $0 != 0 }) else {
            entry.closed = true
            entries[key] = entry
            throw NativeAgentAuthenticatedChildGitError.invalidRequest
        }
        let digest = Data(SHA256.hash(data: ticket))
        guard !entry.consumedAttachTicketDigests.contains(digest) else {
            entry.closed = true
            entries[key] = entry
            throw NativeAgentAuthenticatedChildGitError.attachTicketReplay
        }
        let ticketExpiry = min(
            entry.sessionExpiresAtMilliseconds ?? nowMilliseconds + Self.defaultAttachTicketLifetimeMilliseconds,
            nowMilliseconds + Self.defaultAttachTicketLifetimeMilliseconds
        )
        entry.activeAttachTicketDigest = digest
        entry.activeAttachTicketExpiresAtMilliseconds = ticketExpiry
        entries[key] = entry
        return AttachTicket(value: ticket, expiresAtMilliseconds: ticketExpiry)
    }

    public func sign(
        attachTicket: Data,
        helperIdentity: NativeProcessIdentity,
        worktreeBindingDigest: Data,
        request: AgentPassChildGitSignRequest,
        nowMilliseconds: Int64
    ) throws -> (signature: Data, budget: NativeAgentSignatureBudgetLedger.Snapshot) {
        guard attachTicket.count == AgentPassChildGitXPCContract.attachTicketBytes,
              attachTicket.contains(where: { $0 != 0 }),
              request.attachTicket == attachTicket,
              AgentPassHostXPCContract.isDigest(worktreeBindingDigest),
              AgentPassHostXPCContract.isTimestamp(nowMilliseconds) else {
            throw NativeAgentAuthenticatedChildGitError.attachTicketMissing
        }
        let ticketDigest = Data(SHA256.hash(data: attachTicket))
        let signer: any NativeAgentAuthenticatedChildSigning
        let signatureBudget: NativeAgentSignatureBudgetLedger
        lock.lock()
        let matching = entries.keys.compactMap { key -> (String, Entry)? in
            guard let entry = entries[key],
                  entry.activeAttachTicketDigest == ticketDigest || entry.consumedAttachTicketDigests.contains(ticketDigest) else {
                return nil
            }
            return (key, entry)
        }
        guard matching.count == 1 else {
            lock.unlock()
            throw matching.isEmpty
                ? NativeAgentAuthenticatedChildGitError.attachTicketMissing
                : NativeAgentAuthenticatedChildGitError.attachTicketReplay
        }
        let key = matching[0].0
        var entry = matching[0].1
        guard !entry.closed else {
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.closed
        }
        if let sessionExpiry = entry.sessionExpiresAtMilliseconds, nowMilliseconds >= sessionExpiry {
            entry.closed = true
            entry.activeAttachTicketDigest = nil
            entry.activeAttachTicketExpiresAtMilliseconds = nil
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.attachTicketExpired
        }
        guard entry.activeAttachTicketDigest == ticketDigest else {
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.attachTicketReplay
        }
        guard let ticketExpiry = entry.activeAttachTicketExpiresAtMilliseconds,
              nowMilliseconds < ticketExpiry else {
            entry.closed = true
            entry.activeAttachTicketDigest = nil
            entry.activeAttachTicketExpiresAtMilliseconds = nil
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.attachTicketExpired
        }
        guard Self.helperBelongsTo(entry: entry, helperIdentity: helperIdentity) else {
            entry.closed = true
            entry.consumedAttachTicketDigests.insert(ticketDigest)
            entry.activeAttachTicketDigest = nil
            entry.activeAttachTicketExpiresAtMilliseconds = nil
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.childIdentityChanged
        }
        guard entry.worktreeBindingDigest == worktreeBindingDigest else {
            entry.closed = true
            entry.consumedAttachTicketDigests.insert(ticketDigest)
            entry.activeAttachTicketDigest = nil
            entry.activeAttachTicketExpiresAtMilliseconds = nil
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.worktreeChanged
        }
        guard request.requestSequence == 1 else {
            entry.closed = true
            entry.consumedAttachTicketDigests.insert(ticketDigest)
            entry.activeAttachTicketDigest = nil
            entry.activeAttachTicketExpiresAtMilliseconds = nil
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.sequenceMismatch
        }
        let payloadDigest = Data(SHA256.hash(data: request.commitPayload))
        guard !entry.consumedPayloadDigests.contains(payloadDigest) else {
            entry.closed = true
            entry.consumedAttachTicketDigests.insert(ticketDigest)
            entry.activeAttachTicketDigest = nil
            entry.activeAttachTicketExpiresAtMilliseconds = nil
            entries[key] = entry
            lock.unlock()
            throw NativeAgentAuthenticatedChildGitError.replay
        }
        entry.activeAttachTicketDigest = nil
        entry.activeAttachTicketExpiresAtMilliseconds = nil
        entry.consumedAttachTicketDigests.insert(ticketDigest)
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

    private static func helperBelongsTo(
        entry: Entry,
        helperIdentity: NativeProcessIdentity
    ) -> Bool {
        guard helperIdentity.pid != entry.pid || helperIdentity.pidVersion != entry.pidVersion,
              helperIdentity.uid == entry.uid,
              helperIdentity.bootIdentity == entry.bootIdentity else {
            return false
        }
        var found = false
        for ancestor in helperIdentity.ancestry {
            switch ancestor {
            case .unknown:
                return false
            case let .observed(facts):
                if facts.canonicalProcessBindingHash == entry.processFactsBindingHash {
                    found = true
                }
            }
        }
        return found
    }

    private static func currentMilliseconds() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1_000)
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
    public typealias MillisecondClock = @Sendable () -> Int64

    private let registry: NativeAgentAuthenticatedChildGitSessionRegistry
    private let identityObserver: IdentityObserver
    private let worktreeDigestObserver: WorktreeDigestObserver
    private let nowMilliseconds: MillisecondClock
    private let stateLock = NSLock()
    private var attachTicket: Data?
    private var used = false

    public init(
        registry: NativeAgentAuthenticatedChildGitSessionRegistry,
        identityObserver: @escaping IdentityObserver,
        worktreeDigestObserver: @escaping WorktreeDigestObserver,
        nowMilliseconds: @escaping MillisecondClock = {
            Int64(Date().timeIntervalSince1970 * 1_000)
        }
    ) {
        self.registry = registry
        self.identityObserver = identityObserver
        self.worktreeDigestObserver = worktreeDigestObserver
        self.nowMilliseconds = nowMilliseconds
        super.init()
    }

    public func attachChildGit(
        _ request: AgentPassChildGitAttachRequest,
        withReply reply: @escaping (AgentPassChildGitAttachResponse?, NSError?) -> Void
    ) {
        do {
            stateLock.lock()
            defer { stateLock.unlock() }
            guard request.protocolVersion == AgentPassChildGitXPCContract.protocolVersion,
                  attachTicket == nil, !used else {
                throw NativeAgentAuthenticatedChildGitError.attachTicketReplay
            }
            let ticket = try registry.issueAttachTicket(
                helperIdentity: identityObserver(),
                worktreeBindingDigest: worktreeDigestObserver(),
                nowMilliseconds: nowMilliseconds()
            )
            attachTicket = ticket.value
            guard let response = AgentPassChildGitAttachResponse(
                attachTicket: ticket.value,
                expiresAtMilliseconds: ticket.expiresAtMilliseconds
            ) else {
                throw NativeAgentAuthenticatedChildGitError.invalidRequest
            }
            reply(response, nil)
        } catch {
            reply(nil, Self.makeError(error))
        }
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
            guard let attachTicket else {
                stateLock.unlock()
                throw NativeAgentAuthenticatedChildGitError.attachTicketMissing
            }
            guard request.attachTicket == attachTicket else {
                stateLock.unlock()
                throw NativeAgentAuthenticatedChildGitError.attachTicketMismatch
            }
            stateLock.unlock()
            let result = try registry.sign(
                attachTicket: attachTicket,
                helperIdentity: identityObserver(),
                worktreeBindingDigest: worktreeDigestObserver(),
                request: request,
                nowMilliseconds: nowMilliseconds()
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
            reply(nil, Self.makeError(error))
        }
    }

    private static func stableCode(_ error: Error) -> String {
        (error as? NativeAgentAuthenticatedChildGitError)?.rawValue ?? NativeAgentAuthenticatedChildGitError.invalidRequest.rawValue
    }

    private static func makeError(_ error: Error) -> NSError {
        NSError(
            domain: "com.agentpass.native-authenticated-child-git",
            code: errorCode(error),
            userInfo: [NSLocalizedDescriptionKey: stableCode(error)]
        )
    }

    private static func errorCode(_ error: Error) -> Int {
        switch error as? NativeAgentAuthenticatedChildGitError {
        case .childNotRegistered: return 2
        case .attachTicketMissing: return 3
        case .attachTicketMismatch: return 4
        case .attachTicketExpired: return 5
        case .attachTicketReplay: return 6
        case .childIdentityChanged: return 7
        case .worktreeChanged: return 8
        case .replay: return 9
        case .sequenceMismatch: return 10
        case .signerFailed: return 11
        case .closed: return 12
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
