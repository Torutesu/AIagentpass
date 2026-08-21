import CryptoKit
import Foundation

public enum NativeSigningTransactionError: String, Error, Equatable, Sendable {
    case invalidPath = "invalid_path"
    case invalidRequest = "invalid_request"
    case invalidAuthority = "invalid_authority"
    case invalidState = "invalid_state"
    case requestConflict = "request_conflict"
    case phaseConflict = "phase_conflict"
    case authorityConflict = "authority_conflict"
    case capacityExceeded = "capacity_exceeded"
    case uncertain = "signing_outcome_unknown"
}

/// The only request identity accepted by the native durable sign-once ledger.
/// The operation is fixed here and cannot be selected by a caller.
public struct NativeSigningTransactionRequest: Equatable, Sendable {
    public static let operation = "git.commit.sign"

    public let requestID: String
    public let sessionID: String
    public let capabilityID: String
    public let capabilityHash: String
    public let payloadHash: String
    public let requestDigest: String
    public let nonceHash: String
    public let createdAtMilliseconds: Int64

    public init(_ request: AgentPassAgentSignRequest) throws {
        guard Self.uuid(request.requestID), Self.uuid(request.sessionID),
              Self.uuid(request.capabilityID), !request.commitPayload.isEmpty,
              request.commitPayload.count <= AgentPassAgentSignRequest.maximumCommitPayloadBytes,
              (AgentPassAgentSignRequest.minimumNonceBytes...AgentPassAgentSignRequest.maximumNonceBytes).contains(request.requestNonce.count),
              request.createdAtMilliseconds >= 0 else {
            throw NativeSigningTransactionError.invalidRequest
        }
        let payloadHash = Self.hex(SHA256.hash(data: request.commitPayload))
        let capabilityHash = Self.hex(SHA256.hash(data: request.capability))
        let nonceHash = Self.hex(SHA256.hash(data: request.requestNonce))
        let unsigned: [String: Any] = [
            "operation": Self.operation,
            "session_id": request.sessionID.lowercased(),
            "request_id": request.requestID.lowercased(),
            "capability_id": request.capabilityID.lowercased(),
            "capability_sha256": capabilityHash,
            "payload_sha256": payloadHash,
            "nonce_sha256": nonceHash,
            "created_at_ms": request.createdAtMilliseconds,
        ]
        guard let canonical = try? NativeStrictJSON.data(unsigned) else {
            throw NativeSigningTransactionError.invalidRequest
        }
        self.requestID = request.requestID.lowercased()
        self.sessionID = request.sessionID.lowercased()
        self.capabilityID = request.capabilityID.lowercased()
        self.capabilityHash = capabilityHash
        self.payloadHash = payloadHash
        self.nonceHash = nonceHash
        self.requestDigest = Self.hex(SHA256.hash(data: canonical))
        self.createdAtMilliseconds = request.createdAtMilliseconds
    }

    private static func uuid(_ value: String) -> Bool {
        value.utf8.count == 36 && UUID(uuidString: value) != nil
    }

    fileprivate static func hash(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}

/// Complete authority evidence captured from the OS/session snapshot before
/// the fixed provider is allowed to run. Paths and payloads are intentionally
/// represented only by digests in durable state.
public struct NativeSigningTransactionAuthority: Equatable, Sendable {
    public let sessionID: String
    public let agentID: String
    public let capabilityID: String
    public let processBindingHash: String
    public let ancestryBindingHash: String
    public let worktreeBindingHash: String
    public let repositoryIdentityHash: String
    public let branchPolicyHash: String
    public let remotePolicyHash: String
    public let controlSequence: Int64
    public let authorityGeneration: Int64
    public let keyGeneration: Int64
    public let keyLifecycleIdentity: String

    public init(
        request: NativeSigningTransactionRequest,
        binding: NativeAgentSessionBinding,
        worktree: NativeAgentWorktreeBinding,
        keyLifecycleIdentity: String
    ) throws {
        let repositoryIdentity = try NativeStrictJSON.data([
            "path": worktree.repositoryPath,
            "identity": Self.identityObject(worktree.repositoryIdentity),
        ])
        let branchPolicy = try NativeStrictJSON.data([
            "head_kind": worktree.headKind,
            "head": worktree.headValue,
            "object_id": worktree.headObjectID ?? NSNull(),
            "tree_id": worktree.headTreeID ?? NSNull(),
        ])
        let remotePolicy = try NativeStrictJSON.data([
            "remotes": worktree.remotes.map { ["name": $0.name, "url": $0.url] },
        ])
        let hashes = [
            Self.hex(binding.processBindingDigest),
            Self.hex(binding.ancestryBindingDigest),
            Self.hex(binding.worktreeBindingDigest),
            Self.hex(SHA256.hash(data: repositoryIdentity)),
            Self.hex(SHA256.hash(data: branchPolicy)),
            Self.hex(SHA256.hash(data: remotePolicy)),
            keyLifecycleIdentity,
        ]
        guard hashes.allSatisfy(NativeSigningTransactionRequest.hash) else {
            throw NativeSigningTransactionError.invalidAuthority
        }
        try self.init(
            sessionID: request.sessionID,
            agentID: binding.agentID,
            capabilityID: request.capabilityID,
            processBindingHash: hashes[0],
            ancestryBindingHash: hashes[1],
            worktreeBindingHash: hashes[2],
            repositoryIdentityHash: hashes[3],
            branchPolicyHash: hashes[4],
            remotePolicyHash: hashes[5],
            controlSequence: binding.controlSequence,
            authorityGeneration: binding.authorityGeneration,
            keyGeneration: binding.keyGeneration,
            keyLifecycleIdentity: hashes[6]
        )
    }

    private static func identityObject(_ identity: NativeAgentWorktreeDirectoryIdentity) -> [String: Any] {
        [
            "device": String(identity.device),
            "inode": String(identity.inode),
            "generation": identity.generation,
            "owner_user_id": identity.ownerUserID,
            "permissions": identity.permissions,
        ]
    }

    private static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        NativeSigningTransactionRequest.hex(digest)
    }
}

private extension NativeSigningTransactionAuthority {
    init(
        sessionID: String,
        agentID: String,
        capabilityID: String,
        processBindingHash: String,
        ancestryBindingHash: String,
        worktreeBindingHash: String,
        repositoryIdentityHash: String,
        branchPolicyHash: String,
        remotePolicyHash: String,
        controlSequence: Int64,
        authorityGeneration: Int64,
        keyGeneration: Int64,
        keyLifecycleIdentity: String
    ) throws {
        guard UUID(uuidString: sessionID) != nil,
              UUID(uuidString: agentID) != nil,
              UUID(uuidString: capabilityID) != nil,
              [processBindingHash, ancestryBindingHash, worktreeBindingHash,
               repositoryIdentityHash, branchPolicyHash, remotePolicyHash,
               keyLifecycleIdentity].allSatisfy(NativeSigningTransactionRequest.hash),
              controlSequence >= 1, authorityGeneration >= 1, keyGeneration >= 1 else {
            throw NativeSigningTransactionError.invalidAuthority
        }
        self.sessionID = sessionID.lowercased()
        self.agentID = agentID.lowercased()
        self.capabilityID = capabilityID.lowercased()
        self.processBindingHash = processBindingHash
        self.ancestryBindingHash = ancestryBindingHash
        self.worktreeBindingHash = worktreeBindingHash
        self.repositoryIdentityHash = repositoryIdentityHash
        self.branchPolicyHash = branchPolicyHash
        self.remotePolicyHash = remotePolicyHash
        self.controlSequence = controlSequence
        self.authorityGeneration = authorityGeneration
        self.keyGeneration = keyGeneration
        self.keyLifecycleIdentity = keyLifecycleIdentity
    }
}

public struct NativeSigningTransactionRecord: Equatable, Sendable {
    public enum Phase: String, CaseIterable, Sendable {
        case admitted
        case intent
        case providerStarted = "provider_started"
        case signedVerified = "signed_verified"
        case completed
        case uncertain

        // Source compatibility for the earlier ledger API. New persistence
        // always uses the explicit names above.
        public static var signed: Self { .signedVerified }
        public static var complete: Self { .completed }
        public static var outcomeUnknown: Self { .uncertain }
    }

    public let requestID: String
    public let requestHash: String
    public let phase: Phase
    public let signature: String?
    public let agentID: String
    public let repository: String
    public let branch: String
    public let remote: String
    public let payloadHash: String
    public let authority: NativeSigningTransactionAuthority?
    public let budgetSequence: Int
    public let remainingSignatures: Int?
    public let stateSequence: Int
    public let previousPhase: Phase?
}

/// Durable sign-once ledger. Every provider invocation is preceded by a
/// fsynced `provider_started` record. Restart converts that state to terminal
/// `uncertain`, so an invocation whose result was not durably verified can
/// never be repeated. Only an exact completed request digest replays output.
public final class NativeSigningTransactionStore: @unchecked Sendable {
    private static let maximumRecords = 10_000
    private static let maximumBytes = 8 * 1024 * 1024
    private let path: String
    private let lock = NSLock()
    private var records: [String: NativeSigningTransactionRecord] = [:]

    public init(path: String) throws {
        guard path.hasPrefix("/"), URL(fileURLWithPath: path).standardizedFileURL.path == path else {
            throw NativeSigningTransactionError.invalidPath
        }
        self.path = path
        if FileManager.default.fileExists(atPath: path) {
            try load()
            if records.values.contains(where: { $0.phase == .providerStarted }) {
                for (id, old) in records where old.phase == .providerStarted {
                    records[id] = Self.next(old, phase: .uncertain, signature: nil, remaining: nil)
                }
                try persistLocked()
            }
        }
    }

    public func lookup(request: NativeSigningTransactionRequest) throws -> NativeSigningTransactionRecord? {
        try lock.withLock {
            guard let record = records[request.requestID] else { return nil }
            guard record.requestHash == request.requestDigest,
                  record.payloadHash == request.payloadHash,
                  record.authority?.sessionID == request.sessionID,
                  record.authority?.capabilityID == request.capabilityID else {
                throw NativeSigningTransactionError.requestConflict
            }
            return record
        }
    }

    /// Legacy management-endpoint lookup retained while the fixed Agent
    /// endpoint moves to the typed request above.
    public func lookup(requestData: Data) throws -> NativeSigningTransactionRecord? {
        let identity = try Self.requestIdentity(requestData)
        return try lock.withLock {
            guard let record = records[identity.id] else { return nil }
            guard record.requestHash == identity.hash else {
                throw AgentPassNativeError.unauthorizedClient("request_id_conflict")
            }
            return record
        }
    }

    @discardableResult
    public func admit(
        request: NativeSigningTransactionRequest,
        authority: NativeSigningTransactionAuthority,
        budgetSequence: Int = 1
    ) throws -> NativeSigningTransactionRecord {
        guard authority.sessionID == request.sessionID,
              authority.capabilityID == request.capabilityID,
              (1...64).contains(budgetSequence) else {
            throw NativeSigningTransactionError.invalidAuthority
        }
        return try lock.withLock {
            if let old = records[request.requestID] {
                guard old.requestHash == request.requestDigest else { throw NativeSigningTransactionError.requestConflict }
                guard old.authority == authority else { throw NativeSigningTransactionError.authorityConflict }
                throw NativeSigningTransactionError.phaseConflict
            }
            guard records.count < Self.maximumRecords else { throw NativeSigningTransactionError.capacityExceeded }
            let record = NativeSigningTransactionRecord(
                requestID: request.requestID, requestHash: request.requestDigest, phase: .admitted,
                signature: nil, agentID: authority.agentID, repository: "", branch: "", remote: "",
                payloadHash: request.payloadHash, authority: authority, budgetSequence: budgetSequence, remainingSignatures: nil,
                stateSequence: 1, previousPhase: nil)
            records[request.requestID] = record
            do { try persistLocked() } catch { records.removeValue(forKey: request.requestID); throw error }
            return record
        }
    }

    @discardableResult
    public func markIntent(requestID: String, authority: NativeSigningTransactionAuthority) throws -> NativeSigningTransactionRecord {
        try transition(requestID: requestID, from: [.admitted], to: .intent, authority: authority)
    }

    @discardableResult
    public func markProviderStarted(requestID: String) throws -> NativeSigningTransactionRecord {
        try transition(requestID: requestID, from: [.intent], to: .providerStarted)
    }

    @discardableResult
    public func recordVerified(requestID: String, signature: String) throws -> NativeSigningTransactionRecord {
        guard Self.validSignature(signature) else { throw NativeSigningTransactionError.invalidState }
        return try transition(requestID: requestID, from: [.providerStarted], to: .signedVerified, signature: signature)
    }

    @discardableResult
    public func complete(requestID: String, remainingSignatures: Int? = nil) throws -> NativeSigningTransactionRecord {
        try lock.withLock {
            guard let old = records[requestID] else { throw NativeSigningTransactionError.phaseConflict }
            if old.phase == .completed { return old }
            guard old.phase == .signedVerified, old.signature != nil else { throw NativeSigningTransactionError.phaseConflict }
            if let remainingSignatures { guard (0...64).contains(remainingSignatures) else { throw NativeSigningTransactionError.invalidState } }
            let next = Self.next(old, phase: .completed, signature: old.signature, remaining: remainingSignatures ?? old.remainingSignatures)
            records[requestID] = next
            do { try persistLocked() } catch { records[requestID] = old; throw error }
            return next
        }
    }

    @discardableResult
    public func markUncertain(requestID: String) throws -> NativeSigningTransactionRecord {
        try transition(requestID: requestID, from: [.admitted, .intent, .providerStarted, .signedVerified], to: .uncertain, signature: nil)
    }

    // Compatibility adapter for the prior management endpoint.
    @discardableResult
    public func begin(requestData: Data, authorized: AuthorizedSignRequest, payloadHash: String) throws -> NativeSigningTransactionRecord {
        let identity = try Self.requestIdentity(requestData)
        guard identity.id == authorized.requestID, NativeSigningTransactionRequest.hash(payloadHash) else {
            throw AgentPassNativeError.invalidConfiguration("Signing transaction evidence is invalid")
        }
        return try lock.withLock {
            if let old = records[identity.id] {
                guard old.requestHash == identity.hash else { throw AgentPassNativeError.unauthorizedClient("request_id_conflict") }
                return old
            }
            guard records.count < Self.maximumRecords else { throw AgentPassNativeError.unauthorizedClient("signing_transaction_capacity_exceeded") }
            let record = NativeSigningTransactionRecord(
                requestID: identity.id, requestHash: identity.hash, phase: .intent,
                signature: nil, agentID: authorized.agentID, repository: authorized.repository,
                branch: authorized.branch, remote: authorized.remote, payloadHash: payloadHash,
                authority: nil, budgetSequence: 1, remainingSignatures: nil, stateSequence: 1, previousPhase: nil)
            records[identity.id] = record
            do { try persistLocked() } catch { records.removeValue(forKey: identity.id); throw error }
            return record
        }
    }

    @discardableResult
    public func recordSigned(requestID: String, signature: String) throws -> NativeSigningTransactionRecord {
        guard Self.validSignature(signature) else { throw AgentPassNativeError.invalidConfiguration("Signing transaction signature is invalid") }
        return try transition(requestID: requestID, from: [.intent, .providerStarted], to: .signedVerified, signature: signature)
    }

    @discardableResult
    public func markOutcomeUnknown(requestID: String) throws -> NativeSigningTransactionRecord {
        try markUncertain(requestID: requestID)
    }

    private func transition(
        requestID: String,
        from allowed: Set<NativeSigningTransactionRecord.Phase>,
        to phase: NativeSigningTransactionRecord.Phase,
        authority: NativeSigningTransactionAuthority? = nil,
        signature: String? = nil
    ) throws -> NativeSigningTransactionRecord {
        try lock.withLock {
            guard let old = records[requestID], allowed.contains(old.phase) else { throw NativeSigningTransactionError.phaseConflict }
            if let authority, old.authority != authority { throw NativeSigningTransactionError.authorityConflict }
            let next = Self.next(old, phase: phase, signature: signature ?? old.signature, remaining: old.remainingSignatures)
            records[requestID] = next
            do { try persistLocked() } catch { records[requestID] = old; throw error }
            return next
        }
    }

    private func load() throws {
        let data = try nativeV2ReadFile(path, maxBytes: Self.maximumBytes)
        guard data.last == 0x0a else { throw NativeSigningTransactionError.invalidState }
        let payload = Data(data.dropLast())
        let object = try NativeStrictJSON.object(from: payload, maxBytes: Self.maximumBytes, maxDepth: 12)
        guard Set(object.keys) == ["version", "records"],
              let version = nativeInt(object["version"]), (version == 1 || version == 2),
              let values = object["records"] as? [[String: Any]], values.count <= Self.maximumRecords,
              try NativeStrictJSON.data(object) == payload else {
            throw NativeSigningTransactionError.invalidState
        }
        for value in values {
            let record = try version == 2 ? Self.decodeV2(value) : Self.decodeV1(value)
            guard records[record.requestID] == nil else { throw NativeSigningTransactionError.invalidState }
            records[record.requestID] = record
        }
    }

    private func persistLocked() throws {
        let values = records.values.sorted { $0.requestID < $1.requestID }.map(Self.encode)
        let data = try NativeStrictJSON.data(["version": 2, "records": values]) + Data("\n".utf8)
        guard data.count <= Self.maximumBytes else { throw NativeSigningTransactionError.capacityExceeded }
        try nativeV2AtomicWrite(path, data: data)
    }

    private static func encode(_ record: NativeSigningTransactionRecord) -> [String: Any] {
        [
            "request_id": record.requestID, "request_hash": record.requestHash,
            "phase": record.phase.rawValue, "signature": record.signature ?? NSNull(),
            "agent_id": record.agentID, "repository": record.repository,
            "branch": record.branch, "remote": record.remote, "payload_hash": record.payloadHash,
            "authority": record.authority.map(encode) ?? NSNull(),
            "budget_sequence": record.budgetSequence,
            "remaining_signatures": record.remainingSignatures ?? NSNull(),
            "state_sequence": record.stateSequence,
            "previous_phase": record.previousPhase?.rawValue ?? NSNull(),
        ]
    }

    private static func encode(_ authority: NativeSigningTransactionAuthority) -> [String: Any] {
        [
            "session_id": authority.sessionID, "agent_id": authority.agentID,
            "capability_id": authority.capabilityID,
            "process_binding_hash": authority.processBindingHash,
            "ancestry_binding_hash": authority.ancestryBindingHash,
            "worktree_binding_hash": authority.worktreeBindingHash,
            "repository_identity_hash": authority.repositoryIdentityHash,
            "branch_policy_hash": authority.branchPolicyHash,
            "remote_policy_hash": authority.remotePolicyHash,
            "control_sequence": authority.controlSequence,
            "authority_generation": authority.authorityGeneration,
            "key_generation": authority.keyGeneration,
            "key_lifecycle_identity": authority.keyLifecycleIdentity,
        ]
    }

    private static func decodeV2(_ value: [String: Any]) throws -> NativeSigningTransactionRecord {
        let keys: Set<String> = ["request_id", "request_hash", "phase", "signature", "agent_id", "repository", "branch", "remote", "payload_hash", "authority", "budget_sequence", "remaining_signatures", "state_sequence", "previous_phase"]
        guard Set(value.keys) == keys,
              let requestID = value["request_id"] as? String, UUID(uuidString: requestID) != nil,
              let requestHash = value["request_hash"] as? String, NativeSigningTransactionRequest.hash(requestHash),
              let phaseText = value["phase"] as? String, let phase = NativeSigningTransactionRecord.Phase(rawValue: phaseText),
              let signatureValue = value["signature"], let agentID = value["agent_id"] as? String,
              let repository = value["repository"] as? String, let branch = value["branch"] as? String,
              let remote = value["remote"] as? String, let payloadHash = value["payload_hash"] as? String,
              NativeSigningTransactionRequest.hash(payloadHash), let budget = nativeInt(value["budget_sequence"]), (1...64).contains(budget), let sequence = nativeInt(value["state_sequence"]),
              sequence >= 1 else {
            throw NativeSigningTransactionError.invalidState
        }
        let previous: NativeSigningTransactionRecord.Phase?
        if value["previous_phase"] is NSNull { previous = nil }
        else if let text = value["previous_phase"] as? String,
                let decoded = NativeSigningTransactionRecord.Phase(rawValue: text) { previous = decoded }
        else { throw NativeSigningTransactionError.invalidState }
        let remaining = decodeOptionalInt(value["remaining_signatures"])
        if !(value["remaining_signatures"] is NSNull) && remaining == nil { throw NativeSigningTransactionError.invalidState }
        guard UUID(uuidString: agentID) != nil || agentID.isEmpty else { throw NativeSigningTransactionError.invalidState }
        let authority: NativeSigningTransactionAuthority?
        if value["authority"] is NSNull { authority = nil }
        else if let object = value["authority"] as? [String: Any] { authority = try decodeAuthority(object) }
        else { throw NativeSigningTransactionError.invalidState }
        try validateEvidence(phase: phase, sequence: Int(sequence), previous: previous, signature: signatureValue, authority: authority)
        let signature = signatureValue is NSNull ? nil : signatureValue as? String
        return NativeSigningTransactionRecord(requestID: requestID.lowercased(), requestHash: requestHash, phase: phase, signature: signature, agentID: agentID.lowercased(), repository: repository, branch: branch, remote: remote, payloadHash: payloadHash, authority: authority, budgetSequence: Int(budget), remainingSignatures: remaining, stateSequence: Int(sequence), previousPhase: previous)
    }

    private static func decodeV1(_ value: [String: Any]) throws -> NativeSigningTransactionRecord {
        let keys: Set<String> = ["request_id", "request_hash", "phase", "signature", "agent_id", "repository", "branch", "remote", "payload_hash"]
        guard Set(value.keys) == keys,
              let requestID = value["request_id"] as? String, UUID(uuidString: requestID) != nil,
              let requestHash = value["request_hash"] as? String, NativeSigningTransactionRequest.hash(requestHash),
              let oldPhase = value["phase"] as? String, let agentID = value["agent_id"] as? String,
              UUID(uuidString: agentID) != nil, let repository = value["repository"] as? String,
              repository.hasPrefix("/"), let branch = value["branch"] as? String,
              let remote = value["remote"] as? String, let payloadHash = value["payload_hash"] as? String,
              NativeSigningTransactionRequest.hash(payloadHash) else { throw NativeSigningTransactionError.invalidState }
        let signatureValue = value["signature"]
        let signature = signatureValue is NSNull ? nil : signatureValue as? String
        let phase: NativeSigningTransactionRecord.Phase
        switch oldPhase {
        case "intent": phase = .uncertain // v1 did not separate provider_started.
        case "signed": phase = .signedVerified
        case "complete": phase = .completed
        case "outcome_unknown": phase = .uncertain
        default: throw NativeSigningTransactionError.invalidState
        }
        guard phase == .uncertain ? signature == nil : Self.validSignature(signature ?? "") else { throw NativeSigningTransactionError.invalidState }
        return NativeSigningTransactionRecord(requestID: requestID.lowercased(), requestHash: requestHash, phase: phase, signature: signature, agentID: agentID.lowercased(), repository: repository, branch: branch, remote: remote, payloadHash: payloadHash, authority: nil, budgetSequence: 1, remainingSignatures: nil, stateSequence: phase == .completed ? 5 : 4, previousPhase: phase == .uncertain ? .providerStarted : nil)
    }

    private static func decodeAuthority(_ value: [String: Any]) throws -> NativeSigningTransactionAuthority {
        let keys: Set<String> = ["session_id", "agent_id", "capability_id", "process_binding_hash", "ancestry_binding_hash", "worktree_binding_hash", "repository_identity_hash", "branch_policy_hash", "remote_policy_hash", "control_sequence", "authority_generation", "key_generation", "key_lifecycle_identity"]
        guard Set(value.keys) == keys,
              let sessionID = value["session_id"] as? String, UUID(uuidString: sessionID) != nil,
              let agentID = value["agent_id"] as? String, UUID(uuidString: agentID) != nil,
              let capabilityID = value["capability_id"] as? String, UUID(uuidString: capabilityID) != nil,
              let process = value["process_binding_hash"] as? String, NativeSigningTransactionRequest.hash(process),
              let ancestry = value["ancestry_binding_hash"] as? String, NativeSigningTransactionRequest.hash(ancestry),
              let worktree = value["worktree_binding_hash"] as? String, NativeSigningTransactionRequest.hash(worktree),
              let repository = value["repository_identity_hash"] as? String, NativeSigningTransactionRequest.hash(repository),
              let branch = value["branch_policy_hash"] as? String, NativeSigningTransactionRequest.hash(branch),
              let remote = value["remote_policy_hash"] as? String, NativeSigningTransactionRequest.hash(remote),
              let control = nativeInt(value["control_sequence"]), control >= 1,
              let generation = nativeInt(value["authority_generation"]), generation >= 1,
              let keyGeneration = nativeInt(value["key_generation"]), keyGeneration >= 1,
              let keyIdentity = value["key_lifecycle_identity"] as? String, NativeSigningTransactionRequest.hash(keyIdentity) else {
            throw NativeSigningTransactionError.invalidState
        }
        return try NativeSigningTransactionAuthority(
            sessionID: sessionID.lowercased(), agentID: agentID.lowercased(), capabilityID: capabilityID.lowercased(),
            processBindingHash: process, ancestryBindingHash: ancestry, worktreeBindingHash: worktree,
            repositoryIdentityHash: repository, branchPolicyHash: branch, remotePolicyHash: remote,
            controlSequence: control, authorityGeneration: generation, keyGeneration: keyGeneration,
            keyLifecycleIdentity: keyIdentity)
    }

    private static func validateEvidence(
        phase: NativeSigningTransactionRecord.Phase,
        sequence: Int,
        previous: NativeSigningTransactionRecord.Phase?,
        signature: Any,
        authority: NativeSigningTransactionAuthority?
    ) throws {
        guard authority != nil else {
            guard phase == .uncertain || phase == .signedVerified || phase == .completed else { throw NativeSigningTransactionError.invalidState }
            return
        }
        switch phase {
        case .admitted: guard sequence == 1, previous == nil, signature is NSNull else { throw NativeSigningTransactionError.invalidState }
        case .intent: guard sequence == 2, previous == .admitted, signature is NSNull else { throw NativeSigningTransactionError.invalidState }
        case .providerStarted: guard sequence == 3, previous == .intent, signature is NSNull else { throw NativeSigningTransactionError.invalidState }
        case .signedVerified: guard sequence == 4, previous == .providerStarted, let value = signature as? String, validSignature(value) else { throw NativeSigningTransactionError.invalidState }
        case .completed: guard sequence == 5, previous == .signedVerified, let value = signature as? String, validSignature(value) else { throw NativeSigningTransactionError.invalidState }
        case .uncertain:
            guard (sequence == 3 && previous == .intent) || (sequence == 4 && previous == .providerStarted) || (sequence == 5 && previous == .signedVerified), signature is NSNull else { throw NativeSigningTransactionError.invalidState }
        }
    }

    private static func decodeOptionalPhase(_ value: Any?) -> NativeSigningTransactionRecord.Phase? {
        if value is NSNull { return nil }
        guard let text = value as? String else { return nil }
        return NativeSigningTransactionRecord.Phase(rawValue: text)
    }

    private static func decodeOptionalInt(_ value: Any?) -> Int? {
        if value is NSNull { return nil }
        guard let number = nativeInt(value), (0...64).contains(number) else { return nil }
        return Int(number)
    }

    private static func next(_ old: NativeSigningTransactionRecord, phase: NativeSigningTransactionRecord.Phase, signature: String?, remaining: Int?) -> NativeSigningTransactionRecord {
        NativeSigningTransactionRecord(
            requestID: old.requestID, requestHash: old.requestHash, phase: phase,
            signature: signature, agentID: old.agentID, repository: old.repository,
            branch: old.branch, remote: old.remote, payloadHash: old.payloadHash,
            authority: old.authority, budgetSequence: old.budgetSequence, remainingSignatures: remaining,
            stateSequence: old.stateSequence + 1, previousPhase: old.phase)
    }

    private static func validSignature(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= AgentPassAgentSignResponse.maximumSignatureBytes
    }

    private static func requestIdentity(_ data: Data) throws -> (id: String, hash: String) {
        guard !data.isEmpty, data.count <= 12 * 1024 * 1024,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = object["request_id"] as? String, UUID(uuidString: id) != nil else {
            throw AgentPassNativeError.unauthorizedClient("request_id_invalid")
        }
        return (id.lowercased(), NativeSigningTransactionRequest.hex(SHA256.hash(data: data)))
    }
}
