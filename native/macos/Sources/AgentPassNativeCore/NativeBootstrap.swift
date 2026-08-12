import Foundation

public struct NativeBootstrapPlan: Sendable {
    public let role: NativeKeyRole
    public let generation: Int
    public let applicationTag: String
    public let fingerprint: String
    public let statement: NativeKeyTransitionStatement

    public init(role: NativeKeyRole, generation: Int, applicationTag: String, fingerprint: String, statement: NativeKeyTransitionStatement) {
        self.role = role
        self.generation = generation
        self.applicationTag = applicationTag
        self.fingerprint = fingerprint
        self.statement = statement
    }
}

/// Resumable state machine for first-install provisioning. It deliberately has no XPC or
/// ServiceManagement dependency so a separately code-signed, privileged bootstrap command can
/// run it before the production listener exists.
public final class NativeBootstrapCoordinator: @unchecked Sendable {
    private let store: NativeKeyLifecycleStore
    private let serviceKeys: any NativeLifecycleKeyProvider
    private let baseTags: [NativeKeyRole: String]
    private let pinTransaction: NativeLifecyclePinTransaction?
    private let now: @Sendable () -> Date
    private let lock = NSLock()

    public init(store: NativeKeyLifecycleStore, serviceKeys: any NativeLifecycleKeyProvider, baseTags: [NativeKeyRole: String], pinTransaction: NativeLifecyclePinTransaction? = nil, now: @escaping @Sendable () -> Date = Date.init) throws {
        guard NativeKeyRole.allCases.allSatisfy({ baseTags[$0]?.isEmpty == false }) else {
            throw AgentPassNativeError.invalidConfiguration("Bootstrap requires signing, audit, and approval base tags")
        }
        self.store = store
        self.serviceKeys = serviceKeys
        self.baseTags = baseTags
        self.pinTransaction = pinTransaction
        self.now = now
    }

    /// Records the client-owned, user-presence approval public key and returns the exact canonical
    /// statement that the client must sign. Repeating this operation with the same key is safe.
    public func prepareApproval(publicKeyX963: Data) throws -> NativeBootstrapPlan {
        lock.lock()
        defer { lock.unlock() }
        var state = try store.verify()
        guard state.active(for: .sessionApproval) == nil,
              state.active(for: .gitSigning) == nil,
              state.active(for: .auditCheckpoint) == nil,
              let base = baseTags[.sessionApproval] else {
            throw AgentPassNativeError.invalidConfiguration("Approval bootstrap is only valid before any authority is active")
        }
        let tag = "\(base).g1"
        if let staged = state.generation(1, for: .sessionApproval) {
            guard staged.status == .staged, staged.applicationTag == tag, staged.publicKeyX963 == publicKeyX963 else {
                throw AgentPassNativeError.invalidKey("Bootstrap approval key does not match the recorded staged generation")
            }
        } else {
            guard state.sequence == 0 else {
                throw AgentPassNativeError.invalidConfiguration("Bootstrap ledger contains an incomplete or unexpected record")
            }
            let timestamp = Self.timestamp(now())
            let newHead = try store.previewStageHead(role: .sessionApproval, generation: 1, applicationTag: tag, publicKeyX963: publicKeyX963, createdAt: timestamp)
            let preparation = try preparePin(role: .sessionApproval, action: .staged, oldHead: state.headHash, newHead: newHead, preparedAt: timestamp)
            state = try store.stage(role: .sessionApproval, generation: 1, applicationTag: tag, publicKeyX963: publicKeyX963, createdAt: timestamp)
            try commitPin(preparation, oldHead: preparation?.oldLifecycleHead ?? NativeKeyLifecycleStore.zeroHash, newHead: state.headHash)
        }
        let statement = try store.transitionStatement(role: .sessionApproval, generation: 1, reason: "initial-provisioning", challengeID: "bootstrap-session-approval-g1", createdAt: Self.timestamp(now()), continuity: .bootstrap)
        return NativeBootstrapPlan(role: .sessionApproval, generation: 1, applicationTag: tag, fingerprint: NativeKeyLifecycleStore.fingerprint(publicKeyX963), statement: statement)
    }

    /// Activates the initial approval authority. The same user-presence key supplies both
    /// proof-of-possession and bootstrap authorization over the exact plan statement.
    @discardableResult
    public func commitApproval(plan: NativeBootstrapPlan, signature: Data) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        let state = try store.verify()
        if let active = state.active(for: .sessionApproval) {
            guard active.generation == plan.generation, active.fingerprint == plan.fingerprint else {
                throw AgentPassNativeError.invalidKey("A different approval authority is already active")
            }
            return state
        }
        try validate(plan: plan, role: .sessionApproval)
        guard let staged = state.generation(1, for: .sessionApproval), staged.status == .staged,
              staged.applicationTag == plan.applicationTag, staged.fingerprint == plan.fingerprint else {
            throw AgentPassNativeError.invalidConfiguration("Approval bootstrap plan is stale")
        }
        let newHead = try store.previewActivationHead(statement: plan.statement, oldSignature: nil, newSignature: signature, approvalSignature: signature, approvalPublicKeyX963: staged.publicKeyX963)
        let preparation = try preparePin(role: .sessionApproval, action: .activated, oldHead: state.headHash, newHead: newHead, preparedAt: plan.statement.createdAt)
        let next = try store.activate(statement: plan.statement, oldSignature: nil, newSignature: signature, approvalSignature: signature, approvalPublicKeyX963: staged.publicKeyX963)
        try commitPin(preparation, oldHead: state.headHash, newHead: next.headHash)
        return next
    }

    /// Creates or resumes one service-owned Secure Enclave generation and returns the exact
    /// statement that the already-active approval key must authorize.
    public func prepareServiceRole(_ role: NativeKeyRole) throws -> NativeBootstrapPlan {
        lock.lock()
        defer { lock.unlock() }
        guard role == .gitSigning || role == .auditCheckpoint, let base = baseTags[role] else {
            throw AgentPassNativeError.invalidConfiguration("Bootstrap service role is invalid")
        }
        var state = try store.verify()
        guard state.active(for: .sessionApproval) != nil, state.active(for: role) == nil else {
            throw AgentPassNativeError.invalidConfiguration("Service bootstrap requires an active approval authority and an inactive target role")
        }
        let tag = "\(base).g1"
        let key: any NativeLifecycleKeyHandle
        if let staged = state.generation(1, for: role) {
            guard staged.status == .staged, staged.applicationTag == tag else {
                throw AgentPassNativeError.invalidConfiguration("Bootstrap service generation is not resumable")
            }
            key = try serviceKeys.load(applicationTag: tag)
            guard key.publicKeyX963 == staged.publicKeyX963 else {
                throw AgentPassNativeError.invalidKey("Staged bootstrap key does not match its exact keychain binding")
            }
        } else {
            if try serviceKeys.exists(applicationTag: tag) {
                guard let pending = try pinTransaction?.pending(), pending.role == role,
                      pending.action == .staged, pending.oldLifecycleHead == state.headHash else {
                    throw AgentPassNativeError.invalidKey("Unrecorded bootstrap key already occupies the exact generation tag")
                }
                key = try serviceKeys.load(applicationTag: tag)
            } else {
                key = try serviceKeys.create(applicationTag: tag, requiresUserPresence: false)
            }
            do {
                let timestamp = Self.timestamp(now())
                let newHead = try store.previewStageHead(role: role, generation: 1, applicationTag: tag, publicKeyX963: key.publicKeyX963, createdAt: timestamp)
                let preparation = try preparePin(role: role, action: .staged, oldHead: state.headHash, newHead: newHead, preparedAt: timestamp)
                state = try store.stage(role: role, generation: 1, applicationTag: tag, publicKeyX963: key.publicKeyX963, createdAt: timestamp)
                try commitPin(preparation, oldHead: preparation?.oldLifecycleHead ?? NativeKeyLifecycleStore.zeroHash, newHead: state.headHash)
            } catch {
                let hasPendingPin = ((try? pinTransaction?.pending()) ?? nil) != nil
                if !hasPendingPin, let loaded = try? serviceKeys.load(applicationTag: tag), loaded.publicKeyX963 == key.publicKeyX963 {
                    try? serviceKeys.delete(applicationTag: tag)
                }
                throw error
            }
        }
        let statement = try store.transitionStatement(role: role, generation: 1, reason: "initial-provisioning", challengeID: "bootstrap-\(role.rawValue)-g1", createdAt: Self.timestamp(now()), continuity: .bootstrap)
        return NativeBootstrapPlan(role: role, generation: 1, applicationTag: tag, fingerprint: NativeKeyLifecycleStore.fingerprint(key.publicKeyX963), statement: statement)
    }

    @discardableResult
    public func commitServiceRole(plan: NativeBootstrapPlan, approvalSignature: Data, approvalPublicKeyX963: Data) throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        guard plan.role == .gitSigning || plan.role == .auditCheckpoint else {
            throw AgentPassNativeError.invalidConfiguration("Bootstrap service plan role is invalid")
        }
        let state = try store.verify()
        if let active = state.active(for: plan.role) {
            guard active.generation == plan.generation, active.fingerprint == plan.fingerprint else {
                throw AgentPassNativeError.invalidKey("A different service authority is already active")
            }
            return state
        }
        try validate(plan: plan, role: plan.role)
        guard let approval = state.active(for: .sessionApproval), approval.publicKeyX963 == approvalPublicKeyX963,
              let staged = state.generation(1, for: plan.role), staged.status == .staged,
              staged.applicationTag == plan.applicationTag, staged.fingerprint == plan.fingerprint else {
            throw AgentPassNativeError.invalidConfiguration("Service bootstrap plan is stale or uses a substituted approval key")
        }
        let key = try serviceKeys.load(applicationTag: staged.applicationTag)
        guard key.publicKeyX963 == staged.publicKeyX963 else {
            throw AgentPassNativeError.invalidKey("Bootstrap key no longer matches its exact keychain binding")
        }
        let message = try plan.statement.canonicalData()
        let newSignature = try key.sign(message: message)
        let newHead = try store.previewActivationHead(statement: plan.statement, oldSignature: nil, newSignature: newSignature, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963)
        let preparation = try preparePin(role: plan.role, action: .activated, oldHead: state.headHash, newHead: newHead, preparedAt: plan.statement.createdAt)
        let next = try store.activate(statement: plan.statement, oldSignature: nil, newSignature: newSignature, approvalSignature: approvalSignature, approvalPublicKeyX963: approvalPublicKeyX963)
        try commitPin(preparation, oldHead: state.headHash, newHead: next.headHash)
        return next
    }

    /// Returns a verified bootstrap-only snapshot, including an interrupted partial ceremony.
    /// This is the reconciliation boundary used by higher-level installers after a crash between
    /// a durable lifecycle mutation and their user-owned setup journal update.
    public func bootstrapSnapshot() throws -> NativeKeyLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        let state = try store.verify()
        guard (0...6).contains(state.sequence), state.generations.count <= 3,
              state.generations.allSatisfy({ generation in
                  generation.generation == 1 &&
                  generation.applicationTag == "\(baseTags[generation.role]!).g1" &&
                  (generation.status == .staged || generation.status == .active)
              }) else {
            throw AgentPassNativeError.invalidConfiguration("Bootstrap ledger contains non-bootstrap lifecycle state")
        }
        let approval = state.generation(1, for: .sessionApproval)
        let service = [NativeKeyRole.gitSigning, .auditCheckpoint].compactMap { state.generation(1, for: $0) }
        let activeServices = service.filter { $0.status == .active }.count
        let stagedServices = service.filter { $0.status == .staged }.count
        let legal: Bool
        switch state.sequence {
        case 0: legal = approval == nil && service.isEmpty
        case 1: legal = approval?.status == .staged && service.isEmpty
        case 2: legal = approval?.status == .active && service.isEmpty
        case 3: legal = approval?.status == .active && service.count == 1 && stagedServices == 1
        case 4: legal = approval?.status == .active && service.count == 1 && activeServices == 1
        case 5: legal = approval?.status == .active && service.count == 2 && activeServices == 1 && stagedServices == 1
        case 6: legal = approval?.status == .active && service.count == 2 && activeServices == 2
        default: legal = false
        }
        guard legal else {
            throw AgentPassNativeError.invalidConfiguration("Bootstrap ledger is not in a resumable ordered state")
        }
        return state
    }

    public func completedSnapshot() throws -> NativeKeyLifecycleSnapshot {
        let state = try bootstrapSnapshot()
        guard state.sequence == 6 else {
            throw AgentPassNativeError.invalidConfiguration("Bootstrap is incomplete")
        }
        return state
    }

    private func validate(plan: NativeBootstrapPlan, role: NativeKeyRole) throws {
        guard plan.role == role, plan.generation == 1, plan.statement.role == role,
              plan.statement.newGeneration == 1, plan.statement.continuity == .bootstrap,
              plan.statement.newFingerprint == plan.fingerprint,
              plan.statement.reason == "initial-provisioning" else {
            throw AgentPassNativeError.invalidSignature("Bootstrap plan fields are inconsistent")
        }
    }

    private func preparePin(role: NativeKeyRole, action: NativeLifecyclePinAction, oldHead: String, newHead: String, preparedAt: String) throws -> NativeLifecyclePinPreparation? {
        guard let pinTransaction else { return nil }
        if let pending = try pinTransaction.pending() {
            guard pending.role == role, pending.action == action,
                  pending.oldLifecycleHead == oldHead, pending.newLifecycleHead == newHead else {
                throw AgentPassNativeError.invalidSignature("Bootstrap mutation does not match its pending external pin")
            }
            return pending
        }
        let sequence = (try pinTransaction.current()?.sequence ?? 0) + 1
        return try pinTransaction.prepare(operationID: UUID(), sequence: sequence, role: role, action: action, oldLifecycleHead: oldHead, newLifecycleHead: newHead, preparedAt: preparedAt)
    }

    private func commitPin(_ preparation: NativeLifecyclePinPreparation?, oldHead: String, newHead: String) throws {
        guard let pinTransaction, let preparation else { return }
        _ = try pinTransaction.commit(preparation, observedOldLifecycleHead: oldHead, observedNewLifecycleHead: newHead)
    }

    private static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
