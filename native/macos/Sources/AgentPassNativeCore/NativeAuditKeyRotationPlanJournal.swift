import CryptoKit
import Darwin
import Foundation

/// A byte-exact audit-key rotation plan retained before the first network request.
/// The embedded plan is reconstructed from the exact transition and retiring-key bytes,
/// so retry never signs, serializes, or otherwise changes the submitted artifact.
public struct NativeAuditKeyRotationPlanJournalPreparation: Equatable, Sendable {
    public let operationID: String
    public let fromGeneration: Int
    public let toGeneration: Int
    public let tenant: String
    public let plan: NativeAuditKeyRotationPlan
    public let preparedAt: String
    public let planHash: String

    public var transitionData: Data { plan.transitionData }
    public var retiringPublicKeyX963: Data { plan.retiringPublicKeyX963 }
}

public struct NativeAuditKeyRotationPlanJournalCompletion: Equatable, Sendable {
    public let preparation: NativeAuditKeyRotationPlanJournalPreparation
    /// SHA-256 receipt hash from the exact receipt durably accepted by
    /// `NativeAuditKeyTransitionStore`.
    public let transitionStoreReceiptHash: String
    public let completedAt: String
}

public struct NativeAuditKeyRotationPlanJournalStatus: Equatable, Sendable {
    public let completed: [NativeAuditKeyRotationPlanJournalCompletion]
    public let pending: NativeAuditKeyRotationPlanJournalPreparation?
    public var count: Int { completed.count }
}

/// Immutable prepare/completed WAL for audit-key rotation network submissions.
///
/// The first generation is intentionally not fixed. Once the first prepare is
/// completed, every subsequent plan must start at the prior `toGeneration`.
/// A separately fsync'd tip detects removal of an otherwise-valid tail record.
public final class NativeAuditKeyRotationPlanJournal: @unchecked Sendable {
    private static let maximumRecordBytes = 256 * 1024
    private static let maximumEntries = 1_000_000
    private static let tipName = "tip.json"

    private let rootPath: String
    private let rootDescriptor: Int32
    private let rootDevice: dev_t
    private let rootInode: ino_t
    private let tenant: String
    private let processLock = NSLock()

    public init(rootPath: String, tenant: String) throws {
        guard rootPath.hasPrefix("/"),
              tenant.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal path or tenant is invalid")
        }
        let canonical = try Self.realPath(rootPath)
        guard rootPath == canonical else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal path must not traverse symbolic links")
        }
        try Self.validateProtectedAncestors(canonical)
        let descriptor = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
            close(descriptor)
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal must be a private service-owned directory")
        }
        self.rootPath = canonical
        rootDescriptor = descriptor
        rootDevice = info.st_dev
        rootInode = info.st_ino
        self.tenant = tenant
        do {
            try withLock {
                let state = try readState(allowMissingTip: true)
                if !fileExists(Self.tipName) {
                    guard state.preparations.isEmpty, state.completions.isEmpty else {
                        throw AgentPassNativeError.invalidSignature("Audit-key rotation journal tip is missing")
                    }
                    try writeTip(state)
                } else {
                    try verifyOrRecoverTip(state)
                }
            }
        } catch {
            close(descriptor)
            throw error
        }
    }

    deinit { close(rootDescriptor) }

    /// Durably stores the exact plan before any network submission. Exact replay
    /// is idempotent; a different pending plan or historical UUID reuse is rejected.
    @discardableResult
    public func prepare(
        _ plan: NativeAuditKeyRotationPlan,
        preparedAt: String
    ) throws -> NativeAuditKeyRotationPlanJournalPreparation {
        let candidate = try Self.makePreparation(plan: plan, tenant: tenant, preparedAt: preparedAt)
        return try withLock {
            let state = try readVerifiedState()
            if let known = state.preparations[candidate.fromGeneration] {
                guard known == candidate else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation generation or operation UUID equivocates with journal history")
                }
                return known
            }
            guard state.pending == nil else {
                throw AgentPassNativeError.invalidSignature("A different audit-key rotation plan is already pending")
            }
            guard !state.preparations.values.contains(where: { $0.operationID == candidate.operationID }) else {
                throw AgentPassNativeError.invalidSignature("Audit-key rotation operation UUID reuse is forbidden")
            }
            if let latest = state.completed.last {
                guard candidate.fromGeneration == latest.preparation.toGeneration,
                      candidate.plan.transition.previousTransitionHash == latest.preparation.plan.transition.transitionHash,
                      candidate.plan.transition.previousTransitionReceiptHash == latest.transitionStoreReceiptHash else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation plan has a generation or transition-chain gap")
                }
            }
            try writeImmutable(name: Self.prepareName(candidate), data: try Self.encodePrepare(candidate))
            let updated = try readState(allowMissingTip: false)
            try writeTip(updated)
            return candidate
        }
    }

    /// Appends immutable completion evidence only for the exact pending plan.
    /// The supplied hash must be the receipt hash returned by the transition store.
    @discardableResult
    public func complete(
        _ preparation: NativeAuditKeyRotationPlanJournalPreparation,
        transitionStoreReceiptHash: String,
        completedAt: String
    ) throws -> NativeAuditKeyRotationPlanJournalCompletion {
        guard Self.isHash(transitionStoreReceiptHash), Self.validTimestamp(completedAt) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation completion fields are invalid")
        }
        let completion = NativeAuditKeyRotationPlanJournalCompletion(
            preparation: preparation,
            transitionStoreReceiptHash: transitionStoreReceiptHash,
            completedAt: completedAt
        )
        return try withLock {
            let state = try readVerifiedState()
            guard state.preparations[preparation.fromGeneration] == preparation else {
                throw AgentPassNativeError.invalidSignature("Audit-key rotation completion has no byte-exact prepared plan")
            }
            if let known = state.completions[preparation.fromGeneration] {
                guard known == completion else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation completion equivocates with durable receipt evidence")
                }
                return known
            }
            guard state.pending == preparation else {
                throw AgentPassNativeError.invalidSignature("Audit-key rotation completion is stale or out of order")
            }
            if let previous = state.completed.last {
                guard completion.preparation.fromGeneration == previous.preparation.toGeneration,
                      Self.date(completedAt)! >= Self.date(previous.completedAt)! else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation completion has a generation gap or time rollback")
                }
            }
            try writeImmutable(name: Self.completedName(preparation), data: try Self.encodeCompletion(completion))
            let updated = try readState(allowMissingTip: false)
            try writeTip(updated)
            return completion
        }
    }

    public func pending() throws -> NativeAuditKeyRotationPlanJournalPreparation? {
        try withLock { try readVerifiedState().pending }
    }

    public func status() throws -> NativeAuditKeyRotationPlanJournalStatus {
        try withLock {
            let state = try readVerifiedState()
            return NativeAuditKeyRotationPlanJournalStatus(completed: state.completed, pending: state.pending)
        }
    }

    private struct DiskState {
        let preparations: [Int: NativeAuditKeyRotationPlanJournalPreparation]
        let completions: [Int: NativeAuditKeyRotationPlanJournalCompletion]
        let completed: [NativeAuditKeyRotationPlanJournalCompletion]
        let pending: NativeAuditKeyRotationPlanJournalPreparation?
        let recordHashes: [String]
    }

    private struct Tip: Equatable {
        let tenant: String
        let recordCount: Int
        let firstGeneration: Int?
        let lastGeneration: Int?
        let pendingGeneration: Int?
        let latestRecordHash: String
    }

    private func readVerifiedState() throws -> DiskState {
        let state = try readState(allowMissingTip: false)
        try verifyOrRecoverTip(state)
        return state
    }

    private func readState(allowMissingTip: Bool) throws -> DiskState {
        try validateRootIdentity()
        let names = try directoryNames()
        if !allowMissingTip, !names.contains(Self.tipName) {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal tip is missing")
        }
        var preparations: [Int: NativeAuditKeyRotationPlanJournalPreparation] = [:]
        var completions: [Int: NativeAuditKeyRotationPlanJournalCompletion] = [:]
        var orderedHashes: [(Int, Int, String)] = []
        for name in names where name != Self.tipName {
            if let parsed = Self.parsePrepareName(name) {
                let data = try readPrivateFile(name, expectedMode: 0o400)
                let decoded = try Self.decodePrepare(data, tenant: tenant)
                guard decoded.fromGeneration == parsed.generation,
                      Self.hash(Data(decoded.operationID.utf8)) == parsed.operationHash,
                      preparations.updateValue(decoded, forKey: parsed.generation) == nil else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation prepare filename or generation is inconsistent")
                }
                orderedHashes.append((parsed.generation, 0, Self.hash(data)))
            } else if let generation = Self.parseCompletedName(name) {
                let data = try readPrivateFile(name, expectedMode: 0o400)
                let decoded = try Self.decodeCompletion(data, tenant: tenant)
                guard decoded.preparation.fromGeneration == generation,
                      completions.updateValue(decoded, forKey: generation) == nil else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation completion filename or generation is inconsistent")
                }
                orderedHashes.append((generation, 1, Self.hash(data)))
            } else {
                throw AgentPassNativeError.invalidSignature("Audit-key rotation journal contains an unknown entry")
            }
        }
        guard preparations.count + completions.count <= Self.maximumEntries else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal record limit exceeded")
        }
        guard Set(preparations.values.map(\.operationID)).count == preparations.count else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation operation UUID was reused")
        }
        let generations = preparations.keys.sorted()
        var completed: [NativeAuditKeyRotationPlanJournalCompletion] = []
        var pending: NativeAuditKeyRotationPlanJournalPreparation?
        for (offset, generation) in generations.enumerated() {
            let preparation = preparations[generation]!
            if offset > 0 {
                let previous = preparations[generations[offset - 1]]!
                guard generation == previous.toGeneration,
                      preparation.plan.transition.previousTransitionHash == previous.plan.transition.transitionHash else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation journal has a generation or transition hash gap")
                }
                guard let previousCompletion = completions[previous.fromGeneration],
                      preparation.plan.transition.previousTransitionReceiptHash == previousCompletion.transitionStoreReceiptHash else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation journal has a transition receipt-chain gap")
                }
            }
            if let completion = completions[generation] {
                guard completion.preparation == preparation, pending == nil else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation completion is orphaned or follows a pending plan")
                }
                if let latest = completed.last {
                    guard Self.date(completion.completedAt)! >= Self.date(latest.completedAt)! else {
                        throw AgentPassNativeError.invalidSignature("Audit-key rotation completion time moved backwards")
                    }
                }
                completed.append(completion)
            } else {
                guard pending == nil, offset == generations.count - 1 else {
                    throw AgentPassNativeError.invalidSignature("Audit-key rotation journal has multiple or non-terminal pending plans")
                }
                pending = preparation
            }
        }
        guard completions.keys.allSatisfy({ preparations[$0] != nil }) else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal has an orphan completion")
        }
        orderedHashes.sort { ($0.0, $0.1) < ($1.0, $1.1) }
        return DiskState(
            preparations: preparations, completions: completions, completed: completed, pending: pending,
            recordHashes: orderedHashes.map(\.2)
        )
    }

    private func verifyOrRecoverTip(_ state: DiskState) throws {
        let expected = Self.makeTip(state, tenant: tenant)
        let actual = try decodeTip(readPrivateFile(Self.tipName, expectedMode: 0o600))
        guard actual.tenant == tenant else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal crossed a tenant boundary")
        }
        if actual == expected { return }
        // A record is fsync'd before the tip replacement. Only one exact trailing
        // record may therefore be ahead after a crash; all other mismatches fail closed.
        guard actual == Self.tipBeforeLastRecord(state, tenant: tenant) else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal tip detects tampering or truncation")
        }
        try writeTip(state)
    }

    private static func tipBeforeLastRecord(_ state: DiskState, tenant: String) -> Tip {
        let records = orderedRecordKinds(state)
        let previous = Array(records.dropLast())
        return Tip(
            tenant: tenant,
            recordCount: previous.count,
            firstGeneration: previous.first?.generation,
            lastGeneration: previous.last?.generation,
            pendingGeneration: previous.last?.kind == 0 ? previous.last?.generation : nil,
            latestRecordHash: state.recordHashes.dropLast().last ?? String(repeating: "0", count: 64)
        )
    }

    private static func orderedRecordKinds(_ state: DiskState) -> [(generation: Int, kind: Int)] {
        state.preparations.keys.sorted().flatMap { generation in
            state.completions[generation] == nil ? [(generation, 0)] : [(generation, 0), (generation, 1)]
        }
    }

    private func writeTip(_ state: DiskState) throws {
        let data = try Self.encodeTip(Self.makeTip(state, tenant: tenant))
        let temporary = ".tip-\(UUID().uuidString).tmp"
        let descriptor = openat(rootDescriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Self.posixError() }
        var cleanup = true
        defer { close(descriptor); if cleanup { unlinkat(rootDescriptor, temporary, 0) } }
        try Self.writeAll(data, descriptor)
        guard fchmod(descriptor, 0o600) == 0, fsync(descriptor) == 0 else { throw Self.posixError() }
        try validateDescriptor(descriptor, expectedMode: 0o600)
        try validateRootIdentity()
        guard renameat(rootDescriptor, temporary, rootDescriptor, Self.tipName) == 0 else { throw Self.posixError() }
        cleanup = false
        try validatePathIdentity(Self.tipName, descriptor: descriptor)
        guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
        try validateRootIdentity()
    }

    private func writeImmutable(name: String, data: Data) throws {
        guard !data.isEmpty, data.count <= Self.maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal record is too large")
        }
        try validateRootIdentity()
        if fileExists(name) {
            guard try readPrivateFile(name, expectedMode: 0o400) == data else {
                throw AgentPassNativeError.invalidSignature("Refusing to overwrite an audit-key rotation journal record")
            }
            return
        }
        let temporary = ".record-\(UUID().uuidString).tmp"
        let descriptor = openat(rootDescriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw Self.posixError() }
        var cleanup = true
        defer { close(descriptor); if cleanup { unlinkat(rootDescriptor, temporary, 0) } }
        try Self.writeAll(data, descriptor)
        guard fchmod(descriptor, 0o400) == 0, fsync(descriptor) == 0 else { throw Self.posixError() }
        try validateDescriptor(descriptor, expectedMode: 0o400)
        guard renameatx_np(rootDescriptor, temporary, rootDescriptor, name, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST, try readPrivateFile(name, expectedMode: 0o400) == data { return }
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal destination exists or cannot be committed")
        }
        cleanup = false
        try validatePathIdentity(name, descriptor: descriptor)
        guard fsync(rootDescriptor) == 0 else { throw Self.posixError() }
        try validateRootIdentity()
    }

    private static func makePreparation(plan: NativeAuditKeyRotationPlan, tenant: String, preparedAt: String) throws -> NativeAuditKeyRotationPlanJournalPreparation {
        let exact = try NativeAuditKeyRotationPlan(transitionData: plan.transitionData, retiringPublicKeyX963: plan.retiringPublicKeyX963, lifecycleRecordData: plan.lifecycleRecordData)
        guard exact == plan, plan.transition.tenant == tenant,
              isOperationID(plan.transition.operationID),
              plan.transition.fromGeneration > 0,
              plan.transition.toGeneration == plan.transition.fromGeneration + 1,
              validTimestamp(preparedAt) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation plan journal fields are invalid")
        }
        return NativeAuditKeyRotationPlanJournalPreparation(
            operationID: plan.transition.operationID, fromGeneration: plan.transition.fromGeneration,
            toGeneration: plan.transition.toGeneration, tenant: tenant, plan: plan,
            preparedAt: preparedAt, planHash: hash(planBytes(plan))
        )
    }

    private static func planBytes(_ plan: NativeAuditKeyRotationPlan) -> Data {
        var data = Data()
        var transitionLength = UInt64(plan.transitionData.count).bigEndian
        withUnsafeBytes(of: &transitionLength) { data.append(contentsOf: $0) }
        data.append(plan.transitionData)
        var keyLength = UInt64(plan.retiringPublicKeyX963.count).bigEndian
        withUnsafeBytes(of: &keyLength) { data.append(contentsOf: $0) }
        data.append(plan.retiringPublicKeyX963)
        if let lifecycleRecordData = plan.lifecycleRecordData {
            var lifecycleLength = UInt64(lifecycleRecordData.count).bigEndian
            withUnsafeBytes(of: &lifecycleLength) { data.append(contentsOf: $0) }
            data.append(lifecycleRecordData)
        }
        return data
    }

    private static func encodePrepare(_ value: NativeAuditKeyRotationPlanJournalPreparation) throws -> Data {
        try encode(value, kind: "prepare", receiptHash: nil, completedAt: nil)
    }

    private static func encodeCompletion(_ value: NativeAuditKeyRotationPlanJournalCompletion) throws -> Data {
        try encode(value.preparation, kind: "completed", receiptHash: value.transitionStoreReceiptHash, completedAt: value.completedAt)
    }

    private static func encode(_ value: NativeAuditKeyRotationPlanJournalPreparation, kind: String, receiptHash: String?, completedAt: String?) throws -> Data {
        var object: [String: Any] = [
            "version": value.plan.lifecycleRecordData == nil ? 1 : 2, "record_kind": kind, "tenant": value.tenant,
            "operation_id": value.operationID,
            "from_generation": value.fromGeneration, "to_generation": value.toGeneration,
            "prepared_at": value.preparedAt, "transition_encoding": "base64",
            "transition_data": value.transitionData.base64EncodedString(),
            "transition_bytes": value.transitionData.count,
            "retiring_public_key_encoding": "x963-base64",
            "retiring_public_key_x963": value.retiringPublicKeyX963.base64EncodedString(),
            "retiring_public_key_bytes": value.retiringPublicKeyX963.count,
            "plan_hash": value.planHash
        ]
        if let lifecycleRecordData = value.plan.lifecycleRecordData {
            object["lifecycle_record_encoding"] = "base64"
            object["lifecycle_record_data"] = lifecycleRecordData.base64EncodedString()
            object["lifecycle_record_bytes"] = lifecycleRecordData.count
        }
        if let receiptHash, let completedAt {
            object["transition_store_receipt_hash"] = receiptHash
            object["completed_at"] = completedAt
        }
        object["record_hash"] = hash(try canonical(object))
        return try canonical(object)
    }

    private static func decodePrepare(_ data: Data, tenant: String) throws -> NativeAuditKeyRotationPlanJournalPreparation {
        let decoded = try decode(data, expectedKind: "prepare", tenant: tenant)
        guard decoded.receiptHash == nil, decoded.completedAt == nil else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation prepare contains completion evidence")
        }
        return decoded.preparation
    }

    private static func decodeCompletion(_ data: Data, tenant: String) throws -> NativeAuditKeyRotationPlanJournalCompletion {
        let decoded = try decode(data, expectedKind: "completed", tenant: tenant)
        guard let receiptHash = decoded.receiptHash, let completedAt = decoded.completedAt else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation completion evidence is missing")
        }
        return NativeAuditKeyRotationPlanJournalCompletion(preparation: decoded.preparation, transitionStoreReceiptHash: receiptHash, completedAt: completedAt)
    }

    private static func decode(_ data: Data, expectedKind: String, tenant: String) throws -> (preparation: NativeAuditKeyRotationPlanJournalPreparation, receiptHash: String?, completedAt: String?) {
        guard !data.isEmpty, data.count <= maximumRecordBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              try canonical(object) == data,
              let version = exactInteger(object["version"]), version == 1 || version == 2,
              object["record_kind"] as? String == expectedKind,
              object["tenant"] as? String == tenant,
              let operationText = object["operation_id"] as? String,
              isOperationID(operationText),
              let fromGeneration = exactInteger(object["from_generation"]),
              let toGeneration = exactInteger(object["to_generation"]),
              let preparedAt = object["prepared_at"] as? String,
              object["transition_encoding"] as? String == "base64",
              let transitionText = object["transition_data"] as? String,
              let transitionData = Data(base64Encoded: transitionText), transitionData.base64EncodedString() == transitionText,
              exactInteger(object["transition_bytes"]) == transitionData.count,
              object["retiring_public_key_encoding"] as? String == "x963-base64",
              let keyText = object["retiring_public_key_x963"] as? String,
              let key = Data(base64Encoded: keyText), key.base64EncodedString() == keyText,
              exactInteger(object["retiring_public_key_bytes"]) == key.count,
              let planHash = object["plan_hash"] as? String,
              let recordHash = object["record_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal record is not exact canonical schema")
        }
        var prepareKeys: Set<String> = ["version", "record_kind", "tenant", "operation_id", "from_generation", "to_generation", "prepared_at", "transition_encoding", "transition_data", "transition_bytes", "retiring_public_key_encoding", "retiring_public_key_x963", "retiring_public_key_bytes", "plan_hash", "record_hash"]
        var lifecycleRecordData: Data?
        if version == 2 {
            prepareKeys.formUnion(["lifecycle_record_encoding", "lifecycle_record_data", "lifecycle_record_bytes"])
            guard object["lifecycle_record_encoding"] as? String == "base64",
                  let text = object["lifecycle_record_data"] as? String,
                  let decoded = Data(base64Encoded: text), decoded.base64EncodedString() == text,
                  exactInteger(object["lifecycle_record_bytes"]) == decoded.count else {
                throw AgentPassNativeError.invalidSignature("Audit-key rotation lifecycle recovery record is invalid")
            }
            lifecycleRecordData = decoded
        }
        let completedKeys = prepareKeys.union(["transition_store_receipt_hash", "completed_at"])
        guard Set(object.keys) == (expectedKind == "prepare" ? prepareKeys : completedKeys) else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal record has unknown or missing fields")
        }
        var unhashed = object
        unhashed.removeValue(forKey: "record_hash")
        guard recordHash == hash(try canonical(unhashed)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal record hash is invalid")
        }
        let plan = try NativeAuditKeyRotationPlan(transitionData: transitionData, retiringPublicKeyX963: key, lifecycleRecordData: lifecycleRecordData)
        let preparation = try makePreparation(plan: plan, tenant: tenant, preparedAt: preparedAt)
        guard preparation.operationID == operationText, preparation.fromGeneration == fromGeneration,
              preparation.toGeneration == toGeneration, preparation.planHash == planHash else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal plan binding is invalid")
        }
        let receiptHash = object["transition_store_receipt_hash"] as? String
        let completedAt = object["completed_at"] as? String
        if expectedKind == "completed" {
            guard let receiptHash, isHash(receiptHash), let completedAt, validTimestamp(completedAt) else {
                throw AgentPassNativeError.invalidSignature("Audit-key rotation completion binding is invalid")
            }
        }
        return (preparation, receiptHash, completedAt)
    }

    private static func makeTip(_ state: DiskState, tenant: String) -> Tip {
        let ordered = orderedRecordKinds(state)
        return Tip(
            tenant: tenant, recordCount: state.recordHashes.count,
            firstGeneration: ordered.first?.generation, lastGeneration: ordered.last?.generation,
            pendingGeneration: state.pending?.fromGeneration,
            latestRecordHash: state.recordHashes.last ?? String(repeating: "0", count: 64)
        )
    }

    private static func encodeTip(_ tip: Tip) throws -> Data {
        var value: [String: Any] = [
            "version": 1, "tenant": tip.tenant, "record_count": tip.recordCount,
            "latest_record_hash": tip.latestRecordHash
        ]
        value["first_generation"] = tip.firstGeneration ?? NSNull()
        value["last_generation"] = tip.lastGeneration ?? NSNull()
        value["pending_generation"] = tip.pendingGeneration ?? NSNull()
        value["tip_hash"] = hash(try canonical(value))
        return try canonical(value)
    }

    private func decodeTip(_ data: Data) throws -> Tip {
        let keys: Set<String> = ["version", "tenant", "record_count", "first_generation", "last_generation", "pending_generation", "latest_record_hash", "tip_hash"]
        guard !data.isEmpty, data.count <= 4096,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == keys, try Self.canonical(object) == data,
              Self.exactInteger(object["version"]) == 1,
              let tipTenant = object["tenant"] as? String,
              let count = Self.exactInteger(object["record_count"]), count >= 0,
              let latestHash = object["latest_record_hash"] as? String, Self.isHash(latestHash),
              let tipHash = object["tip_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal tip is invalid")
        }
        var unhashed = object
        unhashed.removeValue(forKey: "tip_hash")
        guard tipHash == Self.hash(try Self.canonical(unhashed)) else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal tip hash is invalid")
        }
        func nullableInt(_ key: String) -> Int? {
            object[key] is NSNull ? nil : Self.exactInteger(object[key])
        }
        return Tip(tenant: tipTenant, recordCount: count, firstGeneration: nullableInt("first_generation"), lastGeneration: nullableInt("last_generation"), pendingGeneration: nullableInt("pending_generation"), latestRecordHash: latestHash)
    }

    private func readPrivateFile(_ name: String, expectedMode: mode_t) throws -> Data {
        guard !name.contains("/"), name.first != "." else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal filename is invalid")
        }
        try validateRootIdentity()
        let descriptor = openat(rootDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        defer { close(descriptor) }
        try validateDescriptor(descriptor, expectedMode: expectedMode)
        var before = stat()
        guard fstat(descriptor, &before) == 0, before.st_size > 0, before.st_size <= Self.maximumRecordBytes else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal record size is invalid")
        }
        var data = Data(count: Int(before.st_size))
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let amount = Darwin.read(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard amount > 0 else { throw Self.posixError() }
                offset += amount
            }
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0, before.st_dev == after.st_dev,
              before.st_ino == after.st_ino, before.st_size == after.st_size else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal record changed while being read")
        }
        try validateRootIdentity()
        try validatePathIdentity(name, descriptor: descriptor)
        return data
    }

    private func validateDescriptor(_ descriptor: Int32, expectedMode: mode_t) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(), info.st_mode & 0o777 == expectedMode, info.st_nlink == 1 else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal files must be private service-owned single-link regular files")
        }
    }

    private func validatePathIdentity(_ name: String, descriptor: Int32) throws {
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(descriptor, &descriptorInfo) == 0,
              fstatat(rootDescriptor, name, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
              (pathInfo.st_mode & S_IFMT) == S_IFREG,
              descriptorInfo.st_dev == pathInfo.st_dev, descriptorInfo.st_ino == pathInfo.st_ino else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal pathname was substituted")
        }
    }

    private func validateRootIdentity() throws {
        try Self.validateProtectedAncestors(rootPath)
        var descriptorInfo = stat()
        var pathInfo = stat()
        guard fstat(rootDescriptor, &descriptorInfo) == 0,
              descriptorInfo.st_dev == rootDevice, descriptorInfo.st_ino == rootInode,
              descriptorInfo.st_uid == geteuid(), descriptorInfo.st_mode & 0o777 == 0o700,
              lstat(rootPath, &pathInfo) == 0, (pathInfo.st_mode & S_IFMT) == S_IFDIR,
              pathInfo.st_dev == rootDevice, pathInfo.st_ino == rootInode else {
            throw AgentPassNativeError.invalidSignature("Audit-key rotation journal directory was substituted or made permissive")
        }
    }

    private func directoryNames() throws -> [String] {
        let names = try FileManager.default.contentsOfDirectory(atPath: rootPath)
        guard names.count <= Self.maximumEntries * 2 + 1 else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal record limit exceeded")
        }
        return names.sorted()
    }

    private func fileExists(_ name: String) -> Bool {
        var info = stat()
        return fstatat(rootDescriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        processLock.lock()
        defer { processLock.unlock() }
        guard flock(rootDescriptor, LOCK_EX) == 0 else { throw Self.posixError() }
        defer { flock(rootDescriptor, LOCK_UN) }
        return try body()
    }

    private static func prepareName(_ value: NativeAuditKeyRotationPlanJournalPreparation) -> String {
        String(format: "prepare-%020d-%@.json", value.fromGeneration, hash(Data(value.operationID.utf8)))
    }

    private static func completedName(_ value: NativeAuditKeyRotationPlanJournalPreparation) -> String {
        String(format: "completed-%020d.json", value.fromGeneration)
    }

    private static func parsePrepareName(_ name: String) -> (generation: Int, operationHash: String)? {
        guard let match = name.wholeMatch(of: /^prepare-([0-9]{20})-([0-9a-f]{64})\.json$/),
              let generation = Int(match.1) else { return nil }
        return (generation, String(match.2))
    }

    private static func parseCompletedName(_ name: String) -> Int? {
        guard let match = name.wholeMatch(of: /^completed-([0-9]{20})\.json$/) else { return nil }
        return Int(match.1)
    }

    private static func validateProtectedAncestors(_ path: String) throws {
        var current = "/"
        var root = stat()
        guard lstat(current, &root) == 0, (root.st_mode & S_IFMT) == S_IFDIR,
              root.st_uid == 0, root.st_mode & 0o022 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal filesystem root is not protected")
        }
        for component in path.split(separator: "/", omittingEmptySubsequences: true) {
            current = current == "/" ? "/\(component)" : "\(current)/\(component)"
            var info = stat()
            guard lstat(current, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
                  (info.st_uid == 0 || info.st_uid == geteuid()), info.st_mode & 0o022 == 0 else {
                throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal ancestors must be trusted non-writable directories without symlinks")
            }
        }
    }

    private static func realPath(_ path: String) throws -> String {
        guard let value = Darwin.realpath(path, nil) else { throw posixError() }
        defer { free(value) }
        return String(cString: value)
    }

    private static func exactInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, String(cString: number.objCType) == "q" else { return nil }
        return number.intValue
    }

    private static func validTimestamp(_ value: String) -> Bool {
        value.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", options: .regularExpression) != nil && date(value) != nil
    }

    private static func date(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }

    private static func isHash(_ value: String) -> Bool { value.wholeMatch(of: /^[0-9a-f]{64}$/) != nil }

    private static func isOperationID(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil
    }

    private static func canonical(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw AgentPassNativeError.invalidConfiguration("Audit-key rotation journal record is not JSON")
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func writeAll(_ data: Data, _ descriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let amount = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard amount > 0 else { throw posixError() }
                offset += amount
            }
        }
    }

    private static func posixError() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}
