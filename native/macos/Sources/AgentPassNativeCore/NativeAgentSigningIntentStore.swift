import CoreFoundation
import Foundation

public enum NativeAgentSigningIntentStoreError: String, Error, Equatable, Sendable {
    case invalidPath = "invalid_path"
    case invalidEvidence = "invalid_evidence"
    case invalidState = "invalid_state"
    case requestConflict = "request_conflict"
    case phaseConflict = "phase_conflict"
    case capacityExceeded = "capacity_exceeded"
}

public struct NativeAgentSigningIntentEvidence: Equatable, Sendable {
    public let requestID: String
    public let sessionID: String
    public let capabilityID: String
    public let payloadHash: String
    public let processBindingHash: String
    public let ancestryBindingHash: String
    public let worktreeBindingHash: String
    public let keyGeneration: Int64
    public let controlSequence: Int64
    public let budgetSequence: Int

    public init(requestID: String, sessionID: String, capabilityID: String, payloadHash: String, processBindingHash: String, ancestryBindingHash: String, worktreeBindingHash: String, keyGeneration: Int64, controlSequence: Int64, budgetSequence: Int) throws {
        guard [requestID, sessionID, capabilityID].allSatisfy(Self.uuid),
              [payloadHash, processBindingHash, ancestryBindingHash, worktreeBindingHash].allSatisfy(Self.hash),
              keyGeneration >= 1, controlSequence >= 1, (1...64).contains(budgetSequence) else {
            throw NativeAgentSigningIntentStoreError.invalidEvidence
        }
        self.requestID = requestID.lowercased(); self.sessionID = sessionID.lowercased(); self.capabilityID = capabilityID.lowercased()
        self.payloadHash = payloadHash; self.processBindingHash = processBindingHash; self.ancestryBindingHash = ancestryBindingHash; self.worktreeBindingHash = worktreeBindingHash
        self.keyGeneration = keyGeneration; self.controlSequence = controlSequence; self.budgetSequence = budgetSequence
    }

    private static func uuid(_ value: String) -> Bool { value.utf8.count == 36 && UUID(uuidString: value) != nil }
    private static func hash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
}

public struct NativeAgentSigningIntentRecord: Equatable, Sendable {
    public enum Phase: String, CaseIterable, Sendable { case intent, signed, complete, outcomeUnknown = "outcome_unknown" }
    public let evidence: NativeAgentSigningIntentEvidence
    public let phase: Phase
    public let signatureHash: String?
}

/// Crash-safe forensic ledger for M2 key use. It stores hashes and public IDs,
/// never the commit payload or signature bytes. On restart unresolved intent is
/// made terminal before any record can be returned to a caller.
public final class NativeAgentSigningIntentStore: @unchecked Sendable {
    private static let maximumRecords = 10_000
    private static let maximumBytes = 8 * 1024 * 1024
    private let path: String
    private let lock = NSLock()
    private var records: [String: NativeAgentSigningIntentRecord] = [:]

    public init(path: String) throws {
        guard path.hasPrefix("/") else { throw NativeAgentSigningIntentStoreError.invalidPath }
        self.path = URL(fileURLWithPath: path).standardizedFileURL.path
        if FileManager.default.fileExists(atPath: self.path) {
            try load()
            if records.values.contains(where: { $0.phase == .intent }) {
                for (id, record) in records where record.phase == .intent {
                    records[id] = NativeAgentSigningIntentRecord(evidence: record.evidence, phase: .outcomeUnknown, signatureHash: nil)
                }
                try persistLocked()
            }
        }
    }

    public func lookup(requestID: String) throws -> NativeAgentSigningIntentRecord? {
        guard UUID(uuidString: requestID) != nil else { throw NativeAgentSigningIntentStoreError.invalidEvidence }
        return lock.withLock { records[requestID.lowercased()] }
    }

    @discardableResult
    public func begin(_ evidence: NativeAgentSigningIntentEvidence) throws -> NativeAgentSigningIntentRecord {
        try lock.withLock {
            if let old = records[evidence.requestID] {
                guard old.evidence == evidence else { throw NativeAgentSigningIntentStoreError.requestConflict }
                throw NativeAgentSigningIntentStoreError.phaseConflict
            }
            guard records.count < Self.maximumRecords else { throw NativeAgentSigningIntentStoreError.capacityExceeded }
            let record = NativeAgentSigningIntentRecord(evidence: evidence, phase: .intent, signatureHash: nil)
            records[evidence.requestID] = record
            do { try persistLocked() } catch { records.removeValue(forKey: evidence.requestID); throw error }
            return record
        }
    }

    @discardableResult
    public func recordSigned(requestID: String, signatureHash: String) throws -> NativeAgentSigningIntentRecord {
        guard Self.hash(signatureHash) else { throw NativeAgentSigningIntentStoreError.invalidEvidence }
        return try transition(requestID: requestID, from: .intent, to: .signed, signatureHash: signatureHash)
    }

    @discardableResult
    public func complete(requestID: String) throws -> NativeAgentSigningIntentRecord {
        try transition(requestID: requestID, from: .signed, to: .complete, signatureHash: nil)
    }

    @discardableResult
    public func markOutcomeUnknown(requestID: String) throws -> NativeAgentSigningIntentRecord {
        try transition(requestID: requestID, from: .intent, to: .outcomeUnknown, signatureHash: nil)
    }

    private func transition(requestID: String, from: NativeAgentSigningIntentRecord.Phase, to: NativeAgentSigningIntentRecord.Phase, signatureHash: String?) throws -> NativeAgentSigningIntentRecord {
        guard UUID(uuidString: requestID) != nil else { throw NativeAgentSigningIntentStoreError.invalidEvidence }
        return try lock.withLock {
            let id = requestID.lowercased()
            guard let old = records[id], old.phase == from else { throw NativeAgentSigningIntentStoreError.phaseConflict }
            let next = NativeAgentSigningIntentRecord(evidence: old.evidence, phase: to, signatureHash: signatureHash ?? old.signatureHash)
            records[id] = next
            do { try persistLocked() } catch { records[id] = old; throw error }
            return next
        }
    }

    private func load() throws {
        do {
            let data = try nativeV2ReadFile(path, maxBytes: Self.maximumBytes)
            guard data.last == 0x0a else { throw NativeAgentSigningIntentStoreError.invalidState }
            let payload = Data(data.dropLast())
            let object = try NativeStrictJSON.object(from: payload, maxBytes: Self.maximumBytes, maxDepth: 8)
            guard Set(object.keys) == ["version", "records"], object["version"] as? Int == 1,
                  let values = object["records"] as? [[String: Any]], values.count <= Self.maximumRecords,
                  try NativeStrictJSON.data(object) == payload else { throw NativeAgentSigningIntentStoreError.invalidState }
            for value in values {
                let record = try Self.decode(value)
                guard records[record.evidence.requestID] == nil else { throw NativeAgentSigningIntentStoreError.invalidState }
                records[record.evidence.requestID] = record
            }
        } catch let error as NativeAgentSigningIntentStoreError { throw error }
        catch { throw NativeAgentSigningIntentStoreError.invalidState }
    }

    private func persistLocked() throws {
        let values = records.values.sorted { $0.evidence.requestID < $1.evidence.requestID }.map(Self.encode)
        let data = try NativeStrictJSON.data(["version": 1, "records": values]) + Data("\n".utf8)
        guard data.count <= Self.maximumBytes else { throw NativeAgentSigningIntentStoreError.capacityExceeded }
        try nativeV2AtomicWrite(path, data: data)
    }

    private static func encode(_ record: NativeAgentSigningIntentRecord) -> [String: Any] {
        let e = record.evidence
        return ["request_id":e.requestID,"session_id":e.sessionID,"capability_id":e.capabilityID,"payload_hash":e.payloadHash,"process_binding_hash":e.processBindingHash,"ancestry_binding_hash":e.ancestryBindingHash,"worktree_binding_hash":e.worktreeBindingHash,"key_generation":e.keyGeneration,"control_sequence":e.controlSequence,"budget_sequence":e.budgetSequence,"phase":record.phase.rawValue,"signature_hash":record.signatureHash ?? NSNull()]
    }

    private static func decode(_ value: [String: Any]) throws -> NativeAgentSigningIntentRecord {
        let keys: Set<String> = ["request_id","session_id","capability_id","payload_hash","process_binding_hash","ancestry_binding_hash","worktree_binding_hash","key_generation","control_sequence","budget_sequence","phase","signature_hash"]
        guard Set(value.keys) == keys, let request = value["request_id"] as? String, let session = value["session_id"] as? String, let capability = value["capability_id"] as? String, let payload = value["payload_hash"] as? String, let process = value["process_binding_hash"] as? String, let ancestry = value["ancestry_binding_hash"] as? String, let worktree = value["worktree_binding_hash"] as? String, let keyGeneration = Self.integer(value["key_generation"]), let controlSequence = Self.integer(value["control_sequence"]), let budget = Self.integer(value["budget_sequence"]), let phaseText = value["phase"] as? String, let phase = NativeAgentSigningIntentRecord.Phase(rawValue: phaseText) else { throw NativeAgentSigningIntentStoreError.invalidState }
        let evidence = try NativeAgentSigningIntentEvidence(requestID: request, sessionID: session, capabilityID: capability, payloadHash: payload, processBindingHash: process, ancestryBindingHash: ancestry, worktreeBindingHash: worktree, keyGeneration: keyGeneration, controlSequence: controlSequence, budgetSequence: Int(budget))
        let signatureHash = value["signature_hash"] is NSNull ? nil : value["signature_hash"] as? String
        guard (phase == .signed || phase == .complete) ? signatureHash.map(Self.hash) == true : signatureHash == nil else { throw NativeAgentSigningIntentStoreError.invalidState }
        return NativeAgentSigningIntentRecord(evidence: evidence, phase: phase, signatureHash: signatureHash)
    }

    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue, Double(number.int64Value) == number.doubleValue else { return nil }
        return number.int64Value
    }
    private static func hash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
}
