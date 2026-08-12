import CryptoKit
import Foundation

public struct NativeSigningTransactionRecord: Equatable, Sendable {
    public enum Phase: String, Sendable { case intent, signed, complete, outcomeUnknown = "outcome_unknown" }
    public let requestID: String
    public let requestHash: String
    public let phase: Phase
    public let signature: String?
    public let agentID: String
    public let repository: String
    public let branch: String
    public let remote: String
    public let payloadHash: String
}

public final class NativeSigningTransactionStore: @unchecked Sendable {
    private let path: String
    private let lock = NSLock()
    private var records: [String: NativeSigningTransactionRecord] = [:]
    private static let maximumRecords = 10_000

    public init(path: String) throws {
        guard path.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("Signing transaction path must be absolute") }
        self.path = URL(fileURLWithPath: path).standardizedFileURL.path
        if FileManager.default.fileExists(atPath: self.path) { try load() }
    }

    public func lookup(requestData: Data) throws -> NativeSigningTransactionRecord? {
        let identity = try Self.requestIdentity(requestData)
        lock.lock(); defer { lock.unlock() }
        guard let record = records[identity.id] else { return nil }
        guard record.requestHash == identity.hash else { throw AgentPassNativeError.unauthorizedClient("request_id_conflict") }
        return record
    }

    @discardableResult
    public func begin(requestData: Data, authorized: AuthorizedSignRequest, payloadHash: String) throws -> NativeSigningTransactionRecord {
        let identity = try Self.requestIdentity(requestData)
        guard identity.id == authorized.requestID, Self.hashPattern(payloadHash) else { throw AgentPassNativeError.invalidConfiguration("Signing transaction evidence is invalid") }
        lock.lock(); defer { lock.unlock() }
        if let existing = records[identity.id] {
            guard existing.requestHash == identity.hash else { throw AgentPassNativeError.unauthorizedClient("request_id_conflict") }
            return existing
        }
        guard records.count < Self.maximumRecords else { throw AgentPassNativeError.unauthorizedClient("signing_transaction_capacity_exceeded") }
        let record = NativeSigningTransactionRecord(requestID: identity.id, requestHash: identity.hash, phase: .intent, signature: nil, agentID: authorized.agentID, repository: authorized.repository, branch: authorized.branch, remote: authorized.remote, payloadHash: payloadHash)
        records[identity.id] = record
        try persistLocked()
        return record
    }

    public func recordSigned(requestID: String, signature: String) throws -> NativeSigningTransactionRecord {
        guard !signature.isEmpty, signature.utf8.count <= 64 * 1024 else { throw AgentPassNativeError.invalidConfiguration("Signing transaction signature is invalid") }
        return try transition(requestID: requestID, allowed: [.intent], phase: .signed, signature: signature)
    }

    public func complete(requestID: String) throws -> NativeSigningTransactionRecord {
        try transition(requestID: requestID, allowed: [.signed, .complete], phase: .complete, signature: nil)
    }

    public func markOutcomeUnknown(requestID: String) throws -> NativeSigningTransactionRecord {
        try transition(requestID: requestID, allowed: [.intent, .outcomeUnknown], phase: .outcomeUnknown, signature: nil)
    }

    private func transition(requestID: String, allowed: Set<NativeSigningTransactionRecord.Phase>, phase: NativeSigningTransactionRecord.Phase, signature: String?) throws -> NativeSigningTransactionRecord {
        lock.lock(); defer { lock.unlock() }
        guard let old = records[requestID], allowed.contains(old.phase) else { throw AgentPassNativeError.unauthorizedClient("signing_transaction_phase_conflict") }
        let next = NativeSigningTransactionRecord(requestID: old.requestID, requestHash: old.requestHash, phase: phase, signature: signature ?? old.signature, agentID: old.agentID, repository: old.repository, branch: old.branch, remote: old.remote, payloadHash: old.payloadHash)
        records[requestID] = next
        try persistLocked()
        return next
    }

    private func load() throws {
        let data = try nativeV2ReadFile(path, maxBytes: 4 * 1024 * 1024)
        guard data.count <= 4 * 1024 * 1024, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == ["version", "records"], object["version"] as? Int == 1, let values = object["records"] as? [[String: Any]], values.count <= Self.maximumRecords else { throw AgentPassNativeError.invalidConfiguration("Signing transaction state is invalid") }
        for value in values {
            let record = try Self.decode(value)
            guard records[record.requestID] == nil else { throw AgentPassNativeError.invalidConfiguration("Signing transaction state contains duplicates") }
            records[record.requestID] = record
        }
    }

    private func persistLocked() throws {
        let values = records.values.sorted { $0.requestID < $1.requestID }.map(Self.encode)
        let data = try JSONSerialization.data(withJSONObject: ["version": 1, "records": values], options: [.sortedKeys, .withoutEscapingSlashes]) + Data("\n".utf8)
        try nativeV2AtomicWrite(path, data: data)
    }

    private static func requestIdentity(_ data: Data) throws -> (id: String, hash: String) {
        guard data.count > 0, data.count <= 12 * 1024 * 1024, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], let id = object["request_id"] as? String, UUID(uuidString: id) != nil else { throw AgentPassNativeError.unauthorizedClient("request_id_invalid") }
        return (id.lowercased(), SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
    }

    private static func encode(_ record: NativeSigningTransactionRecord) -> [String: Any] { ["request_id": record.requestID, "request_hash": record.requestHash, "phase": record.phase.rawValue, "signature": record.signature ?? NSNull(), "agent_id": record.agentID, "repository": record.repository, "branch": record.branch, "remote": record.remote, "payload_hash": record.payloadHash] }
    private static func decode(_ value: [String: Any]) throws -> NativeSigningTransactionRecord {
        guard Set(value.keys) == ["request_id", "request_hash", "phase", "signature", "agent_id", "repository", "branch", "remote", "payload_hash"], let requestID = value["request_id"] as? String, UUID(uuidString: requestID) != nil, let requestHash = value["request_hash"] as? String, hashPattern(requestHash), let phaseText = value["phase"] as? String, let phase = NativeSigningTransactionRecord.Phase(rawValue: phaseText), let agentID = value["agent_id"] as? String, UUID(uuidString: agentID) != nil, let repository = value["repository"] as? String, repository.hasPrefix("/"), let branch = value["branch"] as? String, let remote = value["remote"] as? String, let payloadHash = value["payload_hash"] as? String, hashPattern(payloadHash) else { throw AgentPassNativeError.invalidConfiguration("Signing transaction record is invalid") }
        let signature: String? = value["signature"] is NSNull ? nil : value["signature"] as? String
        guard (phase == .intent || phase == .outcomeUnknown) ? signature == nil : signature?.isEmpty == false else { throw AgentPassNativeError.invalidConfiguration("Signing transaction phase evidence is invalid") }
        return NativeSigningTransactionRecord(requestID: requestID, requestHash: requestHash, phase: phase, signature: signature, agentID: agentID, repository: repository, branch: branch, remote: remote, payloadHash: payloadHash)
    }
    private static func hashPattern(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
}
