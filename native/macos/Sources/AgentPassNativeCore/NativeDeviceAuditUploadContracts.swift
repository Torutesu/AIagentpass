import CoreFoundation
import CryptoKit
import Foundation

/// The public, redacted event accepted by the Cloud device-audit endpoint.
/// This is intentionally separate from NativeAuditLog's local record format:
/// the local log may contain optional operational fields, while Cloud accepts
/// one closed tenant-facing schema only.
public struct NativeDeviceAuditEvent: Equatable, Sendable {
    public static let version = 1
    public static let maxBytes = 16 * 1024
    private static let allowedReasons: Set<String> = [
        "allowed", "branch_denied", "branch_not_allowed", "capability_expired",
        "capability_missing", "operation_not_allowed", "policy_changed",
        "remote_control_stale", "remote_denied", "remote_not_allowed",
        "repository_not_allowed", "revoked", "session_required", "signer_failed",
        "tag_denied", "tag_not_allowed"
    ]

    public let version: Int
    public let eventID: String
    public let requestID: String
    public let agentID: String
    public let operation: String
    public let decision: String
    public let reason: String
    public let policySequence: Int64
    public let capabilitySequence: Int64
    public let repository: String
    public let branch: String
    public let remote: String
    public let payloadDigest: String
    public let deviceTimestamp: String
    public let previousHash: String
    public private(set) var eventHash: String

    public init(
        eventID: String, requestID: String, agentID: String,
        operation: String = "git.commit.sign", decision: String,
        reason: String, policySequence: Int64, capabilitySequence: Int64,
        repository: String, branch: String, remote: String,
        payloadDigest: String, deviceTimestamp: String,
        previousHash: String, eventHash: String? = nil
    ) throws {
        let normalized = try Self.validate(
            eventID: eventID, requestID: requestID, agentID: agentID,
            operation: operation, decision: decision, reason: reason,
            policySequence: policySequence, capabilitySequence: capabilitySequence,
            repository: repository, branch: branch, remote: remote,
            payloadDigest: payloadDigest, deviceTimestamp: deviceTimestamp,
            previousHash: previousHash, eventHash: eventHash
        )
        self.version = Self.version
        self.eventID = normalized.eventID; self.requestID = normalized.requestID; self.agentID = normalized.agentID
        self.operation = normalized.operation; self.decision = normalized.decision; self.reason = normalized.reason
        self.policySequence = normalized.policySequence; self.capabilitySequence = normalized.capabilitySequence
        self.repository = normalized.repository; self.branch = normalized.branch; self.remote = normalized.remote
        self.payloadDigest = normalized.payloadDigest; self.deviceTimestamp = normalized.deviceTimestamp
        self.previousHash = normalized.previousHash
        self.eventHash = ""
        let unsigned = try Self.object(self, includeEventHash: false)
        let expectedHash = try Self.hash(unsigned)
        if let eventHash, eventHash != expectedHash { throw NativeDeviceSyncContractError(.invalidHash, "event_hash does not match the canonical event") }
        self.eventHash = eventHash ?? expectedHash
    }

    public func canonicalData() throws -> Data { try NativeStrictJSON.data(Self.object(self, includeEventHash: true)) }
    public func unsignedCanonicalData() throws -> Data { try NativeStrictJSON.data(Self.object(self, includeEventHash: false)) }

    public static func decode(_ data: Data) throws -> NativeDeviceAuditEvent {
        guard data.count <= maxBytes else { throw NativeDeviceSyncContractError(.invalidResult, "audit event is too large") }
        let object = try NativeStrictJSON.object(from: data, maxBytes: maxBytes, maxDepth: 8)
        try rejectUnknown(object)
        guard exactInteger(object["version"]) == Int64(version) else { throw NativeDeviceSyncContractError(.invalidVersion) }
        return try NativeDeviceAuditEvent(
            eventID: try uuid(object["event_id"], field: "event_id"),
            requestID: try uuid(object["request_id"], field: "request_id"),
            agentID: try uuid(object["agent_id"], field: "agent_id"),
            operation: try text(object["operation"], field: "operation", pattern: "^git\\.commit\\.sign$", maxBytes: 64),
            decision: try text(object["decision"], field: "decision", allowed: ["allow", "deny", "error"], maxBytes: 16),
            reason: try text(object["reason"], field: "reason", allowed: Array(allowedReasons), maxBytes: 128),
            policySequence: try sequence(object["policy_sequence"], field: "policy_sequence"),
            capabilitySequence: try sequence(object["capability_sequence"], field: "capability_sequence"),
            repository: try text(object["repository"], field: "repository", absolutePath: true, maxBytes: 4096),
            branch: try text(object["branch"], field: "branch", maxBytes: 2048),
            remote: try text(object["remote"], field: "remote", maxBytes: 2048),
            payloadDigest: try digest(object["payload_digest"], field: "payload_digest"),
            deviceTimestamp: try timestamp(object["device_timestamp"], field: "device_timestamp"),
            previousHash: try digest(object["previous_hash"], field: "previous_hash"),
            eventHash: try digest(object["event_hash"], field: "event_hash")
        )
    }

    public static func hash(_ unsignedObject: [String: Any]) throws -> String {
        let data = try NativeStrictJSON.data(unsignedObject)
        return Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
    }

    private static func object(_ value: NativeDeviceAuditEvent, includeEventHash: Bool) throws -> [String: Any] {
        var object: [String: Any] = [
            "version": value.version, "event_id": value.eventID, "request_id": value.requestID,
            "agent_id": value.agentID, "operation": value.operation, "decision": value.decision,
            "reason": value.reason, "policy_sequence": value.policySequence,
            "capability_sequence": value.capabilitySequence, "repository": value.repository,
            "branch": value.branch, "remote": value.remote, "payload_digest": value.payloadDigest,
            "device_timestamp": value.deviceTimestamp, "previous_hash": value.previousHash
        ]
        if includeEventHash { object["event_hash"] = value.eventHash }
        return object
    }

    private static func rejectUnknown(_ object: [String: Any]) throws {
        let expected: Set<String> = ["version", "event_id", "request_id", "agent_id", "operation", "decision", "reason", "policy_sequence", "capability_sequence", "repository", "branch", "remote", "payload_digest", "device_timestamp", "previous_hash", "event_hash"]
        guard Set(object.keys) == expected else { throw NativeDeviceSyncContractError(.unknownField) }
    }
    private static func exactInteger(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue, number.doubleValue >= 0, number.doubleValue <= 9_007_199_254_740_991 else { return nil }
        return number.int64Value
    }
    private static func uuid(_ value: Any?, field: String) throws -> String { guard let text = value as? String, let uuid = UUID(uuidString: text), uuid.uuidString.lowercased() == text.lowercased() else { throw NativeDeviceSyncContractError(.invalidUUID, field) }; return text.lowercased() }
    private static func sequence(_ value: Any?, field: String) throws -> Int64 { guard let value = exactInteger(value) else { throw NativeDeviceSyncContractError(.invalidSequence, field) }; return value }
    private static func digest(_ value: Any?, field: String) throws -> String { guard let value = value as? String, value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw NativeDeviceSyncContractError(.invalidHash, field) }; return value }
    private static func timestamp(_ value: Any?, field: String) throws -> String { guard let value = value as? String, value.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", options: .regularExpression) != nil else { throw NativeDeviceSyncContractError(.invalidTimestamp, field) }; return value }
    private static func text(_ value: Any?, field: String, allowed: [String] = [], pattern: String? = nil, absolutePath: Bool = false, maxBytes: Int) throws -> String {
        guard let value = value as? String, !value.isEmpty, value.utf8.count <= maxBytes, !value.contains(where: { character in
            if character.isNewline { return true }
            guard character.isASCII, let ascii = character.asciiValue else { return false }
            return ascii < 32 || ascii == 127
        }) else { throw NativeDeviceSyncContractError(.invalidValue, field) }
        if !allowed.isEmpty && !allowed.contains(value) { throw NativeDeviceSyncContractError(.invalidValue, field) }
        if let pattern, value.range(of: pattern, options: .regularExpression) == nil { throw NativeDeviceSyncContractError(.invalidValue, field) }
        if absolutePath && (!value.hasPrefix("/") || value.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) || URL(fileURLWithPath: value).standardizedFileURL.path != value) { throw NativeDeviceSyncContractError(.invalidValue, field) }
        return value
    }
    private static func validate(eventID: String, requestID: String, agentID: String, operation: String, decision: String, reason: String, policySequence: Int64, capabilitySequence: Int64, repository: String, branch: String, remote: String, payloadDigest: String, deviceTimestamp: String, previousHash: String, eventHash: String?) throws -> (eventID: String, requestID: String, agentID: String, operation: String, decision: String, reason: String, policySequence: Int64, capabilitySequence: Int64, repository: String, branch: String, remote: String, payloadDigest: String, deviceTimestamp: String, previousHash: String) {
        _ = try uuid(eventID, field: "event_id"); _ = try uuid(requestID, field: "request_id"); _ = try uuid(agentID, field: "agent_id")
        _ = try text(operation, field: "operation", pattern: "^git\\.commit\\.sign$", maxBytes: 64); _ = try text(decision, field: "decision", allowed: ["allow", "deny", "error"], maxBytes: 16); _ = try text(reason, field: "reason", allowed: Array(allowedReasons), maxBytes: 128)
        guard policySequence >= 0, capabilitySequence >= 0 else { throw NativeDeviceSyncContractError(.invalidSequence) }
        _ = try text(repository, field: "repository", absolutePath: true, maxBytes: 4096); _ = try text(branch, field: "branch", maxBytes: 2048); _ = try text(remote, field: "remote", maxBytes: 2048); _ = try digest(payloadDigest, field: "payload_digest"); _ = try timestamp(deviceTimestamp, field: "device_timestamp"); _ = try digest(previousHash, field: "previous_hash"); if let eventHash { _ = try digest(eventHash, field: "event_hash") }
        if decision == "allow" && reason != "allowed" { throw NativeDeviceSyncContractError(.inconsistentReason) }
        return (eventID.lowercased(), requestID.lowercased(), agentID.lowercased(), operation, decision, reason, policySequence, capabilitySequence, repository, branch, remote, payloadDigest, deviceTimestamp, previousHash)
    }
}

public struct NativeDeviceAuditBatch: Equatable, Sendable {
    public static let maxEvents = 64
    public let batchID: String
    public let events: [NativeDeviceAuditEvent]
    public init(batchID: String, events: [NativeDeviceAuditEvent]) throws {
        guard let uuid = UUID(uuidString: batchID), uuid.uuidString.lowercased() == batchID.lowercased(), !events.isEmpty, events.count <= Self.maxEvents, Set(events.map(\.eventID)).count == events.count else { throw NativeDeviceSyncContractError(.invalidValue, "batch") }
        self.batchID = batchID.lowercased(); self.events = events
    }
    public func canonicalData() throws -> Data { try NativeStrictJSON.data(["batch_id": batchID, "events": try events.map { try JSONSerialization.jsonObject(with: $0.canonicalData()) }]) }

    public static func decode(_ data: Data) throws -> NativeDeviceAuditBatch {
        let object = try NativeStrictJSON.object(from: data, maxBytes: NativeDeviceAuditEvent.maxBytes * Self.maxEvents, maxDepth: 10)
        guard Set(object.keys) == Set(["batch_id", "events"]),
              let batchID = object["batch_id"] as? String,
              let eventObjects = object["events"] as? [[String: Any]],
              !eventObjects.isEmpty, eventObjects.count <= Self.maxEvents else {
            throw NativeDeviceSyncContractError(.invalidResult, "audit batch is invalid")
        }
        let events = try eventObjects.map { try NativeDeviceAuditEvent.decode(try NativeStrictJSON.data($0)) }
        guard Set(events.map(\.eventID)).count == events.count else {
            throw NativeDeviceSyncContractError(.invalidValue, "audit batch contains duplicate event IDs")
        }
        return try NativeDeviceAuditBatch(batchID: batchID, events: events)
    }
}

public struct NativeDeviceAuditIngestionResponse: Equatable, Sendable {
    public let deviceID: String
    public let acceptedEventIDs: [String]
    public let duplicateEventIDs: [String]
    public let gapCount: Int
    public let headHash: String
    public let headEventID: String?
    public let chainStatus: String

    public init(deviceID: String, acceptedEventIDs: [String], duplicateEventIDs: [String], gapCount: Int, headHash: String, headEventID: String?, chainStatus: String) {
        self.deviceID = deviceID
        self.acceptedEventIDs = acceptedEventIDs
        self.duplicateEventIDs = duplicateEventIDs
        self.gapCount = gapCount
        self.headHash = headHash
        self.headEventID = headEventID
        self.chainStatus = chainStatus
    }

    public static func decode(_ data: Data, expectedDeviceID: String) throws -> NativeDeviceAuditIngestionResponse {
        let root = try NativeStrictJSON.object(from: data, maxBytes: 64 * 1024, maxDepth: 10)
        guard Set(root.keys) == Set(["ingestion"]), let ingestion = root["ingestion"] as? [String: Any],
              Set(ingestion.keys) == Set(["device_id", "accepted", "duplicates", "gaps", "head"]),
              let deviceID = ingestion["device_id"] as? String, deviceID == expectedDeviceID,
              let accepted = uuidArray(ingestion["accepted"]), let duplicates = uuidArray(ingestion["duplicates"]),
              let gaps = ingestion["gaps"] as? [[String: Any]], gaps.count <= NativeDeviceAuditBatch.maxEvents,
              let head = ingestion["head"] as? [String: Any],
              Set(head.keys) == Set(["last_hash", "last_event_id", "chain_status", "gap_count"]),
              let headHash = head["last_hash"] as? String, headHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              let chainStatus = head["chain_status"] as? String, ["continuous", "gap"].contains(chainStatus),
              let gapCount = exactNonnegative(head["gap_count"]), gapCount <= Int64.max else {
            throw NativeDeviceSyncContractError(.invalidResult, "audit ingestion response is invalid")
        }
        for gap in gaps {
            guard Set(gap.keys) == Set(["gap_id", "organization_id", "device_id", "event_id", "expected_previous_hash", "received_previous_hash", "recorded_at"]),
                  uuid(gap["gap_id"]), uuid(gap["organization_id"]), uuid(gap["device_id"]), uuid(gap["event_id"]),
                  digest(gap["expected_previous_hash"]), digest(gap["received_previous_hash"]), gap["recorded_at"] is String else {
                throw NativeDeviceSyncContractError(.invalidResult, "audit ingestion gap is invalid")
            }
        }
        let lastEventID: String?
        if head["last_event_id"] is NSNull { lastEventID = nil }
        else if let value = head["last_event_id"] as? String, uuid(value) { lastEventID = value.lowercased() }
        else { throw NativeDeviceSyncContractError(.invalidResult, "audit ingestion head is invalid") }
        return NativeDeviceAuditIngestionResponse(deviceID: deviceID, acceptedEventIDs: accepted, duplicateEventIDs: duplicates, gapCount: Int(gapCount), headHash: headHash, headEventID: lastEventID, chainStatus: chainStatus)
    }

    private static func exactNonnegative(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue, number.doubleValue >= 0, number.doubleValue <= Double(Int64.max) else { return nil }
        return number.int64Value
    }
    private static func uuid(_ value: Any?) -> Bool { guard let value = value as? String, let uuid = UUID(uuidString: value) else { return false }; return uuid.uuidString.lowercased() == value.lowercased() }
    private static func uuidArray(_ value: Any?) -> [String]? { guard let values = value as? [Any], values.count <= NativeDeviceAuditBatch.maxEvents else { return nil }; let result = values.compactMap { ($0 as? String).flatMap { uuid($0) ? $0.lowercased() : nil } }; return result.count == values.count ? result : nil }
    private static func digest(_ value: Any?) -> Bool { guard let value = value as? String else { return false }; return value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
}
