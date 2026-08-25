import CoreFoundation
import Darwin
import Foundation

/// The only durable record that may cross the onboarding reconciliation
/// boundary. It contains public protocol material only: the signed bundle ACK
/// and the bounded server result. No URL, path, credential, or diagnostic is
/// representable by this type.
public struct NativeControlRefreshEvidence: Equatable, Sendable {
    public static let version = 1

    public let version: Int
    public let acknowledgement: NativeBundleAcknowledgement
    public let serverAccepted: Bool
    public let observedGeneration: Int64
    public let refreshState: NativeDeviceRefreshState
    public let refreshGeneration: Int64
    public let refreshSequence: Int64
    public let controlStatementHash: String

    public init(
        version: Int = NativeControlRefreshEvidence.version,
        acknowledgement: NativeBundleAcknowledgement,
        serverAccepted: Bool,
        observedGeneration: Int64,
        refreshState: NativeDeviceRefreshState,
        refreshGeneration: Int64,
        refreshSequence: Int64,
        controlStatementHash: String
    ) {
        self.version = version
        self.acknowledgement = acknowledgement
        self.serverAccepted = serverAccepted
        self.observedGeneration = observedGeneration
        self.refreshState = refreshState
        self.refreshGeneration = refreshGeneration
        self.refreshSequence = refreshSequence
        self.controlStatementHash = controlStatementHash
    }

    public var isAcceptedApplied: Bool {
        serverAccepted &&
            refreshState == .applied &&
            acknowledgement.result == .applied
    }

    public func matches(
        organizationID: String,
        deviceID: String,
        deviceKeyEpoch: Int64,
        formatEpoch: Int,
        generation: Int64,
        sequence: Int64,
        statementHash: String,
        refreshState: NativeDeviceRefreshState,
        refreshNonce: String
    ) -> Bool {
        acknowledgement.organizationID == organizationID.lowercased() &&
            acknowledgement.deviceID == deviceID.lowercased() &&
            acknowledgement.deviceKeyEpoch == deviceKeyEpoch &&
            acknowledgement.formatEpoch == formatEpoch &&
            acknowledgement.sequence == sequence &&
            acknowledgement.statementHash == statementHash &&
            acknowledgement.nonce == refreshNonce &&
            serverAccepted &&
            observedGeneration == generation &&
            self.refreshState == refreshState &&
            refreshGeneration == generation &&
            refreshSequence == sequence &&
            controlStatementHash == statementHash
    }

    /// The response is deliberately narrower than the on-disk schema. A
    /// blocked ACK can be durably retained for fail-closed recovery, but it
    /// can never be converted into onboarding evidence.
    public func publicResponseObject() throws -> [String: Any] {
        guard isAcceptedApplied else {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
        let acknowledgement = try NativeBundleAcknowledgementCodec.canonicalJSON(self.acknowledgement)
        let acknowledgementObject = try NativeStrictJSON.object(
            from: acknowledgement,
            maxBytes: NativeBundleAcknowledgementCodec.maxBytes,
            maxDepth: 8
        )
        return [
            "status": "enabled",
            "control_refreshed": true,
            "control_ack": [
                "acknowledgement": acknowledgementObject,
                "server_accepted": true,
                "observed_generation": observedGeneration,
                "refresh_state": "applied"
            ],
            "refresh_generation": refreshGeneration,
            "refresh_sequence": refreshSequence,
            "control_statement_hash": controlStatementHash
        ]
    }
}

public enum NativeControlRefreshEvidenceError: Error, LocalizedError, Equatable, Sendable {
    case invalidEvidence
    case loadFailed
    case saveFailed

    public var errorDescription: String? {
        switch self {
        case .invalidEvidence: return "control_refresh_evidence_invalid"
        case .loadFailed: return "control_refresh_evidence_load_failed"
        case .saveFailed: return "control_refresh_evidence_save_failed"
        }
    }
}

public enum NativeControlRefreshEvidenceCodec {
    public static let maximumBytes = 24 * 1024

    private static let keys: Set<String> = [
        "version", "acknowledgement", "server_accepted", "observed_generation",
        "refresh_state", "refresh_generation", "refresh_sequence", "control_statement_hash"
    ]

    public static func encode(_ evidence: NativeControlRefreshEvidence) throws -> Data {
        guard evidence.version == NativeControlRefreshEvidence.version,
              evidence.serverAccepted,
              evidence.observedGeneration > 0,
              evidence.refreshGeneration > 0,
              evidence.refreshSequence > 0,
              evidence.observedGeneration == evidence.refreshGeneration,
              evidence.refreshState == .applied || evidence.refreshState == .blocked,
              evidence.acknowledgement.sequence == evidence.refreshSequence,
              evidence.acknowledgement.statementHash == evidence.controlStatementHash,
              evidence.acknowledgement.result == evidence.refreshState.acknowledgementResult,
              validHash(evidence.controlStatementHash) else {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
        let acknowledgement = try NativeBundleAcknowledgementCodec.canonicalJSON(evidence.acknowledgement)
        let acknowledgementObject = try NativeStrictJSON.object(
            from: acknowledgement,
            maxBytes: NativeBundleAcknowledgementCodec.maxBytes,
            maxDepth: 8
        )
        let object: [String: Any] = [
            "version": evidence.version,
            "acknowledgement": acknowledgementObject,
            "server_accepted": true,
            "observed_generation": evidence.observedGeneration,
            "refresh_state": evidence.refreshState.rawValue,
            "refresh_generation": evidence.refreshGeneration,
            "refresh_sequence": evidence.refreshSequence,
            "control_statement_hash": evidence.controlStatementHash
        ]
        do {
            let data = try NativeStrictJSON.data(object)
            guard data.count <= maximumBytes else { throw NativeControlRefreshEvidenceError.invalidEvidence }
            return data
        } catch let error as NativeControlRefreshEvidenceError {
            throw error
        } catch {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
    }

    public static func decode(_ data: Data) throws -> NativeControlRefreshEvidence {
        guard !data.isEmpty, data.count <= maximumBytes else {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
        let object: [String: Any]
        do {
            object = try NativeStrictJSON.object(from: data, maxBytes: maximumBytes, maxDepth: 10)
        } catch {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
        guard Set(object.keys) == keys,
              let version = integer(object["version"]), version == Int64(NativeControlRefreshEvidence.version),
              let serverAccepted = object["server_accepted"] as? Bool,
              serverAccepted,
              let observedGeneration = integer(object["observed_generation"]), observedGeneration > 0,
              let refreshStateValue = object["refresh_state"] as? String,
              let refreshState = NativeDeviceRefreshState(rawValue: refreshStateValue),
              refreshState == .applied || refreshState == .blocked,
              let refreshGeneration = integer(object["refresh_generation"]), refreshGeneration > 0,
              let refreshSequence = integer(object["refresh_sequence"]), refreshSequence > 0,
              let controlStatementHash = object["control_statement_hash"] as? String,
              validHash(controlStatementHash),
              let acknowledgementObject = object["acknowledgement"] as? [String: Any] else {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
        let acknowledgementData: Data
        do {
            acknowledgementData = try NativeStrictJSON.data(acknowledgementObject)
        } catch {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
        let acknowledgement: NativeBundleAcknowledgement
        do {
            acknowledgement = try NativeBundleAcknowledgementCodec.decode(acknowledgementData)
        } catch {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
        let evidence = NativeControlRefreshEvidence(
            version: Int(version),
            acknowledgement: acknowledgement,
            serverAccepted: serverAccepted,
            observedGeneration: observedGeneration,
            refreshState: refreshState,
            refreshGeneration: refreshGeneration,
            refreshSequence: refreshSequence,
            controlStatementHash: controlStatementHash
        )
        guard try encode(evidence) == data else {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
        return evidence
    }

    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFNumberGetTypeID() else { return nil }
        let value = number.int64Value
        guard Double(value) == number.doubleValue else { return nil }
        return value
    }

    private static func validHash(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }
}

public protocol NativeControlRefreshEvidenceStoring: Sendable {
    func load() throws -> NativeControlRefreshEvidence?
    func save(_ evidence: NativeControlRefreshEvidence) throws
}

/// Uses the same root-owned directory and atomic POSIX primitive as the
/// durable refresh snapshot. Reads and writes reject symlinks, hard links,
/// widened permissions, wrong ownership, and oversized records.
public final class NativeControlRefreshEvidencePOSIXStore: NativeControlRefreshEvidenceStoring, @unchecked Sendable {
    public let path: String
    private let lock = NSLock()

    public init(path: String) throws {
        guard path.hasPrefix("/"), URL(fileURLWithPath: path).standardizedFileURL.path == path else {
            throw NativeControlRefreshEvidenceError.invalidEvidence
        }
        self.path = path
    }

    public func load() throws -> NativeControlRefreshEvidence? {
        lock.lock()
        defer { lock.unlock() }
        var metadata = stat()
        if lstat(path, &metadata) != 0 {
            if errno == ENOENT { return nil }
            throw NativeControlRefreshEvidenceError.loadFailed
        }
        do {
            return try NativeControlRefreshEvidenceCodec.decode(
                nativeV2ReadFile(path, maxBytes: NativeControlRefreshEvidenceCodec.maximumBytes)
            )
        } catch let error as NativeControlRefreshEvidenceError {
            throw error
        } catch {
            throw NativeControlRefreshEvidenceError.loadFailed
        }
    }

    public func save(_ evidence: NativeControlRefreshEvidence) throws {
        let data: Data
        do { data = try NativeControlRefreshEvidenceCodec.encode(evidence) }
        catch { throw NativeControlRefreshEvidenceError.saveFailed }
        lock.lock()
        defer { lock.unlock() }
        do { try nativeV2AtomicWrite(path, data: data) }
        catch { throw NativeControlRefreshEvidenceError.saveFailed }
    }
}

private extension NativeDeviceRefreshState {
    var acknowledgementResult: NativeBundleAcknowledgementResult {
        switch self {
        case .applied: return .applied
        case .blocked, .pending, .fetching, .stale, .offline, .revoked: return .blocked
        }
    }
}
