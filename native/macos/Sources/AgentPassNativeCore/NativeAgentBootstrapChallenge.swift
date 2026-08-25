import CryptoKit
import Foundation
import Security

public enum NativeAgentBootstrapChallengeError: String, Error, Equatable, Sendable {
    case invalidInput = "invalid_input"
    case invalidConnectionBinding = "invalid_connection_binding"
    case invalidTime = "invalid_time"
    case randomUnavailable = "random_unavailable"
    case challengeMissing = "challenge_missing"
    case challengeMismatch = "challenge_mismatch"
    case challengeExpired = "challenge_expired"
    case challengeInvalidated = "challenge_invalidated"
}

public protocol NativeAgentRandomBytesGenerating: Sendable {
    func randomBytes(count: Int) throws -> Data
}

public struct NativeAgentSystemRandomBytesGenerator: NativeAgentRandomBytesGenerating, Sendable {
    public init() {}

    public func randomBytes(count: Int) throws -> Data {
        guard (1...64).contains(count) else { throw NativeAgentBootstrapChallengeError.randomUnavailable }
        var data = Data(repeating: 0, count: count)
        let status = data.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw NativeAgentBootstrapChallengeError.randomUnavailable }
        return data
    }
}

/// Immutable OS-derived connection evidence used to bind a bootstrap. Hashes
/// are accepted only in their canonical lower-case SHA-256 representation.
public struct NativeAgentBootstrapConnectionBinding: Equatable, Sendable {
    public let connectionTokenIdentity: String
    public let processBindingHash: String
    public let ancestryBindingHash: String
    public let bootIdentityHash: String

    public init(
        connectionTokenIdentity: String,
        processBindingHash: String,
        ancestryBindingHash: String,
        bootIdentityHash: String
    ) throws {
        guard [connectionTokenIdentity, processBindingHash, ancestryBindingHash, bootIdentityHash]
            .allSatisfy(Self.isHash) else {
            throw NativeAgentBootstrapChallengeError.invalidConnectionBinding
        }
        self.connectionTokenIdentity = connectionTokenIdentity
        self.processBindingHash = processBindingHash
        self.ancestryBindingHash = ancestryBindingHash
        self.bootIdentityHash = bootIdentityHash
    }

    private static func isHash(_ value: String) -> Bool {
        value.utf8.count == 64 && value.unicodeScalars.allSatisfy {
            ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102)
        }
    }
}

/// Secret-free evidence consumed exactly once by the Grant/Lease coordinator.
/// The challenge bytes themselves are not retained after construction.
public struct NativeAgentBootstrapEvidence: Equatable, Sendable {
    public let bootstrapID: String
    public let agentID: String
    public let adapterKind: AgentPassAgentAdapterKind
    public let requestedTTLSeconds: Int
    public let connectionBinding: NativeAgentBootstrapConnectionBinding
    public let clientNonceHash: String
    public let challengeHash: String
    public let issuedAtMilliseconds: Int64
    public let expiresAtMilliseconds: Int64
    public let issuedAtMonotonicNanoseconds: UInt64
    public let expiresAtMonotonicNanoseconds: UInt64
    public let generation: UInt64
}

public struct NativeAgentBootstrapChallenge: Equatable, Sendable {
    public let bootstrapID: String
    public let challenge: Data
    public let expiresAtMilliseconds: Int64
}

/// Connection-scoped one-time bootstrap state. Replacing a pending challenge
/// increments the generation and makes the old identifier unusable.
public final class NativeAgentBootstrapChallengeStore: @unchecked Sendable {
    public static let challengeTTLMilliseconds: Int64 = 60_000
    private static let challengeTTLNanoseconds: UInt64 = 60_000_000_000
    private static let maximumRequestedTTLSeconds = 28_800

    private struct Pending {
        let evidence: NativeAgentBootstrapEvidence
    }

    private let random: any NativeAgentRandomBytesGenerating
    private let lock = NSLock()
    private var generation: UInt64 = 0
    private var pending: Pending?

    public init(random: any NativeAgentRandomBytesGenerating = NativeAgentSystemRandomBytesGenerator()) {
        self.random = random
    }

    public func begin(
        agentID: String,
        adapterKind: AgentPassAgentAdapterKind,
        requestedTTLSeconds: Int,
        clientNonce: Data,
        connectionBinding: NativeAgentBootstrapConnectionBinding,
        nowMilliseconds: Int64,
        nowMonotonicNanoseconds: UInt64
    ) throws -> NativeAgentBootstrapChallenge {
        guard agentID.utf8.count == 36, UUID(uuidString: agentID) != nil,
              (60...Self.maximumRequestedTTLSeconds).contains(requestedTTLSeconds),
              (AgentPassAgentBootstrapRequest.minimumNonceBytes...AgentPassAgentBootstrapRequest.maximumNonceBytes).contains(clientNonce.count) else {
            throw NativeAgentBootstrapChallengeError.invalidInput
        }
        guard nowMilliseconds > 0,
              nowMilliseconds <= Int64.max - Self.challengeTTLMilliseconds,
              nowMonotonicNanoseconds <= UInt64.max - Self.challengeTTLNanoseconds else {
            throw NativeAgentBootstrapChallengeError.invalidTime
        }
        let identifierBytes = try random.randomBytes(count: 16)
        let serverNonce = try random.randomBytes(count: 32)
        guard identifierBytes.count == 16, serverNonce.count == 32 else {
            throw NativeAgentBootstrapChallengeError.randomUnavailable
        }
        let bootstrapID = Self.uuid(bytes: identifierBytes)
        let expiresAtMilliseconds = nowMilliseconds + Self.challengeTTLMilliseconds
        let expiresAtMonotonicNanoseconds = nowMonotonicNanoseconds + Self.challengeTTLNanoseconds

        lock.lock()
        defer { lock.unlock() }
        guard generation < UInt64.max else { throw NativeAgentBootstrapChallengeError.challengeInvalidated }
        generation += 1

        let clientNonceHash = Self.hash(clientNonce)
        let challenge = try Self.challengeData(
            bootstrapID: bootstrapID,
            clientNonceHash: clientNonceHash,
            serverNonce: serverNonce,
            expiresAtMilliseconds: expiresAtMilliseconds
        )
        let evidence = NativeAgentBootstrapEvidence(
            bootstrapID: bootstrapID,
            agentID: agentID.lowercased(),
            adapterKind: adapterKind,
            requestedTTLSeconds: requestedTTLSeconds,
            connectionBinding: connectionBinding,
            clientNonceHash: clientNonceHash,
            challengeHash: Self.hash(challenge),
            issuedAtMilliseconds: nowMilliseconds,
            expiresAtMilliseconds: expiresAtMilliseconds,
            issuedAtMonotonicNanoseconds: nowMonotonicNanoseconds,
            expiresAtMonotonicNanoseconds: expiresAtMonotonicNanoseconds,
            generation: generation
        )
        pending = Pending(evidence: evidence)
        return NativeAgentBootstrapChallenge(bootstrapID: bootstrapID, challenge: challenge, expiresAtMilliseconds: expiresAtMilliseconds)
    }

    /// Removes pending state before returning. Expired or mismatched attempts
    /// also consume the challenge, preventing an online retry oracle.
    public func consume(
        bootstrapID: String,
        nowMilliseconds: Int64,
        nowMonotonicNanoseconds: UInt64
    ) throws -> NativeAgentBootstrapEvidence {
        lock.lock()
        let value = pending
        pending = nil
        lock.unlock()
        guard let value else { throw NativeAgentBootstrapChallengeError.challengeMissing }
        guard value.evidence.bootstrapID == bootstrapID.lowercased(), UUID(uuidString: bootstrapID) != nil else {
            throw NativeAgentBootstrapChallengeError.challengeMismatch
        }
        guard nowMilliseconds >= value.evidence.issuedAtMilliseconds,
              nowMonotonicNanoseconds >= value.evidence.issuedAtMonotonicNanoseconds,
              nowMilliseconds <= value.evidence.expiresAtMilliseconds,
              nowMonotonicNanoseconds <= value.evidence.expiresAtMonotonicNanoseconds else {
            throw NativeAgentBootstrapChallengeError.challengeExpired
        }
        return value.evidence
    }

    public func invalidate() {
        lock.lock()
        pending = nil
        if generation < UInt64.max { generation += 1 }
        lock.unlock()
    }

    private static func challengeData(
        bootstrapID: String,
        clientNonceHash: String,
        serverNonce: Data,
        expiresAtMilliseconds: Int64
    ) throws -> Data {
        guard let identifier = UUID(uuidString: bootstrapID),
              let nonceHash = Data(hexLowercase: clientNonceHash), nonceHash.count == 32 else {
            throw NativeAgentBootstrapChallengeError.invalidInput
        }
        var identifierValue = identifier.uuid
        var expiry = UInt64(expiresAtMilliseconds).bigEndian
        var data = Data("AgentPass-Agent-Bootstrap-v1\0".utf8)
        withUnsafeBytes(of: &identifierValue) { data.append(contentsOf: $0) }
        data.append(serverNonce)
        data.append(nonceHash)
        withUnsafeBytes(of: &expiry) { data.append(contentsOf: $0) }
        guard (AgentPassAgentBootstrapResponse.minimumChallengeBytes...AgentPassAgentBootstrapResponse.maximumChallengeBytes).contains(data.count) else {
            throw NativeAgentBootstrapChallengeError.invalidInput
        }
        return data
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func uuid(bytes: Data) -> String {
        var value = Array(bytes)
        value[6] = (value[6] & 0x0f) | 0x40
        value[8] = (value[8] & 0x3f) | 0x80
        let hex = value.map { String(format: "%02x", $0) }
        return hex[0...3].joined() + "-" + hex[4...5].joined() + "-" + hex[6...7].joined() + "-" + hex[8...9].joined() + "-" + hex[10...15].joined()
    }
}

private extension Data {
    init?(hexLowercase value: String) {
        guard value.count.isMultiple(of: 2), value.unicodeScalars.allSatisfy({
            ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102)
        }) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self = Data(bytes)
    }
}
