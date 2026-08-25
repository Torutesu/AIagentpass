import CryptoKit
import Dispatch
import Foundation
import Testing
@testable import AgentPassNativeCore

private final class BootstrapRandom: NativeAgentRandomBytesGenerating, @unchecked Sendable {
    private let lock = NSLock()
    private var counter: UInt8 = 0
    func randomBytes(count: Int) throws -> Data {
        lock.withLock {
            counter &+= 1
            return Data(repeating: counter, count: count)
        }
    }
}

private struct ShortBootstrapRandom: NativeAgentRandomBytesGenerating {
    func randomBytes(count: Int) throws -> Data { Data(repeating: 1, count: max(0, count - 1)) }
}

private final class BootstrapChallengeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [NativeAgentBootstrapChallenge] = []
    func append(_ value: NativeAgentBootstrapChallenge) { lock.withLock { storage.append(value) } }
    var values: [NativeAgentBootstrapChallenge] { lock.withLock { storage } }
}

private func bootstrapBinding() throws -> NativeAgentBootstrapConnectionBinding {
    try NativeAgentBootstrapConnectionBinding(
        connectionTokenIdentity: String(repeating: "1", count: 64),
        processBindingHash: String(repeating: "2", count: 64),
        ancestryBindingHash: String(repeating: "3", count: 64),
        bootIdentityHash: String(repeating: "4", count: 64)
    )
}

private func beginBootstrap(_ store: NativeAgentBootstrapChallengeStore, wall: Int64 = 1_000_000, monotonic: UInt64 = 2_000_000) throws -> NativeAgentBootstrapChallenge {
    try store.begin(
        agentID: "11111111-1111-4111-8111-111111111111",
        adapterKind: .claudeCode,
        requestedTTLSeconds: 600,
        clientNonce: Data(repeating: 9, count: 32),
        connectionBinding: bootstrapBinding(),
        nowMilliseconds: wall,
        nowMonotonicNanoseconds: monotonic
    )
}

@Test func bootstrapChallengeIsCanonicalBoundedAndOneTime() throws {
    let store = NativeAgentBootstrapChallengeStore(random: BootstrapRandom())
    let challenge = try beginBootstrap(store)
    #expect((AgentPassAgentBootstrapResponse.minimumChallengeBytes...AgentPassAgentBootstrapResponse.maximumChallengeBytes).contains(challenge.challenge.count))
    #expect(challenge.challenge.starts(with: Data("AgentPass-Agent-Bootstrap-v1\0".utf8)))
    let visible = String(decoding: challenge.challenge, as: UTF8.self)
    #expect(!visible.contains("11111111-1111-4111-8111-111111111111"))
    #expect(!visible.contains(String(repeating: "1", count: 64)))
    #expect(!visible.contains(String(repeating: "2", count: 64)))

    let evidence = try store.consume(bootstrapID: challenge.bootstrapID, nowMilliseconds: 1_001_000, nowMonotonicNanoseconds: 3_000_000)
    #expect(evidence.bootstrapID == challenge.bootstrapID)
    #expect(evidence.connectionBinding.processBindingHash == String(repeating: "2", count: 64))
    #expect(evidence.challengeHash == SHA256.hash(data: challenge.challenge).map { String(format: "%02x", $0) }.joined())
    #expect(throws: NativeAgentBootstrapChallengeError.challengeMissing) {
        _ = try store.consume(bootstrapID: challenge.bootstrapID, nowMilliseconds: 1_001_000, nowMonotonicNanoseconds: 3_000_000)
    }
}

@Test func bootstrapRejectsMalformedRandomProviderOutput() throws {
    let store = NativeAgentBootstrapChallengeStore(random: ShortBootstrapRandom())
    #expect(throws: NativeAgentBootstrapChallengeError.randomUnavailable) {
        _ = try beginBootstrap(store)
    }
}

@Test func concurrentReplacementLeavesExactlyOneConsumableChallenge() throws {
    let store = NativeAgentBootstrapChallengeStore(random: BootstrapRandom())
    let box = BootstrapChallengeBox()
    DispatchQueue.concurrentPerform(iterations: 32) { _ in
        if let value = try? beginBootstrap(store) {
            box.append(value)
        }
    }
    let values = box.values
    #expect(values.count == 32)
    let final = try beginBootstrap(store)
    #expect(try store.consume(bootstrapID: final.bootstrapID, nowMilliseconds: 1_000_001, nowMonotonicNanoseconds: 2_000_001).bootstrapID == final.bootstrapID)
    for value in values {
        #expect(throws: NativeAgentBootstrapChallengeError.challengeMissing) {
            _ = try store.consume(bootstrapID: value.bootstrapID, nowMilliseconds: 1_000_001, nowMonotonicNanoseconds: 2_000_001)
        }
    }
}

@Test func replacementInvalidatesPriorChallenge() throws {
    let store = NativeAgentBootstrapChallengeStore(random: BootstrapRandom())
    let first = try beginBootstrap(store)
    let second = try beginBootstrap(store)
    #expect(first.bootstrapID != second.bootstrapID)
    #expect(throws: NativeAgentBootstrapChallengeError.challengeMismatch) {
        _ = try store.consume(bootstrapID: first.bootstrapID, nowMilliseconds: 1_001_000, nowMonotonicNanoseconds: 3_000_000)
    }
    #expect(throws: NativeAgentBootstrapChallengeError.challengeMissing) {
        _ = try store.consume(bootstrapID: second.bootstrapID, nowMilliseconds: 1_001_000, nowMonotonicNanoseconds: 3_000_000)
    }
}

@Test func mismatchAndExpiryConsumePendingState() throws {
    let store = NativeAgentBootstrapChallengeStore(random: BootstrapRandom())
    let value = try beginBootstrap(store)
    #expect(throws: NativeAgentBootstrapChallengeError.challengeMismatch) {
        _ = try store.consume(bootstrapID: "77777777-7777-4777-8777-777777777777", nowMilliseconds: 1_000_001, nowMonotonicNanoseconds: 2_000_001)
    }
    #expect(throws: NativeAgentBootstrapChallengeError.challengeMissing) {
        _ = try store.consume(bootstrapID: value.bootstrapID, nowMilliseconds: 1_000_001, nowMonotonicNanoseconds: 2_000_001)
    }

    let expired = try beginBootstrap(store)
    #expect(throws: NativeAgentBootstrapChallengeError.challengeExpired) {
        _ = try store.consume(bootstrapID: expired.bootstrapID, nowMilliseconds: 1_060_001, nowMonotonicNanoseconds: 60_002_000_001)
    }
}

@Test func wallOrMonotonicRollbackFailsClosed() throws {
    let store = NativeAgentBootstrapChallengeStore(random: BootstrapRandom())
    let first = try beginBootstrap(store)
    #expect(throws: NativeAgentBootstrapChallengeError.challengeExpired) {
        _ = try store.consume(bootstrapID: first.bootstrapID, nowMilliseconds: 999_999, nowMonotonicNanoseconds: 2_000_001)
    }
    let second = try beginBootstrap(store)
    #expect(throws: NativeAgentBootstrapChallengeError.challengeExpired) {
        _ = try store.consume(bootstrapID: second.bootstrapID, nowMilliseconds: 1_000_001, nowMonotonicNanoseconds: 1_999_999)
    }
}

@Test func bootstrapRejectsMalformedBindingInputAndTimeOverflow() throws {
    #expect(throws: NativeAgentBootstrapChallengeError.invalidConnectionBinding) {
        _ = try NativeAgentBootstrapConnectionBinding(connectionTokenIdentity: "ABC", processBindingHash: String(repeating: "2", count: 64), ancestryBindingHash: String(repeating: "3", count: 64), bootIdentityHash: String(repeating: "4", count: 64))
    }
    let store = NativeAgentBootstrapChallengeStore(random: BootstrapRandom())
    #expect(throws: NativeAgentBootstrapChallengeError.invalidTime) {
        _ = try beginBootstrap(store, wall: Int64.max, monotonic: 1)
    }
    #expect(throws: NativeAgentBootstrapChallengeError.invalidTime) {
        _ = try beginBootstrap(store, wall: 1, monotonic: UInt64.max)
    }
}
