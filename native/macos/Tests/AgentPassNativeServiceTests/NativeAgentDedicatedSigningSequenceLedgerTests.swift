import Foundation
import Testing
@testable import AgentPassNativeService

private let sequenceSessionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
private let otherSequenceSessionID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
private let sequenceProcessHash = String(repeating: "a", count: 64)
private let otherSequenceProcessHash = String(repeating: "b", count: 64)

private func sequenceBinding(
    sessionID: String = sequenceSessionID,
    processBindingHash: String = sequenceProcessHash
) throws -> NativeAgentDedicatedSigningSequenceBinding {
    try NativeAgentDedicatedSigningSequenceBinding(
        sessionID: sessionID,
        processBindingHash: processBindingHash
    )
}

private final class SequenceResults: @unchecked Sendable {
    private let lock = NSLock()
    private var consumed: [UInt64] = []
    private var errors: [NativeAgentDedicatedSigningSequenceLedgerError] = []

    func append(_ result: Result<NativeAgentDedicatedSigningSequenceConsumption, Error>) {
        lock.lock()
        defer { lock.unlock() }
        switch result {
        case let .success(receipt):
            consumed.append(receipt.sequence)
        case let .failure(error):
            errors.append(
                (error as? NativeAgentDedicatedSigningSequenceLedgerError)
                    ?? .invalidated
            )
        }
    }

    func snapshot() -> (consumed: [UInt64], errors: [NativeAgentDedicatedSigningSequenceLedgerError]) {
        lock.lock()
        defer { lock.unlock() }
        return (consumed, errors)
    }
}

@Test("Dedicated sequence ledger starts at one and binds canonical identity")
func dedicatedSequenceLedgerStartsAtOne() throws {
    let binding = try sequenceBinding()
    let ledger = try NativeAgentDedicatedSigningSequenceLedger(
        binding: binding,
        maximumSequence: 3
    )

    let initial = ledger.snapshot()
    #expect(initial.binding == binding)
    #expect(initial.nextSequence == 1)
    #expect(initial.maximumSequence == 3)
    #expect(initial.isInvalidated == false)
    #expect(initial.isExhausted == false)

    let receipt = try ledger.consume(binding: binding, sequence: 1)
    #expect(receipt.binding == binding)
    #expect(receipt.sequence == 1)
    #expect(receipt.isTerminal == false)
    #expect(ledger.snapshot().nextSequence == 2)
}

@Test("Dedicated sequence ledger rejects replay, skip, and wrong binding")
func dedicatedSequenceLedgerRejectsInvalidConsumption() throws {
    let binding = try sequenceBinding()
    let ledger = try NativeAgentDedicatedSigningSequenceLedger(
        binding: binding,
        maximumSequence: 4
    )

    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.skipped) {
        _ = try ledger.consume(binding: binding, sequence: 2)
    }
    #expect(ledger.snapshot().nextSequence == 1)

    _ = try ledger.consume(binding: binding, sequence: 1)
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.replay) {
        _ = try ledger.consume(binding: binding, sequence: 1)
    }
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.skipped) {
        _ = try ledger.consume(binding: binding, sequence: 3)
    }

    let wrongSession = try sequenceBinding(sessionID: otherSequenceSessionID)
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.wrongSession) {
        _ = try ledger.consume(binding: wrongSession, sequence: 2)
    }

    let wrongProcess = try sequenceBinding(processBindingHash: otherSequenceProcessHash)
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.wrongProcessBindingHash) {
        _ = try ledger.consume(binding: wrongProcess, sequence: 2)
    }
    #expect(ledger.snapshot().nextSequence == 2)
}

@Test("Dedicated sequence ledger rejects overflow and makes the bound finite range terminal")
func dedicatedSequenceLedgerRejectsOverflow() throws {
    let binding = try sequenceBinding()
    let ledger = try NativeAgentDedicatedSigningSequenceLedger(
        binding: binding,
        maximumSequence: 2
    )

    _ = try ledger.consume(binding: binding, sequence: 1)
    let finalReceipt = try ledger.consume(binding: binding, sequence: 2)
    #expect(finalReceipt.isTerminal)

    let exhausted = ledger.snapshot()
    #expect(exhausted.nextSequence == nil)
    #expect(exhausted.isExhausted)
    #expect(exhausted.isInvalidated == false)

    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.overflow) {
        _ = try ledger.consume(binding: binding, sequence: 3)
    }
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.overflow) {
        _ = try ledger.consume(binding: binding, sequence: 2)
    }
}

@Test("Dedicated sequence ledger invalidation is terminal")
func dedicatedSequenceLedgerInvalidationIsTerminal() throws {
    let binding = try sequenceBinding()
    let ledger = try NativeAgentDedicatedSigningSequenceLedger(
        binding: binding,
        maximumSequence: 4
    )

    _ = try ledger.consume(binding: binding, sequence: 1)
    ledger.invalidate()
    ledger.invalidate()

    let invalidated = ledger.snapshot()
    #expect(invalidated.nextSequence == nil)
    #expect(invalidated.isInvalidated)
    #expect(invalidated.isExhausted == false)

    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.invalidated) {
        _ = try ledger.consumeNext(binding: binding)
    }
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.invalidated) {
        _ = try ledger.consume(binding: binding, sequence: 2)
    }
}

@Test("Dedicated sequence ledger validates canonical construction and bounds")
func dedicatedSequenceLedgerValidatesInputs() throws {
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.invalidSessionID) {
        _ = try NativeAgentDedicatedSigningSequenceBinding(
            sessionID: sequenceSessionID.uppercased(),
            processBindingHash: sequenceProcessHash
        )
    }
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.invalidProcessBindingHash) {
        _ = try NativeAgentDedicatedSigningSequenceBinding(
            sessionID: sequenceSessionID,
            processBindingHash: sequenceProcessHash.uppercased()
        )
    }
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.invalidProcessBindingHash) {
        _ = try NativeAgentDedicatedSigningSequenceBinding(
            sessionID: sequenceSessionID,
            processBindingHash: "not-a-process-hash"
        )
    }
    #expect(throws: NativeAgentDedicatedSigningSequenceLedgerError.invalidMaximumSequence) {
        _ = try NativeAgentDedicatedSigningSequenceLedger(
            binding: try sequenceBinding(),
            maximumSequence: 0
        )
    }

    let digestBinding = try NativeAgentDedicatedSigningSequenceBinding(
        sessionID: sequenceSessionID,
        processBindingHash: Data(repeating: 0xab, count: 32)
    )
    #expect(digestBinding.processBindingHash == String(repeating: "ab", count: 32))
}

@Test("Dedicated sequence ledger is atomic under concurrent next-sequence consumption")
func dedicatedSequenceLedgerIsThreadSafe() throws {
    let binding = try sequenceBinding()
    let count: UInt64 = 128
    let ledger = try NativeAgentDedicatedSigningSequenceLedger(
        binding: binding,
        maximumSequence: count
    )
    let results = SequenceResults()

    DispatchQueue.concurrentPerform(iterations: Int(count)) { _ in
        do {
            results.append(.success(try ledger.consumeNext(binding: binding)))
        } catch {
            results.append(.failure(error))
        }
    }

    let result = results.snapshot()
    #expect(result.errors.isEmpty)
    #expect(result.consumed.sorted() == Array(1...count))
    #expect(ledger.snapshot().isExhausted)
}
