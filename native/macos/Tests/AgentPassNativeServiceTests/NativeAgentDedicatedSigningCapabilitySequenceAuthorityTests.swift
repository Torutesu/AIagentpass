import Foundation
import Testing
@testable import AgentPassNativeService

private let authoritySessionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
private let authorityAgentID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
private let otherAuthoritySessionID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
private let statementHashA = String(repeating: "a", count: 64)
private let statementHashB = String(repeating: "b", count: 64)

private func authorityBinding(
    coordinatorSessionID: String = authoritySessionID,
    agentID: String = authorityAgentID
) throws -> NativeAgentDedicatedSigningCapabilitySequenceBinding {
    try NativeAgentDedicatedSigningCapabilitySequenceBinding(
        coordinatorSessionID: coordinatorSessionID,
        agentID: agentID
    )
}

private func authority(
    maximumSequence: UInt64 = NativeAgentDedicatedSigningCapabilitySequenceAuthority.defaultMaximumSequence
) throws -> NativeAgentDedicatedSigningCapabilitySequenceAuthority {
    try NativeAgentDedicatedSigningCapabilitySequenceAuthority(
        binding: try authorityBinding(),
        maximumSequence: maximumSequence
    )
}

@Test("Dedicated capability sequence authority starts uninitialized and is coordinator-bound")
func capabilitySequenceAuthorityStartsUninitialized() throws {
    let binding = try authorityBinding()
    let authority = try NativeAgentDedicatedSigningCapabilitySequenceAuthority(binding: binding)
    let snapshot = authority.snapshot()

    #expect(snapshot.binding == binding)
    #expect(snapshot.acceptedSequence == nil)
    #expect(snapshot.acceptedStatementHash == nil)
    #expect(snapshot.isInitialized == false)
    #expect(snapshot.isInvalidated == false)
    #expect(authority.maximumSequence == NativeAgentDedicatedSigningCapabilitySequenceAuthority.defaultMaximumSequence)
}

@Test("First capability sequence requires a trusted bootstrap and later accepts are monotonic")
func capabilitySequenceAuthorityBootstrapsAndAdvances() throws {
    let authority = try authority(maximumSequence: 20)
    let first = try authority.prepare(sequence: 7, statementHash: statementHashA)

    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.bootstrapRequired) {
        _ = try authority.accept(first)
    }
    #expect(authority.snapshot().isInitialized == false)

    let bootstrap = NativeAgentDedicatedSigningCapabilityTrustedBootstrap()
    let bootstrapped = try authority.accept(first, trustedBootstrap: bootstrap)
    #expect(bootstrapped.sequence == 7)
    #expect(bootstrapped.statementHash == statementHashA)
    #expect(bootstrapped.disposition == .bootstrapped)

    let replay = try authority.accept(
        try authority.prepare(sequence: 7, statementHash: statementHashA)
    )
    #expect(replay.disposition == .replayed)

    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.statementHashConflict) {
        _ = try authority.prepare(sequence: 7, statementHash: statementHashB)
    }
    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.staleSequence) {
        _ = try authority.prepare(sequence: 6, statementHash: statementHashA)
    }

    let advanced = try authority.accept(
        try authority.prepare(sequence: 12, statementHash: statementHashB)
    )
    #expect(advanced.disposition == .advanced)
    #expect(authority.snapshot().acceptedSequence == 12)
    #expect(authority.snapshot().acceptedStatementHash == statementHashB)
}

@Test("Preparation cannot cross authority or coordinator/Agent binding")
func capabilitySequenceAuthorityRejectsCrossAuthorityPreparation() throws {
    let firstAuthority = try authority()
    let secondAuthority = try NativeAgentDedicatedSigningCapabilitySequenceAuthority(
        binding: try authorityBinding(coordinatorSessionID: otherAuthoritySessionID)
    )
    let preparation = try firstAuthority.prepare(sequence: 1, statementHash: statementHashA)

    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidPreparation) {
        _ = try secondAuthority.accept(
            preparation,
            trustedBootstrap: NativeAgentDedicatedSigningCapabilityTrustedBootstrap()
        )
    }
    #expect(secondAuthority.snapshot().isInitialized == false)

    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidCoordinatorSessionID) {
        _ = try NativeAgentDedicatedSigningCapabilitySequenceBinding(
            coordinatorSessionID: authoritySessionID.uppercased(),
            agentID: authorityAgentID
        )
    }
    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidAgentID) {
        _ = try NativeAgentDedicatedSigningCapabilitySequenceBinding(
            coordinatorSessionID: authoritySessionID,
            agentID: "not-an-agent"
        )
    }
}

@Test("Sequence authority rejects invalid hashes, zero, and overflow without changing state")
func capabilitySequenceAuthorityRejectsMalformedCandidates() throws {
    let authority = try authority(maximumSequence: 2)

    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidSequence) {
        _ = try authority.prepare(sequence: 0, statementHash: statementHashA)
    }
    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidStatementHash) {
        _ = try authority.prepare(sequence: 1, statementHash: statementHashA.uppercased())
    }
    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidStatementHash) {
        _ = try authority.prepare(sequence: 1, statementHash: "short")
    }
    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.overflow) {
        _ = try authority.prepare(sequence: 3, statementHash: statementHashA)
    }

    let bootstrapped = try authority.accept(
        try authority.prepare(sequence: 2, statementHash: statementHashA),
        trustedBootstrap: NativeAgentDedicatedSigningCapabilityTrustedBootstrap()
    )
    #expect(bootstrapped.disposition == .bootstrapped)
    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.overflow) {
        _ = try authority.prepare(sequence: 3, statementHash: statementHashA)
    }
    #expect(authority.snapshot().acceptedSequence == 2)
}

@Test("Concurrent accepts of the same bootstrap are atomic and idempotent")
func capabilitySequenceAuthorityIsThreadSafe() throws {
    let authority = try authority(maximumSequence: 4)
    let preparation = try authority.prepare(sequence: 1, statementHash: statementHashA)
    let bootstrap = NativeAgentDedicatedSigningCapabilityTrustedBootstrap()
    let results = SequenceAuthorityResults()

    DispatchQueue.concurrentPerform(iterations: 128) { _ in
        do {
            results.append(.success(try authority.accept(preparation, trustedBootstrap: bootstrap)))
        } catch {
            results.append(.failure(error))
        }
    }

    let result = results.snapshot()
    #expect(result.errors.isEmpty)
    #expect(result.dispositions.filter { $0 == .bootstrapped }.count == 1)
    #expect(result.dispositions.filter { $0 == .replayed }.count == 127)
    #expect(authority.snapshot().acceptedSequence == 1)
    #expect(authority.snapshot().acceptedStatementHash == statementHashA)
}

@Test("Invalidation is terminal")
func capabilitySequenceAuthorityInvalidationIsTerminal() throws {
    let authority = try authority()
    authority.invalidate()
    authority.invalidate()

    #expect(authority.snapshot().isInvalidated)
    #expect(throws: NativeAgentDedicatedSigningCapabilitySequenceAuthorityError.invalidated) {
        _ = try authority.prepare(sequence: 1, statementHash: statementHashA)
    }
}

private final class SequenceAuthorityResults: @unchecked Sendable {
    private let lock = NSLock()
    private var accepted: [NativeAgentDedicatedSigningCapabilitySequenceAcceptanceDisposition] = []
    private var failures: [NativeAgentDedicatedSigningCapabilitySequenceAuthorityError] = []

    func append(
        _ result: Result<NativeAgentDedicatedSigningCapabilitySequenceAcceptance, Error>
    ) {
        lock.lock()
        defer { lock.unlock() }
        switch result {
        case let .success(value):
            accepted.append(value.disposition)
        case let .failure(error):
            failures.append(
                (error as? NativeAgentDedicatedSigningCapabilitySequenceAuthorityError)
                    ?? .invalidPreparation
            )
        }
    }

    func snapshot() -> (
        dispositions: [NativeAgentDedicatedSigningCapabilitySequenceAcceptanceDisposition],
        errors: [NativeAgentDedicatedSigningCapabilitySequenceAuthorityError]
    ) {
        lock.lock()
        defer { lock.unlock() }
        return (accepted, failures)
    }
}
