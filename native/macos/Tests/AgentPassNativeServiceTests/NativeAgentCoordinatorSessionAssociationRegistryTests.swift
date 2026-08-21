@testable import AgentPassNativeService
import Foundation
import Testing
@testable import AgentPassNativeCore

private final class TestCoordinatorReference: NativeAgentCoordinatorSessionReference, @unchecked Sendable {}

private final class LockedInt: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func increment() {
        lock.withLock { value += 1 }
    }

    func set(_ value: Int) {
        lock.withLock { self.value = value }
    }

    var read: Int {
        lock.withLock { value }
    }
}

private let associationCoordinator = TestCoordinatorReference()

private func associationBinding(
    processByte: UInt8 = 0x31,
    ancestryByte: UInt8 = 0x32,
    worktreeByte: UInt8 = 0x33,
    controlSequence: Int64 = 7,
    authorityGeneration: Int64 = 11,
    keyGeneration: Int64 = 13
) throws -> NativeAgentSessionBinding {
    try NativeAgentSessionBinding(
        agentID: "11111111-1111-4111-8111-111111111111",
        deviceID: "22222222-2222-4222-8222-222222222222",
        processBindingDigest: Data(repeating: processByte, count: 32),
        ancestryBindingDigest: Data(repeating: ancestryByte, count: 32),
        worktreeBindingDigest: Data(repeating: worktreeByte, count: 32),
        controlSequence: controlSequence,
        authorityGeneration: authorityGeneration,
        keyGeneration: keyGeneration
    )
}

private func associationSessionID(_ index: Int) -> String {
    String(format: "%08x-0000-4000-8000-%012x", index, index)
}

@Test func associationRegistryIndexesByTheCompleteObservedBinding() throws {
    let registry = NativeAgentCoordinatorSessionAssociationRegistry()
    let binding = try associationBinding()
    let registered = try registry.register(
        sessionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        binding: binding,
        coordinator: associationCoordinator
    )

    let found = try #require(registry.lookup(binding: binding))
    #expect(found === registered)
    #expect(found.sessionID == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    #expect(found.binding == binding)
    #expect(found.coordinator === associationCoordinator)

    let changedFields: [NativeAgentSessionBinding] = [
        try associationBinding(processByte: 0x41),
        try associationBinding(ancestryByte: 0x42),
        try associationBinding(worktreeByte: 0x43),
        try associationBinding(controlSequence: 8),
        try associationBinding(authorityGeneration: 12),
        try associationBinding(keyGeneration: 14)
    ]
    for changed in changedFields {
        #expect(registry.lookup(binding: changed) == nil)
    }

    #expect(registry.lookup(
        processBindingDigest: binding.processBindingDigest,
        ancestryBindingDigest: binding.ancestryBindingDigest,
        worktreeBindingDigest: binding.worktreeBindingDigest) === registered)
    #expect(registry.lookup(
        processBindingDigest: Data(repeating: 0xff, count: 32),
        ancestryBindingDigest: binding.ancestryBindingDigest,
        worktreeBindingDigest: binding.worktreeBindingDigest) == nil)
}

@Test func associationRegistryRejectsInvalidAndReusedSessionIDs() throws {
    let registry = NativeAgentCoordinatorSessionAssociationRegistry()
    let binding = try associationBinding()

    #expect(throws: NativeAgentCoordinatorSessionAssociationRegistryError.invalidSessionID) {
        _ = try registry.register(
            sessionID: "caller-controlled-session",
            binding: binding,
            coordinator: associationCoordinator
        )
    }

    _ = try registry.register(
        sessionID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        binding: binding,
        coordinator: associationCoordinator
    )
    #expect(throws: NativeAgentCoordinatorSessionAssociationRegistryError.duplicateBinding) {
        _ = try registry.register(
            sessionID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            binding: binding,
            coordinator: associationCoordinator
        )
    }
    #expect(registry.activeCount == 1)

    let differentBinding = try associationBinding(processByte: 0x51)
    #expect(throws: NativeAgentCoordinatorSessionAssociationRegistryError.duplicateSession) {
        _ = try registry.register(
            sessionID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            binding: differentBinding,
            coordinator: associationCoordinator
        )
    }
    #expect(registry.lookup(binding: differentBinding) == nil)
}

@Test func associationRegistryRemovalAndInvalidationAreTerminalForRetainedHandles() throws {
    let registry = NativeAgentCoordinatorSessionAssociationRegistry()
    let removedBinding = try associationBinding(processByte: 0x61)
    let removed = try registry.register(
        sessionID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        binding: removedBinding,
        coordinator: associationCoordinator
    )
    #expect(registry.remove(binding: removedBinding) === removed)
    #expect(removed.lifecycleState == .removed)
    #expect(!removed.isActive)
    #expect(registry.lookup(binding: removedBinding) == nil)
    #expect(registry.remove(binding: removedBinding) == nil)

    let invalidatedBinding = try associationBinding(processByte: 0x71)
    let invalidated = try registry.register(
        sessionID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        binding: invalidatedBinding,
        coordinator: associationCoordinator
    )
    #expect(registry.invalidate(binding: invalidatedBinding) === invalidated)
    #expect(invalidated.lifecycleState == .invalidated)
    #expect(!invalidated.isActive)
    #expect(registry.lookup(binding: invalidatedBinding) == nil)

    #expect(throws: NativeAgentCoordinatorSessionAssociationRegistryError.duplicateSession) {
        _ = try registry.register(
            sessionID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            binding: try associationBinding(processByte: 0x72),
            coordinator: associationCoordinator
        )
    }
}

@Test func associationRegistryRegistrationIsAtomicUnderConcurrentDistinctBindings() throws {
    let registry = NativeAgentCoordinatorSessionAssociationRegistry()
    let count = 64
    let errors = LockedInt()

    DispatchQueue.concurrentPerform(iterations: count) { index in
        do {
            let binding = try associationBinding(
                processByte: UInt8(index),
                ancestryByte: UInt8(index &+ 64),
                worktreeByte: UInt8(index &+ 128),
                controlSequence: Int64(index + 1),
                authorityGeneration: Int64(index + 1),
                keyGeneration: Int64(index + 1)
            )
            _ = try registry.register(
                sessionID: associationSessionID(index),
                binding: binding,
                coordinator: associationCoordinator
            )
        } catch {
            errors.increment()
        }
    }

    #expect(errors.read == 0)
    #expect(registry.activeCount == count)
    for index in 0..<count {
        let binding = try associationBinding(
            processByte: UInt8(index),
            ancestryByte: UInt8(index &+ 64),
            worktreeByte: UInt8(index &+ 128),
            controlSequence: Int64(index + 1),
            authorityGeneration: Int64(index + 1),
            keyGeneration: Int64(index + 1)
        )
        #expect(registry.lookup(binding: binding)?.sessionID == associationSessionID(index))
    }
}

@Test func associationRegistryAllowsExactlyOneConcurrentRegistrationForOneBinding() throws {
    let registry = NativeAgentCoordinatorSessionAssociationRegistry()
    let binding = try associationBinding(processByte: 0x81)
    let successes = LockedInt()

    DispatchQueue.concurrentPerform(iterations: 32) { index in
        do {
            _ = try registry.register(
                sessionID: associationSessionID(index + 100),
                binding: binding,
                coordinator: associationCoordinator
            )
            successes.increment()
        } catch NativeAgentCoordinatorSessionAssociationRegistryError.duplicateBinding {
            // Expected for every registration after the atomic winner.
        } catch {
            successes.set(-100)
        }
    }

    #expect(successes.read == 1)
    #expect(registry.activeCount == 1)
    #expect(registry.lookup(binding: binding) != nil)
}
