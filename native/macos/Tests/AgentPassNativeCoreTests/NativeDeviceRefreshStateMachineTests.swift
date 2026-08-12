import Foundation
import Testing
@testable import AgentPassNativeCore

private let testOrganization = "11111111-1111-4111-8111-111111111111"
private let testDevice = "22222222-2222-4222-8222-222222222222"
private let otherDevice = "33333333-3333-4333-8333-333333333333"
private let testRefreshNonce = Data(repeating: 0x41, count: 16).base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")

private func refreshBinding(
    generation: Int64 = 1,
    sequence: Int64? = nil,
    statementHash: String? = nil,
    refreshNonce: String? = testRefreshNonce,
    deviceID: String = testDevice
) -> NativeDeviceRefreshBinding {
    NativeDeviceRefreshBinding(
        organizationID: testOrganization,
        deviceID: deviceID,
        generation: generation,
        sequence: sequence,
        statementHash: statementHash,
        refreshNonce: refreshNonce
    )
}

private func bundleBinding(
    generation: Int64 = 1,
    sequence: Int64 = 1,
    hashByte: Character = "a",
    deviceID: String = testDevice
) -> NativeDeviceRefreshBinding {
    refreshBinding(
        generation: generation,
        sequence: sequence,
        statementHash: String(repeating: hashByte, count: 64),
        deviceID: deviceID
    )
}

private final class MemoryRefreshStore: @unchecked Sendable, NativeDeviceRefreshSnapshotStore {
    var data: Data?
    var failLoad = false
    var failSave = false

    init(data: Data? = nil) {
        self.data = data
    }

    func load() throws -> Data? {
        if failLoad { throw TestStoreError.failed }
        return data
    }

    func save(_ canonicalSnapshot: Data) throws {
        if failSave { throw TestStoreError.failed }
        data = canonicalSnapshot
    }

    enum TestStoreError: Error {
        case failed
    }
}

private func makeFetchingMachine() throws -> NativeDeviceRefreshStateMachine {
    var machine = try NativeDeviceRefreshStateMachine(
        organizationID: testOrganization,
        deviceID: testDevice
    )
    _ = try machine.receiveHint(refreshBinding())
    _ = try machine.beginFetch()
    return machine
}

private func makeAppliedMachine() throws -> NativeDeviceRefreshStateMachine {
    var machine = try makeFetchingMachine()
    _ = try machine.receiveFetchedBundle(bundleBinding())
    _ = try machine.markVerificationSucceeded()
    _ = try machine.markStagingSucceeded()
    return machine
}

@Test func refreshMachineExposesTheExactClosedStateSet() {
    #expect(NativeDeviceRefreshMachineState.allCases.map(\.rawValue) == [
        "idle", "hinted", "poll_due", "fetching", "verifying", "staging",
        "applied", "blocked", "acknowledged"
    ])
    #expect(NativeDeviceRefreshStateMachineReasonCode.allCases.count >= 20)
}

@Test func refreshMachineFollowsTheLegalHappyPathAndPersistsOnlyBindings() throws {
    var machine = try NativeDeviceRefreshStateMachine(
        organizationID: testOrganization.uppercased(),
        deviceID: testDevice
    )
    #expect(machine.state == .idle)
    #expect(machine.binding.generation == 0)

    _ = try machine.receiveHint(refreshBinding(generation: 7))
    #expect(machine.state == .hinted)
    _ = try machine.beginFetch()
    #expect(machine.state == .fetching)
    _ = try machine.receiveFetchedBundle(bundleBinding(generation: 7, sequence: 42, hashByte: "b"))
    #expect(machine.state == .verifying)
    #expect(machine.binding.sequence == 42)
    #expect(machine.binding.statementHash == String(repeating: "b", count: 64))
    _ = try machine.markVerificationSucceeded()
    _ = try machine.markStagingSucceeded()
    _ = try machine.recordAcknowledgement()
    #expect(machine.state == .acknowledged)

    let data = try NativeDeviceRefreshSnapshotCodec.encode(machine.snapshot)
    let text = String(decoding: data, as: UTF8.self)
    #expect(text.contains("\"refresh_nonce\""))
    #expect(!text.contains("signature"))
    #expect(!text.contains("payload"))
    #expect(try NativeDeviceRefreshSnapshotCodec.decode(data) == machine.snapshot)
    _ = try machine.resetForNextPoll()
    let resetText = String(decoding: try NativeDeviceRefreshSnapshotCodec.encode(machine.snapshot), as: UTF8.self)
    #expect(resetText.contains("\"refresh_nonce\":null"))
}

@Test func refreshMachineMakesEverySuccessfulEventExactlyIdempotent() throws {
    var machine = try NativeDeviceRefreshStateMachine(
        organizationID: testOrganization,
        deviceID: testDevice
    )
    let events: [NativeDeviceRefreshEvent] = [
        .hint(refreshBinding()), .fetchStarted,
        .fetched(bundleBinding()), .verificationSucceeded,
        .stagingSucceeded, .acknowledgementDurablyRecorded,
        .resetForNextPoll
    ]

    for event in events {
        let first = try machine.apply(event)
        guard case .changed(let changedSnapshot) = first else {
            Issue.record("first application was not a state change")
            continue
        }
        let revision = machine.revision
        let second = try machine.apply(event)
        #expect(second == .duplicate(changedSnapshot))
        #expect(machine.revision == revision)
    }
    #expect(machine.state == .idle)
}

@Test func refreshMachineRejectsIllegalTransitionsWithoutChangingState() throws {
    var machine = try NativeDeviceRefreshStateMachine(
        organizationID: testOrganization,
        deviceID: testDevice
    )
    let original = machine.snapshot
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try machine.beginFetch()
    }
    #expect(machine.snapshot == original)

    _ = try machine.markPollDue()
    let pollDue = machine.snapshot
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try machine.recordAcknowledgement()
    }
    #expect(machine.snapshot == pollDue)
}

@Test func refreshMachineFailsClosedOnAudienceAndGenerationReplay() throws {
    var audienceMachine = try NativeDeviceRefreshStateMachine(
        organizationID: testOrganization,
        deviceID: testDevice
    )
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try audienceMachine.receiveHint(refreshBinding(deviceID: otherDevice))
    }
    #expect(audienceMachine.state == .blocked)
    #expect(audienceMachine.blockedReason == .audienceMismatch)

    var generationMachine = try NativeDeviceRefreshStateMachine(
        organizationID: testOrganization,
        deviceID: testDevice
    )
    _ = try generationMachine.receiveHint(refreshBinding(generation: 9))
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try generationMachine.receiveHint(refreshBinding(generation: 8))
    }
    #expect(generationMachine.state == .blocked)
    #expect(generationMachine.blockedReason == .generationRollback)
}

@Test func refreshMachineFailsClosedOnSequenceAndStatementSubstitution() throws {
    var machine = try makeFetchingMachine()
    _ = try machine.receiveFetchedBundle(bundleBinding(sequence: 20, hashByte: "a"))
    let beforeConflict = machine.snapshot

    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try machine.receiveFetchedBundle(bundleBinding(sequence: 20, hashByte: "b"))
    }
    #expect(machine.state == .blocked)
    #expect(machine.blockedReason == .statementHashConflict)
    #expect(machine.sequenceWatermark == beforeConflict.sequenceWatermark)

    var rollbackMachine = try makeFetchingMachine()
    _ = try rollbackMachine.receiveFetchedBundle(bundleBinding(sequence: 20, hashByte: "a"))
    _ = try rollbackMachine.markVerificationSucceeded()
    _ = try rollbackMachine.markStagingSucceeded()
    _ = try rollbackMachine.recordAcknowledgement()
    _ = try rollbackMachine.resetForNextPoll()
    _ = try rollbackMachine.receiveHint(refreshBinding(generation: 2))
    _ = try rollbackMachine.beginFetch()
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try rollbackMachine.receiveFetchedBundle(bundleBinding(generation: 2, sequence: 19, hashByte: "c"))
    }
    #expect(rollbackMachine.state == .blocked)
    #expect(rollbackMachine.blockedReason == .sequenceRollback)
}

@Test func conflictingReplayIsDurablyBlockedBeforeTheErrorEscapes() throws {
    let source = try makeFetchingMachine()
    let store = MemoryRefreshStore(data: try NativeDeviceRefreshSnapshotCodec.encode(source.snapshot))
    var restarted = try NativeDeviceRefreshStateMachine.load(
        organizationID: testOrganization,
        deviceID: testDevice,
        from: store
    )

    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try restarted.apply(
            .fetched(bundleBinding(sequence: 1, hashByte: "a")),
            persistingTo: store
        )
        try restarted.apply(
            .fetched(bundleBinding(sequence: 1, hashByte: "b")),
            persistingTo: store
        )
    }
    let durable = try #require(store.data)
    let persisted = try NativeDeviceRefreshSnapshotCodec.decode(durable)
    #expect(persisted.state == .blocked)
    #expect(persisted.blockedReason == .statementHashConflict)
}

@Test func refreshMachineRestartsInPlaceAndResumesEveryDurableBoundary() throws {
    let machine = try makeFetchingMachine()
    let store = MemoryRefreshStore()

    _ = try machine.save(to: store)
    var restored = try NativeDeviceRefreshStateMachine.load(
        organizationID: testOrganization,
        deviceID: testDevice,
        from: store
    )
    #expect(restored.state == .fetching)
    _ = try restored.receiveFetchedBundle(bundleBinding(sequence: 5, hashByte: "d"))
    _ = try restored.save(to: store)

    restored = try NativeDeviceRefreshStateMachine.load(
        organizationID: testOrganization,
        deviceID: testDevice,
        from: store
    )
    #expect(restored.state == .verifying)
    _ = try restored.markVerificationSucceeded()
    _ = try restored.save(to: store)
    restored = try NativeDeviceRefreshStateMachine.load(
        organizationID: testOrganization,
        deviceID: testDevice,
        from: store
    )
    _ = try restored.markStagingSucceeded()
    _ = try restored.recordAcknowledgement()
    _ = try restored.save(to: store)

    let final = try NativeDeviceRefreshStateMachine.load(
        organizationID: testOrganization,
        deviceID: testDevice,
        from: store
    )
    #expect(final.state == .acknowledged)
    #expect(final.sequenceWatermark == 5)
    #expect(final.binding.statementHash == String(repeating: "d", count: 64))
}

@Test func refreshMachineCanDurablyResumeBlockedAndPreservesHighWaterMarks() throws {
    var machine = try makeFetchingMachine()
    _ = try machine.receiveFetchedBundle(bundleBinding(sequence: 11, hashByte: "e"))
    _ = try machine.markVerificationBlocked(.bundleSignatureInvalid)
    let store = MemoryRefreshStore()
    _ = try machine.save(to: store)

    var restored = try NativeDeviceRefreshStateMachine.load(
        organizationID: testOrganization,
        deviceID: testDevice,
        from: store
    )
    #expect(restored.state == .blocked)
    #expect(restored.blockedReason == .bundleSignatureInvalid)
    _ = try restored.recordAcknowledgement()
    _ = try restored.resetForNextPoll()
    #expect(restored.state == .idle)
    #expect(restored.sequenceWatermark == 11)
    #expect(restored.binding.sequence == nil)
    #expect(restored.binding.refreshNonce == nil)
}

@Test func periodicPollCanCompleteWithoutChangeOrReceiveANewerHint() throws {
    var machine = try NativeDeviceRefreshStateMachine(organizationID: testOrganization, deviceID: testDevice)
    _ = try machine.markPollDue()
    #expect(machine.state == .pollDue)
    _ = try machine.recordPollCompletedNoChange()
    #expect(machine.state == .idle)

    _ = try machine.markPollDue()
    _ = try machine.receiveHint(refreshBinding(generation: 2))
    #expect(machine.state == .hinted)
    #expect(machine.binding.refreshNonce == testRefreshNonce)
    _ = try machine.beginFetch()
    #expect(machine.state == .fetching)
}

@Test func sameGenerationNonceSubstitutionFailsClosed() throws {
    var machine = try NativeDeviceRefreshStateMachine(organizationID: testOrganization, deviceID: testDevice)
    _ = try machine.receiveHint(refreshBinding())
    let substituted = Data(repeating: 0x42, count: 16).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try machine.receiveHint(refreshBinding(refreshNonce: substituted))
    }
    #expect(machine.state == .blocked)
    #expect(machine.blockedReason == .conflictingReplay)
}

@Test func snapshotCodecIsCanonicalClosedAndRejectsAdversarialInputs() throws {
    let machine = try makeAppliedMachine()
    let canonical = try NativeDeviceRefreshSnapshotCodec.encode(machine.snapshot)
    #expect(try NativeDeviceRefreshSnapshotCodec.decode(canonical) == machine.snapshot)

    let padded = Data(([0x20] + Array(canonical) + [0x0a]))
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try NativeDeviceRefreshSnapshotCodec.decode(padded)
    }

    var unknown = try JSONSerialization.jsonObject(with: canonical) as! [String: Any]
    unknown["unexpected"] = "attacker-controlled"
    let unknownData = try NativeStrictJSON.data(unknown)
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try NativeDeviceRefreshSnapshotCodec.decode(unknownData)
    }

    let canonicalText = String(decoding: canonical, as: UTF8.self)
    let duplicateText = canonicalText.replacingOccurrences(
        of: "\"revision\":",
        with: "\"revision\":",
        options: [],
        range: nil
    )
    let duplicateData = Data((duplicateText.dropLast() + ",\"revision\":1}").utf8)
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try NativeDeviceRefreshSnapshotCodec.decode(duplicateData)
    }

    var invalid = try JSONSerialization.jsonObject(with: canonical) as! [String: Any]
    invalid["blocked_reason"] = "not-a-bounded-code"
    let invalidData = try NativeStrictJSON.data(invalid)
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try NativeDeviceRefreshSnapshotCodec.decode(invalidData)
    }
}

@Test func snapshotCodecRejectsImpossibleCrossFieldCombinations() throws {
    let machine = try makeAppliedMachine()
    var object = try JSONSerialization.jsonObject(
        with: NativeDeviceRefreshSnapshotCodec.encode(machine.snapshot)
    ) as! [String: Any]

    object["sequence"] = NSNull()
    object["statement_hash"] = NSNull()
    let noBundle = try NativeStrictJSON.data(object)
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try NativeDeviceRefreshSnapshotCodec.decode(noBundle)
    }

    object = try JSONSerialization.jsonObject(
        with: NativeDeviceRefreshSnapshotCodec.encode(machine.snapshot)
    ) as! [String: Any]
    object["sequence_watermark"] = 0
    let lowerWatermark = try NativeStrictJSON.data(object)
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try NativeDeviceRefreshSnapshotCodec.decode(lowerWatermark)
    }
}

@Test func persistenceFailuresAndErrorDescriptionsNeverLeakInput() throws {
    var machine = try NativeDeviceRefreshStateMachine(
        organizationID: testOrganization,
        deviceID: testDevice
    )
    let store = MemoryRefreshStore()
    store.failSave = true
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try machine.apply(.pollDue, persistingTo: store)
    }
    #expect(machine.state == .idle)

    let loadStore = MemoryRefreshStore()
    loadStore.failLoad = true
    #expect(throws: NativeDeviceRefreshStateMachineError.self) {
        try NativeDeviceRefreshStateMachine.load(
            organizationID: testOrganization,
            deviceID: testDevice,
            from: loadStore
        )
    }

    let marker = "SECRET_NONCE_AND_PRIVATE_PAYLOAD_4f6c8d"
    let error = NativeDeviceRefreshStateMachineError(.statementHashConflict, failClosed: true)
    #expect(!(error.errorDescription ?? "").contains(marker))
    #expect(!(error.errorDescription ?? "").contains(String(repeating: "a", count: 64)))
}
