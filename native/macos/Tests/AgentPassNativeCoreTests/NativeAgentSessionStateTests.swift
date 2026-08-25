import Foundation
import Testing
@testable import AgentPassNativeCore

private let sessionRecordID = "session-000000000000000000000000000000000000000000000000000000000000"

private let expectedSuccessors: [NativeAgentSessionState: Set<NativeAgentSessionState>] = [
    .none: [.challengePending],
    .challengePending: [.active, .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged, .closed],
    .active: [.requestReserved, .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged, .closed],
    .requestReserved: [.active, .signingIntent, .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged, .closed],
    .signingIntent: [.active, .signed, .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged, .outcomeUnknown],
    .signed: [.active, .closed],
    .expired: [],
    .revoked: [],
    .processLost: [],
    .worktreeLost: [],
    .controlChanged: [],
    .keyChanged: [],
    .outcomeUnknown: [],
    .closed: []
]

private func makeRecord(
    state: NativeAgentSessionState = .none,
    updatedAtMilliseconds: Int64 = 1_000,
    revision: UInt64 = 0
) throws -> NativeAgentSessionRecord {
    try NativeAgentSessionRecord(
        sessionID: sessionRecordID,
        state: state,
        createdAtMilliseconds: 1_000,
        updatedAtMilliseconds: updatedAtMilliseconds,
        expiresAtMilliseconds: 61_000,
        signatureBudget: 4,
        signaturesUsed: 1,
        revision: revision
    )
}

@Test func everyStatePairUsesTheExplicitClosedTransitionTable() {
    for from in NativeAgentSessionState.allCases {
        for to in NativeAgentSessionState.allCases {
            let expected = expectedSuccessors[from, default: []].contains(to)
            #expect(
                NativeAgentSessionTransitionValidator.isAllowed(from: from, to: to) == expected,
                "Unexpected transition \(from.rawValue) -> \(to.rawValue)"
            )
            #expect(
                NativeAgentSessionTransitionValidator.allowedSuccessors(for: from) == expectedSuccessors[from, default: []]
            )
        }
    }
}

@Test func everyTerminalStateCannotLeaveTerminal() {
    let terminalStates = NativeAgentSessionState.allCases.filter(\.isTerminal)
    #expect(terminalStates.count == 8)

    for state in terminalStates {
        for destination in NativeAgentSessionState.allCases {
            #expect(!NativeAgentSessionTransitionValidator.isAllowed(from: state, to: destination))
            #expect(
                NativeAgentSessionTransitionValidator.denialReason(from: state, to: destination) == .terminalState
            )
        }
    }
}

@Test func deniedTransitionReturnsStableReasonAndDoesNotMutateRecord() throws {
    let record = try makeRecord(state: .active)
    let before = record

    #expect(
        NativeAgentSessionTransitionValidator.denialReason(from: .active, to: .signed) == .invalidTransition
    )
    do {
        _ = try record.transitioning(to: .signed, atMilliseconds: 1_001)
        Issue.record("An unspecified transition was accepted")
    } catch let error as NativeAgentSessionTransitionError {
        #expect(error.reason == .invalidTransition)
    }
    #expect(record == before)
}

@Test func criticalHappyPathCanReturnToActiveOrCloseAfterSigning() throws {
    let states: [NativeAgentSessionState] = [
        .none, .challengePending, .active, .requestReserved, .signingIntent, .signed
    ]
    var record = try makeRecord()

    for (index, state) in states.dropFirst().enumerated() {
        record = try record.transitioning(to: state, atMilliseconds: Int64(1_001 + index))
    }
    #expect(record.state == .signed)
    #expect(record.revision == 5)

    let resumed = try record.transitioning(to: .active, atMilliseconds: 2_000)
    #expect(resumed.state == .active)
    #expect(resumed.revision == 6)
    let closed = try record.transitioning(to: .closed, atMilliseconds: 2_000)
    #expect(closed.state == .closed)
    #expect(closed.revision == 6)
}

@Test func preKeyFailureMayReleaseReservationBackToActiveButAmbiguousOutcomeIsTerminal() throws {
    var reserved = try makeRecord(state: .requestReserved)
    reserved = try reserved.transitioning(to: .active, atMilliseconds: 1_001)
    #expect(reserved.state == .active)

    let intent = try makeRecord(state: .signingIntent)
    let unknown = try intent.transitioning(to: .outcomeUnknown, atMilliseconds: 1_001)
    #expect(unknown.state == .outcomeUnknown)
    #expect(unknown.state.isTerminal)
    #expect(!NativeAgentSessionTransitionValidator.isAllowed(from: .outcomeUnknown, to: .active))
}

@Test func invalidationEdgesAreAvailableBeforeSigningAndNeverAfterSigned() {
    let invalidations: Set<NativeAgentSessionState> = [
        .expired, .revoked, .processLost, .worktreeLost, .controlChanged, .keyChanged
    ]
    let preSigningStates: Set<NativeAgentSessionState> = [
        .challengePending, .active, .requestReserved, .signingIntent
    ]

    for source in preSigningStates {
        for destination in invalidations {
            #expect(NativeAgentSessionTransitionValidator.isAllowed(from: source, to: destination))
        }
    }
    for destination in invalidations {
        #expect(!NativeAgentSessionTransitionValidator.isAllowed(from: .signed, to: destination))
    }
}

@Test func recordIsBoundedImmutableCodableAndContainsNoProcessAuthority() throws {
    let record = try makeRecord(state: .active, updatedAtMilliseconds: 2_000, revision: 9)
    #expect(record.remainingSignatureBudget == 3)

    let encoded = try JSONEncoder().encode(record)
    let decoded = try JSONDecoder().decode(NativeAgentSessionRecord.self, from: encoded)
    #expect(decoded == record)
    #expect(String(decoding: encoded, as: UTF8.self).contains("process") == false)
    #expect(String(decoding: encoded, as: UTF8.self).contains("payload") == false)
    #expect(String(decoding: encoded, as: UTF8.self).contains("secret") == false)
}

@Test func recordRejectsUnboundedOrInconsistentValues() {
    #expect(throws: NativeAgentSessionRecordError.invalidIdentifier) {
        _ = try NativeAgentSessionRecord(sessionID: "../private", createdAtMilliseconds: 0, updatedAtMilliseconds: 0, expiresAtMilliseconds: 1, signatureBudget: 1)
    }
    #expect(throws: NativeAgentSessionRecordError.invalidIdentifier) {
        _ = try NativeAgentSessionRecord(sessionID: String(repeating: "a", count: 129), createdAtMilliseconds: 0, updatedAtMilliseconds: 0, expiresAtMilliseconds: 1, signatureBudget: 1)
    }
    #expect(throws: NativeAgentSessionRecordError.invalidTimestamp) {
        _ = try NativeAgentSessionRecord(sessionID: sessionRecordID, createdAtMilliseconds: 2, updatedAtMilliseconds: 1, expiresAtMilliseconds: 3, signatureBudget: 1)
    }
    #expect(throws: NativeAgentSessionRecordError.invalidExpiry) {
        _ = try NativeAgentSessionRecord(sessionID: sessionRecordID, createdAtMilliseconds: 2, updatedAtMilliseconds: 2, expiresAtMilliseconds: 2, signatureBudget: 1)
    }
    #expect(throws: NativeAgentSessionRecordError.invalidBudget) {
        _ = try NativeAgentSessionRecord(sessionID: sessionRecordID, createdAtMilliseconds: 0, updatedAtMilliseconds: 0, expiresAtMilliseconds: 1, signatureBudget: 1, signaturesUsed: 2)
    }
    #expect(throws: NativeAgentSessionRecordError.invalidBudget) {
        _ = try NativeAgentSessionRecord(sessionID: sessionRecordID, createdAtMilliseconds: 0, updatedAtMilliseconds: 0, expiresAtMilliseconds: 1, signatureBudget: 1_025)
    }
}

@Test func recordDecodingReusesBoundsInsteadOfTrustingInput() throws {
    let malformed = Data(#"{"session_id":"safe","state":"active","created_at_ms":0,"updated_at_ms":0,"expires_at_ms":1,"signature_budget":1,"signatures_used":2,"revision":0}"#.utf8)
    #expect(throws: NativeAgentSessionRecordError.invalidBudget) {
        _ = try JSONDecoder().decode(NativeAgentSessionRecord.self, from: malformed)
    }
}
