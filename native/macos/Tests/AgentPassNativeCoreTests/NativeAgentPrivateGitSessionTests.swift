import AgentPassNativeCore
import Dispatch
import Foundation
import Testing

private let sessionPayload = Data("tree abc\n\nmessage\n".utf8)
private let sessionSignature = Data("-----BEGIN SSH SIGNATURE-----\nfixed\n-----END SSH SIGNATURE-----\n".utf8)

@Test func privateGitSessionCodecIsVersionedAndDeterministic() throws {
    let request = NativeAgentPrivateGitSessionMessage.request(sequence: 1, commitPayload: sessionPayload)
    let first = try NativeAgentPrivateGitSessionFrameCodec.encode(request)
    let second = try NativeAgentPrivateGitSessionFrameCodec.encode(request)

    #expect(first == second)
    #expect(first.prefix(4).elementsEqual([0, 0, 0, 34])) // 16-byte body header + 18-byte payload
    #expect(first[4..<8].elementsEqual([0x41, 0x50, 0x47, 0x53]))
    #expect(first[8] == NativeAgentPrivateGitSessionFrameCodec.currentVersion)
    #expect(try NativeAgentPrivateGitSessionFrameCodec.decode(first) == request)
}

@Test func privateGitSessionCodecRoundTripsRequestAndResponseWithoutSelectors() throws {
    let request = NativeAgentPrivateGitSessionMessage.request(sequence: 1, commitPayload: sessionPayload)
    let response = NativeAgentPrivateGitSessionMessage.response(sequence: 1, signature: sessionSignature)

    #expect(try NativeAgentPrivateGitSessionFrameCodec.decode(
        NativeAgentPrivateGitSessionFrameCodec.encode(request)) == request)
    #expect(try NativeAgentPrivateGitSessionFrameCodec.decode(
        NativeAgentPrivateGitSessionFrameCodec.encode(response)) == response)
}

@Test func privateGitSessionCodecRoundTripsCanonicalTerminalClose() throws {
    let close = try NativeAgentPrivateGitSessionFrameCodec.encode(.close)

    #expect(close == Data([
        0, 0, 0, 16,
        0x41, 0x50, 0x47, 0x53,
        NativeAgentPrivateGitSessionFrameCodec.currentVersion, 3,
        0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    ]))
    #expect(try NativeAgentPrivateGitSessionFrameCodec.decode(close) == .close)
}

@Test func privateGitSessionLifecycleErrorsHaveStableF1Codes() {
    #expect(NativeAgentPrivateGitSessionLifecycleError.allCases.map(\.rawValue) == [
        "outcome_unknown",
        "revoked",
        "expired",
        "policy_drift",
        "process_drift",
        "transport_quarantined",
    ])
}

@Test func privateGitSessionCodecRejectsEmptyAndBoundViolations() throws {
    #expect(throws: NativeAgentPrivateGitSessionCodecError.emptyPayload) {
        try NativeAgentPrivateGitSessionFrameCodec.encode(.request(sequence: 1, commitPayload: Data()))
    }
    #expect(throws: NativeAgentPrivateGitSessionCodecError.emptyPayload) {
        try NativeAgentPrivateGitSessionFrameCodec.encode(.response(sequence: 1, signature: Data()))
    }
    #expect(throws: NativeAgentPrivateGitSessionCodecError.payloadTooLarge) {
        try NativeAgentPrivateGitSessionFrameCodec.encode(.request(
            sequence: 1,
            commitPayload: Data(repeating: 0x41, count: NativeAgentPrivateGitSessionFrameCodec.maximumCommitPayloadBytes + 1)))
    }
    #expect(throws: NativeAgentPrivateGitSessionCodecError.signatureTooLarge) {
        try NativeAgentPrivateGitSessionFrameCodec.encode(.response(
            sequence: 1,
            signature: Data(repeating: 0x41, count: NativeAgentPrivateGitSessionFrameCodec.maximumSignatureBytes + 1)))
    }
    #expect(throws: NativeAgentPrivateGitSessionCodecError.invalidSequence) {
        try NativeAgentPrivateGitSessionFrameCodec.encode(.request(sequence: 0, commitPayload: sessionPayload))
    }
}

@Test func privateGitSessionCodecRejectsMalformedAndNonCanonicalFrames() throws {
    let valid = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .request(sequence: 1, commitPayload: sessionPayload))

    #expect(throws: NativeAgentPrivateGitSessionCodecError.frameTooShort) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(Data(valid.prefix(19)))
    }

    var badMagic = valid
    badMagic[4] = 0
    #expect(throws: NativeAgentPrivateGitSessionCodecError.invalidMagic) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(badMagic)
    }

    var badVersion = valid
    badVersion[8] = NativeAgentPrivateGitSessionFrameCodec.currentVersion + 1
    #expect(throws: NativeAgentPrivateGitSessionCodecError.unsupportedVersion) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(badVersion)
    }

    var badKind = valid
    badKind[9] = 9
    #expect(throws: NativeAgentPrivateGitSessionCodecError.invalidMessageKind) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(badKind)
    }

    var badFlags = valid
    badFlags[10] = 1
    #expect(throws: NativeAgentPrivateGitSessionCodecError.nonZeroFlags) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(badFlags)
    }

    var badOuterLength = valid
    badOuterLength[3] += 1
    #expect(throws: NativeAgentPrivateGitSessionCodecError.lengthMismatch) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(badOuterLength)
    }

    var badContentLength = valid
    badContentLength[19] += 1
    #expect(throws: NativeAgentPrivateGitSessionCodecError.lengthMismatch) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(badContentLength)
    }

    #expect(throws: NativeAgentPrivateGitSessionCodecError.lengthMismatch) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(valid + Data([0]))
    }

    let zeroLength = Data(repeating: 0, count: 20)
    #expect(throws: NativeAgentPrivateGitSessionCodecError.invalidLength) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(zeroLength)
    }

    var oversizedBody = Data(repeating: 0, count: 20)
    let oversizedBodyLength = UInt32(NativeAgentPrivateGitSessionFrameCodec.maximumBodyBytes + 1)
    oversizedBody[0] = UInt8((oversizedBodyLength >> 24) & 0xff)
    oversizedBody[1] = UInt8((oversizedBodyLength >> 16) & 0xff)
    oversizedBody[2] = UInt8((oversizedBodyLength >> 8) & 0xff)
    oversizedBody[3] = UInt8(oversizedBodyLength & 0xff)
    #expect(throws: NativeAgentPrivateGitSessionCodecError.frameTooLarge) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(oversizedBody)
    }

    var zeroSequence = valid
    zeroSequence[12] = 0
    zeroSequence[13] = 0
    zeroSequence[14] = 0
    zeroSequence[15] = 0
    #expect(throws: NativeAgentPrivateGitSessionCodecError.invalidSequence) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(zeroSequence)
    }

    var oversizedRequestContent = valid
    let oversizedRequestLength = UInt32(NativeAgentPrivateGitSessionFrameCodec.maximumCommitPayloadBytes + 1)
    oversizedRequestContent[16] = UInt8((oversizedRequestLength >> 24) & 0xff)
    oversizedRequestContent[17] = UInt8((oversizedRequestLength >> 16) & 0xff)
    oversizedRequestContent[18] = UInt8((oversizedRequestLength >> 8) & 0xff)
    oversizedRequestContent[19] = UInt8(oversizedRequestLength & 0xff)
    #expect(throws: NativeAgentPrivateGitSessionCodecError.payloadTooLarge) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(oversizedRequestContent)
    }

    let validResponse = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 1, signature: sessionSignature))
    var oversizedResponseContent = validResponse
    let oversizedResponseLength = UInt32(NativeAgentPrivateGitSessionFrameCodec.maximumSignatureBytes + 1)
    oversizedResponseContent[16] = UInt8((oversizedResponseLength >> 24) & 0xff)
    oversizedResponseContent[17] = UInt8((oversizedResponseLength >> 16) & 0xff)
    oversizedResponseContent[18] = UInt8((oversizedResponseLength >> 8) & 0xff)
    oversizedResponseContent[19] = UInt8(oversizedResponseLength & 0xff)
    #expect(throws: NativeAgentPrivateGitSessionCodecError.signatureTooLarge) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(oversizedResponseContent)
    }
}

@Test func privateGitSessionCodecRejectsCrossProtocolDowngradeAndMalformedCloseFrames() throws {
    let oldOneShotFrame = try NativeAgentGitBridgeFrame.encodeCommitPayload(sessionPayload)
    #expect(throws: NativeAgentPrivateGitSessionCodecError.invalidMagic) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(oldOneShotFrame)
    }

    let valid = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .request(sequence: 1, commitPayload: sessionPayload))
    var downgraded = valid
    downgraded[8] = 0
    #expect(throws: NativeAgentPrivateGitSessionCodecError.unsupportedVersion) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(downgraded)
    }

    var unknownKind = valid
    unknownKind[9] = 9
    #expect(throws: NativeAgentPrivateGitSessionCodecError.invalidMessageKind) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(unknownKind)
    }

    let close = try NativeAgentPrivateGitSessionFrameCodec.encode(.close)
    var closeWithSequence = close
    closeWithSequence[15] = 1
    #expect(throws: NativeAgentPrivateGitSessionCodecError.invalidClose) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(closeWithSequence)
    }

    var closeWithPayloadLength = close
    closeWithPayloadLength[19] = 1
    #expect(throws: NativeAgentPrivateGitSessionCodecError.invalidClose) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(closeWithPayloadLength)
    }

    #expect(throws: NativeAgentPrivateGitSessionCodecError.lengthMismatch) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(close + Data([0]))
    }

    var oversized = Data(repeating: 0, count: NativeAgentPrivateGitSessionFrameCodec.framePrefixBytes + NativeAgentPrivateGitSessionFrameCodec.bodyHeaderBytes)
    let oversizedBody = UInt32(NativeAgentPrivateGitSessionFrameCodec.maximumBodyBytes + 1)
    oversized[0] = UInt8((oversizedBody >> 24) & 0xff)
    oversized[1] = UInt8((oversizedBody >> 16) & 0xff)
    oversized[2] = UInt8((oversizedBody >> 8) & 0xff)
    oversized[3] = UInt8(oversizedBody & 0xff)
    #expect(throws: NativeAgentPrivateGitSessionCodecError.frameTooLarge) {
        try NativeAgentPrivateGitSessionFrameCodec.decode(oversized)
    }
}

@Test func privateGitSessionStateMachineAcceptsExactlyTwoOrderedSigns() throws {
    let machine = NativeAgentPrivateGitSessionStateMachine()

    let request1 = try machine.beginRequest(commitPayload: sessionPayload)
    #expect(machine.state == .awaitingResponse(sequence: 1))
    #expect(try NativeAgentPrivateGitSessionFrameCodec.decode(request1) ==
        .request(sequence: 1, commitPayload: sessionPayload))
    #expect(try machine.acceptResponse(try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 1, signature: sessionSignature))) == sessionSignature)
    #expect(machine.state == .ready(nextSequence: 2))

    let request2 = try machine.beginRequest(commitPayload: Data("second".utf8))
    #expect(try NativeAgentPrivateGitSessionFrameCodec.decode(request2) ==
        .request(sequence: 2, commitPayload: Data("second".utf8)))
    #expect(try machine.acceptResponse(try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 2, signature: sessionSignature))) == sessionSignature)
    #expect(machine.state == .completed)

    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.excess) {
        _ = try machine.beginRequest(commitPayload: Data("third".utf8))
    }
    #expect(machine.state == .quarantined(.excess))
}

@Test func privateGitSessionStateMachineQuarantinesMalformedRequestAndResponse() throws {
    let invalidRequestMachine = NativeAgentPrivateGitSessionStateMachine()
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.malformed) {
        _ = try invalidRequestMachine.beginRequest(commitPayload: Data())
    }
    #expect(invalidRequestMachine.state == .quarantined(.malformed))

    let invalidResponseMachine = NativeAgentPrivateGitSessionStateMachine()
    _ = try invalidResponseMachine.beginRequest(commitPayload: sessionPayload)
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.malformed) {
        _ = try invalidResponseMachine.acceptResponse(Data([0, 0, 0]))
    }
    #expect(invalidResponseMachine.state == .quarantined(.malformed))
}

@Test func privateGitSessionStateMachineQuarantinesConcurrentRequest() throws {
    let machine = NativeAgentPrivateGitSessionStateMachine()
    let group = DispatchGroup()
    let results = SessionRaceResults()

    for _ in 0..<2 {
        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            do {
                _ = try machine.beginRequest(commitPayload: sessionPayload)
                results.recordSuccess()
            } catch let error as NativeAgentPrivateGitSessionStateMachineError {
                results.recordFailure(error)
            } catch {
                Issue.record("unexpected error: \(error)")
            }
        }
    }

    #expect(group.wait(timeout: .now() + .seconds(15)) == .success)
    #expect(results.successCount == 1)
    #expect(results.failures == [.concurrentRequest])
    #expect(machine.state == .quarantined(.concurrentRequest))
}

@Test func privateGitSessionStateMachineRejectsReplayAndQuarantines() throws {
    let machine = NativeAgentPrivateGitSessionStateMachine()
    _ = try machine.beginRequest(commitPayload: sessionPayload)
    let response1 = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 1, signature: sessionSignature))
    _ = try machine.acceptResponse(response1)
    _ = try machine.beginRequest(commitPayload: sessionPayload)

    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.replay) {
        _ = try machine.acceptResponse(response1)
    }
    #expect(machine.state == .quarantined(.replay))
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.terminal) {
        _ = try machine.beginRequest(commitPayload: sessionPayload)
    }
}

@Test func privateGitSessionStateMachineRejectsSkippedAndExcessSequences() throws {
    let skipped = NativeAgentPrivateGitSessionStateMachine()
    _ = try skipped.beginRequest(commitPayload: sessionPayload)
    let response2 = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 2, signature: sessionSignature))
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.skippedSequence) {
        _ = try skipped.acceptResponse(response2)
    }
    #expect(skipped.state == .quarantined(.skippedSequence))

    let excess = NativeAgentPrivateGitSessionStateMachine()
    _ = try excess.beginRequest(commitPayload: sessionPayload)
    let response3 = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 3, signature: sessionSignature))
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.excess) {
        _ = try excess.acceptResponse(response3)
    }
    #expect(excess.state == .quarantined(.excess))
}

@Test func privateGitSessionStateMachineRejectsWrongDirectionAndUnrequestedResponse() throws {
    let wrongDirection = NativeAgentPrivateGitSessionStateMachine()
    _ = try wrongDirection.beginRequest(commitPayload: sessionPayload)
    let requestFrame = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .request(sequence: 1, commitPayload: sessionPayload))
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.wrongResponse) {
        _ = try wrongDirection.acceptResponse(requestFrame)
    }
    #expect(wrongDirection.state == .quarantined(.wrongResponse))

    let unrequested = NativeAgentPrivateGitSessionStateMachine()
    let responseFrame = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 1, signature: sessionSignature))
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.wrongResponse) {
        _ = try unrequested.acceptResponse(responseFrame)
    }
    #expect(unrequested.state == .quarantined(.wrongResponse))
}

@Test func privateGitSessionStateMachineTerminalStateRejectsAllFurtherOperations() throws {
    let machine = NativeAgentPrivateGitSessionStateMachine()
    _ = try machine.beginRequest(commitPayload: sessionPayload)
    _ = try machine.acceptResponse(try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 1, signature: sessionSignature)))
    _ = try machine.beginRequest(commitPayload: sessionPayload)
    _ = try machine.acceptResponse(try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 2, signature: sessionSignature)))

    #expect(machine.state == .completed)
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.excess) {
        _ = try machine.acceptResponse(responseFrame(sequence: 2))
    }
    #expect(machine.state == .quarantined(.excess))
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.terminal) {
        _ = try machine.beginRequest(commitPayload: sessionPayload)
    }
}

@Test func privateGitSessionStateMachineClosesInOrderAfterBudgetCompletion() throws {
    let machine = NativeAgentPrivateGitSessionStateMachine()
    _ = try machine.beginRequest(commitPayload: sessionPayload)
    _ = try machine.acceptResponse(responseFrame(sequence: 1))
    _ = try machine.beginRequest(commitPayload: sessionPayload)
    _ = try machine.acceptResponse(responseFrame(sequence: 2))

    let close = try machine.close()
    #expect(try NativeAgentPrivateGitSessionFrameCodec.decode(close) == .close)
    #expect(machine.state == .closing)
    try machine.acceptEOF()
    #expect(machine.state == .closed)
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.alreadyClosed) {
        _ = try machine.close()
    }
}

@Test func privateGitSessionStateMachineRejectsDuplicateCloseAndPostCloseTraffic() throws {
    let machine = NativeAgentPrivateGitSessionStateMachine()
    _ = try machine.close()

    #expect(machine.state == .closing)
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.alreadyClosed) {
        _ = try machine.close()
    }
    try machine.acceptEOF()
    #expect(machine.state == .closed)
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.alreadyClosed) {
        _ = try machine.beginRequest(commitPayload: sessionPayload)
    }
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.alreadyClosed) {
        _ = try machine.acceptResponse(responseFrame(sequence: 1))
    }
    #expect(machine.state == .closed)
}

@Test func privateGitSessionStateMachineQuarantinesCloseWhileOutstanding() throws {
    let localClose = NativeAgentPrivateGitSessionStateMachine()
    _ = try localClose.beginRequest(commitPayload: sessionPayload)
    do {
        _ = try localClose.close()
        Issue.record("close while outstanding unexpectedly succeeded")
    } catch let error as NativeAgentPrivateGitSessionStateMachineError {
        #expect(error == .closeWhileOutstanding)
        #expect(error.lifecycleError == .outcomeUnknown)
    } catch {
        Issue.record("unexpected error: \(error)")
    }
    #expect(localClose.state == .quarantined(.closeWhileOutstanding))

    let peerClose = NativeAgentPrivateGitSessionStateMachine()
    _ = try peerClose.beginRequest(commitPayload: sessionPayload)
    let closeFrame = try NativeAgentPrivateGitSessionFrameCodec.encode(.close)
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.closeWhileOutstanding) {
        try peerClose.acceptClose(closeFrame)
    }
    #expect(peerClose.state == .quarantined(.closeWhileOutstanding))
}

@Test func privateGitSessionStateMachineAcceptsPeerCloseOnlyAtAStableBoundary() throws {
    let ready = NativeAgentPrivateGitSessionStateMachine()
    let close = try NativeAgentPrivateGitSessionFrameCodec.encode(.close)
    try ready.acceptClose(close)
    #expect(ready.state == .closing)
    try ready.acceptEOF()
    #expect(ready.state == .closed)

    let completed = NativeAgentPrivateGitSessionStateMachine()
    _ = try completed.beginRequest(commitPayload: sessionPayload)
    _ = try completed.acceptResponse(responseFrame(sequence: 1))
    _ = try completed.beginRequest(commitPayload: sessionPayload)
    _ = try completed.acceptResponse(responseFrame(sequence: 2))
    try completed.acceptClose(close)
    #expect(completed.state == .closing)
    try completed.acceptEOF()
    #expect(completed.state == .closed)
}

@Test func privateGitSessionStateMachineRejectsEOFWithoutCommittedClose() throws {
    let ready = NativeAgentPrivateGitSessionStateMachine()
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.unexpectedEOF) {
        try ready.acceptEOF()
    }
    #expect(ready.state == .quarantined(.unexpectedEOF))

    let outstanding = NativeAgentPrivateGitSessionStateMachine()
    _ = try outstanding.beginRequest(commitPayload: sessionPayload)
    do {
        try outstanding.acceptEOF()
        Issue.record("EOF with an outstanding response unexpectedly succeeded")
    } catch let error as NativeAgentPrivateGitSessionStateMachineError {
        #expect(error == .outcomeUnknown)
        #expect(error.lifecycleError == .outcomeUnknown)
    } catch {
        Issue.record("unexpected error: \(error)")
    }
    #expect(outstanding.state == .quarantined(.outcomeUnknown))
}

@Test func privateGitSessionStateMachineQuarantinesTrafficBeforeEOFCommitsClose() throws {
    let machine = NativeAgentPrivateGitSessionStateMachine()
    let close = try machine.close()
    #expect(machine.state == .closing)

    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.trafficAfterClose) {
        _ = try machine.beginRequest(commitPayload: sessionPayload)
    }
    #expect(machine.state == .quarantined(.trafficAfterClose))

    let duplicate = NativeAgentPrivateGitSessionStateMachine()
    try duplicate.acceptClose(close)
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.duplicateClose) {
        try duplicate.acceptClose(close)
    }
    #expect(duplicate.state == .quarantined(.duplicateClose))
}

@Test func privateGitSessionStateMachineQuarantinesWrongCloseDirectionAndMalformedClose() throws {
    let wrongDirection = NativeAgentPrivateGitSessionStateMachine()
    let request = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .request(sequence: 1, commitPayload: sessionPayload))
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.wrongMessage) {
        try wrongDirection.acceptClose(request)
    }
    #expect(wrongDirection.state == .quarantined(.wrongMessage))

    let malformed = NativeAgentPrivateGitSessionStateMachine()
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.malformed) {
        try malformed.acceptClose(Data([0, 0, 0]))
    }
    #expect(malformed.state == .quarantined(.malformed))
}

private func responseFrame(sequence: UInt32) throws -> Data {
    try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: sequence, signature: sessionSignature))
}

private final class SessionRaceResults: @unchecked Sendable {
    private let lock = NSLock()
    private var successes = 0
    private var storedFailures: [NativeAgentPrivateGitSessionStateMachineError] = []

    var successCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return successes
    }

    var failures: [NativeAgentPrivateGitSessionStateMachineError] {
        lock.lock()
        defer { lock.unlock() }
        return storedFailures
    }

    func recordSuccess() {
        lock.lock()
        successes += 1
        lock.unlock()
    }

    func recordFailure(_ error: NativeAgentPrivateGitSessionStateMachineError) {
        lock.lock()
        storedFailures.append(error)
        lock.unlock()
    }
}
