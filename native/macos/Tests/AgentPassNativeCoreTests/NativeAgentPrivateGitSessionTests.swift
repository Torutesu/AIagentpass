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
        _ = try machine.beginRequest(commitPayload: sessionPayload)
    }
    #expect(machine.state == .quarantined(.excess))
    #expect(throws: NativeAgentPrivateGitSessionStateMachineError.terminal) {
        _ = try machine.acceptResponse(responseFrame(sequence: 2))
    }
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
