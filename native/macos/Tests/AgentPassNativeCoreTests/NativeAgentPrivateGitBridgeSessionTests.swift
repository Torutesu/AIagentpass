import AgentPassNativeCore
import Foundation
import Testing

private final class SessionTestIO: @unchecked Sendable {
    private let lock = NSLock()
    var input: Data
    var inputOffset = 0
    var output = Data()
    var closeCalls = 0
    var shutdownCalls = 0
    var shutdownWriteCalls = 0

    init(input: Data = Data()) {
        self.input = input
    }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        _ = descriptor
        lock.lock()
        defer { lock.unlock() }
        guard inputOffset < input.count else { return 0 }
        let amount = min(count, input.count - inputOffset)
        input.withUnsafeBytes { bytes in
            buffer.copyMemory(
                from: bytes.baseAddress!.advanced(by: inputOffset),
                byteCount: amount)
        }
        inputOffset += amount
        return amount
    }

    func write(_ descriptor: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
        _ = descriptor
        lock.lock()
        output.append(Data(bytes: buffer, count: count))
        lock.unlock()
        return count
    }

    func close(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        lock.lock()
        closeCalls += 1
        lock.unlock()
        return 0
    }

    func shutdownWrite(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        lock.lock()
        shutdownWriteCalls += 1
        lock.unlock()
        return 0
    }

    func shutdown(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        lock.lock()
        shutdownCalls += 1
        lock.unlock()
        return 0
    }
}

private final class CountingSessionSigner: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var payloads = [Data]()

    func sign(_ payload: Data) throws -> Data {
        lock.lock()
        payloads.append(payload)
        let sequence = payloads.count
        lock.unlock()
        return Data("signature-\(sequence)".utf8)
    }
}

private func sessionTransport(
    io: SessionTestIO,
    fd: Int32
) throws -> NativeAgentPrivateGitSessionTransport {
    try NativeAgentPrivateGitSessionTransport(
        fd: fd,
        ownership: .owned,
        read: io.read,
        write: io.write,
        close: io.close,
        shutdownWrite: io.shutdownWrite,
        shutdown: io.shutdown)
}

private func requestFrame(_ sequence: UInt32, _ payload: String) throws -> Data {
    try NativeAgentPrivateGitSessionFrameCodec.encode(
        .request(sequence: sequence, commitPayload: Data(payload.utf8)))
}

private func responseFrame(_ sequence: UInt32, _ signature: String) throws -> Data {
    try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: sequence, signature: Data(signature.utf8)))
}

private let closeFrame = try! NativeAgentPrivateGitSessionFrameCodec.encode(.close)

@Test func sessionClientPerformsExactlyTwoSequentialExchangesAndCloseHandshake() throws {
    let io = SessionTestIO(
        input: try responseFrame(1, "sig-1") + responseFrame(2, "sig-2") + closeFrame)
    let client = NativeAgentPrivateGitBridgeSessionClient(
        transport: try sessionTransport(io: io, fd: 401))

    #expect(try client.sign(commitPayload: Data("commit-1".utf8)) == Data("sig-1".utf8))
    #expect(try client.sign(commitPayload: Data("commit-2".utf8)) == Data("sig-2".utf8))
    try client.close()

    #expect(client.state == .closed)
    #expect(io.shutdownWriteCalls == 1)
    #expect(io.closeCalls == 1)
    let first = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .request(sequence: 1, commitPayload: Data("commit-1".utf8)))
    let second = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .request(sequence: 2, commitPayload: Data("commit-2".utf8)))
    #expect(io.output == first + second + closeFrame)
}

@Test func sessionClientMakesResponseLossTerminalAndDoesNotRetry() throws {
    let io = SessionTestIO(input: try responseFrame(1, "sig-1"))
    let client = NativeAgentPrivateGitBridgeSessionClient(
        transport: try sessionTransport(io: io, fd: 402))

    #expect(throws: NativeAgentPrivateGitBridgeSessionClientError.outcomeUnknown) {
        _ = try client.sign(commitPayload: Data("commit-1".utf8))
        _ = try client.sign(commitPayload: Data("commit-2".utf8))
    }
    #expect(client.state == .quarantined(.outcomeUnknown))
    #expect(throws: NativeAgentPrivateGitBridgeSessionClientError.protocolViolation(.terminal)) {
        _ = try client.sign(commitPayload: Data("retry".utf8))
    }
}

@Test func sessionClientRejectsThirdExchangeAndNeverWritesIt() throws {
    let io = SessionTestIO(
        input: try responseFrame(1, "sig-1") + responseFrame(2, "sig-2"))
    let client = NativeAgentPrivateGitBridgeSessionClient(
        transport: try sessionTransport(io: io, fd: 403))

    _ = try client.sign(commitPayload: Data("commit-1".utf8))
    _ = try client.sign(commitPayload: Data("commit-2".utf8))
    #expect(throws: NativeAgentPrivateGitBridgeSessionClientError.protocolViolation(.excess)) {
        _ = try client.sign(commitPayload: Data("commit-3".utf8))
    }
    #expect(client.state == .quarantined(.excess))
}

@Test func sessionServerSignsEachSequenceOnceAndCompletesCloseHandshake() throws {
    let io = SessionTestIO(
        input: try requestFrame(1, "commit-1") + requestFrame(2, "commit-2") + closeFrame)
    let signer = CountingSessionSigner()
    let server = NativeAgentPrivateGitBridgeSessionServer(
        transport: try sessionTransport(io: io, fd: 404),
        signer: signer.sign)

    try server.serveTwoCommits()

    #expect(signer.payloads == [Data("commit-1".utf8), Data("commit-2".utf8)])
    #expect(server.state == .closed)
    #expect(io.shutdownWriteCalls == 1)
    #expect(io.closeCalls == 1)
    let expected = try responseFrame(1, "signature-1")
        + responseFrame(2, "signature-2")
        + closeFrame
    #expect(io.output == expected)
}

@Test func sessionServerFailsClosedOnReplayBeforeSecondSigning() throws {
    let io = SessionTestIO(
        input: try requestFrame(1, "commit-1") + requestFrame(1, "replay"))
    let signer = CountingSessionSigner()
    let server = NativeAgentPrivateGitBridgeSessionServer(
        transport: try sessionTransport(io: io, fd: 405),
        signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeSessionServerError.protocolViolation(.replay)) {
        try server.serveTwoCommits()
    }
    #expect(signer.payloads.count == 1)
    #expect(server.state == .quarantined(.replay))
}

@Test func sessionServerFailsClosedOnSkippedSequenceAndEOF() throws {
    let skipIO = SessionTestIO(input: try requestFrame(3, "skip"))
    let skipSigner = CountingSessionSigner()
    let skipServer = NativeAgentPrivateGitBridgeSessionServer(
        transport: try sessionTransport(io: skipIO, fd: 406),
        signer: skipSigner.sign)
    #expect(throws: NativeAgentPrivateGitBridgeSessionServerError.protocolViolation(.excess)) {
        try skipServer.serveTwoCommits()
    }
    #expect(skipSigner.payloads.isEmpty)

    let eofIO = SessionTestIO()
    let eofSigner = CountingSessionSigner()
    let eofServer = NativeAgentPrivateGitBridgeSessionServer(
        transport: try sessionTransport(io: eofIO, fd: 407),
        signer: eofSigner.sign)
    #expect(throws: NativeAgentPrivateGitBridgeSessionServerError.invalidRequest) {
        try eofServer.serveTwoCommits()
    }
    #expect(eofSigner.payloads.isEmpty)
    #expect(eofServer.state == .quarantined(.unexpectedEOF))
}

@Test func sessionServerRejectsRepeatedServeWithoutAnotherSignerCall() throws {
    let io = SessionTestIO()
    let signer = CountingSessionSigner()
    let server = NativeAgentPrivateGitBridgeSessionServer(
        transport: try sessionTransport(io: io, fd: 408),
        signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeSessionServerError.invalidRequest) {
        try server.serveTwoCommits()
    }
    #expect(throws: NativeAgentPrivateGitBridgeSessionServerError.alreadyUsed) {
        try server.serveTwoCommits()
    }
    #expect(signer.payloads.isEmpty)
}
