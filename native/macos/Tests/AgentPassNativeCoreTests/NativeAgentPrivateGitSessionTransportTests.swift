import AgentPassNativeCore
import Foundation
import Testing

private final class SessionTransportTestIO: @unchecked Sendable {
    var input: Data
    var inputOffset = 0
    var readChunkSizes: [Int]
    var maximumWriteSize: Int?
    var output = Data()
    var closeCallCount = 0
    var shutdownWriteCallCount = 0
    var shutdownCallCount = 0
    var closeFails = false

    init(input: Data = Data(), readChunkSizes: [Int] = []) {
        self.input = input
        self.readChunkSizes = readChunkSizes
    }

    func read(
        _ descriptor: Int32,
        _ buffer: UnsafeMutableRawPointer,
        _ count: Int
    ) -> Int {
        _ = descriptor
        guard inputOffset < input.count else { return 0 }
        let scriptedSize = readChunkSizes.isEmpty
            ? count
            : readChunkSizes.removeFirst()
        let amount = min(count, scriptedSize, input.count - inputOffset)
        input.withUnsafeBytes { source in
            buffer.copyMemory(
                from: source.baseAddress!.advanced(by: inputOffset),
                byteCount: amount)
        }
        inputOffset += amount
        return amount
    }

    func write(
        _ descriptor: Int32,
        _ buffer: UnsafeRawPointer,
        _ count: Int
    ) -> Int {
        _ = descriptor
        let amount = min(count, maximumWriteSize ?? count)
        output.append(Data(bytes: buffer, count: amount))
        return amount
    }

    func close(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        closeCallCount += 1
        if closeFails { return -1 }
        return 0
    }

    func shutdownWrite(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        shutdownWriteCallCount += 1
        return 0
    }

    func shutdown(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        shutdownCallCount += 1
        return 0
    }
}

private func makeSessionTransport(
    io: SessionTransportTestIO,
    ownership: NativeAgentPrivateFDTransportOwnership = .borrowed
) throws -> NativeAgentPrivateGitSessionTransport {
    try NativeAgentPrivateGitSessionTransport(
        fd: 121,
        ownership: ownership,
        read: io.read,
        write: io.write,
        close: io.close,
        shutdownWrite: io.shutdownWrite,
        shutdown: io.shutdown)
}

private func sessionRequestFrame() throws -> Data {
    try NativeAgentPrivateGitSessionFrameCodec.encode(
        .request(sequence: 1, commitPayload: Data("payload".utf8)))
}

private func sessionCloseFrame() throws -> Data {
    try NativeAgentPrivateGitSessionFrameCodec.encode(.close)
}

@Test func privateGitSessionTransportHandlesPartialReadsAndWrites() throws {
    let frame = try sessionRequestFrame()
    let io = SessionTransportTestIO(
        input: frame,
        readChunkSizes: [1, 1, 1, 1, 2, 3, 5, 8])
    io.maximumWriteSize = 2
    let transport = try makeSessionTransport(io: io)

    #expect(try transport.readFrame() == frame)
    try transport.writeFrame(frame)
    #expect(io.output == frame)
}

@Test func privateGitSessionTransportRejectsInitialEOF() throws {
    let transport = try makeSessionTransport(io: SessionTransportTestIO())

    #expect(throws: NativeAgentPrivateGitSessionTransportError.eof) {
        _ = try transport.readFrame()
    }
    #expect(throws: NativeAgentPrivateGitSessionTransportError.alreadyClosed) {
        _ = try transport.readFrame()
    }
}

@Test func privateGitSessionTransportRejectsTruncatedPrefixAndBody() throws {
    let prefixTransport = try makeSessionTransport(
        io: SessionTransportTestIO(input: Data([0, 0])))
    #expect(throws: NativeAgentPrivateGitSessionTransportError.truncated) {
        _ = try prefixTransport.readFrame()
    }

    let frame = try sessionRequestFrame()
    let bodyTransport = try makeSessionTransport(
        io: SessionTransportTestIO(input: Data(frame.prefix(frame.count - 1))))
    #expect(throws: NativeAgentPrivateGitSessionTransportError.truncated) {
        _ = try bodyTransport.readFrame()
    }
}

@Test func privateGitSessionTransportRejectsExtraBytesAfterCloseFrame() throws {
    let closeFrame = try sessionCloseFrame()
    let io = SessionTransportTestIO(input: closeFrame + Data([0xff]))
    let transport = try makeSessionTransport(io: io)

    #expect(try transport.readFrame() == closeFrame)
    #expect(throws: NativeAgentPrivateGitSessionTransportError.extraBytes) {
        try transport.readEOF()
    }
    #expect(throws: NativeAgentPrivateGitSessionTransportError.alreadyClosed) {
        try transport.readEOF()
    }
}

@Test func privateGitSessionTransportCloseIsOwnedAndIdempotent() throws {
    let io = SessionTransportTestIO()
    let transport = try makeSessionTransport(io: io, ownership: .owned)

    try transport.close()
    try transport.close()

    #expect(io.shutdownCallCount == 1)
    #expect(io.closeCallCount == 1)
    #expect(throws: NativeAgentPrivateGitSessionTransportError.alreadyClosed) {
        try transport.finishWriting()
    }
}

@Test func privateGitSessionTransportAbortIsTerminalAndClosesOwnedDescriptor() throws {
    let io = SessionTransportTestIO()
    let transport = try makeSessionTransport(io: io, ownership: .owned)

    transport.abort()
    transport.abort()

    #expect(io.shutdownCallCount == 1)
    #expect(io.closeCallCount == 1)
    #expect(throws: NativeAgentPrivateGitSessionTransportError.alreadyClosed) {
        try transport.writeFrame(try sessionRequestFrame())
    }
}

@Test func privateGitSessionTransportRejectsOversizedAndMismatchedOuterFrames() throws {
    let oversizedBody = UInt32(NativeAgentPrivateGitSessionFrameCodec.maximumBodyBytes + 1)
    let oversized = Data([
        UInt8((oversizedBody >> 24) & 0xff),
        UInt8((oversizedBody >> 16) & 0xff),
        UInt8((oversizedBody >> 8) & 0xff),
        UInt8(oversizedBody & 0xff),
    ])
    let oversizedTransport = try makeSessionTransport(
        io: SessionTransportTestIO(input: oversized))
    #expect(throws: NativeAgentPrivateGitSessionTransportError.invalidFrame(.frameTooLarge)) {
        _ = try oversizedTransport.readFrame()
    }

    let valid = try sessionRequestFrame()
    let mismatchedTransport = try makeSessionTransport(io: SessionTransportTestIO())
    #expect(throws: NativeAgentPrivateGitSessionTransportError.invalidFrame(.lengthMismatch)) {
        try mismatchedTransport.writeFrame(valid + Data([0]))
    }
}

@Test func oneShotTransportUpgradesWithoutDoubleOwningOrClosingDescriptor() throws {
    let io = SessionTransportTestIO()
    let oneShot = try NativeAgentPrivateFDTransport(
        fd: 122,
        ownership: .owned,
        read: io.read,
        write: io.write,
        close: io.close,
        shutdownWrite: io.shutdownWrite,
        shutdown: io.shutdown)

    let session = try oneShot.upgradeToVersionedSessionTransport()
    try oneShot.close()
    try session.close()
    #expect(io.closeCallCount == 1)
}
