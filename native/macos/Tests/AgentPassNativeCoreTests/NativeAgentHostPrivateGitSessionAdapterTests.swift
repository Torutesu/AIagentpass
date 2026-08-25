@testable import AgentPassNativeCore
import Foundation
import Testing

private final class HostSessionAdapterTestIO: @unchecked Sendable {
    var input: Data
    var inputOffset = 0
    var output = Data()
    var readChunkSize: Int?
    var writeChunkSize: Int?
    var closeCount = 0
    var shutdownCount = 0
    var shutdownWriteCount = 0

    init(input: Data) {
        self.input = input
    }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        _ = descriptor
        guard inputOffset < input.count else { return 0 }
        let amount = min(readChunkSize ?? count, count, input.count - inputOffset)
        input.withUnsafeBytes { source in
            buffer.copyMemory(
                from: source.baseAddress!.advanced(by: inputOffset),
                byteCount: amount)
        }
        inputOffset += amount
        return amount
    }

    func write(_ descriptor: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
        _ = descriptor
        let amount = min(writeChunkSize ?? count, count)
        output.append(Data(bytes: buffer, count: amount))
        return amount
    }

    func close(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        closeCount += 1
        return 0
    }

    func shutdownWrite(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        shutdownWriteCount += 1
        return 0
    }

    func shutdown(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        shutdownCount += 1
        return 0
    }
}

private final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func increment() {
        lock.lock()
        value += 1
        lock.unlock()
    }

    func read() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private final class LockedPayloads: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Data] = []

    func append(_ value: Data) {
        lock.lock()
        values.append(value)
        lock.unlock()
    }

    func snapshot() -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return values.count
    }
}

private func makeHostSessionTransport(
    io: HostSessionAdapterTestIO,
    ownership: NativeAgentPrivateFDTransportOwnership = .borrowed
) throws -> NativeAgentPrivateGitSessionTransport {
    try NativeAgentPrivateGitSessionTransport(
        fd: 91,
        ownership: ownership,
        read: io.read,
        write: io.write,
        close: io.close,
        shutdownWrite: io.shutdownWrite,
        shutdown: io.shutdown)
}

private func request(_ sequence: UInt32, _ payload: String) throws -> Data {
    try NativeAgentPrivateGitSessionFrameCodec.encode(
        .request(sequence: sequence, commitPayload: Data(payload.utf8)))
}

private func closeFrame() throws -> Data {
    try NativeAgentPrivateGitSessionFrameCodec.encode(.close)
}

@Test func hostAdapterSelectsOnlyVersionedSessionAndServesExactlyTwoCommits() throws {
    let input = try request(1, "first") + request(2, "second") + closeFrame()
    let io = HostSessionAdapterTestIO(input: input)
    io.readChunkSize = 2
    io.writeChunkSize = 3
    let transport = try makeHostSessionTransport(io: io)
    let authorityChecks = LockedCounter()
    let payloads = LockedPayloads()

    let adapter = try NativeAgentHostPrivateGitSessionAdapter(
        protocol: .versionedSessionV1,
        transport: transport,
        revalidateAuthority: {
            authorityChecks.increment()
        },
        signer: { payload in
            payloads.append(payload)
            return Data("sig-\(payloads.count())".utf8)
        })

    #expect(adapter.selectedProtocol == .versionedSessionV1)
    try adapter.serveTwoCommits()
    #expect(authorityChecks.read() == 2)
    #expect(payloads.snapshot() == [Data("first".utf8), Data("second".utf8)])

    let expectedOutput = try NativeAgentPrivateGitSessionFrameCodec.encode(
        .response(sequence: 1, signature: Data("sig-1".utf8)))
        + NativeAgentPrivateGitSessionFrameCodec.encode(
            .response(sequence: 2, signature: Data("sig-2".utf8)))
        + closeFrame()
    #expect(io.output == expectedOutput)
}

@Test func hostAdapterRejectsMissingSecondCommitWithoutRetryOrFallback() throws {
    let io = HostSessionAdapterTestIO(input: try request(1, "only"))
    let transport = try makeHostSessionTransport(io: io)
    let signCount = LockedCounter()
    let adapter = try NativeAgentHostPrivateGitSessionAdapter(
        protocol: .versionedSessionV1,
        transport: transport,
        revalidateAuthority: {},
        signer: { _ in
            signCount.increment()
            return Data("signature".utf8)
        })

    #expect(throws: NativeAgentHostPrivateGitSessionAdapterError.invalidRequest) {
        try adapter.serveTwoCommits()
    }
    #expect(signCount.read() == 1)
    #expect(throws: NativeAgentHostPrivateGitSessionAdapterError.alreadyUsed) {
        try adapter.serveTwoCommits()
    }
}

@Test func hostAdapterQuarantinesAuthorityFailureBeforeSigner() throws {
    let io = HostSessionAdapterTestIO(input: try request(1, "first") + request(2, "second") + closeFrame())
    let transport = try makeHostSessionTransport(io: io)
    let signCount = LockedCounter()
    let adapter = try NativeAgentHostPrivateGitSessionAdapter(
        protocol: .versionedSessionV1,
        transport: transport,
        revalidateAuthority: {
            throw NativeAgentHostPrivateGitSessionAdapterError.cancelled
        },
        signer: { _ in
            signCount.increment()
            return Data("must-not-sign".utf8)
        })

    #expect(throws: NativeAgentHostPrivateGitSessionAdapterError.signerFailed) {
        try adapter.serveTwoCommits()
    }
    #expect(signCount.read() == 0)
    #expect(throws: NativeAgentHostPrivateGitSessionAdapterError.alreadyUsed) {
        try adapter.serveTwoCommits()
    }
}

@Test func hostAdapterRejectsLegacyOrMalformedTrafficAsTerminal() throws {
    let io = HostSessionAdapterTestIO(input: Data([0, 0, 0, 1, 0]))
    let transport = try makeHostSessionTransport(io: io)
    let signCount = LockedCounter()
    let adapter = try NativeAgentHostPrivateGitSessionAdapter(
        protocol: .versionedSessionV1,
        transport: transport,
        revalidateAuthority: {},
        signer: { _ in
            signCount.increment()
            return Data("must-not-sign".utf8)
        })

    #expect(throws: NativeAgentHostPrivateGitSessionAdapterError.invalidRequest) {
        try adapter.serveTwoCommits()
    }
    #expect(signCount.read() == 0)
}

@Test func hostAdapterCancellationIsTerminal() throws {
    let io = HostSessionAdapterTestIO(input: Data())
    let transport = try makeHostSessionTransport(io: io, ownership: .owned)
    let adapter = try NativeAgentHostPrivateGitSessionAdapter(
        protocol: .versionedSessionV1,
        transport: transport,
        revalidateAuthority: {},
        signer: { _ in Data("must-not-sign".utf8) })

    adapter.cancel()
    #expect(throws: NativeAgentHostPrivateGitSessionAdapterError.alreadyUsed) {
        try adapter.serveTwoCommits()
    }
    #expect(io.shutdownCount == 1)
    #expect(io.closeCount == 1)
}
