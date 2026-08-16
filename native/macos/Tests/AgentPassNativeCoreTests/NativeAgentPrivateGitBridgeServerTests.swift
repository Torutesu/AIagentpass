import AgentPassNativeCore
import Darwin
import Dispatch
import Foundation
import Testing

private final class PrivateGitBridgeServerTestIO: @unchecked Sendable {
    var input: Data
    var inputOffset = 0
    var output = Data()
    var closeCallCount = 0
    var writeError: Int32?
    var closeError: Int32?

    init(input: Data) {
        self.input = input
    }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        _ = descriptor
        guard inputOffset < input.count else { return 0 }
        let amount = min(count, input.count - inputOffset)
        input.withUnsafeBytes { rawBuffer in
            buffer.copyMemory(
                from: rawBuffer.baseAddress!.advanced(by: inputOffset),
                byteCount: amount)
        }
        inputOffset += amount
        return amount
    }

    func write(_ descriptor: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
        _ = descriptor
        if let writeError {
            errno = writeError
            return -1
        }
        output.append(Data(bytes: buffer, count: count))
        return count
    }

    func close(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        closeCallCount += 1
        if let closeError {
            errno = closeError
            return -1
        }
        return 0
    }
}

private final class CountingSigner: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var callCount = 0
    private(set) var receivedPayload: Data?
    var result: Result<Data, Error> = .success(Data("signature".utf8))

    func sign(_ payload: Data) throws -> Data {
        lock.lock()
        callCount += 1
        receivedPayload = payload
        let result = result
        lock.unlock()
        return try result.get()
    }
}

private final class BlockingSigner: @unchecked Sendable {
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private(set) var callCount = 0

    func sign(_ payload: Data) throws -> Data {
        _ = payload
        lock.lock()
        callCount += 1
        lock.unlock()
        entered.signal()
        _ = release.wait(timeout: .now() + .seconds(15))
        return Data("signature".utf8)
    }
}

private func makeServer(
    io: PrivateGitBridgeServerTestIO,
    signer: @escaping NativeAgentPrivateGitBridgeServer.Signer
) throws -> NativeAgentPrivateGitBridgeServer {
    let transport = try NativeAgentPrivateFDTransport(
        fd: 91,
        ownership: .owned,
        read: io.read,
        write: io.write,
        close: io.close)
    return NativeAgentPrivateGitBridgeServer(transport: transport, signer: signer)
}

@Test func privateGitBridgeServerSignsExactlyOnePayloadAndWritesExactlyOneResponse() throws {
    let payload = Data("tree abc\n\nmessage\n".utf8)
    let signature = Data("-----BEGIN SSH SIGNATURE-----\nfixed\n-----END SSH SIGNATURE-----\n".utf8)
    let io = PrivateGitBridgeServerTestIO(
        input: try NativeAgentGitBridgeFrame.encodeCommitPayload(payload))
    let signer = CountingSigner()
    signer.result = .success(signature)
    let server = try makeServer(io: io, signer: signer.sign)

    try server.serve()

    #expect(signer.callCount == 1)
    #expect(signer.receivedPayload == payload)
    #expect(io.output == (try NativeAgentGitBridgeFrame.encodeSignature(signature)))
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeServerRejectsMalformedFrameBeforeSigning() throws {
    let io = PrivateGitBridgeServerTestIO(input: Data([0, 0, 0]))
    let signer = CountingSigner()
    let server = try makeServer(io: io, signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeServerError.invalidRequest) {
        try server.serve()
    }
    #expect(signer.callCount == 0)
    #expect(io.output.isEmpty)
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeServerRejectsTruncatedFrameBeforeSigning() throws {
    let io = PrivateGitBridgeServerTestIO(input: Data([0, 0, 0, 5, 1, 2]))
    let signer = CountingSigner()
    let server = try makeServer(io: io, signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeServerError.invalidRequest) {
        try server.serve()
    }
    #expect(signer.callCount == 0)
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeServerRejectsOversizedRequestBeforeSigning() throws {
    let oversized = UInt32(NativeAgentGitBridgeFrame.maximumCommitPayloadBytes + 1)
    let io = PrivateGitBridgeServerTestIO(input: Data([
        UInt8((oversized >> 24) & 0xff),
        UInt8((oversized >> 16) & 0xff),
        UInt8((oversized >> 8) & 0xff),
        UInt8(oversized & 0xff),
    ]))
    let signer = CountingSigner()
    let server = try makeServer(io: io, signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeServerError.invalidRequest) {
        try server.serve()
    }
    #expect(signer.callCount == 0)
    #expect(io.output.isEmpty)
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeServerRejectsExtraFrameBeforeSigning() throws {
    let frame = try NativeAgentGitBridgeFrame.encodeCommitPayload(Data("payload".utf8))
    let io = PrivateGitBridgeServerTestIO(input: frame + frame)
    let signer = CountingSigner()
    let server = try makeServer(io: io, signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeServerError.invalidRequest) {
        try server.serve()
    }
    #expect(signer.callCount == 0)
    #expect(io.output.isEmpty)
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeServerMapsSignerFailureAndCloses() throws {
    struct SignerFailure: Error {}
    let io = PrivateGitBridgeServerTestIO(
        input: try NativeAgentGitBridgeFrame.encodeCommitPayload(Data("payload".utf8)))
    let signer = CountingSigner()
    signer.result = .failure(SignerFailure())
    let server = try makeServer(io: io, signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeServerError.signerFailed) {
        try server.serve()
    }
    #expect(signer.callCount == 1)
    #expect(io.output.isEmpty)
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeServerMapsWriteFailureAndCloses() throws {
    let io = PrivateGitBridgeServerTestIO(
        input: try NativeAgentGitBridgeFrame.encodeCommitPayload(Data("payload".utf8)))
    io.writeError = Int32(EPIPE)
    let signer = CountingSigner()
    let server = try makeServer(io: io, signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeServerError.responseFailed) {
        try server.serve()
    }
    #expect(signer.callCount == 1)
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeServerRejectsOversizedSignerOutputAndCloses() throws {
    let io = PrivateGitBridgeServerTestIO(
        input: try NativeAgentGitBridgeFrame.encodeCommitPayload(Data("payload".utf8)))
    let signer = CountingSigner()
    signer.result = .success(
        Data(repeating: 0x41, count: NativeAgentGitBridgeFrame.maximumSignatureBytes + 1))
    let server = try makeServer(io: io, signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeServerError.responseFailed) {
        try server.serve()
    }
    #expect(signer.callCount == 1)
    #expect(io.output.isEmpty)
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeServerReportsCloseFailureAfterSuccessfulResponse() throws {
    let io = PrivateGitBridgeServerTestIO(
        input: try NativeAgentGitBridgeFrame.encodeCommitPayload(Data("payload".utf8)))
    io.closeError = Int32(EIO)
    let signer = CountingSigner()
    let server = try makeServer(io: io, signer: signer.sign)

    #expect(throws: NativeAgentPrivateGitBridgeServerError.closeFailed) {
        try server.serve()
    }
    #expect(signer.callCount == 1)
    #expect(!io.output.isEmpty)
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeServerRejectsConcurrentAndRepeatedUse() throws {
    let io = PrivateGitBridgeServerTestIO(
        input: try NativeAgentGitBridgeFrame.encodeCommitPayload(Data("payload".utf8)))
    let signer = BlockingSigner()
    let server = try makeServer(io: io, signer: signer.sign)
    let firstFinished = DispatchSemaphore(value: 0)
    let firstResult = LockedServerResult()

    DispatchQueue.global().async {
        do {
            try server.serve()
            firstResult.record(.success)
        } catch let error as NativeAgentPrivateGitBridgeServerError {
            firstResult.record(.failure(error))
        } catch {
            firstResult.record(.unexpected)
        }
        firstFinished.signal()
    }

    #expect(signer.entered.wait(timeout: .now() + .seconds(15)) == .success)
    #expect(throws: NativeAgentPrivateGitBridgeServerError.alreadyUsed) {
        try server.serve()
    }

    signer.release.signal()
    #expect(firstFinished.wait(timeout: .now() + .seconds(15)) == .success)
    #expect(firstResult.value == .success)
    #expect(signer.callCount == 1)
    #expect(io.closeCallCount == 1)
    #expect(throws: NativeAgentPrivateGitBridgeServerError.alreadyUsed) {
        try server.serve()
    }
}

private final class LockedServerResult: @unchecked Sendable {
    enum Value: Equatable {
        case success
        case failure(NativeAgentPrivateGitBridgeServerError)
        case unexpected
    }

    private let lock = NSLock()
    private var storedValue: Value?

    var value: Value? {
        lock.lock()
        defer { lock.unlock() }
        return storedValue
    }

    func record(_ value: Value) {
        lock.lock()
        storedValue = value
        lock.unlock()
    }
}
