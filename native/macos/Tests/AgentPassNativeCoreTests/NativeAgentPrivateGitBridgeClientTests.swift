import AgentPassNativeCore
import Darwin
import Dispatch
import Foundation
import Testing

private final class PrivateGitBridgeClientTestIO: @unchecked Sendable {
    static let synchronizationTimeout: DispatchTimeInterval = .seconds(15)
    var input: Data
    var inputOffset = 0
    var output = Data()
    var closeCallCount = 0
    var writeError: Int32?
    var readError: Int32?
    var blockReads = false
    let readEntered = DispatchSemaphore(value: 0)
    let releaseRead = DispatchSemaphore(value: 0)

    init(input: Data = Data()) {
        self.input = input
    }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        _ = descriptor
        if blockReads {
            readEntered.signal()
            _ = releaseRead.wait(timeout: .now() + Self.synchronizationTimeout)
        }
        if let readError {
            errno = readError
            return -1
        }
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
        return 0
    }
}

private func makePrivateGitBridgeClient(
    io: PrivateGitBridgeClientTestIO,
    fd: Int32 = 81
) throws -> NativeAgentPrivateGitBridgeClient {
    let transport = try NativeAgentPrivateFDTransport(
        fd: fd,
        ownership: .owned,
        read: io.read,
        write: io.write,
        close: io.close)
    return NativeAgentPrivateGitBridgeClient(transport: transport)
}

@Test func privateGitBridgeClientReturnsOnlySignatureAndClosesAfterSuccess() throws {
    let payload = Data("tree abc\n\nmessage\n".utf8)
    let signature = Data("ssh-signature\n".utf8)
    let io = PrivateGitBridgeClientTestIO(
        input: try NativeAgentGitBridgeFrame.encodeSignature(signature))
    let client = try makePrivateGitBridgeClient(io: io)

    #expect(try client.sign(commitPayload: payload) == signature)
    #expect(io.output == (try NativeAgentGitBridgeFrame.encodeCommitPayload(payload)))
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeClientFailsClosedOnWriteFailureAndCloses() throws {
    let io = PrivateGitBridgeClientTestIO()
    io.writeError = Int32(EPIPE)
    let client = try makePrivateGitBridgeClient(io: io)

    #expect(throws: NativeAgentPrivateGitBridgeClientError.transport(.writeFailed(Int32(EPIPE)))) {
        _ = try client.sign(commitPayload: Data("payload".utf8))
    }
    #expect(io.closeCallCount == 1)
    #expect(throws: NativeAgentPrivateGitBridgeClientError.alreadyUsed) {
        _ = try client.sign(commitPayload: Data("retry".utf8))
    }
}

@Test func privateGitBridgeClientFailsClosedOnReadFailureAfterWriting() throws {
    let io = PrivateGitBridgeClientTestIO()
    io.readError = Int32(ECONNRESET)
    let client = try makePrivateGitBridgeClient(io: io)

    #expect(throws: NativeAgentPrivateGitBridgeClientError.transport(.readFailed(Int32(ECONNRESET)))) {
        _ = try client.sign(commitPayload: Data("payload".utf8))
    }
    #expect(io.output == (try NativeAgentGitBridgeFrame.encodeCommitPayload(Data("payload".utf8))))
    #expect(io.closeCallCount == 1)
}

@Test func privateGitBridgeClientRejectsConcurrentAndRepeatedUse() throws {
    let io = PrivateGitBridgeClientTestIO()
    io.blockReads = true
    let client = try makePrivateGitBridgeClient(io: io)
    let firstFinished = DispatchSemaphore(value: 0)
    let firstResult = LockedClientTestResult()

    DispatchQueue.global().async {
        do {
            _ = try client.sign(commitPayload: Data("first".utf8))
            firstResult.record(.success)
        } catch let error as NativeAgentPrivateGitBridgeClientError {
            firstResult.record(.failure(error))
        } catch {
            firstResult.record(.unexpected)
        }
        firstFinished.signal()
    }

    #expect(io.readEntered.wait(timeout: .now() + PrivateGitBridgeClientTestIO.synchronizationTimeout) == .success)
    #expect(throws: NativeAgentPrivateGitBridgeClientError.alreadyUsed) {
        _ = try client.sign(commitPayload: Data("second".utf8))
    }

    io.releaseRead.signal()
    #expect(firstFinished.wait(timeout: .now() + PrivateGitBridgeClientTestIO.synchronizationTimeout) == .success)
    #expect(firstResult.value == .failure(.transport(.truncated)))
    #expect(io.closeCallCount == 1)
    #expect(throws: NativeAgentPrivateGitBridgeClientError.alreadyUsed) {
        _ = try client.sign(commitPayload: Data("third".utf8))
    }
}

private final class LockedClientTestResult: @unchecked Sendable {
    enum Value: Equatable {
        case success
        case failure(NativeAgentPrivateGitBridgeClientError)
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
