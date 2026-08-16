import AgentPassNativeCore
import Darwin
import Foundation
import Testing

private final class PrivateFDTestIO: @unchecked Sendable {
    var input: Data
    var inputOffset = 0
    var readChunkSizes: [Int]
    var readCallCount = 0
    var output = Data()
    var writeCallCount = 0
    var closeCallCount = 0
    var interruptNextRead = false
    var interruptNextWrite = false

    init(input: Data = Data(), readChunkSizes: [Int] = []) {
        self.input = input
        self.readChunkSizes = readChunkSizes
    }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        _ = descriptor
        readCallCount += 1
        if interruptNextRead {
            interruptNextRead = false
            errno = EINTR
            return -1
        }
        guard inputOffset < input.count else { return 0 }
        let scriptedSize = readChunkSizes.isEmpty
            ? count
            : readChunkSizes.removeFirst()
        let amount = min(count, scriptedSize, input.count - inputOffset)
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
        writeCallCount += 1
        if interruptNextWrite {
            interruptNextWrite = false
            errno = EINTR
            return -1
        }
        let amount = min(3, count)
        output.append(Data(bytes: buffer, count: amount))
        return amount
    }

    func close(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        closeCallCount += 1
        return 0
    }
}

private final class TransportConcurrencyProbe: @unchecked Sendable {
    let firstWriteEntered = DispatchSemaphore(value: 0)
    let releaseFirstWrite = DispatchSemaphore(value: 0)
    let firstWriteReturned = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private(set) var writeCallCount = 0
    private(set) var closeCallCount = 0
    private(set) var shutdownCallCount = 0
    private(set) var closeObservedAfterWriteReturned = false

    func write(_ descriptor: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
        _ = descriptor
        _ = buffer
        lock.lock()
        writeCallCount += 1
        let isFirst = writeCallCount == 1
        lock.unlock()
        if isFirst {
            firstWriteEntered.signal()
            _ = releaseFirstWrite.wait(timeout: .now() + .seconds(5))
            lock.lock()
            closeObservedAfterWriteReturned = false
            lock.unlock()
            firstWriteReturned.signal()
        }
        return count
    }

    func shutdown(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        lock.lock()
        shutdownCallCount += 1
        lock.unlock()
        releaseFirstWrite.signal()
        return 0
    }

    func close(_ descriptor: Int32) -> Int32 {
        _ = descriptor
        lock.lock()
        closeCallCount += 1
        closeObservedAfterWriteReturned = firstWriteReturned.wait(timeout: .now()) == .success
        lock.unlock()
        return 0
    }
}

private final class TransportErrorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: NativeAgentPrivateFDTransportError?

    func set(_ error: NativeAgentPrivateFDTransportError) {
        lock.lock()
        stored = error
        lock.unlock()
    }

    func get() -> NativeAgentPrivateFDTransportError? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}

@Test func privateFDTransportWritesOneExactBoundedFrameWithEINTRAndShortWrites() throws {
    let io = PrivateFDTestIO()
    io.interruptNextWrite = true
    let transport = try NativeAgentPrivateFDTransport(
        fd: 41,
        ownership: .borrowed,
        read: io.read,
        write: io.write,
        close: io.close)
    let payload = Data("tree abc\n\nmessage\n".utf8)

    try transport.writeCommitPayload(payload)

    #expect(io.output == (try NativeAgentGitBridgeFrame.encodeCommitPayload(payload)))
    #expect(io.writeCallCount > 1)
    #expect(io.closeCallCount == 0)
}

@Test func privateFDTransportReadsExactSignatureFrameWithEINTRPartialReadsAndEOF() throws {
    let signature = Data("-----BEGIN SSH SIGNATURE-----\nfixed\n-----END SSH SIGNATURE-----\n".utf8)
    let frame = try NativeAgentGitBridgeFrame.encodeSignature(signature)
    let io = PrivateFDTestIO(input: frame, readChunkSizes: [1, 3, 1, 2, 4, 8, 64])
    io.interruptNextRead = true
    let transport = try NativeAgentPrivateFDTransport(
        fd: 42,
        ownership: .borrowed,
        read: io.read,
        write: io.write,
        close: io.close)

    #expect(try transport.readSignature() == signature)
    #expect(io.readCallCount > 4)
    #expect(io.closeCallCount == 0)
}

@Test func privateFDTransportRejectsTruncationAndClosesOwnedDescriptor() throws {
    let truncatedFrame = Data([0, 0, 0, 4, 1, 2])
    let io = PrivateFDTestIO(input: truncatedFrame, readChunkSizes: [4, 2])
    let transport = try NativeAgentPrivateFDTransport(
        fd: 43,
        ownership: .owned,
        read: io.read,
        write: io.write,
        close: io.close)

    do {
        _ = try transport.readSignature()
        Issue.record("truncated frame was accepted")
    } catch let error as NativeAgentPrivateFDTransportError {
        #expect(error == .truncated)
    }
    #expect(io.closeCallCount == 1)
    #expect(throws: NativeAgentPrivateFDTransportError.alreadyClosed) {
        _ = try transport.readSignature()
    }
}

@Test func privateFDTransportRejectsTrailingBytesAndOversizedDeclaredLength() throws {
    let signature = Data("signature".utf8)
    let validFrame = try NativeAgentGitBridgeFrame.encodeSignature(signature)

    let extraIO = PrivateFDTestIO(input: validFrame + Data([0xff]))
    let extraTransport = try NativeAgentPrivateFDTransport(
        fd: 44,
        ownership: .owned,
        read: extraIO.read,
        write: extraIO.write,
        close: extraIO.close)
    do {
        _ = try extraTransport.readSignature()
        Issue.record("extra byte was accepted")
    } catch let error as NativeAgentPrivateFDTransportError {
        #expect(error == .extraBytes)
    }
    #expect(extraIO.closeCallCount == 1)

    let oversized = UInt32(NativeAgentGitBridgeFrame.maximumSignatureBytes + 1)
    let oversizedFrame = Data([
        UInt8((oversized >> 24) & 0xff),
        UInt8((oversized >> 16) & 0xff),
        UInt8((oversized >> 8) & 0xff),
        UInt8(oversized & 0xff),
    ])
    let oversizedIO = PrivateFDTestIO(input: oversizedFrame)
    let oversizedTransport = try NativeAgentPrivateFDTransport(
        fd: 45,
        ownership: .owned,
        read: oversizedIO.read,
        write: oversizedIO.write,
        close: oversizedIO.close)
    do {
        _ = try oversizedTransport.readSignature()
        Issue.record("oversized frame was accepted")
    } catch let error as NativeAgentPrivateFDTransportError {
        #expect(error == .invalidFrame(.payloadTooLarge))
    }
    #expect(oversizedIO.closeCallCount == 1)
}

@Test func privateFDTransportMakesCloseOwnershipExplicitAndIdempotent() throws {
    let borrowedIO = PrivateFDTestIO()
    let borrowed = try NativeAgentPrivateFDTransport(
        fd: 46,
        ownership: .borrowed,
        read: borrowedIO.read,
        write: borrowedIO.write,
        close: borrowedIO.close)
    try borrowed.close()
    try borrowed.close()
    #expect(borrowedIO.closeCallCount == 0)

    let ownedIO = PrivateFDTestIO()
    let owned = try NativeAgentPrivateFDTransport(
        fd: 47,
        ownership: .owned,
        read: ownedIO.read,
        write: ownedIO.write,
        close: ownedIO.close)
    try owned.close()
    try owned.close()
    #expect(ownedIO.closeCallCount == 1)
}

@Test func privateFDTransportSerializesOperationsAndAbortWaitsBeforePhysicalClose() throws {
    let probe = TransportConcurrencyProbe()
    let transport = try NativeAgentPrivateFDTransport(
        fd: 48,
        ownership: .owned,
        read: { _, _, _ in 0 },
        write: probe.write,
        close: probe.close,
        shutdownWrite: { _ in 0 },
        shutdown: probe.shutdown
    )

    let firstFinished = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        try? transport.writeCommitPayload(Data("first".utf8))
        firstFinished.signal()
    }
    #expect(probe.firstWriteEntered.wait(timeout: .now() + .seconds(2)) == .success)

    let secondFinished = DispatchSemaphore(value: 0)
    let secondResult = TransportErrorBox()
    DispatchQueue.global().async {
        do {
            try transport.writeCommitPayload(Data("second".utf8))
        } catch let error as NativeAgentPrivateFDTransportError {
            secondResult.set(error)
        } catch {
            Issue.record("unexpected transport error")
        }
        secondFinished.signal()
    }

    transport.abort()
    #expect(firstFinished.wait(timeout: .now() + .seconds(2)) == .success)
    #expect(secondFinished.wait(timeout: .now() + .seconds(2)) == .success)
    #expect(probe.writeCallCount == 1)
    #expect(probe.shutdownCallCount == 1)
    #expect(probe.closeCallCount == 1)
    #expect(probe.closeObservedAfterWriteReturned)
    #expect(secondResult.get() == .alreadyClosed)
    #expect(throws: NativeAgentPrivateFDTransportError.alreadyClosed) {
        try transport.writeCommitPayload(Data("third".utf8))
    }
}

@Test func privateFDTransportRejectsNegativeDescriptor() {
    #expect(throws: NativeAgentPrivateFDTransportError.invalidFileDescriptor) {
        _ = try NativeAgentPrivateFDTransport(
            fd: -1,
            ownership: .borrowed,
            read: { _, _, _ in 0 },
            write: { _, _, _ in 0 },
            close: { _ in 0 })
    }
}
