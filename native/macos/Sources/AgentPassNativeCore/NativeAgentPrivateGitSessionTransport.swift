import Darwin
import Foundation

/// Fail-closed errors for the versioned multi-request Git session transport.
/// The transport never exposes peer-controlled frame bytes or authority data
/// through its errors.
public enum NativeAgentPrivateGitSessionTransportError: Error, Equatable, Sendable {
    case invalidFileDescriptor
    case alreadyClosed
    case alreadyFinishedWriting
    case eof
    case truncated
    case extraBytes
    case readFailed
    case writeFailed
    case shutdownFailed
    case closeFailed
    case invalidFrame(NativeAgentPrivateGitSessionCodecError)
}

/// A bounded, explicitly framed stream for the v1 multi-request private Git
/// bridge. This is intentionally separate from `NativeAgentPrivateFDTransport`:
/// the latter remains the existing one-shot protocol and requires EOF after
/// every request/response transaction.
public final class NativeAgentPrivateGitSessionTransport: @unchecked Sendable {
    public typealias ReadClosure = @Sendable (Int32, UnsafeMutableRawPointer, Int) -> Int
    public typealias WriteClosure = @Sendable (Int32, UnsafeRawPointer, Int) -> Int
    public typealias CloseClosure = @Sendable (Int32) -> Int32
    public typealias ShutdownWriteClosure = @Sendable (Int32) -> Int32
    public typealias ShutdownClosure = @Sendable (Int32) -> Int32

    private let descriptor: Int32
    private let ownership: NativeAgentPrivateFDTransportOwnership
    private let readClosure: ReadClosure
    private let writeClosure: WriteClosure
    private let closeClosure: CloseClosure
    private let shutdownWriteClosure: ShutdownWriteClosure
    private let shutdownClosure: ShutdownClosure
    private let stateLock = NSLock()
    private let operationLock = NSLock()
    private var closed = false
    private var physicallyClosed = false
    private var writingFinished = false

    public convenience init(
        fd: Int32,
        ownership: NativeAgentPrivateFDTransportOwnership
    ) throws {
        try self.init(
            fd: fd,
            ownership: ownership,
            read: { descriptor, buffer, count in Darwin.read(descriptor, buffer, count) },
            write: { descriptor, buffer, count in Darwin.write(descriptor, buffer, count) },
            close: { descriptor in Darwin.close(descriptor) },
            shutdownWrite: { descriptor in Darwin.shutdown(descriptor, SHUT_WR) },
            shutdown: { descriptor in Darwin.shutdown(descriptor, SHUT_RDWR) })
    }

    public init(
        fd: Int32,
        ownership: NativeAgentPrivateFDTransportOwnership,
        read: @escaping ReadClosure,
        write: @escaping WriteClosure,
        close: @escaping CloseClosure,
        shutdownWrite: @escaping ShutdownWriteClosure = { _ in 0 },
        shutdown: @escaping ShutdownClosure = { descriptor in
            Darwin.shutdown(descriptor, SHUT_RDWR)
        }
    ) throws {
        guard fd >= 0 else {
            throw NativeAgentPrivateGitSessionTransportError.invalidFileDescriptor
        }
        self.descriptor = fd
        self.ownership = ownership
        self.readClosure = read
        self.writeClosure = write
        self.closeClosure = close
        self.shutdownWriteClosure = shutdownWrite
        self.shutdownClosure = shutdown
    }

    /// Writes one already-canonical session frame. Multiple frames may be
    /// written over the same connection; EOF is reserved for the close
    /// handshake and is never used as a request delimiter.
    public func writeFrame(_ frame: Data) throws {
        try withOpenDescriptor {
            guard frame.count >= NativeAgentPrivateGitSessionFrameCodec.framePrefixBytes else {
                throw NativeAgentPrivateGitSessionTransportError.invalidFrame(.frameTooShort)
            }
            let bodyLength = Self.readUInt32(frame, offset: 0)
            guard bodyLength > 0 else {
                throw NativeAgentPrivateGitSessionTransportError.invalidFrame(.invalidLength)
            }
            guard bodyLength <= UInt32(NativeAgentPrivateGitSessionFrameCodec.maximumBodyBytes) else {
                throw NativeAgentPrivateGitSessionTransportError.invalidFrame(.frameTooLarge)
            }
            guard frame.count == NativeAgentPrivateGitSessionFrameCodec.framePrefixBytes + Int(bodyLength) else {
                throw NativeAgentPrivateGitSessionTransportError.invalidFrame(.lengthMismatch)
            }
            try writeExactly(frame)
        }
    }

    /// Reads exactly one outer-length-delimited frame. A clean EOF before a
    /// frame starts is distinct from truncation after any prefix byte.
    public func readFrame() throws -> Data {
        try withOpenDescriptor {
            var prefix = Data(count: NativeAgentPrivateGitSessionFrameCodec.framePrefixBytes)
            try readExactly(&prefix, allowInitialEOF: true)
            let bodyLength = Self.readUInt32(prefix, offset: 0)
            guard bodyLength > 0 else {
                throw NativeAgentPrivateGitSessionTransportError.invalidFrame(.invalidLength)
            }
            guard bodyLength <= UInt32(NativeAgentPrivateGitSessionFrameCodec.maximumBodyBytes) else {
                throw NativeAgentPrivateGitSessionTransportError.invalidFrame(.frameTooLarge)
            }
            var frame = prefix
            var body = Data(count: Int(bodyLength))
            try readExactly(&body, allowInitialEOF: false)
            frame.append(body)
            return frame
        }
    }

    /// Half-closes only the local write direction. It is used after a close
    /// frame so the peer can distinguish a complete close handshake from a
    /// response-loss EOF.
    public func finishWriting() throws {
        try withOpenDescriptor {
            stateLock.lock()
            if writingFinished {
                stateLock.unlock()
                throw NativeAgentPrivateGitSessionTransportError.alreadyFinishedWriting
            }
            writingFinished = true
            stateLock.unlock()
            guard shutdownWriteClosure(descriptor) == 0 else {
                throw NativeAgentPrivateGitSessionTransportError.shutdownFailed
            }
        }
    }

    /// Requires EOF immediately after a peer close frame. Any byte is
    /// protocol traffic after close and therefore quarantines the transport.
    public func readEOF() throws {
        try withOpenDescriptor {
            var byte: UInt8 = 0
            let result = try withUnsafeMutableBytes(of: &byte) { buffer in
                try readOnce(into: buffer.baseAddress!, count: 1)
            }
            guard result == 0 else {
                throw NativeAgentPrivateGitSessionTransportError.extraBytes
            }
        }
    }

    /// Closes the descriptor exactly once. The stream transport is terminal
    /// after close, while an owned descriptor also receives the OS close.
    public func close() throws {
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            return
        }
        closed = true
        let shouldClose = ownership == .owned
        stateLock.unlock()

        if shouldClose { _ = shutdownClosure(descriptor) }
        operationLock.lock()
        operationLock.unlock()
        guard shouldClose else { return }
        try finishPhysicalClose()
    }

    /// Interrupts a blocked operation and permanently disables the stream.
    public func abort() {
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            return
        }
        closed = true
        let shouldClose = ownership == .owned
        stateLock.unlock()

        _ = shutdownClosure(descriptor)
        if shouldClose {
            operationLock.lock()
            operationLock.unlock()
            try? finishPhysicalClose()
        }
    }

    deinit { abort() }

    private func withOpenDescriptor<T>(_ operation: () throws -> T) throws -> T {
        operationLock.lock()
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            operationLock.unlock()
            throw NativeAgentPrivateGitSessionTransportError.alreadyClosed
        }
        stateLock.unlock()

        do {
            let result = try operation()
            operationLock.unlock()
            return result
        } catch {
            markClosedAndInterrupt()
            operationLock.unlock()
            try? finishPhysicalClose()
            throw error
        }
    }

    private func readExactly(_ data: inout Data, allowInitialEOF: Bool) throws {
        var offset = 0
        while offset < data.count {
            let count = data.count - offset
            let result = data.withUnsafeMutableBytes { buffer in
                readClosure(descriptor, buffer.baseAddress!.advanced(by: offset), count)
            }
            if result == -1 {
                throw NativeAgentPrivateGitSessionTransportError.readFailed
            }
            if result == 0 {
                if offset == 0 && allowInitialEOF {
                    throw NativeAgentPrivateGitSessionTransportError.eof
                }
                throw NativeAgentPrivateGitSessionTransportError.truncated
            }
            guard result <= count else {
                throw NativeAgentPrivateGitSessionTransportError.readFailed
            }
            offset += result
        }
    }

    private func readOnce(into buffer: UnsafeMutableRawPointer, count: Int) throws -> Int {
        let result = readClosure(descriptor, buffer, count)
        if result == -1 { throw NativeAgentPrivateGitSessionTransportError.readFailed }
        guard result >= 0, result <= count else {
            throw NativeAgentPrivateGitSessionTransportError.readFailed
        }
        return result
    }

    private func writeExactly(_ data: Data) throws {
        var offset = 0
        while offset < data.count {
            let count = data.count - offset
            let result = data.withUnsafeBytes { buffer in
                writeClosure(descriptor, buffer.baseAddress!.advanced(by: offset), count)
            }
            guard result > 0, result <= count else {
                throw NativeAgentPrivateGitSessionTransportError.writeFailed
            }
            offset += result
        }
    }

    private func markClosedAndInterrupt() {
        stateLock.lock()
        let shouldInterrupt = !closed
        closed = true
        stateLock.unlock()
        if shouldInterrupt { _ = shutdownClosure(descriptor) }
    }

    private func finishPhysicalClose() throws {
        guard ownership == .owned else { return }
        stateLock.lock()
        guard !physicallyClosed else {
            stateLock.unlock()
            return
        }
        physicallyClosed = true
        stateLock.unlock()
        guard closeClosure(descriptor) == 0 else {
            throw NativeAgentPrivateGitSessionTransportError.closeFailed
        }
    }

    private static func readUInt32(_ data: Data, offset: Int) -> UInt32 {
        (UInt32(data[offset]) << 24)
            | (UInt32(data[offset + 1]) << 16)
            | (UInt32(data[offset + 2]) << 8)
            | UInt32(data[offset + 3])
    }
}
