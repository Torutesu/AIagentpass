import Darwin
import Foundation

public enum NativeAgentPrivateFDTransportOwnership: Sendable {
    case borrowed
    case owned
}

public enum NativeAgentPrivateFDTransportError: Error, Equatable, Sendable {
    case invalidFileDescriptor
    case alreadyClosed
    case readFailed(Int32)
    case writeFailed(Int32)
    case shutdownFailed(Int32)
    case closeFailed(Int32)
    case truncated
    case extraBytes
    case invalidFrame(NativeAgentGitBridgeFrameError)
}

/// One fixed-descriptor request/response transport for the private Git bridge.
///
/// The descriptor is supplied by the caller and is the only transport locator.
/// This type does not open, discover, or configure any other communication
/// channel. A request is one bounded commit frame; a response is one bounded
/// signature frame followed immediately by EOF.
public final class NativeAgentPrivateFDTransport: @unchecked Sendable {
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
    /// Serializes complete frame operations without preventing abort from
    /// acquiring stateLock and issuing shutdown against a blocked syscall.
    private let operationLock = NSLock()
    private var closed = false
    private var physicallyClosed = false
    private var ownershipTransferred = false

    public convenience init(
        fd: Int32,
        ownership: NativeAgentPrivateFDTransportOwnership
    ) throws {
        try self.init(
            fd: fd,
            ownership: ownership,
            read: { descriptor, buffer, count in
                Darwin.read(descriptor, buffer, count)
            },
            write: { descriptor, buffer, count in
                Darwin.write(descriptor, buffer, count)
            },
            close: { descriptor in
                Darwin.close(descriptor)
            },
            shutdownWrite: { descriptor in
                Darwin.shutdown(descriptor, SHUT_WR)
            })
    }

    public convenience init(
        fd: Int32,
        ownership: NativeAgentPrivateFDTransportOwnership,
        read: @escaping ReadClosure,
        write: @escaping WriteClosure,
        close: @escaping CloseClosure
    ) throws {
        try self.init(
            fd: fd,
            ownership: ownership,
            read: read,
            write: write,
            close: close,
            shutdownWrite: { _ in 0 })
    }

    public init(
        fd: Int32,
        ownership: NativeAgentPrivateFDTransportOwnership,
        read: @escaping ReadClosure,
        write: @escaping WriteClosure,
        close: @escaping CloseClosure,
        shutdownWrite: @escaping ShutdownWriteClosure,
        shutdown: @escaping ShutdownClosure = { descriptor in
            Darwin.shutdown(descriptor, SHUT_RDWR)
        }
    ) throws {
        guard fd >= 0 else {
            throw NativeAgentPrivateFDTransportError.invalidFileDescriptor
        }
        self.descriptor = fd
        self.ownership = ownership
        self.readClosure = read
        self.writeClosure = write
        self.closeClosure = close
        self.shutdownWriteClosure = shutdownWrite
        self.shutdownClosure = shutdown
    }

    /// Writes exactly one bounded commit-payload frame, retrying interrupted
    /// writes and rejecting short/failed system calls.
    public func writeCommitPayload(_ payload: Data) throws {
        let frame: Data
        do {
            frame = try NativeAgentGitBridgeFrame.encodeCommitPayload(payload)
        } catch let error as NativeAgentGitBridgeFrameError {
            throw NativeAgentPrivateFDTransportError.invalidFrame(error)
        }

        try withOpenDescriptor {
            try writeExactly(frame)
        }
    }

    /// Permanently half-closes the request direction. The Host requires the
    /// resulting EOF before it signs, eliminating a trailing-frame race while
    /// leaving the response direction available on the full-duplex socket.
    public func finishRequestWriting() throws {
        try withOpenDescriptor {
            guard shutdownWriteClosure(descriptor) == 0 else {
                throw NativeAgentPrivateFDTransportError.shutdownFailed(Self.currentErrno())
            }
        }
    }

    /// Reads exactly one bounded commit-payload frame and requires EOF after
    /// it. The peer half-closes its request direction before waiting for the
    /// response, so a second or late frame fails closed before signing.
    public func readCommitPayload() throws -> Data {
        try withOpenDescriptor {
            var frame = Data(count: NativeAgentGitBridgeFrame.headerBytes)
            try readExactly(&frame)

            let bytes = [UInt8](frame)
            let length = (UInt32(bytes[0]) << 24)
                | (UInt32(bytes[1]) << 16)
                | (UInt32(bytes[2]) << 8)
                | UInt32(bytes[3])
            guard length > 0 else {
                throw NativeAgentPrivateFDTransportError.invalidFrame(.invalidLength)
            }
            guard length <= UInt32(NativeAgentGitBridgeFrame.maximumCommitPayloadBytes) else {
                throw NativeAgentPrivateFDTransportError.invalidFrame(.payloadTooLarge)
            }

            var payload = Data(count: Int(length))
            try readExactly(&payload)
            frame.append(payload)

            var extraByte: UInt8 = 0
            let extraCount = try withUnsafeMutableBytes(of: &extraByte) { rawBuffer in
                try readOnce(into: rawBuffer.baseAddress!, count: 1)
            }
            guard extraCount == 0 else {
                throw NativeAgentPrivateFDTransportError.extraBytes
            }

            do {
                return try NativeAgentGitBridgeFrame.decodeCommitPayload(frame)
            } catch let error as NativeAgentGitBridgeFrameError {
                throw NativeAgentPrivateFDTransportError.invalidFrame(error)
            }
        }
    }

    /// Writes exactly one bounded signature frame, retrying interrupted
    /// writes and short system calls. No second response frame can be
    /// emitted through this transport operation.
    public func writeSignature(_ signature: Data) throws {
        let frame: Data
        do {
            frame = try NativeAgentGitBridgeFrame.encodeSignature(signature)
        } catch let error as NativeAgentGitBridgeFrameError {
            throw NativeAgentPrivateFDTransportError.invalidFrame(error)
        }

        try withOpenDescriptor {
            try writeExactly(frame)
        }
    }

    /// Reads exactly one bounded signature frame and requires EOF immediately
    /// after its payload. A trailing byte is protocol data, not a harmless
    /// read-ahead, and therefore fails closed.
    public func readSignature() throws -> Data {
        try withOpenDescriptor {
            var frame = Data(count: NativeAgentGitBridgeFrame.headerBytes)
            try readExactly(&frame)

            let bytes = [UInt8](frame)
            let length = (UInt32(bytes[0]) << 24)
                | (UInt32(bytes[1]) << 16)
                | (UInt32(bytes[2]) << 8)
                | UInt32(bytes[3])
            guard length > 0 else {
                throw NativeAgentPrivateFDTransportError.invalidFrame(.invalidLength)
            }
            guard length <= UInt32(NativeAgentGitBridgeFrame.maximumSignatureBytes) else {
                throw NativeAgentPrivateFDTransportError.invalidFrame(.payloadTooLarge)
            }

            var payload = Data(count: Int(length))
            try readExactly(&payload)
            frame.append(payload)

            var extraByte: UInt8 = 0
            let extraCount = try withUnsafeMutableBytes(of: &extraByte) { rawBuffer in
                try readOnce(into: rawBuffer.baseAddress!, count: 1)
            }
            guard extraCount == 0 else {
                throw NativeAgentPrivateFDTransportError.extraBytes
            }

            do {
                return try NativeAgentGitBridgeFrame.decodeSignature(frame)
            } catch let error as NativeAgentGitBridgeFrameError {
                throw NativeAgentPrivateFDTransportError.invalidFrame(error)
            }
        }
    }

    /// Atomically hands the descriptor lease to the versioned session
    /// transport. The existing one-shot transport becomes permanently
    /// unusable and will not close or shut down the descriptor after this
    /// method returns. The operation lock makes the handoff mutually
    /// exclusive with an in-flight one-shot frame operation and with close or
    /// abort, so the two transport objects never own the same descriptor at
    /// the same time.
    ///
    /// This is an explicit upgrade only; it does not negotiate a protocol and
    /// it does not provide a fallback to the one-shot bridge.
    public func upgradeToVersionedSessionTransport() throws -> NativeAgentPrivateGitSessionTransport {
        operationLock.lock()
        defer { operationLock.unlock() }

        stateLock.lock()
        guard !closed, !ownershipTransferred else {
            stateLock.unlock()
            throw NativeAgentPrivateFDTransportError.alreadyClosed
        }

        let upgraded: NativeAgentPrivateGitSessionTransport
        do {
            upgraded = try NativeAgentPrivateGitSessionTransport(
                fd: descriptor,
                ownership: ownership,
                read: readClosure,
                write: writeClosure,
                close: closeClosure,
                shutdownWrite: shutdownWriteClosure,
                shutdown: shutdownClosure
            )
        } catch NativeAgentPrivateGitSessionTransportError.invalidFileDescriptor {
            stateLock.unlock()
            throw NativeAgentPrivateFDTransportError.invalidFileDescriptor
        } catch {
            stateLock.unlock()
            throw NativeAgentPrivateFDTransportError.alreadyClosed
        }

        // Mark the old wrapper closed before releasing the state lock. Its
        // deinit/abort path therefore cannot perform a second OS close after
        // the new wrapper takes over the same descriptor.
        closed = true
        ownershipTransferred = true
        stateLock.unlock()
        return upgraded
    }

    /// Closes an owned descriptor exactly once. Borrowed descriptors are only
    /// marked unusable here; their caller retains OS-level close ownership.
    public func close() throws {
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            return
        }
        closed = true
        let shouldClose = ownership == .owned
        stateLock.unlock()

        // Interrupt first, then wait for the serialized operation to leave
        // the syscall. Closing an in-flight descriptor before that point can
        // let the kernel reuse the number for an unrelated object. Borrowed
        // descriptors remain the caller's OS-level responsibility and are
        // therefore not shut down by ordinary close.
        if shouldClose {
            _ = shutdownClosure(descriptor)
        }
        operationLock.lock()
        operationLock.unlock()
        guard shouldClose else { return }
        try finishPhysicalClose()
    }

    /// Interrupts an in-flight operation and makes the descriptor unusable.
    /// The Host uses this when the supervised child or its authority fails
    /// while the bridge server is blocked waiting for a helper frame.
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

    deinit {
        abort()
    }

    private func withOpenDescriptor<T>(_ operation: () throws -> T) throws -> T {
        operationLock.lock()
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            operationLock.unlock()
            throw NativeAgentPrivateFDTransportError.alreadyClosed
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

    private func markClosedAndInterrupt() {
        stateLock.lock()
        let shouldInterrupt = !closed
        closed = true
        stateLock.unlock()
        if shouldInterrupt {
            _ = shutdownClosure(descriptor)
        }
    }

    private func finishPhysicalClose() throws {
        guard ownership == .owned else { return }
        stateLock.lock()
        guard !physicallyClosed, !ownershipTransferred else {
            stateLock.unlock()
            return
        }
        physicallyClosed = true
        stateLock.unlock()
        guard closeClosure(descriptor) == 0 else {
            throw NativeAgentPrivateFDTransportError.closeFailed(Self.currentErrno())
        }
    }

    private func readExactly(_ data: inout Data) throws {
        var offset = 0
        while offset < data.count {
            let count = data.count - offset
            let result = data.withUnsafeMutableBytes { rawBuffer in
                readClosure(
                    descriptor,
                    rawBuffer.baseAddress!.advanced(by: offset),
                    count)
            }
            if result == -1 {
                let error = Self.currentErrno()
                if error == Int32(EINTR) { continue }
                throw NativeAgentPrivateFDTransportError.readFailed(error)
            }
            guard result > 0 else {
                throw NativeAgentPrivateFDTransportError.truncated
            }
            guard result <= count else {
                throw NativeAgentPrivateFDTransportError.readFailed(Int32(EIO))
            }
            offset += result
        }
    }

    private func writeExactly(_ data: Data) throws {
        var offset = 0
        while offset < data.count {
            let count = data.count - offset
            let result = data.withUnsafeBytes { rawBuffer in
                writeClosure(
                    descriptor,
                    rawBuffer.baseAddress!.advanced(by: offset),
                    count)
            }
            if result == -1 {
                let error = Self.currentErrno()
                if error == Int32(EINTR) { continue }
                throw NativeAgentPrivateFDTransportError.writeFailed(error)
            }
            guard result > 0 else {
                throw NativeAgentPrivateFDTransportError.writeFailed(Int32(EIO))
            }
            guard result <= count else {
                throw NativeAgentPrivateFDTransportError.writeFailed(Int32(EIO))
            }
            offset += result
        }
    }

    private func readOnce(into buffer: UnsafeMutableRawPointer, count: Int) throws -> Int {
        while true {
            let result = readClosure(descriptor, buffer, count)
            if result == -1 {
                let error = Self.currentErrno()
                if error == Int32(EINTR) { continue }
                throw NativeAgentPrivateFDTransportError.readFailed(error)
            }
            guard result >= 0, result <= count else {
                throw NativeAgentPrivateFDTransportError.readFailed(Int32(EIO))
            }
            return result
        }
    }

    private static func currentErrno() -> Int32 {
        let error = Int32(errno)
        return error == 0 ? Int32(EIO) : error
    }

}
