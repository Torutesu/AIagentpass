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
public final class NativeAgentPrivateFDTransport {
    public typealias ReadClosure = @Sendable (Int32, UnsafeMutableRawPointer, Int) -> Int
    public typealias WriteClosure = @Sendable (Int32, UnsafeRawPointer, Int) -> Int
    public typealias CloseClosure = @Sendable (Int32) -> Int32

    private let descriptor: Int32
    private let ownership: NativeAgentPrivateFDTransportOwnership
    private let readClosure: ReadClosure
    private let writeClosure: WriteClosure
    private let closeClosure: CloseClosure
    private let stateLock = NSLock()
    private var closed = false

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
            })
    }

    public init(
        fd: Int32,
        ownership: NativeAgentPrivateFDTransportOwnership,
        read: @escaping ReadClosure,
        write: @escaping WriteClosure,
        close: @escaping CloseClosure
    ) throws {
        guard fd >= 0 else {
            throw NativeAgentPrivateFDTransportError.invalidFileDescriptor
        }
        self.descriptor = fd
        self.ownership = ownership
        self.readClosure = read
        self.writeClosure = write
        self.closeClosure = close
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
        let result = shouldClose ? closeClosure(descriptor) : 0
        let closeError = result == -1 ? Self.currentErrno() : nil
        stateLock.unlock()

        if let closeError {
            throw NativeAgentPrivateFDTransportError.closeFailed(closeError)
        }
    }

    deinit {
        guard ownership == .owned, !closed else { return }
        _ = closeClosure(descriptor)
    }

    private func withOpenDescriptor<T>(_ operation: () throws -> T) throws -> T {
        stateLock.lock()
        guard !closed else {
            stateLock.unlock()
            throw NativeAgentPrivateFDTransportError.alreadyClosed
        }

        do {
            let result = try operation()
            stateLock.unlock()
            return result
        } catch {
            closed = true
            if ownership == .owned {
                _ = closeClosure(descriptor)
            }
            stateLock.unlock()
            throw error
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
