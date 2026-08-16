import Darwin
import Foundation

/// Stable, secret-free failures for the fixed Git SSH signing helper.
public enum NativeAgentGitSigningHelperError: Error, Equatable, Sendable {
    case invalidInvocation
    case unsupportedNamespace
    case unsupportedSignerReference
    case invalidPayloadPath
    case payloadUnavailable
    case payloadNotOwned
    case payloadTooLarge
    case payloadChanged
    case signatureAlreadyExists
    case signatureUnavailable
    case signatureWriteFailed
    case invalidSignature
    case bridgeUnavailable
}

/// The only invocation accepted by the native Git helper.
///
/// Git still supplies its normal `ssh-keygen -Y sign` shape, but the `-f`
/// value is a fixed opaque marker. It is not a path, key selector, or source
/// of authority. The native service selects the enrolled signing key after
/// the private FD3 bridge has been authenticated by the Host lifecycle.
public struct NativeAgentGitSigningInvocation: Equatable, Sendable {
    public static let fixedSignerReference = "agentpass-managed"
    public static let maximumPathBytes = 4 * 1024

    public let payloadPath: String

    public init(arguments: [String]) throws {
        guard arguments.count == 7 else {
            throw NativeAgentGitSigningHelperError.invalidInvocation
        }
        guard arguments[0] == "-Y", arguments[1] == "sign" else {
            throw NativeAgentGitSigningHelperError.invalidInvocation
        }
        guard arguments[2] == "-n", arguments[3] == "git" else {
            throw NativeAgentGitSigningHelperError.unsupportedNamespace
        }
        guard arguments[4] == "-f" else {
            throw NativeAgentGitSigningHelperError.invalidInvocation
        }
        guard arguments[5] == Self.fixedSignerReference else {
            throw NativeAgentGitSigningHelperError.unsupportedSignerReference
        }

        let path = arguments[6]
        guard !path.isEmpty,
              path.utf8.count <= Self.maximumPathBytes,
              path.hasPrefix("/"),
              !path.contains("\0") else {
            throw NativeAgentGitSigningHelperError.invalidPayloadPath
        }
        self.payloadPath = path
    }

    public var signaturePath: String {
        payloadPath + ".sig"
    }
}

/// Fixed-path Git helper runtime.
///
/// It consumes exactly one inherited FD3 request, never discovers a socket,
/// and never retries after the bridge has been used. The payload path is only
/// Git's temporary object input; it cannot select a repository, key, policy,
/// session, or operation.
public enum NativeAgentGitSigningHelper {
    public static let fixedBridgeFileDescriptor: Int32 = 3

    public static func run(
        arguments: [String],
        bridgeFileDescriptor: Int32 = fixedBridgeFileDescriptor
    ) throws {
        let invocation = try NativeAgentGitSigningInvocation(arguments: arguments)
        let payload = try readPayload(at: invocation.payloadPath)
        try reserveSignaturePath(invocation.signaturePath)
        try validateBridgeDescriptor(bridgeFileDescriptor)

        let transport: NativeAgentPrivateFDTransport
        do {
            transport = try NativeAgentPrivateFDTransport(
                fd: bridgeFileDescriptor,
                ownership: .owned
            )
        } catch {
            throw NativeAgentGitSigningHelperError.bridgeUnavailable
        }

        let client = NativeAgentPrivateGitBridgeClient(transport: transport)
        let signature: Data
        do {
            signature = try client.sign(commitPayload: payload)
        } catch {
            throw NativeAgentGitSigningHelperError.bridgeUnavailable
        }
        guard isArmoredGitSignature(signature) else {
            throw NativeAgentGitSigningHelperError.invalidSignature
        }
        try writeSignature(signature, at: invocation.signaturePath)
    }

    private static func readPayload(at path: String) throws -> Data {
        var linkInfo = stat()
        guard lstat(path, &linkInfo) == 0 else {
            throw NativeAgentGitSigningHelperError.payloadUnavailable
        }
        guard linkInfo.st_mode & UInt16(S_IFMT) == UInt16(S_IFREG) else {
            throw NativeAgentGitSigningHelperError.payloadUnavailable
        }
        guard linkInfo.st_uid == geteuid() else {
            throw NativeAgentGitSigningHelperError.payloadNotOwned
        }
        guard linkInfo.st_size > 0,
              linkInfo.st_size <= off_t(AgentPassAgentSignRequest.maximumCommitPayloadBytes) else {
            throw NativeAgentGitSigningHelperError.payloadTooLarge
        }

        let descriptor = open(path, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw NativeAgentGitSigningHelperError.payloadUnavailable
        }
        defer { _ = close(descriptor) }

        var openedInfo = stat()
        guard fstat(descriptor, &openedInfo) == 0,
              openedInfo.st_mode & UInt16(S_IFMT) == UInt16(S_IFREG),
              openedInfo.st_uid == geteuid(),
              openedInfo.st_dev == linkInfo.st_dev,
              openedInfo.st_ino == linkInfo.st_ino,
              openedInfo.st_size == linkInfo.st_size else {
            throw NativeAgentGitSigningHelperError.payloadChanged
        }

        var payload = Data(count: Int(openedInfo.st_size))
        var offset = 0
        while offset < payload.count {
            let remaining = payload.count - offset
            let result = payload.withUnsafeMutableBytes { buffer in
                read(
                    descriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    remaining
                )
            }
            if result < 0 {
                if errno == EINTR { continue }
                throw NativeAgentGitSigningHelperError.payloadUnavailable
            }
            guard result > 0 else {
                throw NativeAgentGitSigningHelperError.payloadChanged
            }
            offset += result
        }
        return payload
    }

    private static func reserveSignaturePath(_ path: String) throws {
        var info = stat()
        if lstat(path, &info) == 0 {
            throw NativeAgentGitSigningHelperError.signatureAlreadyExists
        }
        guard errno == ENOENT else {
            throw NativeAgentGitSigningHelperError.signatureUnavailable
        }
    }

    private static func writeSignature(_ signature: Data, at path: String) throws {
        let descriptor = open(
            path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            mode_t(0o600)
        )
        guard descriptor >= 0 else {
            throw errno == EEXIST
                ? NativeAgentGitSigningHelperError.signatureAlreadyExists
                : NativeAgentGitSigningHelperError.signatureUnavailable
        }

        defer {
            _ = close(descriptor)
        }

        var offset = 0
        while offset < signature.count {
            let result = signature.withUnsafeBytes { buffer in
                write(
                    descriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    signature.count - offset
                )
            }
            if result < 0 {
                if errno == EINTR { continue }
                throw NativeAgentGitSigningHelperError.signatureWriteFailed
            }
            guard result > 0 else {
                throw NativeAgentGitSigningHelperError.signatureWriteFailed
            }
            offset += result
        }
        guard fsync(descriptor) == 0 else {
            throw NativeAgentGitSigningHelperError.signatureWriteFailed
        }
    }

    private static func validateBridgeDescriptor(_ descriptor: Int32) throws {
        guard descriptor >= 0 else {
            throw NativeAgentGitSigningHelperError.bridgeUnavailable
        }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              info.st_mode & UInt16(S_IFMT) == UInt16(S_IFSOCK) else {
            throw NativeAgentGitSigningHelperError.bridgeUnavailable
        }
        var socketType: Int32 = 0
        var socketTypeLength = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(
            descriptor,
            SOL_SOCKET,
            SO_TYPE,
            &socketType,
            &socketTypeLength
        ) == 0,
        socketType == Int32(SOCK_STREAM) else {
            throw NativeAgentGitSigningHelperError.bridgeUnavailable
        }
    }

    private static func isArmoredGitSignature(_ signature: Data) -> Bool {
        guard signature.count > 0,
              signature.count <= AgentPassAgentSignResponse.maximumSignatureBytes,
              let text = String(data: signature, encoding: .utf8) else {
            return false
        }
        return text.hasPrefix("-----BEGIN SSH SIGNATURE-----\n")
            && text.hasSuffix("-----END SSH SIGNATURE-----\n")
    }
}
