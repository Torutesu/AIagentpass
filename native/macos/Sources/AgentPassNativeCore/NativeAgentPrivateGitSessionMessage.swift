import Foundation

/// A single message in the versioned, multi-request private Git session.
///
/// The message intentionally contains only a direction, a sequence number,
/// and bounded opaque bytes. Authority, identity, key, algorithm, repository,
/// capability, and policy selectors are deliberately not representable.
public enum NativeAgentPrivateGitSessionMessage: Equatable, Sendable {
    case request(sequence: UInt32, commitPayload: Data)
    case response(sequence: UInt32, signature: Data)
}

/// Stable, secret-free failures for the private Git session wire codec.
public enum NativeAgentPrivateGitSessionCodecError: Error, Equatable, Sendable {
    case frameTooShort
    case frameTooLarge
    case invalidLength
    case lengthMismatch
    case invalidMagic
    case unsupportedVersion
    case invalidMessageKind
    case nonZeroFlags
    case invalidSequence
    case emptyPayload
    case payloadTooLarge
    case signatureTooLarge
}

/// Canonical version-one codec for the private Git multi-request session.
///
/// Every encoded frame has exactly this layout, in network byte order:
///
///     body_length:u32
///     magic:[4] = "APGS"
///     version:u8 = 1
///     kind:u8 = 1(request) | 2(response)
///     flags:u16 = 0
///     sequence:u32
///     content_length:u32
///     content:[content_length]
///
/// The outer length and content length are both retained so a stream decoder
/// can bound allocation before accepting any content. The fixed representation
/// has no alternate encodings, making `encode` deterministic by construction.
/// Sequence and two-sign policy are semantic session checks and are enforced by
/// `NativeAgentPrivateGitSessionStateMachine`; the codec preserves positive
/// out-of-window sequence values so the state machine can classify skip/excess
/// attacks rather than collapsing them into generic malformed input.
public enum NativeAgentPrivateGitSessionFrameCodec {
    public static let currentVersion: UInt8 = 1
    public static let maximumAcceptedSigns: UInt32 = 2
    public static let framePrefixBytes = 4
    public static let bodyHeaderBytes = 16
    public static let maximumCommitPayloadBytes = AgentPassAgentSignRequest.maximumCommitPayloadBytes
    public static let maximumSignatureBytes = AgentPassAgentSignResponse.maximumSignatureBytes
    public static let maximumBodyBytes = bodyHeaderBytes + maximumCommitPayloadBytes

    private static let magic: [UInt8] = [0x41, 0x50, 0x47, 0x53] // APGS
    private static let requestKind: UInt8 = 1
    private static let responseKind: UInt8 = 2

    public static func encode(_ message: NativeAgentPrivateGitSessionMessage) throws -> Data {
        let kind: UInt8
        let sequence: UInt32
        let content: Data
        let maximumContentBytes: Int

        switch message {
        case let .request(requestSequence, commitPayload):
            kind = requestKind
            sequence = requestSequence
            content = commitPayload
            maximumContentBytes = maximumCommitPayloadBytes
        case let .response(responseSequence, signature):
            kind = responseKind
            sequence = responseSequence
            content = signature
            maximumContentBytes = maximumSignatureBytes
        }

        guard sequence > 0 else { throw NativeAgentPrivateGitSessionCodecError.invalidSequence }
        guard !content.isEmpty else { throw NativeAgentPrivateGitSessionCodecError.emptyPayload }
        guard content.count <= maximumContentBytes else {
            throw message.isRequest
                ? NativeAgentPrivateGitSessionCodecError.payloadTooLarge
                : NativeAgentPrivateGitSessionCodecError.signatureTooLarge
        }

        let bodyLength = bodyHeaderBytes + content.count
        guard let bodyLength32 = UInt32(exactly: bodyLength), bodyLength <= maximumBodyBytes else {
            throw NativeAgentPrivateGitSessionCodecError.frameTooLarge
        }
        guard let contentLength32 = UInt32(exactly: content.count) else {
            throw NativeAgentPrivateGitSessionCodecError.frameTooLarge
        }

        var frame = Data(capacity: framePrefixBytes + bodyLength)
        appendUInt32(bodyLength32, to: &frame)
        frame.append(contentsOf: magic)
        frame.append(currentVersion)
        frame.append(kind)
        appendUInt16(0, to: &frame)
        appendUInt32(sequence, to: &frame)
        appendUInt32(contentLength32, to: &frame)
        frame.append(content)
        return frame
    }

    public static func decode(_ frame: Data) throws -> NativeAgentPrivateGitSessionMessage {
        guard frame.count >= framePrefixBytes + bodyHeaderBytes else {
            throw NativeAgentPrivateGitSessionCodecError.frameTooShort
        }

        let bodyLength = readUInt32(frame, offset: 0)
        guard bodyLength > 0 else { throw NativeAgentPrivateGitSessionCodecError.invalidLength }
        guard bodyLength <= UInt32(maximumBodyBytes) else {
            throw NativeAgentPrivateGitSessionCodecError.frameTooLarge
        }
        guard frame.count == framePrefixBytes + Int(bodyLength) else {
            throw NativeAgentPrivateGitSessionCodecError.lengthMismatch
        }

        let bodyOffset = framePrefixBytes
        guard Array(frame[bodyOffset..<(bodyOffset + magic.count)]) == magic else {
            throw NativeAgentPrivateGitSessionCodecError.invalidMagic
        }

        let version = frame[bodyOffset + 4]
        guard version == currentVersion else {
            throw NativeAgentPrivateGitSessionCodecError.unsupportedVersion
        }

        let kind = frame[bodyOffset + 5]
        guard kind == requestKind || kind == responseKind else {
            throw NativeAgentPrivateGitSessionCodecError.invalidMessageKind
        }

        let flags = readUInt16(frame, offset: bodyOffset + 6)
        guard flags == 0 else { throw NativeAgentPrivateGitSessionCodecError.nonZeroFlags }

        let sequence = readUInt32(frame, offset: bodyOffset + 8)
        guard sequence > 0 else { throw NativeAgentPrivateGitSessionCodecError.invalidSequence }

        let contentLength = readUInt32(frame, offset: bodyOffset + 12)
        let maximumContentBytes = kind == requestKind
            ? maximumCommitPayloadBytes
            : maximumSignatureBytes
        guard contentLength > 0 else { throw NativeAgentPrivateGitSessionCodecError.emptyPayload }
        guard contentLength <= UInt32(maximumContentBytes) else {
            throw kind == requestKind
                ? NativeAgentPrivateGitSessionCodecError.payloadTooLarge
                : NativeAgentPrivateGitSessionCodecError.signatureTooLarge
        }
        guard Int(bodyLength) == bodyHeaderBytes + Int(contentLength) else {
            throw NativeAgentPrivateGitSessionCodecError.lengthMismatch
        }

        let contentStart = bodyOffset + bodyHeaderBytes
        let contentEnd = contentStart + Int(contentLength)
        let content = Data(frame[contentStart..<contentEnd])
        if kind == requestKind {
            return .request(sequence: sequence, commitPayload: content)
        }
        return .response(sequence: sequence, signature: content)
    }

    private static func appendUInt16(_ value: UInt16, to data: inout Data) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private static func appendUInt32(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private static func readUInt16(_ data: Data, offset: Int) -> UInt16 {
        (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    private static func readUInt32(_ data: Data, offset: Int) -> UInt32 {
        (UInt32(data[offset]) << 24)
            | (UInt32(data[offset + 1]) << 16)
            | (UInt32(data[offset + 2]) << 8)
            | UInt32(data[offset + 3])
    }
}

private extension NativeAgentPrivateGitSessionMessage {
    var isRequest: Bool {
        if case .request = self { return true }
        return false
    }
}
