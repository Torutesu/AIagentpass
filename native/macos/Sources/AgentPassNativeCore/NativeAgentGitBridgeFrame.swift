import Foundation

public enum NativeAgentGitBridgeFrameError: Error, Equatable, Sendable {
    case invalidLength
    case payloadTooLarge
    case malformedFrame
}

/// The private Host/helper transport carries one length-prefixed byte string.
/// It deliberately has no operation, namespace, key, algorithm, capability,
/// session, or policy selector. The Host supplies all authority-bound fields
/// when it constructs the fixed `AgentPassAgentSignRequest`.
public enum NativeAgentGitBridgeFrame {
    public static let headerBytes = 4
    public static let maximumCommitPayloadBytes = AgentPassAgentSignRequest.maximumCommitPayloadBytes
    public static let maximumSignatureBytes = AgentPassAgentSignResponse.maximumSignatureBytes

    public static func encodeCommitPayload(_ payload: Data) throws -> Data {
        try encode(payload, maximumBytes: maximumCommitPayloadBytes)
    }

    public static func decodeCommitPayload(_ frame: Data) throws -> Data {
        try decode(frame, maximumBytes: maximumCommitPayloadBytes)
    }

    public static func encodeSignature(_ signature: Data) throws -> Data {
        try encode(signature, maximumBytes: maximumSignatureBytes)
    }

    public static func decodeSignature(_ frame: Data) throws -> Data {
        try decode(frame, maximumBytes: maximumSignatureBytes)
    }

    private static func encode(_ payload: Data, maximumBytes: Int) throws -> Data {
        guard !payload.isEmpty else { throw NativeAgentGitBridgeFrameError.invalidLength }
        guard payload.count <= maximumBytes else { throw NativeAgentGitBridgeFrameError.payloadTooLarge }
        guard let length = UInt32(exactly: payload.count) else { throw NativeAgentGitBridgeFrameError.payloadTooLarge }
        var frame = Data(capacity: headerBytes + payload.count)
        frame.append(UInt8((length >> 24) & 0xff))
        frame.append(UInt8((length >> 16) & 0xff))
        frame.append(UInt8((length >> 8) & 0xff))
        frame.append(UInt8(length & 0xff))
        frame.append(payload)
        return frame
    }

    private static func decode(_ frame: Data, maximumBytes: Int) throws -> Data {
        guard frame.count >= headerBytes else { throw NativeAgentGitBridgeFrameError.malformedFrame }
        let bytes = [UInt8](frame.prefix(headerBytes))
        let length = (UInt32(bytes[0]) << 24)
            | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8)
            | UInt32(bytes[3])
        guard length > 0 else { throw NativeAgentGitBridgeFrameError.invalidLength }
        guard length <= UInt32(maximumBytes) else { throw NativeAgentGitBridgeFrameError.payloadTooLarge }
        guard frame.count == headerBytes + Int(length) else { throw NativeAgentGitBridgeFrameError.malformedFrame }
        return Data(frame.dropFirst(headerBytes))
    }
}
