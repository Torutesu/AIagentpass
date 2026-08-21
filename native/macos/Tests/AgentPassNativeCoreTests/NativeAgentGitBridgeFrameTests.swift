import AgentPassNativeCore
import Foundation
import Testing

@Test func gitBridgeRoundTripsOnlyBoundedPayloadAndSignatureBytes() throws {
    let payload = Data("tree abc\n\nmessage\n".utf8)
    let payloadFrame = try NativeAgentGitBridgeFrame.encodeCommitPayload(payload)
    #expect(try NativeAgentGitBridgeFrame.decodeCommitPayload(payloadFrame) == payload)

    let signature = Data("-----BEGIN SSH SIGNATURE-----\nfixed\n-----END SSH SIGNATURE-----\n".utf8)
    let signatureFrame = try NativeAgentGitBridgeFrame.encodeSignature(signature)
    #expect(try NativeAgentGitBridgeFrame.decodeSignature(signatureFrame) == signature)
}

@Test func gitBridgeRejectsEmptyOversizedTruncatedAndExtendedFrames() throws {
    #expect(throws: NativeAgentGitBridgeFrameError.invalidLength) {
        try NativeAgentGitBridgeFrame.encodeCommitPayload(Data())
    }
    #expect(throws: NativeAgentGitBridgeFrameError.payloadTooLarge) {
        try NativeAgentGitBridgeFrame.encodeCommitPayload(Data(repeating: 1, count: NativeAgentGitBridgeFrame.maximumCommitPayloadBytes + 1))
    }
    #expect(throws: NativeAgentGitBridgeFrameError.malformedFrame) {
        try NativeAgentGitBridgeFrame.decodeCommitPayload(Data([0, 0, 0]))
    }
    #expect(throws: NativeAgentGitBridgeFrameError.malformedFrame) {
        try NativeAgentGitBridgeFrame.decodeCommitPayload(Data([0, 0, 0, 2, 1]))
    }
    #expect(throws: NativeAgentGitBridgeFrameError.malformedFrame) {
        try NativeAgentGitBridgeFrame.decodeCommitPayload(Data([0, 0, 0, 1, 1, 2]))
    }
}

@Test func gitBridgeRejectsZeroAndOversizedDeclaredLengthsBeforeReturningBytes() throws {
    #expect(throws: NativeAgentGitBridgeFrameError.invalidLength) {
        try NativeAgentGitBridgeFrame.decodeCommitPayload(Data([0, 0, 0, 0]))
    }
    let oversized = UInt32(NativeAgentGitBridgeFrame.maximumSignatureBytes + 1)
    let frame = Data([
        UInt8((oversized >> 24) & 0xff),
        UInt8((oversized >> 16) & 0xff),
        UInt8((oversized >> 8) & 0xff),
        UInt8(oversized & 0xff),
    ])
    #expect(throws: NativeAgentGitBridgeFrameError.payloadTooLarge) {
        try NativeAgentGitBridgeFrame.decodeSignature(frame)
    }
}
