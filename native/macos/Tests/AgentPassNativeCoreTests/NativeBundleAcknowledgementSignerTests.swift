import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct AcknowledgementTestSigner: P256MessageSigner {
    let key: P256.Signing.PrivateKey
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

@Test func acknowledgementSignerCreatesCanonicalLowSDeviceProof() throws {
    let signer = AcknowledgementTestSigner(key: P256.Signing.PrivateKey())
    let acknowledgement = try NativeBundleAcknowledgementSigner.create(
        organizationID: "11111111-1111-4111-8111-111111111111",
        deviceID: "22222222-2222-4222-8222-222222222222",
        deviceKeyEpoch: 3,
        sequence: 9,
        statementHash: String(repeating: "a", count: 64),
        result: .applied,
        observedAtMilliseconds: 1_786_579_200_000,
        nonce: Data(repeating: 0x41, count: 16).ackBase64URL,
        signer: signer
    )
    let signature = try #require(Data(ackBase64URL: acknowledgement.signature))
    let signingData = try NativeBundleAcknowledgementCodec.signingData(acknowledgement)
    let parsedSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
    #expect(NativeP256CanonicalSignature.isCanonicalLowS(signature))
    #expect(signer.key.publicKey.isValidSignature(parsedSignature, for: signingData))
    #expect(acknowledgement.reasonCode == nil)
    #expect(acknowledgement.observedAt == "2026-08-13T00:00:00.000Z")
}

@Test func acknowledgementSignerCreatesBoundedBlockedProof() throws {
    let signer = AcknowledgementTestSigner(key: P256.Signing.PrivateKey())
    let acknowledgement = try NativeBundleAcknowledgementSigner.create(
        organizationID: "11111111-1111-4111-8111-111111111111",
        deviceID: "22222222-2222-4222-8222-222222222222",
        deviceKeyEpoch: 3,
        sequence: 9,
        statementHash: String(repeating: "b", count: 64),
        result: .blocked,
        reasonCode: .bundleSignatureInvalid,
        observedAtMilliseconds: 1_786_579_200_000,
        nonce: Data(repeating: 0x42, count: 16).ackBase64URL,
        signer: signer
    )
    #expect(acknowledgement.result == .blocked)
    #expect(acknowledgement.reasonCode == .bundleSignatureInvalid)
}

@Test func acknowledgementSignerRejectsInvalidBindingsBeforeSigning() throws {
    final class CountingSigner: P256MessageSigner {
        let key = P256.Signing.PrivateKey()
        var calls = 0
        var publicKeyX963: Data { key.publicKey.x963Representation }
        func sign(message: Data) throws -> Data { calls += 1; return try key.signature(for: message).rawRepresentation }
    }
    let signer = CountingSigner()
    #expect(throws: NativeDeviceSyncContractError.self) {
        try NativeBundleAcknowledgementSigner.create(
            organizationID: "11111111-1111-4111-8111-111111111111",
            deviceID: "22222222-2222-4222-8222-222222222222",
            deviceKeyEpoch: 0,
            sequence: 9,
            statementHash: String(repeating: "a", count: 64),
            result: .applied,
            reasonCode: .internalError,
            observedAtMilliseconds: 1_786_579_200_000,
            nonce: Data(repeating: 0x41, count: 16).ackBase64URL,
            signer: signer
        )
    }
    #expect(signer.calls == 0)
}

@Test func acknowledgementSignerRejectsMismatchedEnrolledKey() throws {
    struct MismatchedSigner: P256MessageSigner {
        let signingKey = P256.Signing.PrivateKey()
        let enrolledKey = P256.Signing.PrivateKey()
        var publicKeyX963: Data { enrolledKey.publicKey.x963Representation }
        func sign(message: Data) throws -> Data { try signingKey.signature(for: message).rawRepresentation }
    }
    #expect(throws: NativeDeviceSyncContractError.self) {
        try NativeBundleAcknowledgementSigner.create(
            organizationID: "11111111-1111-4111-8111-111111111111",
            deviceID: "22222222-2222-4222-8222-222222222222",
            deviceKeyEpoch: 3,
            sequence: 9,
            statementHash: String(repeating: "a", count: 64),
            result: .applied,
            observedAtMilliseconds: 1_786_579_200_000,
            nonce: Data(repeating: 0x41, count: 16).ackBase64URL,
            signer: MismatchedSigner()
        )
    }
}

private extension Data {
    var ackBase64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    init?(ackBase64URL value: String) {
        var encoded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        self.init(base64Encoded: encoded)
    }
}
