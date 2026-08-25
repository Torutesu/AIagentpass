import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private let refreshOrganizationID = "11111111-1111-4111-8111-111111111111"
private let refreshDeviceID = "22222222-2222-4222-8222-222222222222"
private let refreshNow: Int64 = 1_786_579_200_000

private func refreshPEM(_ key: Curve25519.Signing.PublicKey) -> String {
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    return "-----BEGIN PUBLIC KEY-----\n\((prefix + key.rawRepresentation).base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func signedRefreshHint(
    key: Curve25519.Signing.PrivateKey,
    keyID: String = "refresh-2026-08",
    organizationID: String = refreshOrganizationID,
    deviceID: String = refreshDeviceID,
    generation: Int64 = 8,
    publishedAt: String = "2026-08-13T00:00:00.000Z",
    expiresAt: String = "2026-08-13T00:05:00.000Z"
) throws -> Data {
    let unsigned = NativeRefreshHint(
        organizationID: organizationID,
        deviceID: deviceID,
        authorityGeneration: generation,
        publishedAt: publishedAt,
        expiresAt: expiresAt,
        nonce: Data(repeating: 0x41, count: 16).base64URLEncoded,
        keyID: keyID,
        signature: Data(repeating: 0, count: 64).base64URLEncoded
    )
    let signature = try key.signature(for: NativeRefreshHintCodec.signingData(unsigned))
    return try NativeRefreshHintCodec.canonicalJSON(NativeRefreshHint(
        organizationID: organizationID,
        deviceID: deviceID,
        authorityGeneration: generation,
        publishedAt: publishedAt,
        expiresAt: expiresAt,
        nonce: unsigned.nonce,
        keyID: keyID,
        signature: signature.base64URLEncoded
    ))
}

@Test func refreshHintVerifierPinsSignatureAudienceTimeAndGeneration() throws {
    let key = Curve25519.Signing.PrivateKey()
    let trust = try NativeRefreshHintTrust(
        organizationID: refreshOrganizationID,
        deviceID: refreshDeviceID,
        publicKeysPEM: ["refresh:2026-08": refreshPEM(key.publicKey)]
    )
    let hint = try NativeRefreshHintVerifier(trust: trust).verify(try signedRefreshHint(key: key, keyID: "refresh:2026-08"), afterGeneration: 7, nowMilliseconds: refreshNow)
    #expect(hint.authorityGeneration == 8)
    #expect(hint.organizationID == refreshOrganizationID)
    #expect(hint.deviceID == refreshDeviceID)
}

@Test func refreshHintVerifierSupportsPinnedKeyRotationWithoutFallback() throws {
    let old = Curve25519.Signing.PrivateKey()
    let current = Curve25519.Signing.PrivateKey()
    let verifier = NativeRefreshHintVerifier(trust: try NativeRefreshHintTrust(
        organizationID: refreshOrganizationID,
        deviceID: refreshDeviceID,
        publicKeysPEM: ["refresh-2026-07": refreshPEM(old.publicKey), "refresh-2026-08": refreshPEM(current.publicKey)]
    ))
    #expect(try verifier.verify(try signedRefreshHint(key: old, keyID: "refresh-2026-07"), afterGeneration: 7, nowMilliseconds: refreshNow).keyID == "refresh-2026-07")
    #expect(try verifier.verify(try signedRefreshHint(key: current), afterGeneration: 7, nowMilliseconds: refreshNow).keyID == "refresh-2026-08")

    let retired = NativeRefreshHintVerifier(trust: try NativeRefreshHintTrust(
        organizationID: refreshOrganizationID,
        deviceID: refreshDeviceID,
        publicKeysPEM: ["refresh-2026-08": refreshPEM(current.publicKey)]
    ))
    #expect(throws: NativeDeviceSyncContractError.self) {
        try retired.verify(try signedRefreshHint(key: old, keyID: "refresh-2026-07"), afterGeneration: 7, nowMilliseconds: refreshNow)
    }
}

@Test func refreshHintVerifierRejectsSubstitutionRollbackExpiryAndForgery() throws {
    let key = Curve25519.Signing.PrivateKey()
    let other = Curve25519.Signing.PrivateKey()
    let verifier = NativeRefreshHintVerifier(trust: try NativeRefreshHintTrust(
        organizationID: refreshOrganizationID,
        deviceID: refreshDeviceID,
        publicKeysPEM: ["refresh-2026-08": refreshPEM(key.publicKey)]
    ))
    for candidate in [
        try signedRefreshHint(key: key, organizationID: "33333333-3333-4333-8333-333333333333"),
        try signedRefreshHint(key: key, deviceID: "44444444-4444-4444-8444-444444444444"),
        try signedRefreshHint(key: key, generation: 7),
        try signedRefreshHint(key: key, publishedAt: "2026-08-12T23:50:00.000Z", expiresAt: "2026-08-12T23:55:00.000Z"),
        try signedRefreshHint(key: other)
    ] {
        #expect(throws: NativeDeviceSyncContractError.self) {
            try verifier.verify(candidate, afterGeneration: 7, nowMilliseconds: refreshNow)
        }
    }
}

@Test func refreshHintTrustRejectsMalformedAndUnboundedKeyConfiguration() throws {
    let key = Curve25519.Signing.PrivateKey()
    #expect(throws: NativeDeviceSyncContractError.self) {
        try NativeRefreshHintTrust(organizationID: refreshOrganizationID, deviceID: refreshDeviceID, publicKeysPEM: [:])
    }
    #expect(throws: NativeDeviceSyncContractError.self) {
        try NativeRefreshHintTrust(organizationID: refreshOrganizationID, deviceID: refreshDeviceID, publicKeysPEM: ["refresh-2026-08": "not a key"])
    }
    let oversized = Dictionary(uniqueKeysWithValues: (1...17).map { ("refresh-\($0)", refreshPEM(key.publicKey)) })
    #expect(throws: NativeDeviceSyncContractError.self) {
        try NativeRefreshHintTrust(organizationID: refreshOrganizationID, deviceID: refreshDeviceID, publicKeysPEM: oversized)
    }
}

private extension Data {
    var base64URLEncoded: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
