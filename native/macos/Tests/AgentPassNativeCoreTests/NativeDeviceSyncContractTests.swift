import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private func deviceSyncFixture(_ name: String) throws -> Data {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    return try Data(contentsOf: testDirectory
        .appendingPathComponent("../../../../contracts/fixtures", isDirectory: true)
        .appendingPathComponent(name)
        .standardizedFileURL)
}

private func deviceSyncObject(_ data: Data) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as! [String: Any]
}

private func deviceSyncMutated(_ data: Data, _ mutate: (inout [String: Any]) -> Void) throws -> Data {
    var object = try deviceSyncObject(data)
    mutate(&object)
    return try NativeStrictJSON.data(object)
}

private func deviceSyncHash(_ data: Data) -> String {
    Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
}

private func deviceSyncDecodeBase64URL(_ value: String) -> Data {
    var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    base64 += String(repeating: "=", count: (4 - base64.utf8.count % 4) % 4)
    return Data(base64Encoded: base64)!
}

private func deviceSyncBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func deviceSyncHighSSignature(from low: Data) -> Data {
    let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    ]
    let scalar = [UInt8](low.suffix(32))
    var highScalar = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    for index in stride(from: 31, through: 0, by: -1) {
        var difference = Int(order[index]) - Int(scalar[index]) - borrow
        if difference < 0 { difference += 256; borrow = 1 } else { borrow = 0 }
        highScalar[index] = UInt8(difference)
    }
    return Data(low.prefix(32)) + Data(highScalar)
}

private let refreshHintKeys: Set<String> = [
    "version", "type", "organization_id", "device_id", "authority_generation",
    "published_at", "expires_at", "nonce", "key_id", "signature_algorithm", "signature"
]

private let appliedAcknowledgementKeys: Set<String> = [
    "version", "type", "organization_id", "device_id", "device_key_epoch", "format_epoch",
    "sequence", "statement_hash", "result", "observed_at", "nonce", "signature_algorithm", "signature"
]

@Test func nativeDeviceRefreshStatesMatchTheFrozenProtocol() {
    #expect(NativeDeviceRefreshState.allCases.map(\.rawValue) == [
        "pending", "fetching", "applied", "blocked", "stale", "offline", "revoked"
    ])
}

@Test func nativeRefreshHintFixtureHasExactShapeAndSigningVector() throws {
    let data = try deviceSyncFixture("refresh-hint.valid.json")
    let object = try deviceSyncObject(data)
    #expect(Set(object.keys) == refreshHintKeys)

    let hint = try NativeRefreshHintCodec.decode(data)
    #expect(hint.version == 1)
    #expect(hint.type == "agentpass.refresh-hint")
    #expect(hint.authorityGeneration > 0)
    #expect(hint.signatureAlgorithm == "ed25519")
    #expect(Data(hint.nonce.utf8).count == 22)

    let signingData = try NativeRefreshHintCodec.signingData(data)
    let unsigned = try NativeRefreshHintCodec.unsignedCanonicalJSON(hint)
    #expect(deviceSyncHash(signingData) == "a059221ce35bb6149443a20d1a7c137717d6bb2ab2baee06c727bdcf43407dd3")
    #expect(signingData.prefix(NativeRefreshHintCodec.signatureDomain.utf8.count) == Data(NativeRefreshHintCodec.signatureDomain.utf8))
    #expect(signingData.dropFirst(NativeRefreshHintCodec.signatureDomain.utf8.count) == unsigned)
    #expect(try NativeRefreshHintCodec.canonicalJSON(data) == NativeStrictJSON.data(object))
}

@Test func nativeBundleAcknowledgementFixtureHasExactShapeAndSigningVector() throws {
    let data = try deviceSyncFixture("bundle-ack.valid.json")
    let object = try deviceSyncObject(data)
    #expect(Set(object.keys) == appliedAcknowledgementKeys)

    let acknowledgement = try NativeBundleAcknowledgementCodec.decode(data)
    #expect(acknowledgement.version == 1)
    #expect(acknowledgement.type == "agentpass.bundle-ack")
    #expect(acknowledgement.formatEpoch == 2)
    #expect(acknowledgement.sequence > 0)
    #expect(acknowledgement.result == .applied)
    #expect(acknowledgement.reasonCode == nil)
    #expect(acknowledgement.signatureAlgorithm == "p256-sha256")

    let signingData = try NativeBundleAcknowledgementCodec.signingData(data)
    let unsigned = try NativeBundleAcknowledgementCodec.unsignedCanonicalJSON(acknowledgement)
    #expect(deviceSyncHash(signingData) == "ab820c77106f942649f3853ae76e1c96dbc9d9f1d5dbdbd0df05efa9cde05f55")
    #expect(signingData.prefix(NativeBundleAcknowledgementCodec.signatureDomain.utf8.count) == Data(NativeBundleAcknowledgementCodec.signatureDomain.utf8))
    #expect(signingData.dropFirst(NativeBundleAcknowledgementCodec.signatureDomain.utf8.count) == unsigned)
    #expect(try NativeBundleAcknowledgementCodec.canonicalJSON(data) == NativeStrictJSON.data(object))
}

@Test func nativeDeviceSyncContractsRejectUnknownDuplicateAndNoncanonicalFields() throws {
    let refresh = try deviceSyncFixture("refresh-hint.valid.json")
    let acknowledgement = try deviceSyncFixture("bundle-ack.valid.json")

    #expect(throws: (any Error).self) {
        _ = try NativeRefreshHintCodec.decode(try deviceSyncMutated(refresh) { $0["extra"] = true })
    }
    #expect(throws: (any Error).self) {
        _ = try NativeBundleAcknowledgementCodec.decode(try deviceSyncMutated(acknowledgement) { $0["extra"] = true })
    }
    #expect(throws: (any Error).self) {
        _ = try NativeStrictJSON.object(from: Data(#"{"version":1,"version":1}"#.utf8), maxBytes: 16 * 1024, maxDepth: 8)
    }
    #expect(throws: (any Error).self) {
        _ = try NativeRefreshHintCodec.decode(Data(" {\n  \"version\": 1\n} ".utf8))
    }

    for invalid in [
        try deviceSyncMutated(refresh) { $0["version"] = "1" },
        try deviceSyncMutated(refresh) { $0["authority_generation"] = 0 },
        try deviceSyncMutated(refresh) { $0["nonce"] = "EREREREREREREREREREREQ==" },
        try deviceSyncMutated(refresh) { $0["expires_at"] = "2026-08-12T00:00:00.000Z" },
        try deviceSyncMutated(refresh) { $0["expires_at"] = "2026-08-12T00:06:00.000Z" },
        try deviceSyncMutated(refresh) { $0["signature"] = "A" },
        try deviceSyncMutated(refresh) { $0["signature_algorithm"] = "Ed25519" }
    ] {
        #expect(throws: (any Error).self) { _ = try NativeRefreshHintCodec.decode(invalid) }
    }

    for invalid in [
        try deviceSyncMutated(acknowledgement) { $0["device_key_epoch"] = 0 },
        try deviceSyncMutated(acknowledgement) { $0["format_epoch"] = 1 },
        try deviceSyncMutated(acknowledgement) { $0["sequence"] = 0 },
        try deviceSyncMutated(acknowledgement) { $0["statement_hash"] = String(repeating: "A", count: 64) },
        try deviceSyncMutated(acknowledgement) { $0["result"] = "applied-but-not" },
        try deviceSyncMutated(acknowledgement) { $0["reason_code"] = "internal_error" },
        try deviceSyncMutated(acknowledgement) { $0["observed_at"] = "2026-08-12T00:00:00Z" },
        try deviceSyncMutated(acknowledgement) { $0["nonce"] = "EREREREREREREREREREREQ==" },
        try deviceSyncMutated(acknowledgement) { $0["signature"] = String(repeating: "A", count: 86) },
        try deviceSyncMutated(acknowledgement) { $0["signature_algorithm"] = "P256" }
    ] {
        #expect(throws: (any Error).self) { _ = try NativeBundleAcknowledgementCodec.decode(invalid) }
    }
}

@Test func nativeBundleAcknowledgementConditionalReasonIsStrict() throws {
    let data = try deviceSyncFixture("bundle-ack.valid.json")

    let blocked = try deviceSyncMutated(data) {
        $0["result"] = "blocked"
        $0["reason_code"] = "bundle_signature_invalid"
    }
    let decoded = try NativeBundleAcknowledgementCodec.decode(blocked)
    #expect(decoded.result == .blocked)
    #expect(decoded.reasonCode == .bundleSignatureInvalid)

    let missingReason = try deviceSyncMutated(blocked) { $0.removeValue(forKey: "reason_code") }
    #expect(throws: (any Error).self) { _ = try NativeBundleAcknowledgementCodec.decode(missingReason) }
}

@Test func nativeBundleAcknowledgementRequiresNonzeroLowSAndRejectsHighS() throws {
    let data = try deviceSyncFixture("bundle-ack.valid.json")
    let object = try deviceSyncObject(data)
    let low = deviceSyncDecodeBase64URL(object["signature"] as! String)
    #expect(low.count == 64)
    #expect(low.prefix(32).contains(where: { $0 != 0 }))
    #expect(low.suffix(32).contains(where: { $0 != 0 }))
    #expect(NativeP256CanonicalSignature.isCanonicalLowS(low))
    #expect(try NativeBundleAcknowledgementCodec.decode(data).signature == object["signature"] as! String)

    var highObject = object
    let high = deviceSyncHighSSignature(from: low)
    #expect(!NativeP256CanonicalSignature.isCanonicalLowS(high))
    highObject["signature"] = deviceSyncBase64URL(high)
    let highData = try NativeStrictJSON.data(highObject)
    #expect(throws: (any Error).self) { _ = try NativeBundleAcknowledgementCodec.decode(highData) }

    var zeroObject = object
    zeroObject["signature"] = String(repeating: "A", count: 86)
    let zeroData = try NativeStrictJSON.data(zeroObject)
    #expect(throws: (any Error).self) { _ = try NativeBundleAcknowledgementCodec.decode(zeroData) }
}
