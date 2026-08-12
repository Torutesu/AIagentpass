import AgentPassNativeCore
import CoreFoundation
import CryptoKit
import Foundation

public struct NativeAuditPruneReceiptHeadVerifier: Sendable {
    public static let maximumBytes = 512 * 1024
    private let tenant: String
    private let anchorKey: Curve25519.Signing.PublicKey
    private let anchorFingerprint: String

    public init(tenant: String, anchorPublicKeyPEM: String) throws {
        guard tenant.wholeMatch(of: /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/) != nil else { throw AgentPassNativeError.invalidConfiguration("Native audit prune head tenant is invalid") }
        let identity = try NativeAuditPruneAnchorEnvelopeCodec.ed25519PublicKey(anchorPublicKeyPEM)
        self.tenant = tenant; anchorKey = identity.key; anchorFingerprint = identity.fingerprint
    }

    public func verify(_ data: Data, requestNonce: String, now: Date = Date()) throws -> NativeAuditPruneExternalReceiptHead {
        let keys: Set<String> = ["anchor_key_fingerprint", "configured", "issued_at", "receipt", "receipt_hash", "request_nonce", "sequence", "signature", "tenant", "version"]
        guard !data.isEmpty, data.count <= Self.maximumBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
              try NativeAuditPruneAnchorEnvelopeCodec.canonical(object) == data,
              NativeAuditPruneAnchorEnvelopeCodec.exactInteger(object["version"]) == 2,
              object["tenant"] as? String == tenant,
              NativeAuditPruneAnchorEnvelopeCodec.exactBoolean(object["configured"]) == true,
              let sequence = NativeAuditPruneAnchorEnvelopeCodec.exactInteger(object["sequence"]),
              let receiptHash = object["receipt_hash"] as? String,
              object["request_nonce"] as? String == requestNonce,
              requestNonce.wholeMatch(of: /^[A-Za-z0-9_-]{43}$/) != nil,
              let issuedAtText = object["issued_at"] as? String,
              let issuedAt = NativeAuditPruneAnchorEnvelopeCodec.date(issuedAtText),
              issuedAt <= now.addingTimeInterval(5), now.timeIntervalSince(issuedAt) <= 60,
              object["anchor_key_fingerprint"] as? String == anchorFingerprint,
              let signatureText = object["signature"] as? String,
              let signature = NativeAuditPruneAnchorEnvelopeCodec.canonicalBase64(signatureText, count: 64) else {
            throw AgentPassNativeError.invalidSignature("Native audit prune head response is not exact, fresh canonical schema")
        }
        let statement: [String: Any] = ["version": 2, "tenant": tenant, "configured": true, "sequence": sequence, "receipt_hash": receiptHash, "receipt": object["receipt"]!, "request_nonce": requestNonce, "issued_at": issuedAtText]
        guard anchorKey.isValidSignature(signature, for: try NativeAuditPruneAnchorEnvelopeCodec.canonical(statement)) else { throw AgentPassNativeError.invalidSignature("Native audit prune head envelope signature is invalid") }
        let position = try verifyPosition(sequence: sequence, receiptHash: receiptHash, receiptValue: object["receipt"]!)
        return .init(canonicalData: data, position: position)
    }

    private func verifyPosition(sequence: Int, receiptHash: String, receiptValue: Any) throws -> NativeAuditPruneExternalReceiptPosition? {
        if sequence == 0 {
            guard receiptHash == NativeAuditLog.zeroHash, receiptValue is NSNull else { throw AgentPassNativeError.invalidSignature("Native audit prune head zero state is invalid") }
            return nil
        }
        guard sequence > 0, sequence <= 9_007_199_254_740_991, let object = receiptValue as? [String: Any] else { throw AgentPassNativeError.invalidSignature("Native audit prune head position is invalid") }
        let receipt = try NativeAuditPruneReceipt.decodeCanonical(NativeAuditPruneAnchorEnvelopeCodec.canonical(object))
        guard receipt.sequence == sequence, receipt.receiptHash == receiptHash, receipt.tenant == tenant, receipt.anchorKeyFingerprint == anchorFingerprint,
              let signature = NativeAuditPruneAnchorEnvelopeCodec.canonicalBase64(receipt.signature, count: 64) else { throw AgentPassNativeError.invalidSignature("Native audit prune head receipt binding is invalid") }
        let statement: [String: Any] = ["version": receipt.version, "tenant": receipt.tenant, "sequence": receipt.sequence, "authorization_hash": receipt.authorizationHash, "previous_receipt_hash": receipt.previousReceiptHash, "anchor_event_index": receipt.anchorEventIndex, "previous_anchor_event_hash": receipt.previousAnchorEventHash, "received_at": receipt.receivedAt]
        guard anchorKey.isValidSignature(signature, for: try NativeAuditPruneAnchorEnvelopeCodec.canonical(statement)) else { throw AgentPassNativeError.invalidSignature("Native audit prune receipt signature is invalid") }
        var signed = statement; signed["anchor_key_fingerprint"] = receipt.anchorKeyFingerprint; signed["signature"] = receipt.signature
        guard NativeAuditPruneAnchorEnvelopeCodec.hash(try NativeAuditPruneAnchorEnvelopeCodec.canonical(signed)) == receiptHash else { throw AgentPassNativeError.invalidSignature("Native audit prune receipt hash is invalid") }
        return .init(sequence: sequence, receiptHash: receiptHash)
    }
}

enum NativeAuditPruneAnchorEnvelopeCodec {
    static func exactInteger(_ value: Any?) -> Int? { guard let number = value as? NSNumber, String(cString: number.objCType) == "q" else { return nil }; return number.intValue }
    static func exactBoolean(_ value: Any?) -> Bool? { guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }; return number.boolValue }
    static func canonical(_ object: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func date(_ text: String) -> Date? { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; guard let value = f.date(from: text), f.string(from: value) == text else { return nil }; return value }
    static func canonicalBase64(_ text: String, count: Int) -> Data? { guard let data = Data(base64Encoded: text), data.count == count, data.base64EncodedString() == text else { return nil }; return data }
    static func ed25519PublicKey(_ pem: String) throws -> (key: Curve25519.Signing.PublicKey, fingerprint: String) {
        let lines = pem.split(whereSeparator: \.isNewline).map(String.init)
        guard pem.utf8.count <= 4096, lines.first == "-----BEGIN PUBLIC KEY-----", lines.last == "-----END PUBLIC KEY-----", let der = Data(base64Encoded: lines.dropFirst().dropLast().joined()), der.count == 44, der.prefix(12) == Data([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]) else { throw AgentPassNativeError.invalidKey("Native audit prune anchor key must be canonical Ed25519 SPKI PEM") }
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return (try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)), fingerprint)
    }
}
