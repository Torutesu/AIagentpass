import CryptoKit
import Foundation

public struct NativeRefreshHintTrust: Sendable {
    public static let maximumKeys = 16

    public let organizationID: String
    public let deviceID: String
    private let keys: [String: Curve25519.Signing.PublicKey]

    public init(organizationID: String, deviceID: String, publicKeysPEM: [String: String]) throws {
        self.organizationID = try Self.uuid(organizationID, field: "organization_id")
        self.deviceID = try Self.uuid(deviceID, field: "device_id")
        guard !publicKeysPEM.isEmpty, publicKeysPEM.count <= Self.maximumKeys else {
            throw NativeDeviceSyncContractError(.invalidValue, "refresh hint trust key count is invalid")
        }
        var parsed: [String: Curve25519.Signing.PublicKey] = [:]
        for (keyID, pem) in publicKeysPEM {
            guard keyID.range(of: "^[A-Za-z0-9][A-Za-z0-9._:~-]{0,63}$", options: .regularExpression) != nil else {
                throw NativeDeviceSyncContractError(.invalidIdentifier, "refresh hint trust key id is invalid")
            }
            let body = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
            guard pem.hasPrefix("-----BEGIN PUBLIC KEY-----\n"), pem.hasSuffix("\n-----END PUBLIC KEY-----\n"),
                  let der = Data(base64Encoded: body), der.count == 44,
                  der.prefix(12) == Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) else {
                throw NativeDeviceSyncContractError(.invalidValue, "refresh hint trust key must be Ed25519 SPKI PEM")
            }
            parsed[keyID] = try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32))
        }
        keys = parsed
    }

    fileprivate func key(_ keyID: String) throws -> Curve25519.Signing.PublicKey {
        guard let key = keys[keyID] else {
            throw NativeDeviceSyncContractError(.invalidSignature, "refresh hint signer is not trusted")
        }
        return key
    }

    private static func uuid(_ value: String, field: String) throws -> String {
        guard value.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", options: .regularExpression) != nil else {
            throw NativeDeviceSyncContractError(.invalidUUID, "\(field) is invalid")
        }
        return value
    }
}

/// Verifies a refresh hint only as a bounded wake-up signal. The result does
/// not contain policy or capability authority; callers must fetch and verify
/// the newer ControlBundle independently before changing authorization.
public struct NativeRefreshHintVerifier: Sendable {
    public static let clockSkewMilliseconds: Int64 = 60_000
    public let trust: NativeRefreshHintTrust

    public init(trust: NativeRefreshHintTrust) {
        self.trust = trust
    }

    public func verify(
        _ data: Data,
        afterGeneration: Int64,
        nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1_000)
    ) throws -> NativeRefreshHint {
        guard afterGeneration >= 0, afterGeneration <= 9_007_199_254_740_991,
              nowMilliseconds >= 0, nowMilliseconds <= 9_007_199_254_740_991 else {
            throw NativeDeviceSyncContractError(.invalidGeneration, "refresh hint verification boundary is invalid")
        }
        let hint = try NativeRefreshHintCodec.decode(data)
        guard hint.organizationID == trust.organizationID, hint.deviceID == trust.deviceID else {
            throw NativeDeviceSyncContractError(.invalidValue, "refresh hint audience does not match this device")
        }
        guard hint.authorityGeneration > afterGeneration else {
            throw NativeDeviceSyncContractError(.invalidGeneration, "refresh hint generation is not newer")
        }
        let publishedAt = try milliseconds(hint.publishedAt)
        let expiresAt = try milliseconds(hint.expiresAt)
        guard publishedAt <= nowMilliseconds + Self.clockSkewMilliseconds, expiresAt > nowMilliseconds else {
            throw NativeDeviceSyncContractError(.invalidWindow, "refresh hint is outside its accepted time window")
        }
        guard let signature = canonicalBase64URL(hint.signature, bytes: 64),
              try trust.key(hint.keyID).isValidSignature(signature, for: NativeRefreshHintCodec.signingData(hint)) else {
            throw NativeDeviceSyncContractError(.invalidSignature, "refresh hint signature is invalid")
        }
        return hint
    }

    private func milliseconds(_ value: String) throws -> Int64 {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: value) else {
            throw NativeDeviceSyncContractError(.invalidTimestamp, "refresh hint timestamp is invalid")
        }
        let milliseconds = date.timeIntervalSince1970 * 1_000
        guard milliseconds >= 0, milliseconds <= 9_007_199_254_740_991 else {
            throw NativeDeviceSyncContractError(.invalidTimestamp, "refresh hint timestamp is outside the supported range")
        }
        return Int64(milliseconds)
    }

    private func canonicalBase64URL(_ value: String, bytes: Int) -> Data? {
        guard value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else { return nil }
        var padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded), decoded.count == bytes,
              decoded.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == value else { return nil }
        return decoded
    }
}
