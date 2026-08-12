import AgentPassNativeCore
import CryptoKit
import Foundation

public enum NativeAuditPruneLeaseProtocol {
    public static func acquisitionRequest(tenant: String, nonce: String, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String, expected: NativeAuditPruneExternalReceiptPosition?, issuedAt: Date, signer: P256MessageSigner) throws -> Data {
        var statement: [String: Any] = ["version": 1, "tenant": tenant, "nonce": nonce, "purpose": purpose.rawValue, "operation_id": operationID, "expected_sequence": expected?.sequence ?? 0, "expected_receipt_hash": expected?.receiptHash ?? NativeAuditLog.zeroHash, "issued_at": timestamp(issuedAt), "audit_key_fingerprint": NativeAuditCheckpoints.fingerprint(signer.publicKeyX963)]
        statement["signature"] = try signature(statement, signer: signer)
        return try NativeAuditPruneAnchorEnvelopeCodec.canonical(statement)
    }

    public static func releaseRequest(tenant: String, nonce: String, lease: NativeAuditPruneExternalReceiptLease, issuedAt: Date, signer: P256MessageSigner) throws -> Data {
        var statement: [String: Any] = ["version": 1, "action": "release", "tenant": tenant, "nonce": nonce, "purpose": lease.purpose.rawValue, "operation_id": lease.operationID ?? NSNull(), "lease_id": lease.leaseID, "lease_hash": NativeAuditPruneAnchorEnvelopeCodec.hash(lease.canonicalData), "issued_at": timestamp(issuedAt), "audit_key_fingerprint": NativeAuditCheckpoints.fingerprint(signer.publicKeyX963)]
        statement["signature"] = try signature(statement, signer: signer)
        return try NativeAuditPruneAnchorEnvelopeCodec.canonical(statement)
    }

    private static func signature(_ statement: [String: Any], signer: P256MessageSigner) throws -> String {
        let raw = try NativeP256CanonicalSignature.canonicalized(signer.sign(message: NativeAuditPruneAnchorEnvelopeCodec.canonical(statement)))
        guard raw.count == 64 else { throw AgentPassNativeError.invalidSignature("Audit prune lease request signature must be raw P-256") }
        return raw.base64EncodedString()
    }

    private static func timestamp(_ date: Date) -> String { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return f.string(from: date) }
}

public struct NativeAuditPruneLeaseVerifier: Sendable {
    private let tenant: String
    private let anchorKey: Curve25519.Signing.PublicKey
    private let anchorFingerprint: String
    private let principalFingerprint: String
    public init(tenant: String, anchorPublicKeyPEM: String, principalPublicKeyX963: Data) throws {
        let identity = try NativeAuditPruneAnchorEnvelopeCodec.ed25519PublicKey(anchorPublicKeyPEM)
        self.tenant = tenant; anchorKey = identity.key; anchorFingerprint = identity.fingerprint
        principalFingerprint = NativeAuditCheckpoints.fingerprint(principalPublicKeyX963)
    }
    public func verify(_ data: Data, requestNonce: String, purpose: NativeAuditPruneExternalObservationPurpose, operationID: String, expected: NativeAuditPruneExternalReceiptPosition?, now: Date = Date(), uptime: UInt64 = DispatchTime.now().uptimeNanoseconds) throws -> NativeAuditPruneExternalReceiptLease {
        let keys: Set<String> = ["anchor_key_fingerprint","issued_at","lease_expires_at","lease_id","operation_id","principal_fingerprint","process_epoch","purpose","receipt_hash","request_nonce","sequence","signature","tenant","version"]
        guard !data.isEmpty, data.count <= NativeAuditPruneReceiptHeadVerifier.maximumBytes, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys, try NativeAuditPruneAnchorEnvelopeCodec.canonical(object) == data,
              NativeAuditPruneAnchorEnvelopeCodec.exactInteger(object["version"]) == 4, object["tenant"] as? String == tenant, object["purpose"] as? String == purpose.rawValue, object["operation_id"] as? String == operationID,
              object["principal_fingerprint"] as? String == principalFingerprint, object["request_nonce"] as? String == requestNonce,
              let sequence = NativeAuditPruneAnchorEnvelopeCodec.exactInteger(object["sequence"]), sequence == (expected?.sequence ?? 0), object["receipt_hash"] as? String == (expected?.receiptHash ?? NativeAuditLog.zeroHash),
              let leaseID = object["lease_id"] as? String, leaseID.wholeMatch(of: /^[A-Za-z0-9_-]{43}$/) != nil, let epoch = object["process_epoch"] as? String, epoch.wholeMatch(of: /^[A-Za-z0-9_-]{43}$/) != nil,
              let issuedText = object["issued_at"] as? String, let issued = NativeAuditPruneAnchorEnvelopeCodec.date(issuedText), let expiryText = object["lease_expires_at"] as? String, let expiry = NativeAuditPruneAnchorEnvelopeCodec.date(expiryText), expiry.timeIntervalSince(issued) == 30, issued <= now.addingTimeInterval(5), now.timeIntervalSince(issued) <= 60, expiry.timeIntervalSince(now) > 5,
              object["anchor_key_fingerprint"] as? String == anchorFingerprint, let signatureText = object["signature"] as? String, let signature = NativeAuditPruneAnchorEnvelopeCodec.canonicalBase64(signatureText, count: 64) else { throw AgentPassNativeError.invalidSignature("Audit prune lease envelope is invalid") }
        var statement = object; statement.removeValue(forKey: "anchor_key_fingerprint"); statement.removeValue(forKey: "signature")
        guard anchorKey.isValidSignature(signature, for: try NativeAuditPruneAnchorEnvelopeCodec.canonical(statement)) else { throw AgentPassNativeError.invalidSignature("Audit prune lease envelope signature is invalid") }
        let safeNs = UInt64((expiry.timeIntervalSince(now) - 5) * 1_000_000_000)
        guard !uptime.addingReportingOverflow(safeNs).overflow else { throw AgentPassNativeError.invalidSignature("Audit prune lease deadline overflow") }
        return .init(canonicalData: data, leaseID: leaseID, purpose: purpose, operationID: operationID, position: expected, principalFingerprint: principalFingerprint, processEpoch: epoch, destructiveDeadlineUptimeNanoseconds: uptime + safeNs)
    }
}
