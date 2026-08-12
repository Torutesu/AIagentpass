import AgentPassNativeCore
import AgentPassNativeServiceSupport
import CryptoKit
import Foundation
import Testing

private func canonical(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]) }
private func sha(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
private let nonce = String(repeating: "A", count: 43)
private let epoch = String(repeating: "E", count: 43)
private let issued = "2030-01-02T03:04:06.000Z"
private let expiry = "2030-01-02T03:04:36.000Z"
private let now: Date = { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return f.date(from: issued)! }()

private struct TestSigner: P256MessageSigner {
    let key: P256.Signing.PrivateKey
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private func anchor() throws -> (Curve25519.Signing.PrivateKey, String, String) {
    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
    let der = Data([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]) + key.publicKey.rawRepresentation
    let pem = "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
    let fp = "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    return (key, pem, fp)
}

private func signedHead(configured: Bool = true, receiptIncluded: Bool = true, requestNonce: String = nonce, issuedAt: String = issued) throws -> (Data, String, NativeAuditPruneExternalReceiptPosition?) {
    let (key, pem, fp) = try anchor()
    let receiptStatement: [String: Any] = ["version":1,"tenant":"tenant-1","sequence":2,"authorization_hash":String(repeating:"1",count:64),"previous_receipt_hash":String(repeating:"2",count:64),"anchor_event_index":8,"previous_anchor_event_hash":String(repeating:"3",count:64),"received_at":"2030-01-02T03:04:05.000Z"]
    var receipt = receiptStatement; receipt["anchor_key_fingerprint"] = fp; receipt["signature"] = try key.signature(for: canonical(receiptStatement)).base64EncodedString(); let hash = sha(try canonical(receipt)); receipt["receipt_hash"] = hash
    let statement: [String: Any] = ["version":2,"tenant":"tenant-1","configured":configured,"sequence":receiptIncluded ? 2 : 0,"receipt_hash":receiptIncluded ? hash : String(repeating:"0",count:64),"receipt":receiptIncluded ? receipt : NSNull(),"request_nonce":requestNonce,"issued_at":issuedAt]
    var envelope = statement; envelope["anchor_key_fingerprint"] = fp; envelope["signature"] = try key.signature(for: canonical(statement)).base64EncodedString()
    return (try canonical(envelope), pem, receiptIncluded ? .init(sequence: 2, receiptHash: hash) : nil)
}

private func signedLease(principal: TestSigner, purpose: NativeAuditPruneExternalObservationPurpose = .execute, operation: String = "operation-1", expected: NativeAuditPruneExternalReceiptPosition? = nil, requestNonce: String = nonce) throws -> (Data, String) {
    let (key, pem, fp) = try anchor()
    let statement: [String: Any] = ["version":4,"tenant":"tenant-1","purpose":purpose.rawValue,"operation_id":operation,"sequence":expected?.sequence ?? 0,"receipt_hash":expected?.receiptHash ?? NativeAuditLog.zeroHash,"principal_fingerprint":NativeAuditCheckpoints.fingerprint(principal.publicKeyX963),"request_nonce":requestNonce,"lease_id":String(repeating:"L",count:43),"issued_at":issued,"lease_expires_at":expiry,"process_epoch":epoch]
    var envelope = statement; envelope["anchor_key_fingerprint"] = fp; envelope["signature"] = try key.signature(for: canonical(statement)).base64EncodedString()
    return (try canonical(envelope), pem)
}

@Test func auditPruneHeadRouteAndVerifierAreReadOnlySchema() throws {
    let base = URL(string: "https://anchor.example/v1/audit-prunes/tenant-1/head")!
    let request = try NativeAuditPruneReceiptHeadRequest(baseEndpoint: base, nonce: nonce)
    #expect(request.endpoint.absoluteString == "https://anchor.example/v1/audit-prunes/tenant-1/head?nonce=\(nonce)")
    let (data, pem, position) = try signedHead()
    let verifier = try NativeAuditPruneReceiptHeadVerifier(tenant: "tenant-1", anchorPublicKeyPEM: pem)
    #expect(try verifier.verify(data, requestNonce: nonce, now: now).position == position)
    let (zero, _, _) = try signedHead(receiptIncluded: false)
    #expect(try verifier.verify(zero, requestNonce: nonce, now: now).position == nil)
}

@Test func auditPruneHeadRejectsReplaySubstitutionBooleanUnknownAndOversize() throws {
    let (data, pem, _) = try signedHead(); let verifier = try NativeAuditPruneReceiptHeadVerifier(tenant: "tenant-1", anchorPublicKeyPEM: pem)
    let original = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    for mutation in [
        { (v: inout [String:Any]) in v["sequence"] = true }, { (v: inout [String:Any]) in v["configured"] = 1 },
        { (v: inout [String:Any]) in v["tenant"] = "other" }, { (v: inout [String:Any]) in v["unknown"] = true },
        { (v: inout [String:Any]) in v["signature"] = Data(repeating:0,count:64).base64EncodedString() }
    ] { var changed = original; mutation(&changed); #expect(throws: (any Error).self) { _ = try verifier.verify(canonical(changed), requestNonce: nonce, now: now) } }
    #expect(throws: (any Error).self) { _ = try verifier.verify(data, requestNonce: String(repeating:"B",count:43), now: now) }
    #expect(throws: (any Error).self) { _ = try verifier.verify(data, requestNonce: nonce, now: now.addingTimeInterval(61)) }
    #expect(throws: (any Error).self) { _ = try verifier.verify(Data(repeating:0,count:NativeAuditPruneReceiptHeadVerifier.maximumBytes + 1), requestNonce: nonce, now: now) }
}

@Test func auditPruneLeaseRequestAndEnvelopeBindPrincipalHeadPurposeAndOperation() throws {
    let principal = TestSigner(key: P256.Signing.PrivateKey())
    let expected = NativeAuditPruneExternalReceiptPosition(sequence: 2, receiptHash: String(repeating:"a",count:64))
    let request = try NativeAuditPruneLeaseProtocol.acquisitionRequest(tenant:"tenant-1", nonce:nonce, purpose:.execute, operationID:"operation-1", expected:expected, issuedAt:now, signer:principal)
    let requestObject = try JSONSerialization.jsonObject(with: request) as! [String:Any]
    #expect(requestObject["audit_key_fingerprint"] as? String == NativeAuditCheckpoints.fingerprint(principal.publicKeyX963))
    #expect(requestObject["expected_sequence"] as? Int == 2)
    let (leaseData, pem) = try signedLease(principal: principal, expected: expected)
    let verifier = try NativeAuditPruneLeaseVerifier(tenant:"tenant-1", anchorPublicKeyPEM:pem, principalPublicKeyX963:principal.publicKeyX963)
    let lease = try verifier.verify(leaseData, requestNonce:nonce, purpose:.execute, operationID:"operation-1", expected:expected, now:now, uptime:1_000)
    #expect(lease.principalFingerprint == NativeAuditCheckpoints.fingerprint(principal.publicKeyX963)); #expect(lease.processEpoch == epoch)
    #expect(throws: (any Error).self) { _ = try verifier.verify(leaseData, requestNonce:nonce, purpose:.submit, operationID:"operation-1", expected:expected, now:now) }
    #expect(throws: (any Error).self) { _ = try verifier.verify(leaseData, requestNonce:nonce, purpose:.execute, operationID:"operation-2", expected:expected, now:now) }
    #expect(throws: (any Error).self) { _ = try verifier.verify(leaseData, requestNonce:nonce, purpose:.execute, operationID:"operation-1", expected:nil, now:now) }
    let other = TestSigner(key:P256.Signing.PrivateKey()); let wrong = try NativeAuditPruneLeaseVerifier(tenant:"tenant-1", anchorPublicKeyPEM:pem, principalPublicKeyX963:other.publicKeyX963)
    #expect(throws: (any Error).self) { _ = try wrong.verify(leaseData, requestNonce:nonce, purpose:.execute, operationID:"operation-1", expected:expected, now:now) }
    let release = try NativeAuditPruneLeaseProtocol.releaseRequest(tenant:"tenant-1", nonce:String(repeating:"R",count:43), lease:lease, issuedAt:now, signer:principal)
    #expect((try JSONSerialization.jsonObject(with:release) as! [String:Any])["lease_id"] as? String == lease.leaseID)
}
