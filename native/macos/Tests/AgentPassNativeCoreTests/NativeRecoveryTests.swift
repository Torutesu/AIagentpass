import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private let recoveryNow: Int64 = 1_800_000_000_000

private struct RecoveryTestFixture {
    let first: Curve25519.Signing.PrivateKey
    let second: Curve25519.Signing.PrivateKey
    let third: Curve25519.Signing.PrivateKey
    let policyObject: [String: Any]
    let policyData: Data
    let requestObject: [String: Any]
    let requestData: Data

    init(threshold: Int = 2) throws {
        let first = Curve25519.Signing.PrivateKey()
        let second = Curve25519.Signing.PrivateKey()
        let third = Curve25519.Signing.PrivateKey()
        self.first = first
        self.second = second
        self.third = third
        policyObject = [
            "version": 1,
            "policy_id": "offline-recovery",
            "threshold": threshold,
            "authorities": [
                ["id": "security-1", "public_key": recoveryPEM(first.publicKey.rawRepresentation)],
                ["id": "security-2", "public_key": recoveryPEM(second.publicKey.rawRepresentation)],
                ["id": "security-3", "public_key": recoveryPEM(third.publicKey.rawRepresentation)]
            ]
        ]
        policyData = try recoveryCanonical(policyObject)
        let replacement = P256.Signing.PrivateKey().publicKey.x963Representation
        requestObject = [
            "version": 1,
            "installation_id": "build-mac-01",
            "role": "audit_checkpoint",
            "from_generation": 1,
            "from_fingerprint": "SHA256:" + recoveryBase64URL(Data(repeating: 1, count: 32)),
            "proposed_generation": 2,
            "proposed_public_key": try SSHSIG.authorizedKey(publicKeyX963: replacement),
            "recovery_policy_version": 1,
            "recovery_policy_id": "offline-recovery",
            "recovery_policy_hash": recoverySHA256(policyData),
            "lifecycle_head_hash": String(repeating: "a", count: 64),
            "audit_entries": 42,
            "audit_head_hash": String(repeating: "b", count: 64),
            "latest_checkpoint_hash": String(repeating: "c", count: 64),
            "latest_receipt_hash": String(repeating: "d", count: 64),
            "control_sequence": 7,
            "nonce": recoveryBase64URL(Data(repeating: 9, count: 32)),
            "issued_at": recoveryTimestamp(recoveryNow - 1_000),
            "expires_at": recoveryTimestamp(recoveryNow + 14 * 60_000)
        ]
        requestData = try recoveryCanonical(requestObject)
    }

    func authorization(id: String, key: Curve25519.Signing.PrivateKey, signedAt: Int64 = recoveryNow) throws -> Data {
        var statement: [String: Any] = [
            "version": 1,
            "signer_id": id,
            "request_hash": recoverySHA256(requestData),
            "signed_at": recoveryTimestamp(signedAt),
            "public_key_fingerprint": recoveryFingerprint(key.publicKey.rawRepresentation)
        ]
        statement["signature"] = try key.signature(for: recoveryCanonical(statement)).base64EncodedString()
        return try recoveryCanonical(statement)
    }
}

@Test func nativeRecoveryVerifiesCompleteThresholdCeremony() throws {
    let fixture = try RecoveryTestFixture()
    let first = try fixture.authorization(id: "security-1", key: fixture.first)
    let second = try fixture.authorization(id: "security-2", key: fixture.second)
    let result = try NativeRecoveryVerifier.verify(
        requestData: fixture.requestData,
        policyData: fixture.policyData,
        authorizationData: [second, first],
        nowMilliseconds: recoveryNow
    )

    #expect(result.valid)
    #expect(result.threshold == 2)
    #expect(result.acceptedSignerIDs == ["security-1", "security-2"])
    #expect(result.requestHash == recoverySHA256(fixture.requestData))
    #expect(result.policyHash == recoverySHA256(fixture.policyData))
    #expect(result.request.role == .auditCheckpoint)
    #expect(result.request.fromGeneration == 1)
    #expect(result.request.proposedGeneration == 2)
    #expect(result.request.proposedPublicKeyX963.count == 65)
    #expect(result.acceptedPublicKeyFingerprints.count == 2)
    #expect(try NativeRecoveryVerifier.requestHash(fixture.requestData) == result.requestHash)
    #expect(try NativeRecoveryVerifier.policyHash(fixture.policyData) == result.policyHash)

    let newlineRequest = fixture.requestData + Data("\n".utf8)
    #expect(try NativeRecoveryVerifier.validateRequest(newlineRequest, nowMilliseconds: recoveryNow).installationID == "build-mac-01")
}

@Test func nativeRecoveryServiceRequestBuilderEmitsExactVerifierCompatibleBytes() throws {
    let fixture = try RecoveryTestFixture()
    let parsed = try NativeRecoveryVerifier.validateRequest(fixture.requestData, nowMilliseconds: recoveryNow)
    let state = NativeRecoveryRuntimeState(
        installationID: parsed.installationID, role: parsed.role,
        activeGeneration: parsed.fromGeneration, activeFingerprint: parsed.fromFingerprint,
        stagedGeneration: parsed.proposedGeneration, stagedPublicKeyX963: parsed.proposedPublicKeyX963,
        lifecycleHeadHash: parsed.lifecycleHeadHash, auditEntries: parsed.auditEntries,
        auditHeadHash: parsed.auditHeadHash, latestCheckpointHash: parsed.latestCheckpointHash,
        latestReceiptHash: parsed.latestReceiptHash, controlSequence: parsed.controlSequence
    )
    let created = try NativeRecoveryVerifier.createRequest(
        state: state,
        policyData: fixture.policyData,
        nonce: parsed.nonce,
        issuedAt: parsed.issuedAt,
        expiresAt: parsed.expiresAt,
        nowMilliseconds: recoveryNow
    )
    #expect(created == fixture.requestData)
    #expect(try NativeRecoveryVerifier.validateRequest(created, nowMilliseconds: recoveryNow) == parsed)
    let metadata = try NativeRecoveryVerifier.policyMetadata(fixture.policyData)
    #expect(metadata.id == "offline-recovery")
    #expect(metadata.threshold == 2)
    #expect(metadata.authorityPublicKeyFingerprints.count == 3)
}

@Test func nativeRecoveryEvidenceReplaysThresholdAndBindsExactRuntimeState() throws {
    let fixture = try RecoveryTestFixture()
    let first = try fixture.authorization(id: "security-1", key: fixture.first)
    let second = try fixture.authorization(id: "security-2", key: fixture.second)
    let evidence = NativeRecoveryEvidenceBundle(requestData: fixture.requestData, policyData: fixture.policyData, authorizationData: [first, second])
    let encoded = try evidence.canonicalData()
    #expect(try NativeRecoveryEvidenceBundle.decode(encoded) == evidence)
    let verification = try NativeRecoveryVerifier.verifyHistoricalEvidence(encoded)
    let request = verification.request
    let state = NativeRecoveryRuntimeState(
        installationID: request.installationID, role: request.role,
        activeGeneration: request.fromGeneration, activeFingerprint: request.fromFingerprint,
        stagedGeneration: request.proposedGeneration, stagedPublicKeyX963: request.proposedPublicKeyX963,
        lifecycleHeadHash: request.lifecycleHeadHash, auditEntries: request.auditEntries,
        auditHeadHash: request.auditHeadHash, latestCheckpointHash: request.latestCheckpointHash,
        latestReceiptHash: request.latestReceiptHash, controlSequence: request.controlSequence
    )
    try NativeRecoveryVerifier.validateRuntimeState(verification, state: state)
    let substituted = NativeRecoveryRuntimeState(
        installationID: state.installationID, role: state.role,
        activeGeneration: state.activeGeneration, activeFingerprint: state.activeFingerprint,
        stagedGeneration: state.stagedGeneration, stagedPublicKeyX963: state.stagedPublicKeyX963,
        lifecycleHeadHash: String(repeating: "0", count: 64), auditEntries: state.auditEntries,
        auditHeadHash: state.auditHeadHash, latestCheckpointHash: state.latestCheckpointHash,
        latestReceiptHash: state.latestReceiptHash, controlSequence: state.controlSequence
    )
    #expect(throws: AgentPassNativeError.self) { try NativeRecoveryVerifier.validateRuntimeState(verification, state: substituted) }

    var noncanonical = encoded
    noncanonical.append(0x0a)
    #expect(throws: AgentPassNativeError.self) { try NativeRecoveryVerifier.verifyHistoricalEvidence(noncanonical) }
}

@Test func nativeRecoveryRequiresThresholdAndRevalidatesEveryAuthorization() throws {
    let fixture = try RecoveryTestFixture()
    let first = try fixture.authorization(id: "security-1", key: fixture.first)
    let second = try fixture.authorization(id: "security-2", key: fixture.second)
    let third = try fixture.authorization(id: "security-3", key: fixture.third)

    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(requestData: fixture.requestData, policyData: fixture.policyData, authorizationData: [first], nowMilliseconds: recoveryNow)
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(requestData: fixture.requestData, policyData: fixture.policyData, authorizationData: [first, first], nowMilliseconds: recoveryNow)
    }

    var invalidThird = try recoveryObject(third)
    invalidThird["request_hash"] = String(repeating: "0", count: 64)
    invalidThird["signature"] = Data(repeating: 0, count: 64).base64EncodedString()
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(
            requestData: fixture.requestData,
            policyData: fixture.policyData,
            authorizationData: [first, second, try recoveryCanonical(invalidThird)],
            nowMilliseconds: recoveryNow
        )
    }
}

@Test func nativeRecoveryRejectsDuplicateAuthorityIDsAndKeys() throws {
    let fixture = try RecoveryTestFixture()
    var duplicateID = fixture.policyObject
    var authorities = duplicateID["authorities"] as! [[String: Any]]
    authorities[1]["id"] = "security-1"
    duplicateID["authorities"] = authorities
    #expect(throws: AgentPassNativeError.self) { try NativeRecoveryVerifier.policyHash(recoveryCanonical(duplicateID)) }

    var duplicateKey = fixture.policyObject
    authorities = duplicateKey["authorities"] as! [[String: Any]]
    authorities[1]["public_key"] = authorities[0]["public_key"]
    duplicateKey["authorities"] = authorities
    #expect(throws: AgentPassNativeError.self) { try NativeRecoveryVerifier.policyHash(recoveryCanonical(duplicateKey)) }

    var excessiveThreshold = fixture.policyObject
    excessiveThreshold["threshold"] = 4
    #expect(throws: AgentPassNativeError.self) { try NativeRecoveryVerifier.policyHash(recoveryCanonical(excessiveThreshold)) }
}

@Test func nativeRecoveryBindsRequestToExactPolicyIdentityVersionAndHash() throws {
    let fixture = try RecoveryTestFixture()
    let first = try fixture.authorization(id: "security-1", key: fixture.first)
    let second = try fixture.authorization(id: "security-2", key: fixture.second)

    var substituted = fixture.policyObject
    substituted["policy_id"] = "attacker-policy"
    let substitutedData = try recoveryCanonical(substituted)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(requestData: fixture.requestData, policyData: substitutedData, authorizationData: [first, second], nowMilliseconds: recoveryNow)
    }

    var reboundRequest = fixture.requestObject
    reboundRequest["recovery_policy_hash"] = recoverySHA256(substitutedData)
    reboundRequest["recovery_policy_id"] = "attacker-policy"
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(requestData: recoveryCanonical(reboundRequest), policyData: substitutedData, authorizationData: [first, second], nowMilliseconds: recoveryNow)
    }

    var wrongVersion = fixture.policyObject
    wrongVersion["version"] = 2
    #expect(throws: AgentPassNativeError.self) { try NativeRecoveryVerifier.policyHash(recoveryCanonical(wrongVersion)) }
}

@Test func nativeRecoveryRejectsUnknownMissingAndDuplicateJSONKeys() throws {
    let fixture = try RecoveryTestFixture()
    var unknown = fixture.requestObject
    unknown["cli_valid"] = true
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(recoveryCanonical(unknown), nowMilliseconds: recoveryNow)
    }
    var missing = fixture.requestObject
    missing.removeValue(forKey: "latest_receipt_hash")
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(recoveryCanonical(missing), nowMilliseconds: recoveryNow)
    }

    let canonicalText = String(decoding: fixture.requestData, as: UTF8.self)
    let duplicateRequest = Data(canonicalText.replacingOccurrences(of: "{", with: "{\"version\":1,", options: [], range: canonicalText.startIndex..<canonicalText.index(after: canonicalText.startIndex)).utf8)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(duplicateRequest, nowMilliseconds: recoveryNow)
    }

    let policyText = String(decoding: fixture.policyData, as: UTF8.self)
    let duplicateNested = Data(policyText.replacingOccurrences(of: "{\"id\":", with: "{\"id\":\"shadow\",\"id\":", options: [], range: policyText.startIndex..<policyText.endIndex).utf8)
    #expect(throws: AgentPassNativeError.self) { try NativeRecoveryVerifier.policyHash(duplicateNested) }
}

@Test func nativeRecoveryRequiresCanonicalBoundedUTF8Documents() throws {
    let fixture = try RecoveryTestFixture()
    let requestText = String(decoding: fixture.requestData, as: UTF8.self)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(Data(" \(requestText)".utf8), nowMilliseconds: recoveryNow)
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(fixture.requestData + Data("\n\n".utf8), nowMilliseconds: recoveryNow)
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(Data([0xff, 0xfe]), nowMilliseconds: recoveryNow)
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(Data(repeating: 0x61, count: NativeRecoveryVerifier.maximumRequestBytes + 1), nowMilliseconds: recoveryNow)
    }

    let unsorted = Data("{\"version\":1,\"audit_entries\":42}".utf8)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(unsorted, nowMilliseconds: recoveryNow)
    }
    let excessiveNesting = Data((String(repeating: "[", count: 32) + "null" + String(repeating: "]", count: 32)).utf8)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(excessiveNesting, nowMilliseconds: recoveryNow)
    }
}

@Test func nativeRecoveryStrictnessCoversPolicyAndAuthorizationDocuments() throws {
    let fixture = try RecoveryTestFixture()
    let first = try fixture.authorization(id: "security-1", key: fixture.first)
    let second = try fixture.authorization(id: "security-2", key: fixture.second)

    var unknownPolicy = fixture.policyObject
    unknownPolicy["comment"] = "not signed schema"
    #expect(throws: AgentPassNativeError.self) { try NativeRecoveryVerifier.policyHash(recoveryCanonical(unknownPolicy)) }
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.policyHash(Data(repeating: 0x61, count: NativeRecoveryVerifier.maximumPolicyBytes + 1))
    }

    var unknownAuthorization = try recoveryObject(first)
    unknownAuthorization["valid"] = true
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(
            requestData: fixture.requestData,
            policyData: fixture.policyData,
            authorizationData: [try recoveryCanonical(unknownAuthorization), second],
            nowMilliseconds: recoveryNow
        )
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(
            requestData: fixture.requestData,
            policyData: fixture.policyData,
            authorizationData: [Data(repeating: 0x61, count: NativeRecoveryVerifier.maximumAuthorizationBytes + 1), second],
            nowMilliseconds: recoveryNow
        )
    }

    let authorizationText = String(decoding: first, as: UTF8.self)
    let duplicateAuthorization = Data(authorizationText.replacingOccurrences(of: "{", with: "{\"version\":1,", options: [], range: authorizationText.startIndex..<authorizationText.index(after: authorizationText.startIndex)).utf8)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(
            requestData: fixture.requestData,
            policyData: fixture.policyData,
            authorizationData: [duplicateAuthorization, second],
            nowMilliseconds: recoveryNow
        )
    }

    let noncanonicalAuthorization = Data((" " + authorizationText).utf8)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(
            requestData: fixture.requestData,
            policyData: fixture.policyData,
            authorizationData: [noncanonicalAuthorization, second],
            nowMilliseconds: recoveryNow
        )
    }
}

@Test func nativeRecoveryValidatesGenerationP256KeyAndAllHistoryBindings() throws {
    let fixture = try RecoveryTestFixture()
    var invalid = fixture.requestObject
    invalid["proposed_generation"] = 3
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(recoveryCanonical(invalid), nowMilliseconds: recoveryNow)
    }

    invalid = fixture.requestObject
    invalid["from_fingerprint"] = NSNull()
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(recoveryCanonical(invalid), nowMilliseconds: recoveryNow)
    }

    invalid = fixture.requestObject
    invalid["proposed_public_key"] = recoveryPEM(fixture.first.publicKey.rawRepresentation)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(recoveryCanonical(invalid), nowMilliseconds: recoveryNow)
    }

    for key in ["lifecycle_head_hash", "audit_head_hash", "latest_checkpoint_hash", "latest_receipt_hash"] {
        invalid = fixture.requestObject
        invalid[key] = NSNull()
        #expect(throws: AgentPassNativeError.self) {
            try NativeRecoveryVerifier.validateRequest(recoveryCanonical(invalid), nowMilliseconds: recoveryNow)
        }
        invalid[key] = String(repeating: "A", count: 64)
        #expect(throws: AgentPassNativeError.self) {
            try NativeRecoveryVerifier.validateRequest(recoveryCanonical(invalid), nowMilliseconds: recoveryNow)
        }
    }
}

@Test func nativeRecoveryEnforcesRequestAndAuthorizationTimeWindows() throws {
    let fixture = try RecoveryTestFixture()
    var invalid = fixture.requestObject
    invalid["expires_at"] = recoveryTimestamp(recoveryNow + 16 * 60_000)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(recoveryCanonical(invalid), nowMilliseconds: recoveryNow)
    }
    invalid = fixture.requestObject
    invalid["issued_at"] = recoveryTimestamp(recoveryNow + 5_001)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(recoveryCanonical(invalid), nowMilliseconds: recoveryNow)
    }
    invalid = fixture.requestObject
    invalid["expires_at"] = recoveryTimestamp(recoveryNow - 1)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.validateRequest(recoveryCanonical(invalid), nowMilliseconds: recoveryNow)
    }

    let early = try fixture.authorization(id: "security-1", key: fixture.first, signedAt: recoveryNow - 1_001)
    let second = try fixture.authorization(id: "security-2", key: fixture.second)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(requestData: fixture.requestData, policyData: fixture.policyData, authorizationData: [early, second], nowMilliseconds: recoveryNow)
    }
    let future = try fixture.authorization(id: "security-1", key: fixture.first, signedAt: recoveryNow + 5_001)
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(requestData: fixture.requestData, policyData: fixture.policyData, authorizationData: [future, second], nowMilliseconds: recoveryNow)
    }
}

@Test func nativeRecoveryRejectsMalformedSPKIAndSignatureEncodings() throws {
    let fixture = try RecoveryTestFixture()
    var badPolicy = fixture.policyObject
    var authorities = badPolicy["authorities"] as! [[String: Any]]
    authorities[0]["public_key"] = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
    badPolicy["authorities"] = authorities
    #expect(throws: AgentPassNativeError.self) { try NativeRecoveryVerifier.policyHash(recoveryCanonical(badPolicy)) }

    let first = try fixture.authorization(id: "security-1", key: fixture.first)
    let second = try fixture.authorization(id: "security-2", key: fixture.second)
    var malformed = try recoveryObject(first)
    malformed["signature"] = "A==="
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(requestData: fixture.requestData, policyData: fixture.policyData, authorizationData: [try recoveryCanonical(malformed), second], nowMilliseconds: recoveryNow)
    }
    malformed = try recoveryObject(first)
    malformed["signature"] = Data(repeating: 0, count: 63).base64EncodedString()
    #expect(throws: AgentPassNativeError.self) {
        try NativeRecoveryVerifier.verify(requestData: fixture.requestData, policyData: fixture.policyData, authorizationData: [try recoveryCanonical(malformed), second], nowMilliseconds: recoveryNow)
    }
}

@Test func nativeRecoveryMatchesNodeCanonicalSchemaAndSignatureVector() throws {
    let policy = Data(#"{"authorities":[{"id":"security-1","public_key":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=\n-----END PUBLIC KEY-----\n"}],"policy_id":"offline-recovery","threshold":1,"version":1}"#.utf8)
    let request = Data(#"{"audit_entries":42,"audit_head_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","control_sequence":7,"expires_at":"2027-01-15T08:14:00.000Z","from_fingerprint":"SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","from_generation":1,"installation_id":"build-mac-01","issued_at":"2027-01-15T08:00:00.000Z","latest_checkpoint_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","latest_receipt_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","lifecycle_head_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk","proposed_generation":2,"proposed_public_key":"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=","recovery_policy_hash":"adecf7a436af32ab61b2e1a9c22db36e9983c3344bf1aff37211e00236d0aaa6","recovery_policy_id":"offline-recovery","recovery_policy_version":1,"role":"audit_checkpoint","version":1}"#.utf8)
    let authorization = Data(#"{"public_key_fingerprint":"SHA256:Mkvi3qi8REYbAjPlH6SJAu1rHMZx53Oa8lUeC_5o9U4","request_hash":"fea739739b88015bd7fc7350a736240817bc83558492e468df5066fcfd508b22","signature":"NKRil5esY0V52zTBxH1msWbkaSZ7MBMCqOyqNAUMr4snQhkEbwfqloD9c0mBraso7s5ObcthHFez6hb21iLmAA==","signed_at":"2027-01-15T08:00:01.000Z","signer_id":"security-1","version":1}"#.utf8)

    #expect(try NativeRecoveryVerifier.policyHash(policy) == "adecf7a436af32ab61b2e1a9c22db36e9983c3344bf1aff37211e00236d0aaa6")
    #expect(try NativeRecoveryVerifier.requestHash(request) == "fea739739b88015bd7fc7350a736240817bc83558492e468df5066fcfd508b22")
    let result = try NativeRecoveryVerifier.verify(
        requestData: request,
        policyData: policy,
        authorizationData: [authorization],
        nowMilliseconds: 1_800_000_001_000
    )
    #expect(result.valid)
    #expect(result.acceptedSignerIDs == ["security-1"])
}

private func recoveryCanonical(_ object: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
}

private func recoveryObject(_ data: Data) throws -> [String: Any] {
    try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
}

private func recoverySHA256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func recoveryBase64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func recoveryFingerprint(_ rawPublicKey: Data) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + rawPublicKey
    return "SHA256:" + recoveryBase64URL(Data(SHA256.hash(data: der)))
}

private func recoveryPEM(_ rawPublicKey: Data) -> String {
    let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + rawPublicKey
    return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
}

private func recoveryTimestamp(_ milliseconds: Int64) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    return formatter.string(from: Date(timeIntervalSince1970: Double(milliseconds) / 1_000))
}
