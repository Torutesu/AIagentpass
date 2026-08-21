import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct EvidenceSigner: P256MessageSigner {
    let key: P256.Signing.PrivateKey
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private let evidenceOrganization = "11111111-1111-4111-8111-111111111111"
private let evidenceDevice = "22222222-2222-4222-8222-222222222222"
private let evidenceHash = String(repeating: "a", count: 64)
private let evidenceNonce = Data(repeating: 0x41, count: 16).evidenceBase64URL

private func appliedEvidence() throws -> NativeControlRefreshEvidence {
    let acknowledgement = try NativeBundleAcknowledgementSigner.create(
        organizationID: evidenceOrganization,
        deviceID: evidenceDevice,
        deviceKeyEpoch: 3,
        sequence: 7,
        statementHash: evidenceHash,
        result: .applied,
        observedAtMilliseconds: 1_786_579_200_000,
        nonce: evidenceNonce,
        signer: EvidenceSigner(key: P256.Signing.PrivateKey())
    )
    return NativeControlRefreshEvidence(
        acknowledgement: acknowledgement,
        serverAccepted: true,
        observedGeneration: 4,
        refreshState: .applied,
        refreshGeneration: 4,
        refreshSequence: 7,
        controlStatementHash: evidenceHash
    )
}

@Test func controlRefreshEvidenceIsCanonicalClosedAndPublicOnly() throws {
    let evidence = try appliedEvidence()
    let data = try NativeControlRefreshEvidenceCodec.encode(evidence)
    #expect(try NativeControlRefreshEvidenceCodec.decode(data) == evidence)
    #expect(try NativeControlRefreshEvidenceCodec.encode(try NativeControlRefreshEvidenceCodec.decode(data)) == data)
    let response = try evidence.publicResponseObject()
    #expect(Set(response.keys) == ["status", "control_refreshed", "control_ack", "refresh_generation", "refresh_sequence", "control_statement_hash"])
    #expect(JSONSerialization.isValidJSONObject(response))
    let text = String(data: try JSONSerialization.data(withJSONObject: response), encoding: .utf8) ?? ""
    #expect(!text.contains("https://"))
    #expect(!text.contains("/var/"))
    #expect(!text.contains("/Users/"))

    var expanded = try NativeStrictJSON.object(from: data, maxBytes: NativeControlRefreshEvidenceCodec.maximumBytes, maxDepth: 10)
    expanded["unexpected"] = true
    let expandedData = try NativeStrictJSON.data(expanded)
    #expect(throws: NativeControlRefreshEvidenceError.self) {
        try NativeControlRefreshEvidenceCodec.decode(expandedData)
    }
}

@Test func controlRefreshEvidencePOSIXStoreSurvivesRestartAndRejectsHardLinks() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-evidence-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("refresh-ack.json").path
    let store = try NativeControlRefreshEvidencePOSIXStore(path: path)
    let evidence = try appliedEvidence()
    try store.save(evidence)
    let restarted = try NativeControlRefreshEvidencePOSIXStore(path: path)
    #expect(try restarted.load() == evidence)

    let hardLink = directory.appendingPathComponent("hard-link.json").path
    try FileManager.default.linkItem(atPath: path, toPath: hardLink)
    #expect(throws: NativeControlRefreshEvidenceError.self) {
        try restarted.save(evidence)
    }
}

private extension Data {
    var evidenceBase64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
