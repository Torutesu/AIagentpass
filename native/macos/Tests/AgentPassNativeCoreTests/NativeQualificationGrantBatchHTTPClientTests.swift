import CryptoKit
import Foundation
import Testing

@testable import AgentPassNativeCore

private final class QualificationHTTPTransport: NativeAgentHTTPTransporting, @unchecked Sendable {
  var response: NativeAgentHTTPResponse
  var error: Error?
  private(set) var calls: [(URL, String, [String: String], Data, Int)] = []

  init(response: NativeAgentHTTPResponse) { self.response = response }

  func send(url: URL, method: String, headers: [String: String], body: Data, timeoutSeconds: Int)
    throws -> NativeAgentHTTPResponse
  {
    calls.append((url, method, headers, body, timeoutSeconds))
    if let error { throw error }
    return response
  }
}

private struct QualificationRandom: NativeAgentRandomBytesGenerating {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 0x42, count: count) }
}

private struct QualificationWall: NativeAgentWallClock {
  let milliseconds: Int64
  func sample() throws -> NativeAgentWallClockValue {
    .init(millisecondsSinceUnixEpoch: milliseconds)
  }
}

private final class QualificationDeviceSigner: P256MessageSigner {
  private let key = P256.Signing.PrivateKey()
  var publicKeyX963: Data { key.publicKey.x963Representation }
  func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private enum QualificationFixture {
  static let organization = "11111111-1111-4111-8111-111111111111"
  static let device = "22222222-2222-4222-8222-222222222222"
  static let agent = "33333333-3333-4333-8333-333333333333"
  static let batch = "44444444-4444-4444-8444-444444444444"
  static let requestID = "55555555-5555-4555-8555-555555555555"
  static let adapter = "66666666-6666-4666-8666-666666666666"
  static let now = Date.parseQualification("2026-08-14T10:00:00.000Z")
  static let expires = "2026-08-14T10:10:00.000Z"
  static let request = try! NativeQualificationGrantBatchClaimRequest(
    candidateSHA256: String(repeating: "a", count: 64),
    sourceCommit: String(repeating: "b", count: 40),
    artifactSHA256: String(repeating: "c", count: 64),
    teamID: "TEAMID1234",
    releaseTrustSHA256: String(repeating: "d", count: 64),
    candidateCheckpointSHA256: String(repeating: "e", count: 64))
}

private func qualificationDigest(_ data: Data) -> String {
  Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
}

private func qualificationSignature(_ key: Curve25519.Signing.PrivateKey, domain: String, statement: [String: Any]) throws -> String {
  var message = Data(domain.utf8)
  message.append(try NativeStrictJSON.data(statement))
  return (try key.signature(for: message)).base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

private func qualificationStepIdentity(_ index: Int) -> (String, String?, String?) {
  switch index {
  case 0: return ("unarmed-control", nil, nil)
  case 1: return ("scenario", "pre-cloud-kill", "pre-cloud")
  case 2: return ("scenario", "post-cloud-pre-local-kill", "post-cloud-pre-local")
  case 3: return ("scenario", "post-activation-pre-audit-kill", "post-activation-pre-audit")
  case 4: return ("scenario", "post-audit-pre-reply-loss", "post-audit-pre-reply")
  case 5: return ("scenario", "audit-fsync-failure", "audit-fsync")
  default: return ("scenario", "transport-reply-loss", "transport-reply")
  }
}

private func qualificationGrant(
  index: Int, key: Curve25519.Signing.PrivateKey, expiresAt: String = QualificationFixture.expires
) throws -> [String: Any] {
  let statement: [String: Any] = [
    "adapter_id": QualificationFixture.adapter,
    "adapter_version": "1.2.3",
    "agent_id": QualificationFixture.agent,
    "agent_kind": "claude-code",
    "authority_generation": 7,
    "control_sequence": index + 10,
    "device_id": QualificationFixture.device,
    "expires_at": expiresAt,
    "grant_id": String(format: "70000000-0000-4000-8000-%012d", index + 1),
    "issuer": "agentpass-cloud",
    "key_id": "agent-session-2026-08",
    "max_signatures": 1,
    "not_before": "2026-08-14T09:59:00.000Z",
    "organization_id": QualificationFixture.organization,
    "process_binding_policy_id": "qualification-v1",
    "scope": [
      "operations": ["git.commit.sign"],
      "repositories": ["/Users/agentpass/qualification"],
      "branches": ["allow": ["main"], "deny": []],
      "remotes": ["allow": ["origin"], "deny": []],
    ],
    "version": 1,
    "worktree_binding_sha256": String(repeating: "f", count: 64),
  ]
  let statementBytes = try NativeStrictJSON.data(statement)
  return [
    "version": 1,
    "type": "agentpass.agent-session-grant",
    "statement": statement,
    "statement_hash": qualificationDigest(statementBytes),
    "signature": try qualificationSignature(
      key, domain: "AgentPass-Agent-Session-Grant-v1\0", statement: statement),
  ]
}

private func qualificationResponse(
  trustKey: Curve25519.Signing.PrivateKey,
  batchMutation: ((inout [String: Any]) -> Void)? = nil,
  manifestMutation: ((inout [String: Any]) -> Void)? = nil,
  envelopeMutation: ((inout [String: Any]) -> Void)? = nil,
  expiresAt: String = QualificationFixture.expires
) throws -> Data {
  var steps = [[String: Any]]()
  for index in 0..<7 {
    let identity = qualificationStepIdentity(index)
    let grant = try qualificationGrant(index: index, key: trustKey, expiresAt: expiresAt)
    steps.append([
      "grant": grant,
      "index": index,
      "kind": identity.0,
      "phase": identity.2 as Any,
      "run_binding": "qualification-run-\(index)",
      "scenario": identity.1 as Any,
    ])
  }
  var batch: [String: Any] = [
    "agent_id": QualificationFixture.agent,
    "agent_kind": "claude-code",
    "artifact_sha256": QualificationFixture.request.artifactSHA256,
    "batch_id": QualificationFixture.batch,
    "candidate_checkpoint_sha256": QualificationFixture.request.candidateCheckpointSHA256,
    "candidate_sha256": QualificationFixture.request.candidateSHA256,
    "device_id": QualificationFixture.device,
    "expires_at": expiresAt,
    "kind": "agentpass-n3e-qualification-grant-batch",
    "organization_id": QualificationFixture.organization,
    "release_trust_sha256": QualificationFixture.request.releaseTrustSHA256,
    "requested_ttl_seconds": 600,
    "schema_version": 1,
    "source_commit": QualificationFixture.request.sourceCommit,
    "steps": steps,
    "team_id": QualificationFixture.request.teamID,
  ]
  batchMutation?(&batch)
  var inventory = [[String: Any]]()
  for (index, step) in steps.enumerated() {
    let grant = step["grant"] as! [String: Any]
    let statement = grant["statement"] as! [String: Any]
    let identity = qualificationStepIdentity(index)
    inventory.append([
      "grant_hash": qualificationDigest(try NativeStrictJSON.data(grant)),
      "grant_id": statement["grant_id"]!,
      "index": index,
      "kind": identity.0,
      "phase": identity.2 as Any,
      "run_binding": step["run_binding"]!,
      "scenario": identity.1 as Any,
      "statement_hash": grant["statement_hash"]!,
    ])
  }
  let manifestStatement: [String: Any] = [
    "artifact_sha256": QualificationFixture.request.artifactSHA256,
    "batch_id": QualificationFixture.batch,
    "candidate_checkpoint_sha256": QualificationFixture.request.candidateCheckpointSHA256,
    "candidate_sha256": QualificationFixture.request.candidateSHA256,
    "device_id": QualificationFixture.device,
    "expires_at": expiresAt,
    "organization_id": QualificationFixture.organization,
    "release_trust_sha256": QualificationFixture.request.releaseTrustSHA256,
    "schema_version": 1,
    "source_commit": QualificationFixture.request.sourceCommit,
    "steps": inventory,
    "team_id": QualificationFixture.request.teamID,
  ]
  var manifest: [String: Any] = [
    "signature": try qualificationSignature(
      trustKey, domain: "AgentPass-Qualification-Grant-Batch-Manifest-v1\0", statement: manifestStatement),
    "statement": manifestStatement,
    "statement_hash": qualificationDigest(try NativeStrictJSON.data(manifestStatement)),
    "type": "agentpass.qualification-grant-batch-manifest",
    "version": 1,
  ]
  manifestMutation?(&manifest)
  var envelope: [String: Any] = ["batch": batch, "manifest": manifest, "request_id": QualificationFixture.requestID]
  envelopeMutation?(&envelope)
  return try NativeStrictJSON.data(envelope)
}

private func qualificationClient(
  transport: QualificationHTTPTransport, trustKey: Curve25519.Signing.PrivateKey,
  baseURL: URL = URL(string: "https://api.agentpass.test")!,
  expectedGrantKeyID: String? = "agent-session-2026-08"
) throws -> NativeQualificationGrantBatchHTTPClient {
  try .init(
    baseURL: baseURL, organizationID: QualificationFixture.organization,
    deviceID: QualificationFixture.device, batchID: QualificationFixture.batch,
    transport: transport, signer: QualificationDeviceSigner(), trustKey: trustKey.publicKey,
    expectedGrantKeyID: expectedGrantKeyID, random: QualificationRandom(),
    wallClock: QualificationWall(milliseconds: QualificationFixture.now), timeoutSeconds: 9)
}

@Test("claims the exact path and canonical request, then verifies the manifest and seven existing Grants")
func qualificationClaimUsesDeviceAuthAndReturnsRelayBytes() throws {
  let trust = Curve25519.Signing.PrivateKey()
  let transport = QualificationHTTPTransport(response: .init(statusCode: 200, body: try qualificationResponse(trustKey: trust)))
  let value = try qualificationClient(transport: transport, trustKey: trust).claim(QualificationFixture.request)
  let call = try #require(transport.calls.first)
  #expect(call.0.absoluteString == "https://api.agentpass.test/v1/organizations/\(QualificationFixture.organization)/devices/\(QualificationFixture.device)/qualification-grant-batches/\(QualificationFixture.batch)/claim")
  #expect(call.1 == "POST")
  #expect(call.4 == 9)
  #expect(Set(call.2.keys) == ["Accept", "Content-Type", "AgentPass-Device", "AgentPass-Timestamp", "AgentPass-Nonce", "AgentPass-Content-SHA256", "AgentPass-Signature"])
  #expect(call.2["AgentPass-Device"] == QualificationFixture.device)
  #expect(call.2["AgentPass-Nonce"]?.count == 44)
  #expect(call.2["AgentPass-Content-SHA256"] == qualificationDigest(call.3))
  let requestObject = try NativeStrictJSON.object(from: call.3, maxBytes: 16 * 1024, maxDepth: 8)
  #expect(Set(requestObject.keys) == ["artifact_sha256", "candidate_checkpoint_sha256", "candidate_sha256", "release_trust_sha256", "schema_version", "source_commit", "team_id"])
  #expect(requestObject["request_nonce"] == nil)
  #expect(value.agentKind == "claude-code")
  #expect(value.steps.count == 7)
  #expect(value.steps.map(\.index) == Array(0..<7))
  #expect(value.steps.map(\.runBinding).count == Set(value.steps.map(\.runBinding)).count)
  #expect(value.steps.allSatisfy { $0.grantCanonicalBytes.count > 0 })
  #expect(value.steps[0].grantCanonicalBytes.contains(Data("agentpass.agent-session-grant".utf8)))
}

@Test("requires a trusted Ed25519 key for the manifest and every existing Grant")
func qualificationClaimRejectsWrongTrustKeyOrSignature() throws {
  let signer = Curve25519.Signing.PrivateKey()
  let wrong = Curve25519.Signing.PrivateKey()
  let transport = QualificationHTTPTransport(response: .init(statusCode: 200, body: try qualificationResponse(trustKey: signer)))
  #expect(throws: NativeQualificationGrantBatchHTTPError.invalidResponse) {
    _ = try qualificationClient(transport: transport, trustKey: wrong).claim(QualificationFixture.request)
  }
  let tampered = QualificationHTTPTransport(response: .init(statusCode: 200, body: try qualificationResponse(trustKey: signer, manifestMutation: { $0["signature"] = String(repeating: "A", count: 86) })))
  #expect(throws: NativeQualificationGrantBatchHTTPError.invalidResponse) {
    _ = try qualificationClient(transport: tampered, trustKey: signer).claim(QualificationFixture.request)
  }
}

@Test("rejects transport failures, status failures, and a non-HTTPS or path-bearing origin")
func qualificationClaimRejectsTransportAndOriginSubstitutions() throws {
  let trust = Curve25519.Signing.PrivateKey()
  let response = try qualificationResponse(trustKey: trust)
  let transport = QualificationHTTPTransport(response: .init(statusCode: 200, body: response))
  transport.error = NativeQualificationGrantBatchHTTPError.unavailable
  #expect(throws: NativeQualificationGrantBatchHTTPError.unavailable) {
    _ = try qualificationClient(transport: transport, trustKey: trust).claim(QualificationFixture.request)
  }
  for status in [400, 401, 403, 404, 409, 429, 500] {
    let t = QualificationHTTPTransport(response: .init(statusCode: status, body: response))
    let expected: NativeQualificationGrantBatchHTTPError = status == 400 ? .invalidRequest : status == 409 ? .conflict : status == 429 ? .rateLimited : status == 500 ? .unavailable : .unauthorized
    #expect(throws: expected) { _ = try qualificationClient(transport: t, trustKey: trust).claim(QualificationFixture.request) }
  }
  #expect(throws: NativeQualificationGrantBatchHTTPError.invalidConfiguration) {
    _ = try qualificationClient(transport: transport, trustKey: trust, baseURL: URL(string: "http://api.agentpass.test")!)
  }
  #expect(throws: NativeQualificationGrantBatchHTTPError.invalidConfiguration) {
    _ = try qualificationClient(transport: transport, trustKey: trust, baseURL: URL(string: "https://api.agentpass.test/prefix")!)
  }
}

@Test("rejects manifest and Grant substitutions, duplicates, order changes, binding changes, and expiry")
func qualificationClaimRejectsResponseAttacks() throws {
  let trust = Curve25519.Signing.PrivateKey()
  let cases: [Data] = [
    try qualificationResponse(trustKey: trust, batchMutation: { batch in
      var steps = batch["steps"] as! [[String: Any]]; steps.swapAt(0, 1); batch["steps"] = steps
    }),
    try qualificationResponse(trustKey: trust, manifestMutation: { manifest in
      var statement = manifest["statement"] as! [String: Any]; statement["candidate_sha256"] = String(repeating: "f", count: 64); manifest["statement"] = statement
    }),
    try qualificationResponse(trustKey: trust, manifestMutation: { manifest in
      var statement = manifest["statement"] as! [String: Any]; var steps = statement["steps"] as! [[String: Any]]; steps[1]["run_binding"] = steps[0]["run_binding"]!; statement["steps"] = steps; manifest["statement"] = statement
    }),
    try qualificationResponse(trustKey: trust, manifestMutation: { manifest in
      var statement = manifest["statement"] as! [String: Any]; var steps = statement["steps"] as! [[String: Any]]; steps[1]["grant_id"] = steps[0]["grant_id"]!; statement["steps"] = steps; manifest["statement"] = statement
    }),
    try qualificationResponse(trustKey: trust, batchMutation: { batch in batch["expires_at"] = "2026-08-14T09:59:00.000Z" }),
  ]
  for body in cases {
    let transport = QualificationHTTPTransport(response: .init(statusCode: 200, body: body))
    #expect(throws: NativeQualificationGrantBatchHTTPError.invalidResponse) {
      _ = try qualificationClient(transport: transport, trustKey: trust).claim(QualificationFixture.request)
    }
  }
}

@Test("rejects duplicate fields, unknown fields, and bounded oversized responses")
func qualificationClaimRejectsClosedShapeAndOversize() throws {
  let trust = Curve25519.Signing.PrivateKey()
  let duplicate = Data("{\"batch\":{},\"batch\":{},\"manifest\":{},\"request_id\":\"\(QualificationFixture.requestID)\"}".utf8)
  let duplicateTransport = QualificationHTTPTransport(response: .init(statusCode: 200, body: duplicate))
  #expect(throws: NativeQualificationGrantBatchHTTPError.invalidResponse) {
    _ = try qualificationClient(transport: duplicateTransport, trustKey: trust).claim(QualificationFixture.request)
  }
  let unknown = try qualificationResponse(trustKey: trust, envelopeMutation: { $0["unexpected"] = true })
  let unknownTransport = QualificationHTTPTransport(response: .init(statusCode: 200, body: unknown))
  #expect(throws: NativeQualificationGrantBatchHTTPError.invalidResponse) {
    _ = try qualificationClient(transport: unknownTransport, trustKey: trust).claim(QualificationFixture.request)
  }
  let oversized = QualificationHTTPTransport(response: .init(statusCode: 200, body: Data(repeating: 0x20, count: NativeQualificationGrantBatchHTTPClient.maximumResponseBytes + 1)))
  #expect(throws: NativeQualificationGrantBatchHTTPError.invalidResponse) {
    _ = try qualificationClient(transport: oversized, trustKey: trust).claim(QualificationFixture.request)
  }
}

private extension Date {
  static func parseQualification(_ value: String) -> Int64 {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return Int64(formatter.date(from: value)!.timeIntervalSince1970 * 1_000)
  }
}
