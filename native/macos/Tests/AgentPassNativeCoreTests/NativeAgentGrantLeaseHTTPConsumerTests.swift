import CryptoKit
import Foundation
import Testing

@testable import AgentPassNativeCore

private final class GrantHTTPTransport: NativeAgentHTTPTransporting, @unchecked Sendable {
  var response: NativeAgentHTTPResponse
  private(set) var calls: [(URL, [String: String], Data)] = []
  init(_ response: NativeAgentHTTPResponse) { self.response = response }
  func send(url: URL, method: String, headers: [String: String], body: Data, timeoutSeconds: Int)
    throws -> NativeAgentHTTPResponse
  {
    calls.append((url, headers, body))
    return response
  }
}
private struct GrantFixedRandom: NativeAgentRandomBytesGenerating {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 7, count: count) }
}
private struct GrantFixedWall: NativeAgentWallClock {
  func sample() throws -> NativeAgentWallClockValue {
    .init(millisecondsSinceUnixEpoch: 1_786_615_201_000)
  }
}
private final class GrantSigner: P256MessageSigner {
  let key = P256.Signing.PrivateKey()
  var publicKeyX963: Data { key.publicKey.x963Representation }
  func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}
private func grantBinding() throws -> NativeAgentSessionBinding {
  try .init(
    agentID: "33333333-3333-4333-8333-333333333333",
    deviceID: "44444444-4444-4444-8444-444444444444",
    processBindingDigest: Data(repeating: 0xbb, count: 32),
    ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
    worktreeBindingDigest: Data(repeating: 0xaa, count: 32), controlSequence: 12,
    authorityGeneration: 7, keyGeneration: 99)
}
private func grantObject() -> [String: Any] {
  let statement: [String: Any] = [
    "version": 1, "grant_id": "55555555-5555-4555-8555-555555555555",
    "organization_id": "66666666-6666-4666-8666-666666666666",
    "device_id": "44444444-4444-4444-8444-444444444444",
    "agent_id": "33333333-3333-4333-8333-333333333333", "agent_kind": "claude-code",
    "adapter_id": "77777777-7777-4777-8777-777777777777", "adapter_version": "1.0.0",
    "worktree_binding_sha256": String(repeating: "a", count: 64),
    "process_binding_policy_id": "claude-code-v1",
    "scope": [
      "operations": ["git.commit.sign"], "repositories": ["example/repository"],
      "branches": ["allow": ["main"], "deny": []],
      "remotes": ["allow": ["origin"], "deny": []],
    ],
    "max_signatures": 2, "not_before": "2026-08-13T10:00:00.000Z",
    "expires_at": "2026-08-13T10:15:00.000Z", "control_sequence": 12,
    "authority_generation": 7, "issuer": "agentpass-cloud", "key_id": "agent-session-2026-08",
  ]
  let statementData = try! NativeStrictJSON.data(statement)
  let statementHash = Data(SHA256.hash(data: statementData)).map { String(format: "%02x", $0) }
    .joined()
  return [
    "version": 1, "type": "agentpass.agent-session-grant",
    "statement": statement, "statement_hash": statementHash,
    "signature": String(repeating: "A", count: 86),
  ]
}
private func leaseObject() -> [String: Any] {
  [
    "version": 1, "type": "agentpass.agent-session-lease",
    "session_id": "11111111-1111-4111-8111-111111111111",
    "grant_id": "55555555-5555-4555-8555-555555555555",
    "organization_id": "66666666-6666-4666-8666-666666666666",
    "device_id": "44444444-4444-4444-8444-444444444444",
    "agent_id": "33333333-3333-4333-8333-333333333333", "agent_kind": "claude-code",
    "adapter_id": "77777777-7777-4777-8777-777777777777", "adapter_version": "1.0.0",
    "process_binding_sha256": String(repeating: "b", count: 64),
    "ancestry_binding_sha256": String(repeating: "c", count: 64),
    "worktree_binding_sha256": String(repeating: "a", count: 64), "max_signatures": 2,
    "used_signatures": 0, "not_before": "2026-08-13T10:00:00.000Z",
    "expires_at": "2026-08-13T10:15:00.000Z", "control_sequence": 12, "authority_generation": 7,
  ]
}
private func consumer(_ transport: GrantHTTPTransport) throws -> NativeAgentGrantLeaseHTTPConsumer {
  try .init(
    baseURL: URL(string: "https://api.agentpass.test")!,
    organizationID: "66666666-6666-4666-8666-666666666666", transport: transport,
    signer: GrantSigner(), random: GrantFixedRandom(), wallClock: GrantFixedWall())
}

@Test func grantConsumerSendsExactSignedPathBodyAndDecodesLease() throws {
  let response = try NativeStrictJSON.data([
    "lease": leaseObject(), "request_id": "88888888-8888-4888-8888-888888888888",
  ])
  let transport = GrantHTTPTransport(.init(statusCode: 201, body: response))
  let binding = try grantBinding()
  let proof = try NativeStrictJSON.data(grantObject())
  let lease = try consumer(transport).consumeGrant(
    .init(bootstrapID: "99999999-9999-4999-8999-999999999999", proof: proof, binding: binding))
  #expect(lease.sessionID == "11111111-1111-4111-8111-111111111111")
  let call = try #require(transport.calls.first)
  #expect(
    call.0.path
      == "/v1/organizations/66666666-6666-4666-8666-666666666666/devices/44444444-4444-4444-8444-444444444444/agent-session-grants/55555555-5555-4555-8555-555555555555/consume"
  )
  #expect(call.1["AgentPass-Signature"] != nil)
  let body = try NativeStrictJSON.object(from: call.2, maxBytes: 16384, maxDepth: 32)
  #expect(Set(body.keys) == ["grant", "process_binding_sha256", "ancestry_binding_sha256"])
  #expect(body["process_binding_sha256"] as? String == String(repeating: "b", count: 64))
}

@Test func grantConsumerRejectsGrantFromAnotherConfiguredOrganizationBeforeTransport() throws {
  let transport = GrantHTTPTransport(.init(statusCode: 500, body: Data()))
  var grant = grantObject()
  var statement = grant["statement"] as! [String: Any]
  statement["organization_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  grant["statement"] = statement
  grant["statement_hash"] = Data(SHA256.hash(data: try NativeStrictJSON.data(statement))).map {
    String(format: "%02x", $0)
  }.joined()
  #expect(throws: NativeAgentGrantLeaseHTTPError.unauthorized) {
    _ = try consumer(transport).consumeGrant(
      .init(
        bootstrapID: "99999999-9999-4999-8999-999999999999",
        proof: try NativeStrictJSON.data(grant), binding: try grantBinding()))
  }
  #expect(transport.calls.isEmpty)
}
@Test func grantConsumerRejectsAudienceAndBindingSubstitutionBeforeTransport() throws {
  let t = GrantHTTPTransport(.init(statusCode: 500, body: Data()))
  var grant = grantObject()
  var statement = grant["statement"] as! [String: Any]
  statement["device_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  grant["statement"] = statement
  let statementData = try NativeStrictJSON.data(statement)
  grant["statement_hash"] = Data(SHA256.hash(data: statementData)).map {
    String(format: "%02x", $0)
  }.joined()
  #expect(throws: NativeAgentGrantLeaseHTTPError.unauthorized) {
    _ = try consumer(t).consumeGrant(
      .init(
        bootstrapID: "99999999-9999-4999-8999-999999999999",
        proof: try NativeStrictJSON.data(grant), binding: try grantBinding()))
  }
  #expect(t.calls.isEmpty)
}

@Test func grantConsumerRejectsWorktreeAndStatementHashSubstitutionBeforeTransport() throws {
  let transport = GrantHTTPTransport(.init(statusCode: 500, body: Data()))
  var grant = grantObject()
  var statement = grant["statement"] as! [String: Any]
  statement["worktree_binding_sha256"] = String(repeating: "f", count: 64)
  grant["statement"] = statement
  let statementData = try NativeStrictJSON.data(statement)
  grant["statement_hash"] = Data(SHA256.hash(data: statementData)).map {
    String(format: "%02x", $0)
  }.joined()

  #expect(throws: NativeAgentGrantLeaseHTTPError.unauthorized) {
    _ = try consumer(transport).consumeGrant(
      .init(
        bootstrapID: "99999999-9999-4999-8999-999999999999",
        proof: try NativeStrictJSON.data(grant), binding: try grantBinding()))
  }
  #expect(transport.calls.isEmpty)

  var tampered = grantObject()
  tampered["statement_hash"] = String(repeating: "0", count: 64)
  #expect(throws: NativeAgentGrantLeaseHTTPError.invalidGrant) {
    _ = try consumer(transport).consumeGrant(
      .init(
        bootstrapID: "99999999-9999-4999-8999-999999999999",
        proof: try NativeStrictJSON.data(tampered), binding: try grantBinding()))
  }
  #expect(transport.calls.isEmpty)
}
@Test func grantConsumerMapsStatusesAndMalformedResponsesStably() throws {
  let binding = try grantBinding()
  let proof = try NativeStrictJSON.data(grantObject())
  for (status, error) in [
    (409, NativeAgentGrantLeaseHTTPError.conflict), (429, .rateLimited), (503, .unavailable),
  ] {
    let t = GrantHTTPTransport(.init(statusCode: status, body: Data()))
    #expect(throws: error) {
      _ = try consumer(t).consumeGrant(
        .init(bootstrapID: "99999999-9999-4999-8999-999999999999", proof: proof, binding: binding))
    }
  }
  let t = GrantHTTPTransport(.init(statusCode: 201, body: Data("secret".utf8)))
  #expect(throws: NativeAgentGrantLeaseHTTPError.invalidResponse) {
    _ = try consumer(t).consumeGrant(
      .init(bootstrapID: "99999999-9999-4999-8999-999999999999", proof: proof, binding: binding))
  }
}
