import CryptoKit
import Foundation
import Testing

@testable import AgentPassNativeCore

private final class LaunchHandoffHTTPTransport: NativeAgentHTTPTransporting, @unchecked Sendable {
  typealias ResponseFactory = (Data) throws -> NativeAgentHTTPResponse

  let responseFactory: ResponseFactory
  private(set) var calls: [(URL, String, [String: String], Data, Int)] = []

  init(responseFactory: @escaping ResponseFactory) {
    self.responseFactory = responseFactory
  }

  func send(
    url: URL, method: String, headers: [String: String], body: Data, timeoutSeconds: Int
  ) throws -> NativeAgentHTTPResponse {
    calls.append((url, method, headers, body, timeoutSeconds))
    return try responseFactory(body)
  }
}

private struct LaunchHandoffRandom: NativeAgentRandomBytesGenerating {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 0x42, count: count) }
}

private struct LaunchHandoffWall: NativeAgentWallClock {
  func sample() throws -> NativeAgentWallClockValue {
    .init(millisecondsSinceUnixEpoch: 1_786_615_201_000)
  }
}

private final class LaunchHandoffSigner: P256MessageSigner {
  private let key = P256.Signing.PrivateKey()
  var publicKeyX963: Data { key.publicKey.x963Representation }
  func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private enum LaunchHandoffFixture {
  static let organization = "11111111-1111-4111-8111-111111111111"
  static let device = "22222222-2222-4222-8222-222222222222"
  static let session = "33333333-3333-4333-8333-333333333333"
  static let agent = "44444444-4444-4444-8444-444444444444"
  static let adapter = "55555555-5555-4555-8555-555555555555"
  static let requestAdapterVersion = "1.2.3"
  static let baseURL = URL(string: "https://api.agentpass.test")!

  static let request = try! NativeAgentLaunchAuthorityHandoffRequest(
    sessionID: session,
    agentID: agent,
    agentKind: .claudeCode,
    requestedTTLSeconds: 600,
    adapterID: adapter,
    adapterVersion: requestAdapterVersion)
}

private func launchGrantProof(
  agentID: String = LaunchHandoffFixture.agent,
  agentKind: String = "claude-code"
) throws -> Data {
  let statement: [String: Any] = [
    "adapter_id": LaunchHandoffFixture.adapter,
    "adapter_version": LaunchHandoffFixture.requestAdapterVersion,
    "agent_id": agentID,
    "agent_kind": agentKind,
    "authority_generation": 7,
    "control_sequence": 12,
    "device_id": LaunchHandoffFixture.device,
    "expires_at": "2026-08-19T03:15:00.000Z",
    "grant_id": "66666666-6666-4666-8666-666666666666",
    "issuer": "agentpass-cloud",
    "key_id": "agent-session-2026-08",
    "max_signatures": 2,
    "not_before": "2026-08-19T03:00:00.000Z",
    "organization_id": LaunchHandoffFixture.organization,
    "process_binding_policy_id": "claude-code-v1",
    "scope": [
      "branches": ["allow": ["main"], "deny": []],
      "operations": ["git.commit.sign"],
      "remotes": ["allow": ["origin"], "deny": []],
      "repositories": ["example/repository"],
    ],
    "version": 1,
    "worktree_binding_sha256": String(repeating: "a", count: 64),
  ]
  let statementData = try NativeStrictJSON.data(statement)
  let statementHash = Data(SHA256.hash(data: statementData)).map {
    String(format: "%02x", $0)
  }.joined()
  return try NativeStrictJSON.data([
    "signature": String(repeating: "A", count: 86),
    "statement": statement,
    "statement_hash": statementHash,
    "type": "agentpass.agent-session-grant",
    "version": 1,
  ])
}

private func launchHandoff(
  agentID: String = LaunchHandoffFixture.agent,
  agentKind: AgentPassAgentAdapterKind = .claudeCode,
  requestedTTLSeconds: Int = 600,
  proof: Data? = nil
) throws -> NativeAgentLaunchAuthorityHandoff {
  try NativeAgentLaunchAuthorityHandoff(
    agentID: agentID,
    agentKind: agentKind,
    requestedTTLSeconds: requestedTTLSeconds,
    proof: try proof ?? launchGrantProof(
      agentID: agentID,
      agentKind: agentKind == .claudeCode ? "claude-code" : "cursor"))
}

private func launchHandoffConsumer(
  transport: any NativeAgentHTTPTransporting
) throws -> NativeAgentLaunchAuthorityHandoffHTTPConsumer {
  try NativeAgentLaunchAuthorityHandoffHTTPConsumer(
    baseURL: LaunchHandoffFixture.baseURL,
    organizationID: LaunchHandoffFixture.organization,
    deviceID: LaunchHandoffFixture.device,
    transport: transport,
    signer: LaunchHandoffSigner(),
    random: LaunchHandoffRandom(),
    wallClock: LaunchHandoffWall(),
    timeoutSeconds: 9)
}

private func responseFor(
  requestBody: Data,
  handoff: NativeAgentLaunchAuthorityHandoff,
  requestID: String? = nil
) throws -> NativeAgentHTTPResponse {
  _ = requestBody
  let response = try NativeStrictJSON.data([
    "grant": try NativeStrictJSON.object(from: handoff.proof, maxBytes: 4 * 1024, maxDepth: 32),
    "request_id": requestID ?? "77777777-7777-4777-8777-777777777777",
  ])
  return .init(statusCode: 201, body: response)
}

@Test("requests the exact Cloud contract and returns exact canonical Host bytes")
func launchHandoffConsumerUsesDeviceAuthAndConstructsFixedHostEnvelope() throws {
  let expectedHandoff = try launchHandoff()
  let transport = LaunchHandoffHTTPTransport { body in
    try responseFor(requestBody: body, handoff: expectedHandoff)
  }
  let consumer = try launchHandoffConsumer(transport: transport)

  let actual = try consumer.requestLaunchAuthorityHandoff(LaunchHandoffFixture.request)
  #expect(actual == expectedHandoff)
  #expect(try actual.canonicalJSON() == expectedHandoff.canonicalJSON())

  let call = try #require(transport.calls.first)
  #expect(call.0.absoluteString == "https://api.agentpass.test/v1/organizations/\(LaunchHandoffFixture.organization)/devices/\(LaunchHandoffFixture.device)/agent-sessions/\(LaunchHandoffFixture.session)/launch-authority-handoff")
  #expect(call.1 == "POST")
  #expect(call.4 == 9)
  #expect(Set(call.2.keys) == [
    "Accept", "Content-Type", "AgentPass-Device", "AgentPass-Timestamp",
    "AgentPass-Nonce", "AgentPass-Content-SHA256", "AgentPass-Signature",
  ])
  #expect(call.2["AgentPass-Device"] == LaunchHandoffFixture.device)
  #expect(call.2["AgentPass-Device-ID"] == nil)
  #expect(call.2["AgentPass-Content-SHA256"] != nil)

  let request = try NativeStrictJSON.object(from: call.3, maxBytes: 16 * 1024, maxDepth: 8)
  #expect(Set(request.keys) == [
    "adapter_id", "adapter_version", "nonce", "request_id", "type", "version",
  ])
  #expect(request["adapter_id"] as? String == LaunchHandoffFixture.adapter)
  #expect(request["adapter_version"] as? String == LaunchHandoffFixture.requestAdapterVersion)
  #expect(request["type"] as? String == "agentpass.agent-launch-authority-handoff-request")
  #expect(request["version"] as? Int == 1)
  #expect((request["nonce"] as? String)?.count == 43)
  #expect(request["proof"] == nil)
  #expect(request["token"] == nil)
}

@Test("rejects invalid request inputs before device API transport")
func launchHandoffConsumerRejectsInvalidRequestBeforeTransport() throws {
  let transport = LaunchHandoffHTTPTransport { _ in
    .init(statusCode: 500, body: Data())
  }
  let consumer = try launchHandoffConsumer(transport: transport)
  #expect(throws: NativeAgentLaunchAuthorityHandoffHTTPError.invalidRequest) {
    _ = try NativeAgentLaunchAuthorityHandoffRequest(
      sessionID: LaunchHandoffFixture.session,
      agentID: LaunchHandoffFixture.agent,
      agentKind: .generic,
      requestedTTLSeconds: 600,
      adapterID: LaunchHandoffFixture.adapter,
      adapterVersion: LaunchHandoffFixture.requestAdapterVersion)
  }
  #expect(transport.calls.isEmpty)
  _ = consumer
}

@Test("maps unavailable atomic handoff and transport failure without retry")
func launchHandoffConsumerFailsClosedWhenAtomicAPIIsUnavailable() throws {
  let unavailable = LaunchHandoffHTTPTransport { _ in
    .init(statusCode: 503, body: Data("{\"error\":{\"code\":\"agent_launch_authority_handoff_native_proof_unavailable\"}}".utf8))
  }
  let consumer = try launchHandoffConsumer(transport: unavailable)
  #expect(throws: NativeAgentLaunchAuthorityHandoffHTTPError.unavailable) {
    _ = try consumer.requestLaunchAuthorityHandoff(LaunchHandoffFixture.request)
  }
  #expect(unavailable.calls.count == 1)

  let transportFailure = LaunchHandoffHTTPTransport { _ in
    throw NativeAgentLaunchAuthorityHandoffHTTPError.unavailable
  }
  let failedConsumer = try launchHandoffConsumer(transport: transportFailure)
  #expect(throws: NativeAgentLaunchAuthorityHandoffHTTPError.unavailable) {
    _ = try failedConsumer.requestLaunchAuthorityHandoff(LaunchHandoffFixture.request)
  }
  #expect(transportFailure.calls.count == 1)
}

@Test("rejects response substitution, noncanonical JSON, and malformed proof")
func launchHandoffConsumerRejectsResponseSubstitutions() throws {
  let expected = try launchHandoff()
  let invalidRequestID = LaunchHandoffHTTPTransport { body in
    try responseFor(
      requestBody: body,
      handoff: expected,
      requestID: "not-a-request-id")
  }
  #expect(throws: NativeAgentLaunchAuthorityHandoffHTTPError.invalidResponse) {
    _ = try launchHandoffConsumer(transport: invalidRequestID)
      .requestLaunchAuthorityHandoff(LaunchHandoffFixture.request)
  }

  let changedAgent = try launchHandoff(
    agentID: "77777777-7777-4777-8777-777777777777")
  let audienceMismatch = LaunchHandoffHTTPTransport { body in
    try responseFor(requestBody: body, handoff: changedAgent)
  }
  #expect(throws: NativeAgentLaunchAuthorityHandoffHTTPError.unauthorized) {
    _ = try launchHandoffConsumer(transport: audienceMismatch)
      .requestLaunchAuthorityHandoff(LaunchHandoffFixture.request)
  }

  let noncanonical = LaunchHandoffHTTPTransport { body in
    let request = try NativeStrictJSON.object(from: body, maxBytes: 16 * 1024, maxDepth: 8)
    let inner = try NativeStrictJSON.object(from: expected.proof, maxBytes: 4 * 1024, maxDepth: 32)
    let raw = "{\"request_id\":\"\(request["request_id"] as! String)\",\"handoff\":\(String(decoding: try NativeStrictJSON.data(inner), as: UTF8.self))}"
    return .init(statusCode: 200, body: Data(raw.replacingOccurrences(of: "handoff", with: "grant").utf8))
  }
  #expect(throws: NativeAgentLaunchAuthorityHandoffHTTPError.invalidResponse) {
    _ = try launchHandoffConsumer(transport: noncanonical)
      .requestLaunchAuthorityHandoff(LaunchHandoffFixture.request)
  }

  let malformedProof = LaunchHandoffHTTPTransport { body in
    let request = try NativeStrictJSON.object(from: body, maxBytes: 16 * 1024, maxDepth: 8)
    let inner: [String: Any] = [
      "agent_id": LaunchHandoffFixture.agent,
      "agent_kind": "claude-code",
      "proof": "{\"version\":1}",
      "requested_ttl_seconds": 600,
      "schema_version": 1,
    ]
    let response = try NativeStrictJSON.data([
      "grant": inner,
      "request_id": request["request_id"] as! String,
    ])
    return .init(statusCode: 200, body: response)
  }
  #expect(throws: NativeAgentLaunchAuthorityHandoffHTTPError.invalidResponse) {
    _ = try launchHandoffConsumer(transport: malformedProof)
      .requestLaunchAuthorityHandoff(LaunchHandoffFixture.request)
  }
}

@Test("maps Cloud status classes and rejects an invalid successful body")
func launchHandoffConsumerMapsStatusesAndMalformedSuccess() throws {
  for (status, expected) in [
    (400, NativeAgentLaunchAuthorityHandoffHTTPError.invalidRequest),
    (401, .unauthorized), (403, .unauthorized), (404, .unauthorized),
    (409, .conflict), (429, .rateLimited), (500, .unavailable),
  ] {
    let transport = LaunchHandoffHTTPTransport { _ in .init(statusCode: status, body: Data()) }
    #expect(throws: expected) {
      _ = try launchHandoffConsumer(transport: transport)
        .requestLaunchAuthorityHandoff(LaunchHandoffFixture.request)
    }
  }

  let invalidSuccess = LaunchHandoffHTTPTransport { _ in
    .init(statusCode: 200, body: Data("{}".utf8))
  }
  #expect(throws: NativeAgentLaunchAuthorityHandoffHTTPError.invalidResponse) {
    _ = try launchHandoffConsumer(transport: invalidSuccess)
      .requestLaunchAuthorityHandoff(LaunchHandoffFixture.request)
  }
}
