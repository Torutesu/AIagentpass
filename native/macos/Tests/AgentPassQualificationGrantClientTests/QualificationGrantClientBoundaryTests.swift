import CryptoKit
import Darwin
import Foundation
import Testing

@testable import AgentPassQualificationGrantClient

private struct QualificationClientTestFiles {
  let root: URL
  let paths: QualificationGrantClientPaths
  let owner: uid_t

  init() throws {
    owner = getuid()
    let temporaryPath = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().path
    let canonicalTemporaryPath = temporaryPath.hasPrefix("/var/")
      ? "/private\(temporaryPath)" : temporaryPath
    root = URL(fileURLWithPath: canonicalTemporaryPath)
      .appendingPathComponent("agentpass-qualification-client-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o700)], ofItemAtPath: root.path)
    paths = QualificationGrantClientPaths(
      configuration: root.appendingPathComponent("device-client-config.json").path,
      request: root.appendingPathComponent("relay-request.json").path,
      response: root.appendingPathComponent("device-response.json").path
    )
  }

  func write(_ data: Data, at path: String, mode: Int16 = 0o600) throws {
    FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: NSNumber(value: mode)])
    try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: mode)], ofItemAtPath: path)
  }

  func tearDown() { try? FileManager.default.removeItem(at: root) }
}

private let testOrganization = "11111111-1111-4111-8111-111111111111"
private let testDevice = "22222222-2222-4222-8222-222222222222"
private let testBatch = "33333333-3333-4333-8333-333333333333"
private let testAgent = "44444444-4444-4444-8444-444444444444"

private func pretty(_ object: [String: Any]) throws -> Data {
  try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) + Data("\n".utf8)
}

private func configData() throws -> Data {
  let grantKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
  let manifestKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
  return try pretty([
    "agent_session_key_id": "agent-session-2026-08",
    "agent_session_public_key_base64": grantKey,
    "api_origin": "https://api.agentpass.test",
    "batch_id": testBatch,
    "device_id": testDevice,
    "keychain_access_group": "TEAMID1234.dev.agentpass.service-keys",
    "kind": "agentpass-qualification-grant-client-config",
    "manifest_key_id": "qualification-manifest-2026-08",
    "manifest_public_key_base64": manifestKey,
    "organization_id": testOrganization,
    "schema_version": 1,
  ])
}

private func requestObject() -> [String: Any] {
  [
    "agent_id": testAgent,
    "agent_kind": "claude-code",
    "artifact_sha256": String(repeating: "c", count: 64),
    "batch_id": testBatch,
    "candidate_checkpoint_sha256": String(repeating: "e", count: 64),
    "candidate_sha256": String(repeating: "a", count: 64),
    "device_id": testDevice,
    "expires_at": "2026-08-14T10:10:00.000Z",
    "kind": "agentpass-n3e-qualification-relay-claim-request",
    "organization_id": testOrganization,
    "release_trust_sha256": String(repeating: "d", count: 64),
    "request_id": "55555555-5555-4555-8555-555555555555",
    "requested_ttl_seconds": 600,
    "schema_version": 1,
    "source_commit": String(repeating: "b", count: 40),
    "team_id": "TEAMID1234",
  ]
}

@Test("production paths are fixed and never selected from caller input")
func productionPathsAreFixed() {
  #expect(QualificationGrantClientPaths.production.configuration == "/private/var/db/agentpass-qualification/device-client-config.json")
  #expect(QualificationGrantClientPaths.production.request == "/private/var/db/agentpass-qualification/relay-request.json")
  #expect(QualificationGrantClientPaths.production.response == "/private/var/db/agentpass-qualification/device-response.json")
}

@Test("configuration and relay request are closed documents with strict bindings")
func closedConfigurationAndRequestParsing() throws {
  let configuration = try FixedQualificationClientParser.configuration(configData())
  #expect(configuration.organizationID == testOrganization)
  #expect(configuration.deviceID == testDevice)
  #expect(configuration.batchID == testBatch)
  #expect(configuration.keychainAccessGroup == "TEAMID1234.dev.agentpass.service-keys")
  #expect(configuration.expectedGrantKeyID == "agent-session-2026-08")
  #expect(configuration.expectedManifestKeyID == "qualification-manifest-2026-08")
  #expect(configuration.grantPublicKey.rawRepresentation != configuration.manifestPublicKey.rawRepresentation)
  let request = try FixedQualificationClientParser.request(try pretty(requestObject()))
  #expect(request.agentID == testAgent)
  #expect(request.requestedTTLSeconds == 600)
  #expect(try request.claimRequest.candidateSHA256 == String(repeating: "a", count: 64))

  var extra = requestObject()
  extra["request_nonce"] = "forbidden"
  #expect(throws: QualificationGrantClientError.self) {
    try FixedQualificationClientParser.request(try pretty(extra))
  }
  var badKey = try JSONSerialization.jsonObject(with: configData()) as! [String: Any]
  badKey["unexpected"] = true
  #expect(throws: QualificationGrantClientError.self) {
    try FixedQualificationClientParser.configuration(try pretty(badKey))
  }

  var samePurposeKey = try JSONSerialization.jsonObject(with: configData()) as! [String: Any]
  samePurposeKey["manifest_key_id"] = samePurposeKey["agent_session_key_id"]
  #expect(throws: QualificationGrantClientError.self) {
    try FixedQualificationClientParser.configuration(try pretty(samePurposeKey))
  }

  var samePublicKey = try JSONSerialization.jsonObject(with: configData()) as! [String: Any]
  samePublicKey["manifest_public_key_base64"] = samePublicKey["agent_session_public_key_base64"]
  #expect(throws: QualificationGrantClientError.self) {
    try FixedQualificationClientParser.configuration(try pretty(samePublicKey))
  }

  var badAccessGroup = try JSONSerialization.jsonObject(with: configData()) as! [String: Any]
  badAccessGroup["keychain_access_group"] = "EVIL.dev.agentpass.service-keys"
  #expect(throws: QualificationGrantClientError.self) {
    try FixedQualificationClientParser.configuration(try pretty(badAccessGroup))
  }
}

@Test("fixed file boundary rejects symlinks, unsafe modes, and hard links")
func protectedFileReadFailsClosed() throws {
  let files = try QualificationClientTestFiles()
  defer { files.tearDown() }
  let data = try pretty(requestObject())
  try files.write(data, at: files.paths.request)
  #expect(try QualificationGrantClientFileBoundary.read(path: files.paths.request, maximumBytes: 32 * 1024, expectedOwner: files.owner, requireRootOwnedParents: false) == data)

  let unsafe = files.root.appendingPathComponent("unsafe.json").path
  try files.write(data, at: unsafe, mode: 0o644)
  #expect(throws: QualificationGrantClientError.self) {
    try QualificationGrantClientFileBoundary.read(path: unsafe, maximumBytes: 32 * 1024, expectedOwner: files.owner, requireRootOwnedParents: false)
  }

  let link = files.root.appendingPathComponent("link.json").path
  try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: files.paths.request)
  #expect(throws: QualificationGrantClientError.self) {
    try QualificationGrantClientFileBoundary.read(path: link, maximumBytes: 32 * 1024, expectedOwner: files.owner, requireRootOwnedParents: false)
  }

  let hardLink = files.root.appendingPathComponent("hard-link.json").path
  try FileManager.default.linkItem(atPath: files.paths.request, toPath: hardLink)
  #expect(throws: QualificationGrantClientError.self) {
    try QualificationGrantClientFileBoundary.read(path: hardLink, maximumBytes: 32 * 1024, expectedOwner: files.owner, requireRootOwnedParents: false)
  }
}

@Test("response publication is private, durable-bound, and non-overwriting")
func responsePublicationDoesNotOverwrite() throws {
  let files = try QualificationClientTestFiles()
  defer { files.tearDown() }
  let response = Data("{\"batch\":{},\"manifest\":{},\"request_id\":\"55555555-5555-4555-8555-555555555555\"}\n".utf8)
  let result = try QualificationGrantClientFileBoundary.publish(response, path: files.paths.response, expectedOwner: files.owner, requireRootOwnedParents: false)
  #expect(result.responseBytes == response.count)
  #expect(try Data(contentsOf: URL(fileURLWithPath: files.paths.response)) == response)
  let attributes = try FileManager.default.attributesOfItem(atPath: files.paths.response)
  #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
  #expect((attributes[.referenceCount] as? NSNumber)?.intValue == 1)
  #expect(throws: QualificationGrantClientError.self) {
    try QualificationGrantClientFileBoundary.publish(Data("replacement".utf8), path: files.paths.response, expectedOwner: files.owner, requireRootOwnedParents: false)
  }
  #expect(try Data(contentsOf: URL(fileURLWithPath: files.paths.response)) == response)
}

@Test("Cloud response keeps manifest nested inside batch")
func cloudResponseUsesExactTopLevelContract() throws {
  let nested: [String: Any] = [
    "batch": ["manifest": ["type": "agentpass.qualification-grant-batch-manifest"]],
    "request_id": "55555555-5555-4555-8555-555555555555",
  ]
  #expect(try FixedQualificationClientParser.cloudResponseEnvelope(try pretty(nested))["batch"] != nil)

  var wrong = nested
  wrong["manifest"] = ["type": "wrong-top-level-field"]
  #expect(throws: QualificationGrantClientError.self) {
    try FixedQualificationClientParser.cloudResponseEnvelope(try pretty(wrong))
  }
  var missingNested = nested
  missingNested["batch"] = [:]
  #expect(throws: QualificationGrantClientError.self) {
    try FixedQualificationClientParser.cloudResponseEnvelope(try pretty(missingNested))
  }
}
