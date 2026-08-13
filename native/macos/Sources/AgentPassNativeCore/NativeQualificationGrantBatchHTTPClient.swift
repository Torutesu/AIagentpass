import CoreFoundation
import CryptoKit
import Foundation

public enum NativeQualificationGrantBatchHTTPError: String, Error, Equatable, Sendable {
  case invalidConfiguration = "invalid_configuration"
  case invalidRequest = "invalid_request"
  case authenticationFailed = "authentication_failed"
  case unauthorized = "unauthorized"
  case conflict = "conflict"
  case rateLimited = "rate_limited"
  case unavailable = "unavailable"
  case invalidResponse = "invalid_response"
}

/// The public candidate identity sent to the Device API. The device-auth
/// nonce is deliberately not part of this document; it is generated for each
/// call and exists only in the signed AgentPass authentication headers.
public struct NativeQualificationGrantBatchClaimRequest: Equatable, Sendable {
  public let candidateSHA256: String
  public let sourceCommit: String
  public let artifactSHA256: String
  public let teamID: String
  public let releaseTrustSHA256: String
  public let candidateCheckpointSHA256: String

  public init(
    candidateSHA256: String,
    sourceCommit: String,
    artifactSHA256: String,
    teamID: String,
    releaseTrustSHA256: String,
    candidateCheckpointSHA256: String
  ) throws {
    guard NativeQualificationGrantBatchHTTPClient.isDigest(candidateSHA256),
      NativeQualificationGrantBatchHTTPClient.isCommit(sourceCommit),
      NativeQualificationGrantBatchHTTPClient.isDigest(artifactSHA256),
      NativeQualificationGrantBatchHTTPClient.isTeamID(teamID),
      NativeQualificationGrantBatchHTTPClient.isDigest(releaseTrustSHA256),
      NativeQualificationGrantBatchHTTPClient.isDigest(candidateCheckpointSHA256)
    else { throw NativeQualificationGrantBatchHTTPError.invalidRequest }
    self.candidateSHA256 = candidateSHA256
    self.sourceCommit = sourceCommit
    self.artifactSHA256 = artifactSHA256
    self.teamID = teamID
    self.releaseTrustSHA256 = releaseTrustSHA256
    self.candidateCheckpointSHA256 = candidateCheckpointSHA256
  }

  public func canonicalJSON() throws -> Data {
    try NativeStrictJSON.data([
      "artifact_sha256": artifactSHA256,
      "candidate_checkpoint_sha256": candidateCheckpointSHA256,
      "candidate_sha256": candidateSHA256,
      "release_trust_sha256": releaseTrustSHA256,
      "schema_version": 1,
      "source_commit": sourceCommit,
      "team_id": teamID,
    ])
  }
}

/// One verified step. Only the canonical existing agent-session-grant-v1
/// bytes are retained for the immediate protected relay. Parsed Cloud Grant
/// dictionaries and the full HTTP response are intentionally not retained.
public struct NativeQualificationGrantBatchStep: Sendable {
  public let index: Int
  public let kind: String
  public let scenario: String?
  public let phase: String?
  public let runBinding: String
  public let grantID: String
  public let grantHash: String
  public let statementHash: String
  public let grantCanonicalBytes: Data

  fileprivate init(
    index: Int, kind: String, scenario: String?, phase: String?, runBinding: String,
    grantID: String, grantHash: String, statementHash: String, grantCanonicalBytes: Data
  ) {
    self.index = index
    self.kind = kind
    self.scenario = scenario
    self.phase = phase
    self.runBinding = runBinding
    self.grantID = grantID
    self.grantHash = grantHash
    self.statementHash = statementHash
    self.grantCanonicalBytes = grantCanonicalBytes
  }
}

/// A verified claim result. This type deliberately does not conform to
/// Codable, CustomStringConvertible, or CustomDebugStringConvertible.
/// Authority-bearing material retained by the result is limited to the seven
/// canonical Grant byte strings in `steps`.
public struct NativeQualificationGrantBatchClaim: Sendable {
  public let requestID: String
  public let batchID: String
  public let organizationID: String
  public let deviceID: String
  public let agentID: String
  /// Cloud's value is intentionally preserved (`claude-code` or `cursor`).
  /// Adapter activation maps it later at the protected execution boundary.
  public let agentKind: String
  public let requestedTTLSeconds: Int
  public let candidateSHA256: String
  public let sourceCommit: String
  public let artifactSHA256: String
  public let teamID: String
  public let releaseTrustSHA256: String
  public let candidateCheckpointSHA256: String
  public let expiresAt: String
  public let steps: [NativeQualificationGrantBatchStep]

  fileprivate init(
    requestID: String, batchID: String, organizationID: String, deviceID: String,
    agentID: String, agentKind: String, requestedTTLSeconds: Int,
    candidateSHA256: String, sourceCommit: String, artifactSHA256: String, teamID: String,
    releaseTrustSHA256: String, candidateCheckpointSHA256: String, expiresAt: String,
    steps: [NativeQualificationGrantBatchStep]
  ) {
    self.requestID = requestID
    self.batchID = batchID
    self.organizationID = organizationID
    self.deviceID = deviceID
    self.agentID = agentID
    self.agentKind = agentKind
    self.requestedTTLSeconds = requestedTTLSeconds
    self.candidateSHA256 = candidateSHA256
    self.sourceCommit = sourceCommit
    self.artifactSHA256 = artifactSHA256
    self.teamID = teamID
    self.releaseTrustSHA256 = releaseTrustSHA256
    self.candidateCheckpointSHA256 = candidateCheckpointSHA256
    self.expiresAt = expiresAt
    self.steps = steps
  }
}

/// Native client for the device-authenticated, one-shot qualification claim.
/// The trust key is the Cloud Ed25519 authority used for both the unchanged
/// agent-session-grant-v1 envelopes and the separately signed batch manifest.
public final class NativeQualificationGrantBatchHTTPClient: @unchecked Sendable {
  public static let maximumRequestBytes = 16 * 1024
  public static let maximumResponseBytes = 512 * 1024
  public static let maximumGrantBytes = 32 * 1024
  public static let maximumManifestBytes = 64 * 1024
  public static let maximumBatchTTLSeconds = 3_600

  private static let grantSigningDomain = Data("AgentPass-Agent-Session-Grant-v1\0".utf8)
  // Cross-language protocol constant; keep byte-exact with
  // qualification-grant-batch-manifest.mjs.
  private static let manifestSigningDomain = Data("AgentPass-Qualification-Grant-Batch-v1\0".utf8)
  private static let uuidPattern = try! NSRegularExpression(
    pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
  private static let digestPattern = try! NSRegularExpression(pattern: "^[0-9a-f]{64}$")
  private static let commitPattern = try! NSRegularExpression(pattern: "^[0-9a-f]{40}$")
  private static let teamPattern = try! NSRegularExpression(pattern: "^[A-Z0-9]{10}$")
  private static let safeIdentifierPattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
  private static let semverPattern = try! NSRegularExpression(
    pattern: "^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$")
  private static let timestampPattern = try! NSRegularExpression(
    pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$")
  private static let signaturePattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9_-]{86}$")
  private static let runBindingPattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

  private let baseURL: URL
  private let organizationID: String
  private let deviceID: String
  private let batchID: String
  private let transport: any NativeAgentHTTPTransporting
  private let signer: any P256MessageSigner
  private let trustKey: Curve25519.Signing.PublicKey
  private let expectedGrantKeyID: String?
  private let random: any NativeAgentRandomBytesGenerating
  private let wallClock: any NativeAgentWallClock
  private let timeoutSeconds: Int

  public init(
    baseURL: URL,
    organizationID: String,
    deviceID: String,
    batchID: String,
    transport: any NativeAgentHTTPTransporting,
    signer: any P256MessageSigner,
    trustKey: Curve25519.Signing.PublicKey,
    expectedGrantKeyID: String? = nil,
    random: any NativeAgentRandomBytesGenerating = NativeAgentSystemRandomBytesGenerator(),
    wallClock: any NativeAgentWallClock = NativeAgentSystemWallClock(),
    timeoutSeconds: Int = 10
  ) throws {
    guard Self.validHTTPSOrigin(baseURL), Self.validUUID(organizationID), Self.validUUID(deviceID),
      Self.validUUID(batchID), (1...30).contains(timeoutSeconds),
      expectedGrantKeyID == nil || Self.validSafeIdentifier(expectedGrantKeyID!)
    else { throw NativeQualificationGrantBatchHTTPError.invalidConfiguration }
    self.baseURL = baseURL
    self.organizationID = organizationID
    self.deviceID = deviceID
    self.batchID = batchID
    self.transport = transport
    self.signer = signer
    self.trustKey = trustKey
    self.expectedGrantKeyID = expectedGrantKeyID
    self.random = random
    self.wallClock = wallClock
    self.timeoutSeconds = timeoutSeconds
  }

  public func claim(_ request: NativeQualificationGrantBatchClaimRequest) throws
    -> NativeQualificationGrantBatchClaim
  {
    let body: Data
    do { body = try request.canonicalJSON() } catch { throw NativeQualificationGrantBatchHTTPError.invalidRequest }
    guard !body.isEmpty, body.count <= Self.maximumRequestBytes else {
      throw NativeQualificationGrantBatchHTTPError.invalidRequest
    }
    let url = try claimURL()
    let wall: NativeAgentWallClockValue
    let nonce: Data
    do {
      wall = try wallClock.sample()
      nonce = try random.randomBytes(count: 32)
    } catch { throw NativeQualificationGrantBatchHTTPError.unavailable }
    guard nonce.count == 32 else { throw NativeQualificationGrantBatchHTTPError.unavailable }

    let authentication: NativeDeviceAuthenticationHeaders
    do {
      authentication = try nativeDeviceAuthenticationHeaders(
        method: "POST", url: url, body: body, deviceID: deviceID,
        timestampMilliseconds: wall.millisecondsSinceUnixEpoch, nonceBytes: nonce, signer: signer)
    } catch { throw NativeQualificationGrantBatchHTTPError.authenticationFailed }
    let headers = [
      "Content-Type": "application/json",
      "Accept": "application/json",
      "AgentPass-Device": authentication.deviceID,
      "AgentPass-Timestamp": authentication.timestamp,
      "AgentPass-Nonce": authentication.nonce,
      "AgentPass-Content-SHA256": authentication.contentSHA256,
      "AgentPass-Signature": authentication.signature,
    ]

    let response: NativeAgentHTTPResponse
    do {
      response = try transport.send(
        url: url, method: "POST", headers: headers, body: body, timeoutSeconds: timeoutSeconds)
    } catch { throw NativeQualificationGrantBatchHTTPError.unavailable }
    switch response.statusCode {
    case 200, 201: break
    case 400: throw NativeQualificationGrantBatchHTTPError.invalidRequest
    case 401, 403, 404: throw NativeQualificationGrantBatchHTTPError.unauthorized
    case 409: throw NativeQualificationGrantBatchHTTPError.conflict
    case 429: throw NativeQualificationGrantBatchHTTPError.rateLimited
    default: throw NativeQualificationGrantBatchHTTPError.unavailable
    }
    guard !response.body.isEmpty, response.body.count <= Self.maximumResponseBytes else {
      throw NativeQualificationGrantBatchHTTPError.invalidResponse
    }
    do {
      return try parseResponse(response.body, request: request, nowMilliseconds: wall.millisecondsSinceUnixEpoch)
    } catch let error as NativeQualificationGrantBatchHTTPError { throw error }
    catch { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
  }

  private func claimURL() throws -> URL {
    let path = "/v1/organizations/\(organizationID)/devices/\(deviceID)/qualification-grant-batches/\(batchID)/claim"
    guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
      url.scheme == "https", url.host == baseURL.host, url.port == baseURL.port,
      url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
      url.path == path
    else { throw NativeQualificationGrantBatchHTTPError.invalidConfiguration }
    return url
  }

  private func parseResponse(
    _ data: Data, request: NativeQualificationGrantBatchClaimRequest, nowMilliseconds: Int64
  ) throws -> NativeQualificationGrantBatchClaim {
    let envelope = try NativeStrictJSON.object(
      from: data, maxBytes: Self.maximumResponseBytes, maxDepth: 32)
    guard Self.exactKeys(envelope, ["batch", "manifest", "request_id"]),
      let batch = envelope["batch"] as? [String: Any],
      let manifest = envelope["manifest"] as? [String: Any],
      let requestID = envelope["request_id"] as? String,
      Self.validUUID(requestID)
    else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
    let batchValue = try parseBatch(batch, request: request, nowMilliseconds: nowMilliseconds)
    let manifestValue = try parseManifest(manifest, request: request, batch: batchValue)
    guard manifestValue.steps.count == batchValue.steps.count else {
      throw NativeQualificationGrantBatchHTTPError.invalidResponse
    }
    for (batchStep, manifestStep) in zip(batchValue.steps, manifestValue.steps) {
      guard batchStep.index == manifestStep.index,
        batchStep.kind == manifestStep.kind, batchStep.scenario == manifestStep.scenario,
        batchStep.phase == manifestStep.phase, batchStep.runBinding == manifestStep.runBinding,
        batchStep.grantID == manifestStep.grantID, batchStep.grantHash == manifestStep.grantHash,
        batchStep.statementHash == manifestStep.statementHash
      else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
    }
    return NativeQualificationGrantBatchClaim(
      requestID: requestID, batchID: batchValue.batchID, organizationID: batchValue.organizationID,
      deviceID: batchValue.deviceID, agentID: batchValue.agentID, agentKind: batchValue.agentKind,
      requestedTTLSeconds: batchValue.requestedTTLSeconds, candidateSHA256: batchValue.candidateSHA256,
      sourceCommit: batchValue.sourceCommit, artifactSHA256: batchValue.artifactSHA256,
      teamID: batchValue.teamID, releaseTrustSHA256: batchValue.releaseTrustSHA256,
      candidateCheckpointSHA256: batchValue.candidateCheckpointSHA256, expiresAt: batchValue.expiresAt,
      steps: batchValue.steps)
  }

  private struct ParsedBatch {
    let batchID: String
    let organizationID: String
    let deviceID: String
    let agentID: String
    let agentKind: String
    let requestedTTLSeconds: Int
    let candidateSHA256: String
    let sourceCommit: String
    let artifactSHA256: String
    let teamID: String
    let releaseTrustSHA256: String
    let candidateCheckpointSHA256: String
    let expiresAt: String
    let expiresAtMilliseconds: Int64
    let steps: [NativeQualificationGrantBatchStep]
  }

  private struct ParsedManifest {
    let steps: [NativeQualificationGrantBatchStep]
  }

  private func parseBatch(
    _ value: [String: Any], request: NativeQualificationGrantBatchClaimRequest,
    nowMilliseconds: Int64
  ) throws -> ParsedBatch {
    let keys = [
      "agent_id", "agent_kind", "artifact_sha256", "batch_id", "candidate_checkpoint_sha256",
      "candidate_sha256", "device_id", "expires_at", "kind", "organization_id", "release_trust_sha256",
      "requested_ttl_seconds", "schema_version", "source_commit", "steps", "team_id",
    ]
    guard Self.exactKeys(value, keys), value["schema_version"] as? Int == 1,
      value["kind"] as? String == "agentpass-n3e-qualification-grant-batch",
      let batchID = Self.uuid(value["batch_id"]), batchID == self.batchID,
      let organizationID = Self.uuid(value["organization_id"]), organizationID == self.organizationID,
      let deviceID = Self.uuid(value["device_id"]), deviceID == self.deviceID,
      let agentID = Self.uuid(value["agent_id"]),
      let agentKind = value["agent_kind"] as? String, ["claude-code", "cursor"].contains(agentKind),
      let ttl = Self.safeInt(value["requested_ttl_seconds"]), (60...Self.maximumBatchTTLSeconds).contains(ttl),
      let candidate = Self.digest(value["candidate_sha256"]), candidate == request.candidateSHA256,
      let source = Self.commit(value["source_commit"]), source == request.sourceCommit,
      let artifact = Self.digest(value["artifact_sha256"]), artifact == request.artifactSHA256,
      let team = Self.teamID(value["team_id"]), team == request.teamID,
      let trust = Self.digest(value["release_trust_sha256"]), trust == request.releaseTrustSHA256,
      let checkpoint = Self.digest(value["candidate_checkpoint_sha256"]), checkpoint == request.candidateCheckpointSHA256,
      let expires = Self.timestamp(value["expires_at"]), let expiresMilliseconds = Self.dateMilliseconds(expires),
      expiresMilliseconds > nowMilliseconds,
      expiresMilliseconds <= nowMilliseconds + Int64(Self.maximumBatchTTLSeconds) * 1_000,
      let rawSteps = value["steps"] as? [[String: Any]], rawSteps.count == 7
    else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
    let steps = try rawSteps.enumerated().map { try parseBatchStep($0.offset, value: $0.element, batch: ParsedBatchPlaceholder(
      batchID: batchID, organizationID: organizationID, deviceID: deviceID, agentID: agentID,
      agentKind: agentKind, expiresAt: expires, candidateSHA256: candidate, sourceCommit: source,
      artifactSHA256: artifact, teamID: team, releaseTrustSHA256: trust,
      candidateCheckpointSHA256: checkpoint, expiresAtMilliseconds: expiresMilliseconds), nowMilliseconds: nowMilliseconds) }
    return ParsedBatch(
      batchID: batchID, organizationID: organizationID, deviceID: deviceID, agentID: agentID,
      agentKind: agentKind, requestedTTLSeconds: ttl, candidateSHA256: candidate, sourceCommit: source,
      artifactSHA256: artifact, teamID: team, releaseTrustSHA256: trust,
      candidateCheckpointSHA256: checkpoint, expiresAt: expires, expiresAtMilliseconds: expiresMilliseconds,
      steps: steps)
  }

  private struct ParsedBatchPlaceholder {
    let batchID: String
    let organizationID: String
    let deviceID: String
    let agentID: String
    let agentKind: String
    let expiresAt: String
    let candidateSHA256: String
    let sourceCommit: String
    let artifactSHA256: String
    let teamID: String
    let releaseTrustSHA256: String
    let candidateCheckpointSHA256: String
    let expiresAtMilliseconds: Int64
  }

  private func parseBatchStep(_ index: Int, value: [String: Any], batch: ParsedBatchPlaceholder, nowMilliseconds: Int64) throws -> NativeQualificationGrantBatchStep {
    let identity = Self.stepIdentity(index)
    guard Self.exactKeys(value, ["grant", "index", "kind", "phase", "run_binding", "scenario"]),
      value["index"] as? Int == index, value["kind"] as? String == identity.kind,
      Self.optionalString(value["scenario"]) == identity.scenario,
      Self.optionalString(value["phase"]) == identity.phase,
      let runBinding = value["run_binding"] as? String, Self.validRunBinding(runBinding),
      let grant = value["grant"] as? [String: Any]
    else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
    let parsed = try parseGrant(
      grant, batchID: batch.batchID, organizationID: batch.organizationID, deviceID: batch.deviceID,
      agentID: batch.agentID, agentKind: batch.agentKind, expiresAt: batch.expiresAt,
      runBinding: runBinding, index: index, kind: identity.kind, scenario: identity.scenario,
      phase: identity.phase, nowMilliseconds: nowMilliseconds, expectedGrantID: nil,
      expectedGrantHash: nil, expectedStatementHash: nil)
    return NativeQualificationGrantBatchStep(
      index: index, kind: identity.kind, scenario: identity.scenario, phase: identity.phase,
      runBinding: runBinding, grantID: parsed.grantID, grantHash: parsed.grantHash,
      statementHash: parsed.statementHash, grantCanonicalBytes: parsed.grantCanonicalBytes)
  }

  private func parseManifest(
    _ value: [String: Any], request: NativeQualificationGrantBatchClaimRequest, batch: ParsedBatch
  ) throws -> ParsedManifest {
    let envelopeKeys = ["signature", "statement", "statement_hash", "type", "version"]
    guard Self.exactKeys(value, envelopeKeys), value["version"] as? Int == 1,
      value["type"] as? String == "agentpass.qualification-grant-batch-manifest",
      let statement = value["statement"] as? [String: Any],
      let statementHash = Self.digest(value["statement_hash"]),
      let signatureText = value["signature"] as? String,
      let signature = Self.base64URL(signatureText), signature.count == 64,
      Self.matchesHash(statementHash, data: try NativeStrictJSON.data(statement)),
      trustKey.isValidSignature(signature, for: Self.signedData(domain: Self.manifestSigningDomain, statement: statement))
    else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
    let keys = [
      "artifact_sha256", "batch_id", "candidate_checkpoint_sha256", "candidate_sha256",
      "device_id", "expires_at", "organization_id", "release_trust_sha256", "schema_version",
      "source_commit", "steps", "team_id",
    ]
    guard Self.exactKeys(statement, keys), statement["schema_version"] as? Int == 1,
      Self.uuid(statement["batch_id"]) == batch.batchID,
      Self.uuid(statement["organization_id"]) == batch.organizationID,
      Self.uuid(statement["device_id"]) == batch.deviceID,
      Self.digest(statement["candidate_sha256"]) == request.candidateSHA256,
      Self.commit(statement["source_commit"]) == request.sourceCommit,
      Self.digest(statement["artifact_sha256"]) == request.artifactSHA256,
      Self.teamID(statement["team_id"]) == request.teamID,
      Self.digest(statement["release_trust_sha256"]) == request.releaseTrustSHA256,
      Self.digest(statement["candidate_checkpoint_sha256"]) == request.candidateCheckpointSHA256,
      Self.timestamp(statement["expires_at"]) == batch.expiresAt,
      let rawSteps = statement["steps"] as? [[String: Any]], rawSteps.count == 7
    else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
    var seenGrantIDs = Set<String>()
    var seenGrantHashes = Set<String>()
    var seenStatementHashes = Set<String>()
    var seenSignatures = Set<String>()
    var seenRunBindings = Set<String>()
    let steps = try rawSteps.enumerated().map { position, raw in
      let identity = Self.stepIdentity(position)
      let keys = ["grant_hash", "grant_id", "index", "kind", "phase", "run_binding", "scenario", "statement_hash"]
      guard Self.exactKeys(raw, keys), raw["index"] as? Int == position,
        raw["kind"] as? String == identity.kind, Self.optionalString(raw["scenario"]) == identity.scenario,
        Self.optionalString(raw["phase"]) == identity.phase,
        let runBinding = raw["run_binding"] as? String, Self.validRunBinding(runBinding),
        seenRunBindings.insert(runBinding).inserted,
        let grantID = Self.uuid(raw["grant_id"]), let grantHash = Self.digest(raw["grant_hash"]),
        let statementHash = Self.digest(raw["statement_hash"]), seenGrantIDs.insert(grantID).inserted,
        seenGrantHashes.insert(grantHash).inserted, seenStatementHashes.insert(statementHash).inserted
      else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
      let batchStep = batch.steps[position]
      let grant = try parseGrant(
        batchStep.grantCanonicalBytes, batchID: batch.batchID, organizationID: batch.organizationID,
        deviceID: batch.deviceID, agentID: batch.agentID, agentKind: batch.agentKind,
        expiresAt: batch.expiresAt, runBinding: runBinding, index: position, kind: identity.kind,
        scenario: identity.scenario, phase: identity.phase, nowMilliseconds: batch.expiresAtMilliseconds - 1,
        expectedGrantID: grantID, expectedGrantHash: grantHash, expectedStatementHash: statementHash)
      guard grant.grantID == grantID, grant.grantHash == grantHash,
        grant.statementHash == statementHash, batchStep.runBinding == runBinding,
        seenSignatures.insert(grant.signature).inserted
      else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
      return NativeQualificationGrantBatchStep(
        index: position, kind: identity.kind, scenario: identity.scenario, phase: identity.phase,
        runBinding: runBinding, grantID: grantID, grantHash: grantHash,
        statementHash: statementHash, grantCanonicalBytes: grant.grantCanonicalBytes)
    }
    return ParsedManifest(steps: steps)
  }

  private struct ParsedGrant {
    let grantID: String
    let grantHash: String
    let statementHash: String
    let signature: String
    let grantCanonicalBytes: Data
  }

  private func parseGrant(
    _ value: [String: Any], batchID: String, organizationID: String, deviceID: String,
    agentID: String, agentKind: String, expiresAt: String, runBinding: String, index: Int,
    kind: String, scenario: String?, phase: String?, nowMilliseconds: Int64,
    expectedGrantID: String?, expectedGrantHash: String?, expectedStatementHash: String?
  ) throws -> ParsedGrant {
    let grantBytes = try NativeStrictJSON.data(value)
    return try parseGrant(
      grantBytes, batchID: batchID, organizationID: organizationID, deviceID: deviceID,
      agentID: agentID, agentKind: agentKind, expiresAt: expiresAt, runBinding: runBinding,
      index: index, kind: kind, scenario: scenario, phase: phase, nowMilliseconds: nowMilliseconds,
      expectedGrantID: expectedGrantID, expectedGrantHash: expectedGrantHash,
      expectedStatementHash: expectedStatementHash)
  }

  private func parseGrant(
    _ data: Data, batchID: String, organizationID: String, deviceID: String, agentID: String,
    agentKind: String, expiresAt: String, runBinding: String, index: Int, kind: String,
    scenario: String?, phase: String?, nowMilliseconds: Int64, expectedGrantID: String?,
    expectedGrantHash: String?, expectedStatementHash: String?
  ) throws -> ParsedGrant {
    guard data.count > 0, data.count <= Self.maximumGrantBytes else {
      throw NativeQualificationGrantBatchHTTPError.invalidResponse
    }
    let value = try NativeStrictJSON.object(from: data, maxBytes: Self.maximumGrantBytes, maxDepth: 32)
    guard Self.exactKeys(value, ["signature", "statement", "statement_hash", "type", "version"]),
      value["version"] as? Int == 1, value["type"] as? String == "agentpass.agent-session-grant",
      let statement = value["statement"] as? [String: Any], Self.exactKeys(statement, [
        "adapter_id", "adapter_version", "agent_id", "agent_kind", "authority_generation",
        "control_sequence", "device_id", "expires_at", "grant_id", "issuer", "key_id",
        "max_signatures", "not_before", "organization_id", "process_binding_policy_id", "scope",
        "version", "worktree_binding_sha256",
      ]), statement["version"] as? Int == 1,
      let grantID = Self.uuid(statement["grant_id"]), expectedGrantID == nil || grantID == expectedGrantID,
      Self.uuid(statement["organization_id"]) == organizationID, Self.uuid(statement["device_id"]) == deviceID,
      Self.uuid(statement["agent_id"]) == agentID, statement["agent_kind"] as? String == agentKind,
      Self.uuid(statement["adapter_id"]) != nil,
      Self.validSemver(statement["adapter_version"] as? String),
      Self.digest(statement["worktree_binding_sha256"]) != nil,
      Self.validSafeIdentifier(statement["process_binding_policy_id"] as? String),
      let maxSignatures = Self.safeInt(statement["max_signatures"]), (1...64).contains(maxSignatures),
      let notBefore = Self.timestamp(statement["not_before"]),
      Self.timestamp(statement["expires_at"]) == expiresAt,
      let notBeforeMilliseconds = Self.dateMilliseconds(notBefore),
      let statementExpiresMilliseconds = Self.dateMilliseconds(expiresAt),
      notBeforeMilliseconds < statementExpiresMilliseconds, notBeforeMilliseconds <= nowMilliseconds,
      statementExpiresMilliseconds > nowMilliseconds,
      let controlSequence = Self.positiveSafeInt(statement["control_sequence"]), controlSequence > 0,
      let authorityGeneration = Self.positiveSafeInt(statement["authority_generation"]), authorityGeneration > 0,
      statement["issuer"] as? String == "agentpass-cloud",
      let keyID = statement["key_id"] as? String, Self.validSafeIdentifier(keyID),
      expectedGrantKeyID == nil || keyID == expectedGrantKeyID,
      Self.validScope(statement["scope"] as? [String: Any]),
      let statementHash = Self.digest(value["statement_hash"]),
      Self.matchesHash(statementHash, data: try NativeStrictJSON.data(statement)),
      let signatureText = value["signature"] as? String, Self.validSignature(signatureText),
      let signature = Self.base64URL(signatureText), signature.count == 64,
      trustKey.isValidSignature(signature, for: Self.signedData(domain: Self.grantSigningDomain, statement: statement))
    else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
    let grantHash = Self.sha256Hex(data)
    guard expectedGrantHash == nil || grantHash == expectedGrantHash,
      expectedStatementHash == nil || statementHash == expectedStatementHash
    else { throw NativeQualificationGrantBatchHTTPError.invalidResponse }
    _ = batchID; _ = runBinding; _ = index; _ = kind; _ = scenario; _ = phase
    return ParsedGrant(
      grantID: grantID, grantHash: grantHash, statementHash: statementHash,
      signature: signatureText, grantCanonicalBytes: data)
  }

  private static func stepIdentity(_ index: Int) -> (kind: String, scenario: String?, phase: String?) {
    switch index {
    case 0: return ("unarmed-control", nil, nil)
    case 1: return ("scenario", "pre-cloud-kill", "pre-cloud")
    case 2: return ("scenario", "post-cloud-pre-local-kill", "post-cloud-pre-local")
    case 3: return ("scenario", "post-activation-pre-audit-kill", "post-activation-pre-audit")
    case 4: return ("scenario", "post-audit-pre-reply-loss", "post-audit-pre-reply")
    case 5: return ("scenario", "audit-fsync-failure", "audit-fsync")
    case 6: return ("scenario", "transport-reply-loss", "transport-reply")
    default: return ("", nil, nil)
    }
  }

  private static func validScope(_ value: [String: Any]?) -> Bool {
    guard let value, exactKeys(value, ["branches", "operations", "remotes", "repositories", "tags"], allowMissing: ["tags"]),
      let operations = value["operations"] as? [Any], !operations.isEmpty,
      operations.allSatisfy({ $0 as? String == "git.commit.sign" }),
      let repositories = value["repositories"] as? [Any], !repositories.isEmpty,
      repositories.allSatisfy({ item in guard let text = item as? String else { return false }; return text.hasPrefix("/") && text.utf8.count <= 4096 }),
      validPatternSet(value["branches"] as? [String: Any]), validPatternSet(value["remotes"] as? [String: Any])
    else { return false }
    if let tags = value["tags"] as? [String: Any] { return validPatternSet(tags) }
    return value["tags"] == nil
  }

  private static func validPatternSet(_ value: [String: Any]?) -> Bool {
    guard let value, exactKeys(value, ["allow", "deny"]), let allow = value["allow"] as? [Any],
      let deny = value["deny"] as? [Any], allow.count <= 64, deny.count <= 64 else { return false }
    let values = allow + deny
    guard values.allSatisfy({ item in guard let text = item as? String else { return false }; return !text.isEmpty && text.utf8.count <= 2048 }),
      Set(values.compactMap { $0 as? String }).count == values.count else { return false }
    return true
  }

  private static func exactKeys(_ value: [String: Any], _ expected: [String], allowMissing: [String] = []) -> Bool {
    let allowed = Set(expected)
    let required = allowed.subtracting(allowMissing)
    let actual = Set(value.keys)
    return actual.isSubset(of: allowed) && required.isSubset(of: actual) && actual.count == value.keys.count
  }

  private static func optionalString(_ value: Any?) -> String? { value as? String }
  private static func validHTTPSOrigin(_ url: URL) -> Bool {
    url.scheme == "https" && url.host != nil && url.user == nil && url.password == nil
      && (url.path.isEmpty || url.path == "/") && url.query == nil && url.fragment == nil
  }
  private static func validUUID(_ value: String) -> Bool { uuid(value) != nil }
  private static func uuid(_ value: Any?) -> String? {
    guard let value = value as? String, value.utf8.count == 36, UUID(uuidString: value) != nil,
      matches(uuidPattern, value) else { return nil }
    return value
  }
  fileprivate static func isDigest(_ value: String) -> Bool { digest(value) != nil }
  private static func digest(_ value: Any?) -> String? { guard let value = value as? String, matches(digestPattern, value) else { return nil }; return value }
  fileprivate static func isCommit(_ value: String) -> Bool { commit(value) != nil }
  private static func commit(_ value: Any?) -> String? { guard let value = value as? String, matches(commitPattern, value) else { return nil }; return value }
  fileprivate static func isTeamID(_ value: String) -> Bool { teamID(value) != nil }
  private static func teamID(_ value: Any?) -> String? { guard let value = value as? String, matches(teamPattern, value) else { return nil }; return value }
  private static func validSafeIdentifier(_ value: String?) -> Bool { value.map { matches(safeIdentifierPattern, $0) } ?? false }
  private static func validSemver(_ value: String?) -> Bool { value.map { matches(semverPattern, $0) } ?? false }
  private static func validTimestamp(_ value: String?) -> Bool { timestamp(value) != nil }
  private static func timestamp(_ value: Any?) -> String? {
    guard let value = value as? String, matches(timestampPattern, value), let milliseconds = dateMilliseconds(value),
      Date(timeIntervalSince1970: TimeInterval(milliseconds) / 1_000).timeIntervalSince1970 * 1_000 == Double(milliseconds) else { return nil }
    return value
  }
  private static func dateMilliseconds(_ value: String) -> Int64? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    let parsed = formatter.date(from: value)?.timeIntervalSince1970 ?? .nan
    guard parsed.isFinite else { return nil }
    let milliseconds = parsed * 1_000
    guard milliseconds.rounded() == milliseconds, milliseconds >= 0, milliseconds <= Double(Int64.max) else { return nil }
    return Int64(milliseconds)
  }
  private static func safeInt(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
      number.doubleValue.rounded() == number.doubleValue, number.doubleValue >= 0,
      number.doubleValue <= 9_007_199_254_740_991 else { return nil }
    return number.intValue
  }
  private static func positiveSafeInt(_ value: Any?) -> Int64? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
      number.doubleValue.rounded() == number.doubleValue, number.doubleValue >= 1,
      number.doubleValue <= 9_007_199_254_740_991 else { return nil }
    return number.int64Value
  }
  private static func validRunBinding(_ value: String) -> Bool { value.utf8.count <= 128 && matches(runBindingPattern, value) }
  private static func validSignature(_ value: String) -> Bool { matches(signaturePattern, value) && base64URL(value)?.count == 64 }
  private static func base64URL(_ value: String) -> Data? {
    guard value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil,
      !value.contains("=") else { return nil }
    let remainder = value.count % 4
    let padded = value + String(repeating: "=", count: remainder == 0 ? 0 : 4 - remainder)
    let standard = padded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    guard let data = Data(base64Encoded: standard),
      data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == value else { return nil }
    return data
  }
  private static func matches(_ expression: NSRegularExpression, _ value: String) -> Bool {
    expression.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)) != nil
  }
  private static func sha256Hex(_ data: Data) -> String { Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined() }
  private static func matchesHash(_ expected: String, data: Data) -> Bool { expected == sha256Hex(data) }
  private static func signedData(domain: Data, statement: [String: Any]) -> Data {
    var result = domain
    result.append((try? NativeStrictJSON.data(statement)) ?? Data())
    return result
  }
}
