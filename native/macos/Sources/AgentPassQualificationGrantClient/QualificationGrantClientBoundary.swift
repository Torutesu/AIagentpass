import AgentPassNativeCore
import CryptoKit
import Darwin
import Foundation

/// Stable, non-sensitive failure classes exposed by the fixed executable.
/// The executable never prints an underlying error or a server response.
public enum QualificationGrantClientError: String, Error, Equatable, Sendable {
  case invalidInvocation = "invalid_invocation"
  case unsafeFile = "unsafe_file"
  case invalidConfiguration = "invalid_configuration"
  case invalidRequest = "invalid_request"
  case invalidResponse = "invalid_response"
  case claimFailed = "claim_failed"
  case outputUnavailable = "output_unavailable"
}

/// All production paths are compiled into the client. The internal initializer
/// exists only for filesystem tests and is not used by the executable entrypoint.
public struct QualificationGrantClientPaths: Equatable, Sendable {
  public static let production = QualificationGrantClientPaths(
    configuration: "/private/var/db/agentpass-qualification/device-client-config.json",
    request: "/private/var/db/agentpass-qualification/relay-request.json",
    response: "/private/var/db/agentpass-qualification/device-response.json"
  )

  public let configuration: String
  public let request: String
  public let response: String

  internal init(configuration: String, request: String, response: String) {
    self.configuration = configuration
    self.request = request
    self.response = response
  }
}

public struct QualificationGrantClientRunResult: Equatable, Sendable {
  public let responseSHA256: String
  public let responseBytes: Int

  internal init(responseSHA256: String, responseBytes: Int) {
    self.responseSHA256 = responseSHA256
    self.responseBytes = responseBytes
  }
}

internal struct FixedQualificationClientConfiguration: Sendable {
  let apiOrigin: URL
  let organizationID: String
  let deviceID: String
  let batchID: String
  let keychainAccessGroup: String
  let trustKey: Curve25519.Signing.PublicKey
  let expectedGrantKeyID: String
}

internal struct FixedQualificationRelayRequest: Equatable, Sendable {
  let requestID: String
  let organizationID: String
  let deviceID: String
  let batchID: String
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

  var claimRequest: NativeQualificationGrantBatchClaimRequest {
    get throws {
      try NativeQualificationGrantBatchClaimRequest(
        candidateSHA256: candidateSHA256,
        sourceCommit: sourceCommit,
        artifactSHA256: artifactSHA256,
        teamID: teamID,
        releaseTrustSHA256: releaseTrustSHA256,
        candidateCheckpointSHA256: candidateCheckpointSHA256
      )
    }
  }
}

internal enum FixedQualificationClientParser {
  static let configurationKind = "agentpass-qualification-grant-client-config"
  static let relayRequestKind = "agentpass-n3e-qualification-relay-claim-request"
  static let relayResponseMaximumBytes = 512 * 1024
  static let fileMaximumBytes = 512 * 1024

  private static let uuid = try! NSRegularExpression(
    pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
  )
  private static let digest = try! NSRegularExpression(pattern: "^[0-9a-f]{64}$")
  private static let commit = try! NSRegularExpression(pattern: "^[0-9a-f]{40}$")
  private static let team = try! NSRegularExpression(pattern: "^[A-Z0-9]{10}$")
  private static let safeIdentifier = try! NSRegularExpression(
    pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
  )
  private static let keychainAccessGroup = try! NSRegularExpression(
    pattern: "^[A-Z0-9]{10}\\.dev\\.agentpass\\.service-keys$"
  )
  private static let timestamp = try! NSRegularExpression(
    pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$"
  )

  static func configuration(_ data: Data) throws -> FixedQualificationClientConfiguration {
    let object = try object(data, maximum: 16 * 1024)
    try exactKeys(
      object,
      [
        "api_origin", "batch_id", "device_id", "expected_grant_key_id",
        "keychain_access_group", "kind", "organization_id", "schema_version",
        "trust_public_key_base64"
      ]
    )
    guard object["schema_version"] as? Int == 1,
      object["kind"] as? String == configurationKind,
      let originText = object["api_origin"] as? String,
      let origin = URL(string: originText),
      let organizationID = uuid(object["organization_id"]),
      let deviceID = uuid(object["device_id"]),
      let batchID = uuid(object["batch_id"]),
      let keyID = object["expected_grant_key_id"] as? String,
      validSafeIdentifier(keyID),
      let accessGroup = object["keychain_access_group"] as? String,
      validKeychainAccessGroup(accessGroup),
      let encodedKey = object["trust_public_key_base64"] as? String,
      let rawKey = Data(base64Encoded: encodedKey),
      rawKey.count == 32,
      let trustKey = try? Curve25519.Signing.PublicKey(rawRepresentation: rawKey)
    else { throw QualificationGrantClientError.invalidConfiguration }
    guard let normalizedOrigin = URLComponents(url: origin, resolvingAgainstBaseURL: false),
      normalizedOrigin.scheme == "https",
      normalizedOrigin.host?.isEmpty == false,
      normalizedOrigin.user == nil,
      normalizedOrigin.password == nil,
      normalizedOrigin.query == nil,
      normalizedOrigin.fragment == nil,
      normalizedOrigin.path.isEmpty || normalizedOrigin.path == "/"
    else { throw QualificationGrantClientError.invalidConfiguration }
    return FixedQualificationClientConfiguration(
      apiOrigin: origin,
      organizationID: organizationID,
      deviceID: deviceID,
      batchID: batchID,
      keychainAccessGroup: accessGroup,
      trustKey: trustKey,
      expectedGrantKeyID: keyID
    )
  }

  static func request(_ data: Data) throws -> FixedQualificationRelayRequest {
    let object = try object(data, maximum: 32 * 1024)
    try exactKeys(
      object,
      [
        "agent_id", "agent_kind", "artifact_sha256", "batch_id",
        "candidate_checkpoint_sha256", "candidate_sha256", "device_id", "expires_at",
        "kind", "organization_id", "release_trust_sha256", "request_id",
        "requested_ttl_seconds", "schema_version", "source_commit", "team_id"
      ]
    )
    guard object["schema_version"] as? Int == 1,
      object["kind"] as? String == relayRequestKind,
      let requestID = uuid(object["request_id"]),
      let organizationID = uuid(object["organization_id"]),
      let deviceID = uuid(object["device_id"]),
      let batchID = uuid(object["batch_id"]),
      let agentID = uuid(object["agent_id"]),
      let agentKind = object["agent_kind"] as? String,
      ["claude-code", "cursor"].contains(agentKind),
      let ttl = object["requested_ttl_seconds"] as? Int,
      (60...3_600).contains(ttl),
      let candidate = digest(object["candidate_sha256"]),
      let source = commit(object["source_commit"]),
      let artifact = digest(object["artifact_sha256"]),
      let teamID = team(object["team_id"]),
      let releaseTrust = digest(object["release_trust_sha256"]),
      let checkpoint = digest(object["candidate_checkpoint_sha256"]),
      let expiresAt = timestamp(object["expires_at"])
    else { throw QualificationGrantClientError.invalidRequest }
    return FixedQualificationRelayRequest(
      requestID: requestID,
      organizationID: organizationID,
      deviceID: deviceID,
      batchID: batchID,
      agentID: agentID,
      agentKind: agentKind,
      requestedTTLSeconds: ttl,
      candidateSHA256: candidate,
      sourceCommit: source,
      artifactSHA256: artifact,
      teamID: teamID,
      releaseTrustSHA256: releaseTrust,
      candidateCheckpointSHA256: checkpoint,
      expiresAt: expiresAt
    )
  }

  static func object(_ data: Data, maximum: Int) throws -> [String: Any] {
    guard data.count > 0, data.count <= maximum else {
      throw QualificationGrantClientError.unsafeFile
    }
    let object: [String: Any]
    do {
      object = try NativeStrictJSON.object(from: data, maxBytes: maximum, maxDepth: 32)
    } catch {
      throw QualificationGrantClientError.invalidRequest
    }
    guard object.keys.allSatisfy({ !$0.isEmpty }) else {
      throw QualificationGrantClientError.invalidRequest
    }
    return object
  }

  static func exactKeys(_ object: [String: Any], _ expected: [String]) throws {
    guard Set(object.keys) == Set(expected), object.count == expected.count else {
      throw QualificationGrantClientError.invalidConfiguration
    }
  }

  /// Checks the exact Cloud response envelope. The Core client performs the
  /// full signed Grant and nested manifest verification before this boundary.
  static func cloudResponseEnvelope(_ data: Data) throws -> [String: Any] {
    let object = try object(data, maximum: relayResponseMaximumBytes)
    try exactKeys(object, ["batch", "request_id"])
    guard object["request_id"] as? String != nil,
      let batch = object["batch"] as? [String: Any],
      batch["manifest"] as? [String: Any] != nil
    else { throw QualificationGrantClientError.invalidResponse }
    return object
  }

  static func canonicalPrettyJSON(_ object: [String: Any]) throws -> Data {
    guard JSONSerialization.isValidJSONObject(object) else {
      throw QualificationGrantClientError.invalidResponse
    }
    do {
      return try JSONSerialization.data(
        withJSONObject: object,
        options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
      ) + Data("\n".utf8)
    } catch {
      throw QualificationGrantClientError.invalidResponse
    }
  }

  private static func uuid(_ value: Any?) -> String? { match(value, uuid) }
  private static func digest(_ value: Any?) -> String? { match(value, digest) }
  private static func commit(_ value: Any?) -> String? { match(value, commit) }
  private static func team(_ value: Any?) -> String? { match(value, team) }
  private static func validSafeIdentifier(_ value: String) -> Bool {
    match(value, safeIdentifier) != nil
  }
  private static func validKeychainAccessGroup(_ value: String) -> Bool {
    match(value, keychainAccessGroup) != nil
  }
  private static func timestamp(_ value: Any?) -> String? {
    guard let value = match(value, timestamp), Date.parseQualification(value) != nil else {
      return nil
    }
    return value
  }
  private static func match(_ value: Any?, _ pattern: NSRegularExpression) -> String? {
    guard let value = value as? String else { return nil }
    let range = NSRange(value.startIndex..<value.endIndex, in: value)
    return pattern.firstMatch(in: value, range: range) == nil ? nil : value
  }
}

internal enum QualificationGrantClientFileBoundary {
  static let privateMode: mode_t = 0o600
  static let privateDirectoryMode: mode_t = 0o700

  static func read(
    path: String,
    maximumBytes: Int,
    expectedOwner: uid_t,
    error: QualificationGrantClientError = .unsafeFile,
    requireRootOwnedParents: Bool = true
  ) throws -> Data {
    try verifyParents(
      path: path,
      expectedOwner: expectedOwner,
      requireRootOwnedParents: requireRootOwnedParents
    )
    let descriptor = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw error }
    defer { Darwin.close(descriptor) }
    var before = stat()
    guard fstat(descriptor, &before) == 0,
      (before.st_mode & S_IFMT) == S_IFREG,
      before.st_uid == expectedOwner,
      (before.st_mode & 0o7777) == privateMode,
      before.st_nlink == 1,
      before.st_size > 0,
      before.st_size <= off_t(maximumBytes)
    else { throw error }
    var data = Data(count: Int(before.st_size))
    let count = data.withUnsafeMutableBytes { buffer -> Int in
      guard let base = buffer.baseAddress else { return -1 }
      var offset = 0
      while offset < buffer.count {
        let readCount = Darwin.read(descriptor, base.advanced(by: offset), buffer.count - offset)
        if readCount <= 0 { return -1 }
        offset += readCount
      }
      return offset
    }
    var after = stat()
    var pathState = stat()
    guard count == data.count,
      fstat(descriptor, &after) == 0,
      lstat(path, &pathState) == 0,
      same(before, after),
      before.st_dev == pathState.st_dev,
      before.st_ino == pathState.st_ino
    else { throw error }
    return data
  }

  static func publish(
    _ data: Data,
    path: String,
    expectedOwner: uid_t,
    requireRootOwnedParents: Bool = true
  ) throws -> QualificationGrantClientRunResult {
    guard !data.isEmpty, data.count <= FixedQualificationClientParser.relayResponseMaximumBytes else {
      throw QualificationGrantClientError.outputUnavailable
    }
    try verifyParents(
      path: path,
      expectedOwner: expectedOwner,
      requireRootOwnedParents: requireRootOwnedParents
    )
    let descriptor = Darwin.open(
      path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, privateMode
    )
    guard descriptor >= 0 else { throw QualificationGrantClientError.outputUnavailable }
    var succeeded = false
    defer {
      Darwin.close(descriptor)
      if !succeeded { unlink(path) }
    }
    var opened = stat()
    guard fstat(descriptor, &opened) == 0,
      (opened.st_mode & S_IFMT) == S_IFREG,
      opened.st_uid == expectedOwner,
      opened.st_nlink == 1,
      opened.st_size == 0,
      fchmod(descriptor, privateMode) == 0
    else { throw QualificationGrantClientError.outputUnavailable }
    try writeAll(descriptor: descriptor, data: data)
    guard fsync(descriptor) == 0 else { throw QualificationGrantClientError.outputUnavailable }
    var written = stat()
    guard fstat(descriptor, &written) == 0,
      written.st_uid == expectedOwner,
      (written.st_mode & 0o7777) == privateMode,
      written.st_nlink == 1,
      written.st_size == off_t(data.count)
    else { throw QualificationGrantClientError.outputUnavailable }
    succeeded = true
    let digest = Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
    return QualificationGrantClientRunResult(responseSHA256: digest, responseBytes: data.count)
  }

  private static func verifyParents(
    path: String, expectedOwner: uid_t, requireRootOwnedParents: Bool
  ) throws {
    let url = URL(fileURLWithPath: path)
    let components = path.split(separator: "/", omittingEmptySubsequences: false)
    guard path.hasPrefix("/"), !path.contains("\0"),
      !components.contains(where: { $0 == "." || $0 == ".." })
    else { throw QualificationGrantClientError.unsafeFile }
    var parent = url.deletingLastPathComponent()
    while true {
      var info = stat()
      guard lstat(parent.path, &info) == 0,
        (info.st_mode & S_IFMT) == S_IFDIR,
        (!requireRootOwnedParents || info.st_uid == 0),
        (info.st_mode & 0o022) == 0
      else { throw QualificationGrantClientError.unsafeFile }
      if parent.path == "/" { break }
      parent.deleteLastPathComponent()
    }
  }

  private static func writeAll(descriptor: Int32, data: Data) throws {
    try data.withUnsafeBytes { buffer in
      guard let base = buffer.baseAddress else { throw QualificationGrantClientError.outputUnavailable }
      var offset = 0
      while offset < buffer.count {
        let count = Darwin.write(descriptor, base.advanced(by: offset), buffer.count - offset)
        guard count > 0 else { throw QualificationGrantClientError.outputUnavailable }
        offset += count
      }
    }
  }

  private static func same(_ left: stat, _ right: stat) -> Bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
      left.st_mode == right.st_mode && left.st_nlink == right.st_nlink &&
      left.st_uid == right.st_uid && left.st_size == right.st_size &&
      left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
      left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec &&
      left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec &&
      left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec
  }
}

internal enum QualificationGrantClientResponseBoundary {
  static func canonicalResponse(
    _ data: Data,
    claim: NativeQualificationGrantBatchClaim,
    request: FixedQualificationRelayRequest
  ) throws -> Data {
    let object = try FixedQualificationClientParser.cloudResponseEnvelope(data)
    guard object["request_id"] as? String == claim.requestID,
      let batch = object["batch"] as? [String: Any],
      batch["manifest"] as? [String: Any] != nil
    else { throw QualificationGrantClientError.invalidResponse }
    try FixedQualificationClientParser.exactKeys(
      batch,
      [
        "agent_id", "agent_kind", "artifact_sha256", "batch_id",
        "candidate_checkpoint_sha256", "candidate_sha256", "device_id", "expires_at",
        "kind", "organization_id", "release_trust_sha256", "requested_ttl_seconds",
        "schema_version", "source_commit", "steps", "team_id", "manifest"
      ]
    )
    guard batch["schema_version"] as? Int == 1,
      batch["kind"] as? String == "agentpass-n3e-qualification-grant-batch",
      batch["batch_id"] as? String == claim.batchID,
      batch["organization_id"] as? String == claim.organizationID,
      batch["device_id"] as? String == claim.deviceID,
      batch["agent_id"] as? String == claim.agentID,
      batch["agent_kind"] as? String == claim.agentKind,
      batch["requested_ttl_seconds"] as? Int == claim.requestedTTLSeconds,
      batch["candidate_sha256"] as? String == request.candidateSHA256,
      batch["source_commit"] as? String == request.sourceCommit,
      batch["artifact_sha256"] as? String == request.artifactSHA256,
      batch["team_id"] as? String == request.teamID,
      batch["release_trust_sha256"] as? String == request.releaseTrustSHA256,
      batch["candidate_checkpoint_sha256"] as? String == request.candidateCheckpointSHA256,
      batch["expires_at"] as? String == claim.expiresAt,
      let steps = batch["steps"] as? [[String: Any]], steps.count == claim.steps.count
    else { throw QualificationGrantClientError.invalidResponse }
    for (index, step) in steps.enumerated() {
      let expected = claim.steps[index]
      try FixedQualificationClientParser.exactKeys(
        step, ["grant", "index", "kind", "phase", "run_binding", "scenario"]
      )
      guard step["index"] as? Int == expected.index,
        step["kind"] as? String == expected.kind,
        optionalString(step["scenario"]) == expected.scenario,
        optionalString(step["phase"]) == expected.phase,
        step["run_binding"] as? String == expected.runBinding,
        let grant = step["grant"] as? [String: Any],
        try NativeStrictJSON.data(grant) == expected.grantCanonicalBytes
      else { throw QualificationGrantClientError.invalidResponse }
    }
    return try FixedQualificationClientParser.canonicalPrettyJSON(object)
  }

  private static func optionalString(_ value: Any?) -> String? {
    value is NSNull ? nil : value as? String
  }
}

/// Fixed production composition. The only mutable dependencies are internal
/// test seams; the executable calls the no-argument `runProduction()` path.
public enum FixedQualificationGrantClient {
  public static func runProduction() throws -> QualificationGrantClientRunResult {
    let configurationData = try QualificationGrantClientFileBoundary.read(
      path: QualificationGrantClientPaths.production.configuration,
      maximumBytes: 16 * 1024,
      expectedOwner: 0
    )
    let requestData = try QualificationGrantClientFileBoundary.read(
      path: QualificationGrantClientPaths.production.request,
      maximumBytes: 32 * 1024,
      expectedOwner: 0,
      error: .invalidRequest
    )
    let configuration = try FixedQualificationClientParser.configuration(configurationData)
    let request = try FixedQualificationClientParser.request(requestData)
    try validateBindings(configuration: configuration, request: request)
    let signer = try SecureEnclaveKeyStore.loadExisting(
      applicationTag: NativeEnrollmentKeyMaterial.fixedApplicationTag,
      accessGroup: configuration.keychainAccessGroup
    )
    return try executeLoaded(
      paths: .production,
      expectedOwner: 0,
      transport: NativeAgentURLSessionHTTPTransport(),
      signer: signer,
      configuration: configuration,
      request: request
    )
  }

  internal static func execute(
    paths: QualificationGrantClientPaths,
    expectedOwner: uid_t,
    transport: any NativeAgentHTTPTransporting,
    signer: any P256MessageSigner
  ) throws -> QualificationGrantClientRunResult {
    let configurationData = try QualificationGrantClientFileBoundary.read(
      path: paths.configuration,
      maximumBytes: 16 * 1024,
      expectedOwner: expectedOwner
    )
    let requestData = try QualificationGrantClientFileBoundary.read(
      path: paths.request,
      maximumBytes: 32 * 1024,
      expectedOwner: expectedOwner,
      error: .invalidRequest
    )
    let configuration = try FixedQualificationClientParser.configuration(configurationData)
    let request = try FixedQualificationClientParser.request(requestData)
    try validateBindings(configuration: configuration, request: request)
    return try executeLoaded(
      paths: paths,
      expectedOwner: expectedOwner,
      transport: transport,
      signer: signer,
      configuration: configuration,
      request: request
    )
  }

  private static func executeLoaded(
    paths: QualificationGrantClientPaths,
    expectedOwner: uid_t,
    transport: any NativeAgentHTTPTransporting,
    signer: any P256MessageSigner,
    configuration: FixedQualificationClientConfiguration,
    request: FixedQualificationRelayRequest
  ) throws -> QualificationGrantClientRunResult {
    let claimRequest = try request.claimRequest
    let capture = CapturingQualificationTransport(underlying: transport)
    let client: NativeQualificationGrantBatchHTTPClient
    do {
      client = try NativeQualificationGrantBatchHTTPClient(
        baseURL: configuration.apiOrigin,
        organizationID: configuration.organizationID,
        deviceID: configuration.deviceID,
        batchID: configuration.batchID,
        transport: capture,
        signer: signer,
        trustKey: configuration.trustKey,
        expectedGrantKeyID: configuration.expectedGrantKeyID
      )
    } catch { throw QualificationGrantClientError.invalidConfiguration }
    let claim: NativeQualificationGrantBatchClaim
    do {
      claim = try client.claim(claimRequest)
    } catch { throw QualificationGrantClientError.claimFailed }
    guard claim.organizationID == request.organizationID,
      claim.deviceID == request.deviceID,
      claim.batchID == request.batchID,
      claim.agentID == request.agentID,
      claim.agentKind == request.agentKind,
      claim.requestedTTLSeconds == request.requestedTTLSeconds
    else { throw QualificationGrantClientError.invalidResponse }
    guard let rawResponse = capture.responseBody else {
      throw QualificationGrantClientError.invalidResponse
    }
    let canonicalResponse = try QualificationGrantClientResponseBoundary.canonicalResponse(
      rawResponse, claim: claim, request: request
    )
    return try QualificationGrantClientFileBoundary.publish(
      canonicalResponse, path: paths.response, expectedOwner: expectedOwner
    )
  }

  private static func validateBindings(
    configuration: FixedQualificationClientConfiguration,
    request: FixedQualificationRelayRequest
  ) throws {
    guard configuration.organizationID == request.organizationID,
      configuration.deviceID == request.deviceID,
      configuration.batchID == request.batchID,
      configuration.keychainAccessGroup == "\(request.teamID).dev.agentpass.service-keys"
    else { throw QualificationGrantClientError.invalidRequest }
  }
}

private final class CapturingQualificationTransport: NativeAgentHTTPTransporting, @unchecked Sendable {
  private let lock = NSLock()
  private let underlying: any NativeAgentHTTPTransporting
  private var body: Data?

  init(underlying: any NativeAgentHTTPTransporting) { self.underlying = underlying }

  var responseBody: Data? { lock.withLock { body } }

  func send(
    url: URL, method: String, headers: [String: String], body: Data, timeoutSeconds: Int
  ) throws -> NativeAgentHTTPResponse {
    let response = try underlying.send(
      url: url, method: method, headers: headers, body: body, timeoutSeconds: timeoutSeconds
    )
    lock.withLock { self.body = response.body }
    return response
  }
}

private extension Date {
  static func parseQualification(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: value)
  }
}
