import CryptoKit
import Foundation

public enum NativeAgentGrantLeaseHTTPError: String, Error, Equatable, Sendable {
  case invalidConfiguration = "invalid_configuration"
  case invalidGrant = "invalid_grant"
  case invalidRequest = "invalid_request"
  case authenticationFailed = "authentication_failed"
  case unauthorized = "unauthorized"
  case conflict = "conflict"
  case rateLimited = "rate_limited"
  case unavailable = "unavailable"
  case invalidResponse = "invalid_response"
}

public struct NativeAgentHTTPResponse: Equatable, Sendable {
  public let statusCode: Int
  public let body: Data
  public init(statusCode: Int, body: Data) {
    self.statusCode = statusCode
    self.body = body
  }
}

public protocol NativeAgentHTTPTransporting: Sendable {
  func send(url: URL, method: String, headers: [String: String], body: Data, timeoutSeconds: Int)
    throws -> NativeAgentHTTPResponse
}

private final class NativeAgentHTTPResultBox: @unchecked Sendable {
  private let lock = NSLock()
  private var value: Result<NativeAgentHTTPResponse, NativeAgentGrantLeaseHTTPError>?

  func store(_ value: Result<NativeAgentHTTPResponse, NativeAgentGrantLeaseHTTPError>) {
    lock.withLock { self.value = value }
  }

  func load() -> Result<NativeAgentHTTPResponse, NativeAgentGrantLeaseHTTPError>? {
    lock.withLock { value }
  }
}

/// Synchronous URLSession transport for the privileged service worker queue.
/// Redirects and non-server-trust authentication challenges are rejected.
/// The coordinator must never invoke it on an XPC callback thread that is
/// required for progress.
public final class NativeAgentURLSessionHTTPTransport: NSObject, NativeAgentHTTPTransporting,
  URLSessionTaskDelegate, @unchecked Sendable
{
  public static let maximumResponseBytes = 64 * 1024

  public func send(
    url: URL, method: String, headers: [String: String], body: Data, timeoutSeconds: Int
  ) throws -> NativeAgentHTTPResponse {
    guard url.scheme == "https", url.user == nil, url.password == nil, url.fragment == nil,
      method == "POST", (1...30).contains(timeoutSeconds)
    else { throw NativeAgentGrantLeaseHTTPError.invalidConfiguration }
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpShouldSetCookies = false
    configuration.httpCookieAcceptPolicy = .never
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    defer { session.finishTasksAndInvalidate() }
    var request = URLRequest(
      url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
      timeoutInterval: TimeInterval(timeoutSeconds))
    request.httpMethod = method
    request.httpBody = body
    for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
    let semaphore = DispatchSemaphore(value: 0)
    let result = NativeAgentHTTPResultBox()
    let task = session.dataTask(with: request) { data, response, error in
      let value: Result<NativeAgentHTTPResponse, NativeAgentGrantLeaseHTTPError>
      if error != nil {
        value = .failure(NativeAgentGrantLeaseHTTPError.unavailable)
      } else if let http = response as? HTTPURLResponse, let data,
        data.count <= Self.maximumResponseBytes
      {
        value = .success(NativeAgentHTTPResponse(statusCode: http.statusCode, body: data))
      } else {
        value = .failure(NativeAgentGrantLeaseHTTPError.invalidResponse)
      }
      result.store(value)
      semaphore.signal()
    }
    task.resume()
    guard semaphore.wait(timeout: .now() + .seconds(timeoutSeconds + 1)) == .success else {
      task.cancel()
      throw NativeAgentGrantLeaseHTTPError.unavailable
    }
    guard let completed = result.load() else { throw NativeAgentGrantLeaseHTTPError.unavailable }
    return try completed.get()
  }

  public func urlSession(
    _ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) { completionHandler(nil) }

  public func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
      completionHandler(.performDefaultHandling, nil)
    } else {
      completionHandler(.cancelAuthenticationChallenge, nil)
    }
  }
}

public final class NativeAgentGrantLeaseHTTPConsumer: NativeAgentGrantLeaseConsuming,
  @unchecked Sendable
{
  static let maximumGrantBytes = NativeAgentGrantConsumptionRequest.maximumProofBytes
  private static let maximumBodyBytes = 16 * 1024
  private let baseURL: URL
  private let organizationID: String
  private let transport: any NativeAgentHTTPTransporting
  private let signer: any P256MessageSigner
  private let random: any NativeAgentRandomBytesGenerating
  private let wallClock: any NativeAgentWallClock
  private let timeoutSeconds: Int

  public init(
    baseURL: URL, organizationID: String, transport: any NativeAgentHTTPTransporting,
    signer: any P256MessageSigner,
    random: any NativeAgentRandomBytesGenerating = NativeAgentSystemRandomBytesGenerator(),
    wallClock: any NativeAgentWallClock = NativeAgentSystemWallClock(), timeoutSeconds: Int = 10
  ) throws {
    guard baseURL.scheme == "https", baseURL.user == nil, baseURL.password == nil,
      baseURL.query == nil, baseURL.fragment == nil, (1...30).contains(timeoutSeconds),
      let organizationID = Self.uuid(organizationID)
    else { throw NativeAgentGrantLeaseHTTPError.invalidConfiguration }
    self.baseURL = baseURL
    self.organizationID = organizationID
    self.transport = transport
    self.signer = signer
    self.random = random
    self.wallClock = wallClock
    self.timeoutSeconds = timeoutSeconds
  }

  public func consumeGrant(_ request: NativeAgentGrantConsumptionRequest) throws
    -> NativeAgentVerifiedCloudLease
  {
    let grant = try Self.parseGrant(request.proof)
    guard grant.organizationID == organizationID,
      grant.deviceID == request.binding.deviceID, grant.agentID == request.binding.agentID,
      grant.worktreeBindingSHA256 == Self.hex(request.binding.worktreeBindingDigest),
      grant.controlSequence == request.binding.controlSequence,
      grant.authorityGeneration == request.binding.authorityGeneration
    else { throw NativeAgentGrantLeaseHTTPError.unauthorized }
    let path =
      "/v1/organizations/\(grant.organizationID)/devices/\(grant.deviceID)/agent-session-grants/\(grant.grantID)/consume"
    guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
      url.host == baseURL.host, url.port == baseURL.port, url.scheme == "https", url.query == nil
    else { throw NativeAgentGrantLeaseHTTPError.invalidConfiguration }
    let bodyObject: [String: Any] = [
      "grant": grant.object,
      "process_binding_sha256": Self.hex(request.binding.processBindingDigest),
      "ancestry_binding_sha256": Self.hex(request.binding.ancestryBindingDigest),
    ]
    let body = try NativeStrictJSON.data(bodyObject)
    guard body.count <= Self.maximumBodyBytes else {
      throw NativeAgentGrantLeaseHTTPError.invalidRequest
    }
    let wall: NativeAgentWallClockValue
    let nonce: Data
    do {
      wall = try wallClock.sample()
      nonce = try random.randomBytes(count: 32)
    } catch { throw NativeAgentGrantLeaseHTTPError.unavailable }
    guard nonce.count == 32 else { throw NativeAgentGrantLeaseHTTPError.unavailable }
    let authentication: NativeDeviceAuthenticationHeaders
    do {
      authentication = try nativeDeviceAuthenticationHeaders(
        method: "POST", url: url, body: body, deviceID: grant.deviceID,
        timestampMilliseconds: wall.millisecondsSinceUnixEpoch, nonceBytes: nonce, signer: signer)
    } catch { throw NativeAgentGrantLeaseHTTPError.authenticationFailed }
    let headers = [
      "Content-Type": "application/json", "Accept": "application/json",
      "AgentPass-Device": authentication.deviceID,
      "AgentPass-Timestamp": authentication.timestamp, "AgentPass-Nonce": authentication.nonce,
      "AgentPass-Content-SHA256": authentication.contentSHA256,
      "AgentPass-Signature": authentication.signature,
    ]
    let response: NativeAgentHTTPResponse
    do {
      response = try transport.send(
        url: url, method: "POST", headers: headers, body: body, timeoutSeconds: timeoutSeconds)
    } catch { throw NativeAgentGrantLeaseHTTPError.unavailable }
    switch response.statusCode {
    case 200, 201: break
    case 400: throw NativeAgentGrantLeaseHTTPError.invalidRequest
    case 401, 403, 404: throw NativeAgentGrantLeaseHTTPError.unauthorized
    case 409: throw NativeAgentGrantLeaseHTTPError.conflict
    case 429: throw NativeAgentGrantLeaseHTTPError.rateLimited
    default: throw NativeAgentGrantLeaseHTTPError.unavailable
    }
    guard !response.body.isEmpty,
      response.body.count <= NativeAgentURLSessionHTTPTransport.maximumResponseBytes
    else { throw NativeAgentGrantLeaseHTTPError.invalidResponse }
    do {
      let wrapper = try NativeStrictJSON.object(
        from: response.body, maxBytes: NativeAgentURLSessionHTTPTransport.maximumResponseBytes,
        maxDepth: 12)
      guard Set(wrapper.keys) == ["lease", "request_id"],
        let lease = wrapper["lease"] as? [String: Any],
        let requestID = wrapper["request_id"] as? String, UUID(uuidString: requestID) != nil
      else { throw NativeAgentGrantLeaseHTTPError.invalidResponse }
      return try NativeAgentLeaseCodec.decode(
        NativeStrictJSON.data(lease), expectedBinding: request.binding)
    } catch let error as NativeAgentGrantLeaseHTTPError { throw error } catch {
      throw NativeAgentGrantLeaseHTTPError.invalidResponse
    }
  }

  struct Grant {
    let object: [String: Any]
    let organizationID: String
    let deviceID: String
    let agentID: String
    let agentKind: String
    let adapterID: String
    let adapterVersion: String
    let grantID: String
    let worktreeBindingSHA256: String
    let controlSequence: Int64
    let authorityGeneration: Int64
  }

  private static let grantStatementKeys: Set<String> = [
    "version", "grant_id", "organization_id", "device_id", "agent_id", "agent_kind",
    "adapter_id", "adapter_version", "worktree_binding_sha256", "process_binding_policy_id",
    "scope", "max_signatures", "not_before", "expires_at", "control_sequence",
    "authority_generation", "issuer", "key_id",
  ]

  static func parseGrant(_ data: Data) throws -> Grant {
    guard !data.isEmpty, data.count <= maximumGrantBytes else {
      throw NativeAgentGrantLeaseHTTPError.invalidGrant
    }
    do {
      let object = try NativeStrictJSON.object(
        from: data, maxBytes: maximumGrantBytes, maxDepth: 32)
      guard try NativeStrictJSON.data(object) == data,
        Set(object.keys) == ["version", "type", "statement", "statement_hash", "signature"],
        object["version"] as? Int == 1,
        object["type"] as? String == "agentpass.agent-session-grant",
        let statement = object["statement"] as? [String: Any],
        Set(statement.keys) == grantStatementKeys,
        statement["version"] as? Int == 1,
        let organization = uuid(statement["organization_id"]),
        let device = uuid(statement["device_id"]), let agent = uuid(statement["agent_id"]),
        let agentKind = statement["agent_kind"] as? String,
        ["claude-code", "cursor"].contains(agentKind),
        let adapterID = uuid(statement["adapter_id"]),
        let adapterVersion = statement["adapter_version"] as? String,
        adapterVersion.range(
          of: "^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$",
          options: .regularExpression) != nil,
        let grant = uuid(statement["grant_id"]),
        let worktreeBinding = digest(statement["worktree_binding_sha256"]),
        let controlSequence = positiveSafeInteger(statement["control_sequence"]),
        let authorityGeneration = positiveSafeInteger(statement["authority_generation"]),
        let statementHash = digest(object["statement_hash"]),
        statementHash == sha256Hex(try NativeStrictJSON.data(statement)),
        let signature = object["signature"] as? String,
        signature.range(of: "^[A-Za-z0-9_-]{86}$", options: .regularExpression) != nil
      else { throw NativeAgentGrantLeaseHTTPError.invalidGrant }
      return Grant(
        object: object, organizationID: organization, deviceID: device, agentID: agent,
        agentKind: agentKind, adapterID: adapterID, adapterVersion: adapterVersion,
        grantID: grant, worktreeBindingSHA256: worktreeBinding,
        controlSequence: controlSequence, authorityGeneration: authorityGeneration)
    } catch let error as NativeAgentGrantLeaseHTTPError { throw error } catch {
      throw NativeAgentGrantLeaseHTTPError.invalidGrant
    }
  }
  private static func uuid(_ value: Any?) -> String? {
    guard let value = value as? String, value.utf8.count == 36,
      value.range(
        of: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        options: .regularExpression) != nil,
      UUID(uuidString: value) != nil
    else { return nil }
    return value
  }
  private static func digest(_ value: Any?) -> String? {
    guard let value = value as? String,
      value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    else { return nil }
    return value
  }
  private static func positiveSafeInteger(_ value: Any?) -> Int64? {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID(),
      number.doubleValue.rounded(.towardZero) == number.doubleValue,
      number.doubleValue >= 1, number.doubleValue <= 9_007_199_254_740_991
    else { return nil }
    return number.int64Value
  }
  private static func sha256Hex(_ data: Data) -> String {
    hex(Data(SHA256.hash(data: data)))
  }
  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }
}
