import Foundation

/// The public, non-secret request to prepare one launch authority handoff.
/// The request nonce and request ID are generated inside the consumer and are
/// never exposed through this value.
public struct NativeAgentLaunchAuthorityHandoffRequest: Equatable, Sendable {
  public let sessionID: String
  public let agentID: String
  public let agentKind: AgentPassAgentAdapterKind
  public let requestedTTLSeconds: Int
  public let adapterID: String
  public let adapterVersion: String

  public init(
    sessionID: String,
    agentID: String,
    agentKind: AgentPassAgentAdapterKind,
    requestedTTLSeconds: Int,
    adapterID: String,
    adapterVersion: String
  ) throws {
    guard Self.uuid(sessionID), Self.uuid(agentID), Self.uuid(adapterID),
      agentKind == .claudeCode || agentKind == .cursor,
      (AgentPassAgentBootstrapRequest.minimumSessionTTLSeconds...AgentPassAgentBootstrapRequest.maximumSessionTTLSeconds)
        .contains(requestedTTLSeconds),
      Self.semver(adapterVersion)
    else { throw NativeAgentLaunchAuthorityHandoffHTTPError.invalidRequest }
    self.sessionID = sessionID
    self.agentID = agentID
    self.agentKind = agentKind
    self.requestedTTLSeconds = requestedTTLSeconds
    self.adapterID = adapterID
    self.adapterVersion = adapterVersion
  }

  private static func uuid(_ value: String) -> Bool {
    value.range(
      of: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
      options: .regularExpression) != nil && UUID(uuidString: value)?.uuidString.lowercased() == value
  }

  private static func semver(_ value: String) -> Bool {
    value.range(
      of: "^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$",
      options: .regularExpression) != nil
  }
}

public enum NativeAgentLaunchAuthorityHandoffHTTPError: String, Error, Equatable, Sendable {
  case invalidConfiguration = "invalid_configuration"
  case invalidRequest = "invalid_request"
  case authenticationFailed = "authentication_failed"
  case unauthorized = "unauthorized"
  case conflict = "conflict"
  case rateLimited = "rate_limited"
  case unavailable = "unavailable"
  case invalidResponse = "invalid_response"
}

/// Device-authenticated consumer for the Cloud launch-authority handoff.
///
/// The endpoint is a one-shot atomic boundary. Consequently this consumer
/// never retries an ambiguous response. The returned signed Grant is wrapped
/// as the opaque proof only after the existing strict Grant contract and the
/// request audience are checked; a Lease, capability, nonce, or token is never
/// accepted as a substitute. The handoff remains a memory value for the fixed
/// Host pipe.
public protocol NativeAgentLaunchAuthorityHandoffConsuming: Sendable {
  func requestLaunchAuthorityHandoff(
    _ request: NativeAgentLaunchAuthorityHandoffRequest
  ) throws -> NativeAgentLaunchAuthorityHandoff
}

public final class NativeAgentLaunchAuthorityHandoffHTTPConsumer:
  NativeAgentLaunchAuthorityHandoffConsuming, @unchecked Sendable
{
  public static let maximumRequestBytes = 16 * 1024
  public static let maximumResponseBytes = NativeAgentURLSessionHTTPTransport.maximumResponseBytes

  private let baseURL: URL
  private let organizationID: String
  private let deviceID: String
  private let transport: any NativeAgentHTTPTransporting
  private let signer: any P256MessageSigner
  private let random: any NativeAgentRandomBytesGenerating
  private let wallClock: any NativeAgentWallClock
  private let timeoutSeconds: Int

  public init(
    baseURL: URL,
    organizationID: String,
    deviceID: String,
    transport: any NativeAgentHTTPTransporting,
    signer: any P256MessageSigner,
    random: any NativeAgentRandomBytesGenerating = NativeAgentSystemRandomBytesGenerator(),
    wallClock: any NativeAgentWallClock = NativeAgentSystemWallClock(),
    timeoutSeconds: Int = 10
  ) throws {
    guard Self.validHTTPSOrigin(baseURL), Self.validUUID(organizationID),
      Self.validUUID(deviceID), (1...30).contains(timeoutSeconds)
    else { throw NativeAgentLaunchAuthorityHandoffHTTPError.invalidConfiguration }
    self.baseURL = baseURL
    self.organizationID = organizationID
    self.deviceID = deviceID
    self.transport = transport
    self.signer = signer
    self.random = random
    self.wallClock = wallClock
    self.timeoutSeconds = timeoutSeconds
  }

  public func requestLaunchAuthorityHandoff(
    _ request: NativeAgentLaunchAuthorityHandoffRequest
  ) throws -> NativeAgentLaunchAuthorityHandoff {
    let requestID = UUID().uuidString.lowercased()
    let handoffNonce: Data
    let deviceAuthenticationNonce: Data
    let wall: NativeAgentWallClockValue
    do {
      handoffNonce = try random.randomBytes(count: 32)
      deviceAuthenticationNonce = try random.randomBytes(count: 32)
      wall = try wallClock.sample()
    } catch {
      throw NativeAgentLaunchAuthorityHandoffHTTPError.unavailable
    }
    guard handoffNonce.count == 32, deviceAuthenticationNonce.count == 32 else {
      throw NativeAgentLaunchAuthorityHandoffHTTPError.unavailable
    }

    let body: Data
    do {
      body = try NativeStrictJSON.data([
        "adapter_id": request.adapterID,
        "adapter_version": request.adapterVersion,
        "nonce": Self.base64URL(handoffNonce),
        "request_id": requestID,
        "type": "agentpass.agent-launch-authority-handoff-request",
        "version": 1,
      ])
    } catch {
      throw NativeAgentLaunchAuthorityHandoffHTTPError.invalidRequest
    }
    guard !body.isEmpty, body.count <= Self.maximumRequestBytes else {
      throw NativeAgentLaunchAuthorityHandoffHTTPError.invalidRequest
    }

    let path =
      "/v1/organizations/\(organizationID)/devices/\(deviceID)/agent-sessions/\(request.sessionID)/launch-authority-handoff"
    guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
      url.scheme == "https", url.host == baseURL.host, url.port == baseURL.port,
      url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
      url.path == path
    else { throw NativeAgentLaunchAuthorityHandoffHTTPError.invalidConfiguration }

    let authentication: NativeDeviceAuthenticationHeaders
    do {
      authentication = try nativeDeviceAuthenticationHeaders(
        method: "POST", url: url, body: body, deviceID: deviceID,
        timestampMilliseconds: wall.millisecondsSinceUnixEpoch,
        nonceBytes: deviceAuthenticationNonce, signer: signer)
    } catch {
      throw NativeAgentLaunchAuthorityHandoffHTTPError.authenticationFailed
    }
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
    } catch {
      // The endpoint is atomic and one-use. The caller must reconcile through
      // the authoritative session boundary instead of replaying this POST.
      throw NativeAgentLaunchAuthorityHandoffHTTPError.unavailable
    }
    switch response.statusCode {
    case 200, 201: break
    case 400: throw NativeAgentLaunchAuthorityHandoffHTTPError.invalidRequest
    case 401, 403, 404: throw NativeAgentLaunchAuthorityHandoffHTTPError.unauthorized
    case 409: throw NativeAgentLaunchAuthorityHandoffHTTPError.conflict
    case 429: throw NativeAgentLaunchAuthorityHandoffHTTPError.rateLimited
    default: throw NativeAgentLaunchAuthorityHandoffHTTPError.unavailable
    }
    guard !response.body.isEmpty, response.body.count <= Self.maximumResponseBytes else {
      throw NativeAgentLaunchAuthorityHandoffHTTPError.invalidResponse
    }
    do {
      let wrapper = try NativeStrictJSON.object(
        from: response.body, maxBytes: Self.maximumResponseBytes, maxDepth: 32)
      guard Self.exactKeys(wrapper, ["grant", "request_id"]),
        let requestIDValue = wrapper["request_id"] as? String,
        Self.validUUID(requestIDValue),
        let grantObject = wrapper["grant"] as? [String: Any],
        try NativeStrictJSON.data(wrapper) == response.body
      else { throw NativeAgentLaunchAuthorityHandoffHTTPError.invalidResponse }
      let proof = try NativeStrictJSON.data(grantObject)
      let grant = try NativeAgentGrantLeaseHTTPConsumer.parseGrant(proof)
      guard grant.organizationID == organizationID, grant.deviceID == deviceID,
        grant.agentID == request.agentID,
        grant.agentKind == Self.cloudAgentKind(request.agentKind),
        grant.adapterID == request.adapterID,
        grant.adapterVersion == request.adapterVersion
      else { throw NativeAgentLaunchAuthorityHandoffHTTPError.unauthorized }
      return try NativeAgentLaunchAuthorityHandoff(
        agentID: request.agentID,
        agentKind: request.agentKind,
        requestedTTLSeconds: request.requestedTTLSeconds,
        proof: proof)
    } catch let error as NativeAgentLaunchAuthorityHandoffHTTPError {
      throw error
    } catch {
      throw NativeAgentLaunchAuthorityHandoffHTTPError.invalidResponse
    }
  }

  private static func validHTTPSOrigin(_ value: URL) -> Bool {
    guard let components = URLComponents(url: value, resolvingAgainstBaseURL: false),
      components.scheme == "https", components.host?.isEmpty == false,
      components.user == nil, components.password == nil, components.query == nil,
      components.fragment == nil, components.path.isEmpty || components.path == "/"
    else { return false }
    return true
  }

  private static func validUUID(_ value: String) -> Bool {
    value.range(
      of: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
      options: .regularExpression) != nil && UUID(uuidString: value)?.uuidString.lowercased() == value
  }

  private static func base64URL(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private static func cloudAgentKind(_ value: AgentPassAgentAdapterKind) -> String {
    switch value {
    case .claudeCode: return "claude-code"
    case .cursor: return "cursor"
    case .generic: return "unsupported"
    }
  }

  private static func exactKeys(_ value: [String: Any], _ keys: [String]) -> Bool {
    Set(value.keys) == Set(keys) && value.keys.count == keys.count
  }
}
