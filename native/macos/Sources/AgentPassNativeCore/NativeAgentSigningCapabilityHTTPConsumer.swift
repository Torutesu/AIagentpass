import CryptoKit
import Foundation

public enum NativeAgentSigningCapabilityHTTPError: String, Error, Equatable, Sendable {
    case invalidConfiguration = "invalid_configuration"
    case invalidRequest = "invalid_request"
    case authenticationFailed = "authentication_failed"
    case unauthorized = "unauthorized"
    case replay = "replay"
    case conflict = "conflict"
    case rateLimited = "rate_limited"
    case outcomeUnknown = "outcome_unknown"
    case unavailable = "unavailable"
    case invalidResponse = "invalid_response"
}

/// Device-authenticated client for the Cloud signing-capability endpoint.
/// The response is only a shape-checked envelope; callers must still run the
/// pinned `NativeAgentSigningCapabilityVerifier` before using it as authority.
public final class NativeAgentSigningCapabilityHTTPConsumer: @unchecked Sendable {
    private static let maximumBodyBytes = 8 * 1024
    private static let maximumResponseBytes = 64 * 1024
    private let baseURL: URL
    private let organizationID: String
    private let deviceID: String
    private let sessionID: String
    private let transport: any NativeAgentHTTPTransporting
    private let signer: any P256MessageSigner
    private let random: any NativeAgentRandomBytesGenerating
    private let wallClock: any NativeAgentWallClock
    private let timeoutSeconds: Int

    public init(
        baseURL: URL,
        organizationID: String,
        deviceID: String,
        sessionID: String,
        transport: any NativeAgentHTTPTransporting,
        signer: any P256MessageSigner,
        random: any NativeAgentRandomBytesGenerating = NativeAgentSystemRandomBytesGenerator(),
        wallClock: any NativeAgentWallClock = NativeAgentSystemWallClock(),
        timeoutSeconds: Int = 10
    ) throws {
        guard Self.validHTTPSOrigin(baseURL), Self.validUUID(organizationID),
              Self.validUUID(deviceID), Self.validUUID(sessionID),
              (1...30).contains(timeoutSeconds) else {
            throw NativeAgentSigningCapabilityHTTPError.invalidConfiguration
        }
        self.baseURL = baseURL
        self.organizationID = organizationID.lowercased()
        self.deviceID = deviceID.lowercased()
        self.sessionID = sessionID.lowercased()
        self.transport = transport
        self.signer = signer
        self.random = random
        self.wallClock = wallClock
        self.timeoutSeconds = timeoutSeconds
    }

    public func issue(_ request: NativeAgentSigningCapabilityRequest) throws
        -> NativeAgentSigningCapabilityResponse
    {
        let path = "/v1/organizations/\(organizationID)/devices/\(deviceID)/agent-sessions/\(sessionID)/signing-capabilities"
        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
              url.scheme == "https", url.host == baseURL.host, url.port == baseURL.port,
              url.query == nil, url.fragment == nil else {
            throw NativeAgentSigningCapabilityHTTPError.invalidConfiguration
        }
        let body: Data
        do {
            body = try NativeAgentSigningCapabilityCodec.encodeRequest(request)
        } catch {
            throw NativeAgentSigningCapabilityHTTPError.invalidRequest
        }
        guard body.count <= Self.maximumBodyBytes else {
            throw NativeAgentSigningCapabilityHTTPError.invalidRequest
        }
        let timestamp: Int64
        let nonce: Data
        do {
            timestamp = try wallClock.sample().millisecondsSinceUnixEpoch
            nonce = try random.randomBytes(count: 32)
        } catch {
            throw NativeAgentSigningCapabilityHTTPError.unavailable
        }
        guard nonce.count == 32 else { throw NativeAgentSigningCapabilityHTTPError.unavailable }
        let authentication: NativeDeviceAuthenticationHeaders
        do {
            authentication = try nativeDeviceAuthenticationHeaders(
                method: "POST", url: url, body: body, deviceID: deviceID,
                timestampMilliseconds: timestamp, nonceBytes: nonce, signer: signer)
        } catch {
            throw NativeAgentSigningCapabilityHTTPError.authenticationFailed
        }
        let headers = [
            "Content-Type": "application/json",
            "Accept": "application/json",
            "AgentPass-Device": authentication.deviceID,
            "AgentPass-Timestamp": authentication.timestamp,
            "AgentPass-Nonce": authentication.nonce,
            "AgentPass-Content-SHA256": authentication.contentSHA256,
            "AgentPass-Signature": authentication.signature
        ]
        let response: NativeAgentHTTPResponse
        do {
            response = try transport.send(
                url: url, method: "POST", headers: headers, body: body,
                timeoutSeconds: timeoutSeconds)
        } catch {
            throw NativeAgentSigningCapabilityHTTPError.unavailable
        }
        switch response.statusCode {
        case 200, 201: break
        case 400: throw NativeAgentSigningCapabilityHTTPError.invalidRequest
        case 401, 403, 404: throw NativeAgentSigningCapabilityHTTPError.unauthorized
        case 409: throw NativeAgentSigningCapabilityHTTPError.conflict
        case 429: throw NativeAgentSigningCapabilityHTTPError.rateLimited
        case 503: throw NativeAgentSigningCapabilityHTTPError.unavailable
        default: throw NativeAgentSigningCapabilityHTTPError.unavailable
        }
        guard !response.body.isEmpty, response.body.count <= Self.maximumResponseBytes else {
            throw NativeAgentSigningCapabilityHTTPError.invalidResponse
        }
        return try Self.parseResponse(response.body, expectedRequestID: request.requestID,
                                      organizationID: organizationID, deviceID: deviceID,
                                      sessionID: sessionID)
    }

    private static func parseResponse(
        _ data: Data, expectedRequestID: String, organizationID: String,
        deviceID: String, sessionID: String
    ) throws -> NativeAgentSigningCapabilityResponse {
        do {
            let response = try NativeAgentSigningCapabilityCodec.decodeResponse(data)
            guard response.requestID == expectedRequestID else {
                throw NativeAgentSigningCapabilityHTTPError.invalidResponse
            }
            let envelope = response.capability
            guard envelope.statement.organizationID == organizationID,
                  envelope.statement.deviceID == deviceID,
                  envelope.statement.sessionID == sessionID else {
                throw NativeAgentSigningCapabilityHTTPError.invalidResponse
            }
            return response
        } catch let error as NativeAgentSigningCapabilityHTTPError {
            throw error
        } catch {
            throw NativeAgentSigningCapabilityHTTPError.invalidResponse
        }
    }

    private static func validUUID(_ value: String) -> Bool {
        UUID(uuidString: value)?.uuidString.lowercased() == value.lowercased()
    }

    private static func validHTTPSOrigin(_ value: URL) -> Bool {
        value.scheme == "https" && value.user == nil && value.password == nil
            && (value.path.isEmpty || value.path == "/")
            && value.query == nil && value.fragment == nil
    }
}
