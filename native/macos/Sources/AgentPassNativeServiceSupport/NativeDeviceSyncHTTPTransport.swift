import AgentPassNativeCore
import CoreFoundation
import Foundation
import Security

/// A deliberately small error surface for the device transport.  Values from
/// the request, response body, URL, headers, nonce, signature, or credentials
/// are never attached to an error.  Callers can classify an error, but cannot
/// accidentally log trust-boundary input through this type.
public enum NativeDeviceSyncHTTPTransportError: Error, LocalizedError, Equatable, Sendable {
    case invalidConfiguration
    case invalidRequest
    case authenticationFailed
    case transportFailure
    case redirectRejected
    case unexpectedOrigin
    case unexpectedURL
    case unexpectedStatusCode(Int)
    case unexpectedContentType
    case responseTooLarge
    case malformedResponse
    case unexpectedResponseBody

    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration: return "device_sync_transport_invalid_configuration"
        case .invalidRequest: return "device_sync_transport_invalid_request"
        case .authenticationFailed: return "device_sync_transport_authentication_failed"
        case .transportFailure: return "device_sync_transport_failure"
        case .redirectRejected: return "device_sync_transport_redirect_rejected"
        case .unexpectedOrigin: return "device_sync_transport_unexpected_origin"
        case .unexpectedURL: return "device_sync_transport_unexpected_url"
        case .unexpectedStatusCode: return "device_sync_transport_unexpected_status"
        case .unexpectedContentType: return "device_sync_transport_unexpected_content_type"
        case .responseTooLarge: return "device_sync_transport_response_too_large"
        case .malformedResponse: return "device_sync_transport_malformed_response"
        case .unexpectedResponseBody: return "device_sync_transport_unexpected_response_body"
        }
    }
}

public struct NativeDeviceSyncRefreshPollResponse: Equatable, Sendable {
    /// `nil` is the typed representation of an HTTP 204: no newer generation
    /// was available when the bounded poll completed.
    public let hint: NativeRefreshHint?

    public init(hint: NativeRefreshHint?) {
        self.hint = hint
    }
}

public struct NativeDeviceSyncBundleFetchResponse: Equatable, Sendable {
    /// The canonical, signature-bearing bundle object is retained so the
    /// caller can pass it to the existing ControlBundle verifier.
    public let bundleData: Data
    public let bundle: NativeControlBundleV2Bundle
    public let desiredGeneration: Int64

    public init(bundleData: Data, bundle: NativeControlBundleV2Bundle, desiredGeneration: Int64) {
        self.bundleData = bundleData
        self.bundle = bundle
        self.desiredGeneration = desiredGeneration
    }
}

public struct NativeDeviceSyncAcknowledgementResponse: Equatable, Sendable {
    public let accepted: Bool
    public let duplicate: Bool
    public let observedGeneration: Int64
    public let refreshState: NativeDeviceRefreshState

    public init(accepted: Bool, duplicate: Bool, observedGeneration: Int64, refreshState: NativeDeviceRefreshState) {
        self.accepted = accepted
        self.duplicate = duplicate
        self.observedGeneration = observedGeneration
        self.refreshState = refreshState
    }
}

/// Authenticated, non-retrying transport for the three G4.2 Device API
/// operations.  The transport owns an ephemeral URLSession in production. A
/// supplied session is used as a protocol-class template, which makes custom
/// URLProtocol implementations deterministic in tests while preserving the
/// production session invariants (ephemeral storage, no cookies/cache, one
/// connection per host, and bounded timeouts).
public final class NativeDeviceSyncHTTPTransport: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    public static let maximumPollRequestBytes = NativeRefreshHintCodec.maxBytes
    public static let maximumAcknowledgementBytes = NativeBundleAcknowledgementCodec.maxBytes
    public static let maximumBundleResponseBytes = NativeControlBundleV2Codec.maxBytes
    public static let maximumPollResponseBytes = NativeRefreshHintCodec.maxBytes
    public static let maximumAcknowledgementResponseBytes = NativeBundleAcknowledgementCodec.maxBytes
    public static let requestTimeout: TimeInterval = 35
    public static let resourceTimeout: TimeInterval = 40
    public static let maximumPollWaitMilliseconds = 30_000
    public static let maximumGeneration = Int64(9_007_199_254_740_991)

    private struct Origin: Equatable, Sendable {
        let scheme: String
        let host: String
        let port: Int

        init?(url: URL) {
            guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let scheme = components.scheme?.lowercased(),
                  let host = components.host?.lowercased(),
                  !host.isEmpty else { return nil }
            self.scheme = scheme
            self.host = host
            self.port = components.port ?? (scheme == "https" ? 443 : 80)
        }
    }

    private struct RawResponse: Sendable {
        let statusCode: Int
        let url: URL
        let headers: [String: String]
        let body: Data
    }

    private final class PendingRequest: @unchecked Sendable {
        let expectedURL: URL
        let expectedStatus: Int
        let expectedContentType: String?
        let maximumBytes: Int
        let requiresNoStore: Bool
        let allowNoContent: Bool
        var response: HTTPURLResponse?
        var body = Data()
        var failure: NativeDeviceSyncHTTPTransportError?
        var continuation: CheckedContinuation<RawResponse, Error>?

        init(expectedURL: URL, expectedStatus: Int, expectedContentType: String?, maximumBytes: Int, requiresNoStore: Bool, allowNoContent: Bool) {
            self.expectedURL = expectedURL
            self.expectedStatus = expectedStatus
            self.expectedContentType = expectedContentType
            self.maximumBytes = maximumBytes
            self.requiresNoStore = requiresNoStore
            self.allowNoContent = allowNoContent
        }
    }

    private let baseURL: URL
    private let baseOrigin: Origin
    private let organizationID: String
    private let deviceID: String
    private let signer: any P256MessageSigner
    private let nowMilliseconds: @Sendable () -> Int64
    private let nonceBytes: @Sendable () throws -> Data
    private let stateLock = NSLock()
    private var pending: [Int: PendingRequest] = [:]
    private var session: URLSession!

    public init(
        baseURL: URL,
        organizationID: String,
        deviceID: String,
        signer: any P256MessageSigner,
        session: URLSession? = nil,
        urlProtocolClass: URLProtocol.Type? = nil,
        nowMilliseconds: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1_000) },
        nonceBytes: @escaping @Sendable () throws -> Data = { try nativeDeviceSyncRandomNonce() }
    ) throws {
        guard let normalizedBaseURL = Self.validateBaseURL(baseURL),
              let baseOrigin = Origin(url: normalizedBaseURL),
              let organizationID = Self.normalizeUUID(organizationID),
              let deviceID = Self.normalizeUUID(deviceID) else {
            throw NativeDeviceSyncHTTPTransportError.invalidConfiguration
        }
        self.baseURL = normalizedBaseURL
        self.baseOrigin = baseOrigin
        self.organizationID = organizationID
        self.deviceID = deviceID
        self.signer = signer
        self.nowMilliseconds = nowMilliseconds
        self.nonceBytes = nonceBytes
        super.init()

        let configuration = Self.makeConfiguration(template: session, urlProtocolClass: urlProtocolClass)
        let delegateQueue = OperationQueue()
        delegateQueue.name = "dev.agentpass.device-sync-http"
        delegateQueue.maxConcurrentOperationCount = 1
        self.session = URLSession(configuration: configuration, delegate: self, delegateQueue: delegateQueue)
    }

    deinit {
        session?.invalidateAndCancel()
    }

    /// Implements OpenAPI operation `pollControlRefresh`.
    public func pollControlRefresh(afterGeneration: Int64 = 0, waitMilliseconds: Int = 0) async throws -> NativeDeviceSyncRefreshPollResponse {
        guard (0...Self.maximumGeneration).contains(afterGeneration), (0...Self.maximumPollWaitMilliseconds).contains(waitMilliseconds) else {
            throw NativeDeviceSyncHTTPTransportError.invalidRequest
        }
        let url = try makeURL(
            path: ["organizations", organizationID, "devices", deviceID, "refresh"],
            query: [
                URLQueryItem(name: "after_generation", value: String(afterGeneration)),
                URLQueryItem(name: "wait_ms", value: String(waitMilliseconds))
            ]
        )
        let request = try authenticatedRequest(method: "GET", url: url, body: Data())
        let response = try await perform(
            request,
            expectedStatus: 200,
            expectedContentType: "application/json",
            maximumBytes: Self.maximumPollResponseBytes,
            requiresNoStore: false,
            allowNoContent: true
        )
        if response.statusCode == 204 {
            return NativeDeviceSyncRefreshPollResponse(hint: nil)
        }

        do {
            let object = try NativeStrictJSON.object(from: response.body, maxBytes: Self.maximumPollResponseBytes, maxDepth: 8)
            guard Set(object.keys) == Set(["hint"]), let hintObject = object["hint"] as? [String: Any] else {
                throw NativeDeviceSyncHTTPTransportError.malformedResponse
            }
            let hint = try NativeRefreshHintCodec.decode(try NativeStrictJSON.data(hintObject))
            guard hint.organizationID == organizationID, hint.deviceID == deviceID else {
                throw NativeDeviceSyncHTTPTransportError.malformedResponse
            }
            return NativeDeviceSyncRefreshPollResponse(hint: hint)
        } catch let error as NativeDeviceSyncHTTPTransportError {
            throw error
        } catch {
            throw NativeDeviceSyncHTTPTransportError.malformedResponse
        }
    }

    /// Implements OpenAPI operation `fetchControlBundle`.
    public func fetchControlBundle() async throws -> NativeDeviceSyncBundleFetchResponse {
        let url = try makeURL(path: ["organizations", organizationID, "bundles", deviceID], query: [])
        let request = try authenticatedRequest(method: "GET", url: url, body: Data())
        let response = try await perform(
            request,
            expectedStatus: 200,
            expectedContentType: "application/json",
            maximumBytes: Self.maximumBundleResponseBytes,
            requiresNoStore: true,
            allowNoContent: false
        )

        do {
            let object = try NativeStrictJSON.object(from: response.body, maxBytes: Self.maximumBundleResponseBytes, maxDepth: NativeControlBundleV2Codec.maxDepth)
            guard Set(object.keys) == Set(["bundle", "desired_generation"]),
                  let bundleObject = object["bundle"] as? [String: Any],
                  let desiredGeneration = Self.exactInteger(object["desired_generation"]),
                  desiredGeneration >= 1,
                  desiredGeneration <= Self.maximumGeneration else {
                throw NativeDeviceSyncHTTPTransportError.malformedResponse
            }
            let bundleData = try NativeStrictJSON.data(bundleObject)
            // Parsing is schema validation only. Freshness, signature, audience
            // trust, and monotonic sequence enforcement remain the caller's
            // existing ControlBundle verification boundary.
            let bundle = try NativeControlBundleV2Codec.parse(bundleData, nowMilliseconds: 0, allowExpired: true, allowFuture: true)
            guard bundle.organizationID == organizationID, bundle.deviceID == deviceID,
                  bundle.audience.organizationID == organizationID, bundle.audience.deviceID == deviceID else {
                throw NativeDeviceSyncHTTPTransportError.malformedResponse
            }
            return NativeDeviceSyncBundleFetchResponse(bundleData: bundleData, bundle: bundle, desiredGeneration: desiredGeneration)
        } catch let error as NativeDeviceSyncHTTPTransportError {
            throw error
        } catch {
            throw NativeDeviceSyncHTTPTransportError.malformedResponse
        }
    }

    /// Implements OpenAPI operation `acknowledgeControlBundle`.
    public func acknowledgeControlBundle(_ acknowledgement: NativeBundleAcknowledgement) async throws -> NativeDeviceSyncAcknowledgementResponse {
        guard acknowledgement.organizationID == organizationID, acknowledgement.deviceID == deviceID else {
            throw NativeDeviceSyncHTTPTransportError.invalidRequest
        }
        let body: Data
        do {
            body = try NativeBundleAcknowledgementCodec.canonicalJSON(acknowledgement)
            guard body.count <= Self.maximumAcknowledgementBytes else {
                throw NativeDeviceSyncHTTPTransportError.invalidRequest
            }
            _ = try NativeBundleAcknowledgementCodec.decode(body)
        } catch let error as NativeDeviceSyncHTTPTransportError {
            throw error
        } catch {
            throw NativeDeviceSyncHTTPTransportError.invalidRequest
        }

        let url = try makeURL(path: ["organizations", organizationID, "bundles", deviceID, "acknowledgements"], query: [])
        let request = try authenticatedRequest(method: "POST", url: url, body: body)
        let response = try await perform(
            request,
            expectedStatus: 202,
            expectedContentType: "application/json",
            maximumBytes: Self.maximumAcknowledgementResponseBytes,
            requiresNoStore: false,
            allowNoContent: false
        )

        do {
            let object = try NativeStrictJSON.object(from: response.body, maxBytes: Self.maximumAcknowledgementResponseBytes, maxDepth: 8)
            guard Set(object.keys) == Set(["accepted", "duplicate", "observed_generation", "refresh_state"]),
                  Self.exactBoolean(object["accepted"]) == true,
                  let duplicate = Self.exactBoolean(object["duplicate"]),
                  let observedGeneration = Self.exactInteger(object["observed_generation"]),
                  (1...Self.maximumGeneration).contains(observedGeneration),
                  let refreshStateValue = object["refresh_state"] as? String,
                  let refreshState = NativeDeviceRefreshState(rawValue: refreshStateValue) else {
                throw NativeDeviceSyncHTTPTransportError.malformedResponse
            }
            return NativeDeviceSyncAcknowledgementResponse(
                accepted: true,
                duplicate: duplicate,
                observedGeneration: observedGeneration,
                refreshState: refreshState
            )
        } catch let error as NativeDeviceSyncHTTPTransportError {
            throw error
        } catch {
            throw NativeDeviceSyncHTTPTransportError.malformedResponse
        }
    }

    // Short names make the transport convenient for the native state machine
    // while the OpenAPI operation names above remain the canonical surface.
    public func pollRefresh(afterGeneration: Int64 = 0, waitMilliseconds: Int = 0) async throws -> NativeDeviceSyncRefreshPollResponse {
        try await pollControlRefresh(afterGeneration: afterGeneration, waitMilliseconds: waitMilliseconds)
    }

    public func fetchBundle() async throws -> NativeDeviceSyncBundleFetchResponse {
        try await fetchControlBundle()
    }

    public func submitAcknowledgement(_ acknowledgement: NativeBundleAcknowledgement) async throws -> NativeDeviceSyncAcknowledgementResponse {
        try await acknowledgeControlBundle(acknowledgement)
    }

    // MARK: URLSession delegate and bounded response collection

    private func perform(
        _ request: URLRequest,
        expectedStatus: Int,
        expectedContentType: String?,
        maximumBytes: Int,
        requiresNoStore: Bool,
        allowNoContent: Bool
    ) async throws -> RawResponse {
        guard let session else { throw NativeDeviceSyncHTTPTransportError.transportFailure }
        return try await withCheckedThrowingContinuation { continuation in
            let expectedURL = request.url ?? URL(string: "https://invalid.invalid")!
            let pending = PendingRequest(
                expectedURL: expectedURL,
                expectedStatus: expectedStatus,
                expectedContentType: expectedContentType,
                maximumBytes: maximumBytes,
                requiresNoStore: requiresNoStore,
                allowNoContent: allowNoContent
            )
            pending.continuation = continuation
            let task = session.dataTask(with: request)
            stateLock.lock()
            self.pending[task.taskIdentifier] = pending
            stateLock.unlock()
            // The 204 alternative is checked in didReceive(response); it is
            // carried by the expected status convention and does not permit a
            // response body.
            task.resume()
        }
    }

    public func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        guard let response = response as? HTTPURLResponse else {
            fail(dataTask, with: .unexpectedURL)
            completionHandler(.cancel)
            return
        }
        stateLock.lock()
        let pending = self.pending[dataTask.taskIdentifier]
        stateLock.unlock()
        guard let pending else {
            completionHandler(.cancel)
            return
        }

        if let failure = Self.validateResponse(
            response,
            expectedURL: pending.expectedURL,
            expectedStatus: pending.expectedStatus,
            expectedContentType: pending.expectedContentType,
            maximumBytes: pending.maximumBytes,
            requiresNoStore: pending.requiresNoStore,
            allowNoContent: pending.allowNoContent
        ) {
            fail(dataTask, with: failure)
            completionHandler(.cancel)
            return
        }
        pending.response = response
        completionHandler(.allow)
    }

    public func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        stateLock.lock()
        guard let pending = self.pending[dataTask.taskIdentifier] else {
            stateLock.unlock()
            return
        }
        if pending.response?.statusCode == 204 {
            pending.failure = .unexpectedResponseBody
            stateLock.unlock()
            dataTask.cancel()
            return
        }
        if pending.body.count > pending.maximumBytes - data.count {
            pending.failure = .responseTooLarge
            stateLock.unlock()
            dataTask.cancel()
            return
        }
        pending.body.append(data)
        stateLock.unlock()
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        fail(task, with: .redirectRejected)
        completionHandler(nil)
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        stateLock.lock()
        guard let pending = self.pending.removeValue(forKey: task.taskIdentifier) else {
            stateLock.unlock()
            return
        }
        let failure = pending.failure
        let response = pending.response
        let body = pending.body
        let continuation = pending.continuation
        stateLock.unlock()

        guard let continuation else { return }
        if let failure {
            continuation.resume(throwing: failure)
        } else if error != nil {
            continuation.resume(throwing: NativeDeviceSyncHTTPTransportError.transportFailure)
        } else if let response {
            continuation.resume(returning: RawResponse(
                statusCode: response.statusCode,
                url: response.url ?? pending.expectedURL,
                headers: Self.stringHeaders(response),
                body: body
            ))
        } else {
            continuation.resume(throwing: NativeDeviceSyncHTTPTransportError.unexpectedURL)
        }
    }

    private func fail(_ task: URLSessionTask, with error: NativeDeviceSyncHTTPTransportError) {
        stateLock.lock()
        if let pending = self.pending[task.taskIdentifier], pending.failure == nil {
            pending.failure = error
        }
        stateLock.unlock()
    }

    // MARK: Request construction

    private func authenticatedRequest(method: String, url: URL, body: Data) throws -> URLRequest {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: Self.requestTimeout)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        if method == "POST" {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        do {
            let nonce = try nonceBytes()
            guard nonce.count == 32 else { throw NativeDeviceSyncHTTPTransportError.authenticationFailed }
            let headers = try nativeDeviceAuthenticationHeaders(
                method: method,
                url: url,
                body: body,
                deviceID: deviceID,
                timestampMilliseconds: nowMilliseconds(),
                nonceBytes: nonce,
                signer: signer
            )
            request.setValue(headers.deviceID, forHTTPHeaderField: "AgentPass-Device")
            request.setValue(headers.timestamp, forHTTPHeaderField: "AgentPass-Timestamp")
            request.setValue(headers.nonce, forHTTPHeaderField: "AgentPass-Nonce")
            request.setValue(headers.contentSHA256, forHTTPHeaderField: "AgentPass-Content-SHA256")
            request.setValue(headers.signature, forHTTPHeaderField: "AgentPass-Signature")
            return request
        } catch let error as NativeDeviceSyncHTTPTransportError {
            throw error
        } catch {
            throw NativeDeviceSyncHTTPTransportError.authenticationFailed
        }
    }

    private func makeURL(path: [String], query: [URLQueryItem]) throws -> URL {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw NativeDeviceSyncHTTPTransportError.invalidConfiguration
        }
        var basePath = components.percentEncodedPath
        while basePath.count > 1, basePath.hasSuffix("/") { basePath.removeLast() }
        components.percentEncodedPath = basePath + "/" + path.joined(separator: "/")
        components.queryItems = query.isEmpty ? nil : query
        components.fragment = nil
        guard let url = components.url, let origin = Origin(url: url), origin == baseOrigin,
              url.user == nil, url.password == nil, url.fragment == nil else {
            throw NativeDeviceSyncHTTPTransportError.invalidConfiguration
        }
        return url
    }

    // MARK: Validation and configuration

    private static func validateBaseURL(_ url: URL) -> URL? {
        guard url.isFileURL == false,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              let normalized = components.url,
              Origin(url: normalized) != nil else { return nil }
        return normalized
    }

    private static func normalizeUUID(_ value: String) -> String? {
        guard let uuid = UUID(uuidString: value) else { return nil }
        return uuid.uuidString.lowercased()
    }

    private static func makeConfiguration(template: URLSession?, urlProtocolClass: URLProtocol.Type?) -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        var protocolClasses = template?.configuration.protocolClasses ?? []
        if let urlProtocolClass, !protocolClasses.contains(where: { $0 == urlProtocolClass }) {
            protocolClasses.insert(urlProtocolClass, at: 0)
        }
        configuration.protocolClasses = protocolClasses
        configuration.timeoutIntervalForRequest = Self.requestTimeout
        configuration.timeoutIntervalForResource = Self.resourceTimeout
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpMaximumConnectionsPerHost = 1
        return configuration
    }

    private static func validateResponse(
        _ response: HTTPURLResponse,
        expectedURL: URL,
        expectedStatus: Int,
        expectedContentType: String?,
        maximumBytes: Int,
        requiresNoStore: Bool,
        allowNoContent: Bool
    ) -> NativeDeviceSyncHTTPTransportError? {
        guard let responseURL = response.url else { return .unexpectedURL }
        guard let expectedOrigin = Origin(url: expectedURL), let responseOrigin = Origin(url: responseURL), expectedOrigin == responseOrigin else {
            return .unexpectedOrigin
        }
        guard responseURL.absoluteString == expectedURL.absoluteString else { return .unexpectedURL }
        let isNoContent = response.statusCode == 204
        guard response.statusCode == expectedStatus || (allowNoContent && isNoContent) else {
            return .unexpectedStatusCode(response.statusCode)
        }
        let contentType = header("Content-Type", response: response)
        if isNoContent {
            guard contentType == nil else { return .unexpectedContentType }
        } else if let expectedContentType {
            guard contentType == expectedContentType else { return .unexpectedContentType }
        }
        if requiresNoStore {
            guard header("Cache-Control", response: response) == "no-store" else { return .unexpectedContentType }
        }
        if response.expectedContentLength >= 0, response.expectedContentLength > Int64(maximumBytes) {
            return .responseTooLarge
        }
        return nil
    }

    private static func header(_ name: String, response: HTTPURLResponse) -> String? {
        response.allHeaderFields.first {
            String(describing: $0.key).caseInsensitiveCompare(name) == .orderedSame
        }.flatMap { $0.value as? String }
    }

    private static func stringHeaders(_ response: HTTPURLResponse) -> [String: String] {
        response.allHeaderFields.reduce(into: [String: String]()) { result, entry in
            if let value = entry.value as? String { result[String(describing: entry.key)] = value }
        }
    }

    private static func exactInteger(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite,
              number.doubleValue.rounded() == number.doubleValue,
              number.doubleValue >= 0,
              number.doubleValue <= Double(Self.maximumGeneration) else { return nil }
        return number.int64Value
    }

    private static func exactBoolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }
}

@usableFromInline
internal func nativeDeviceSyncRandomNonce() throws -> Data {
    var data = Data(count: 32)
    let status = data.withUnsafeMutableBytes { buffer -> OSStatus in
        guard let address = buffer.baseAddress else { return errSecParam }
        return SecRandomCopyBytes(kSecRandomDefault, buffer.count, address)
    }
    guard status == errSecSuccess else { throw NativeDeviceSyncHTTPTransportError.authenticationFailed }
    return data
}
