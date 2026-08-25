import AgentPassNativeCore
import AgentPassNativeServiceSupport
import CryptoKit
import Foundation
import Testing

private let transportOrganizationID = "11111111-1111-4111-8111-111111111111"
private let transportDeviceID = "22222222-2222-4222-8222-222222222222"
private let transportNow: Int64 = 1_786_579_200_000

private final class TransportTestSigner: P256MessageSigner, @unchecked Sendable {
    private let key = P256.Signing.PrivateKey()

    var publicKeyX963: Data { key.publicKey.x963Representation }

    func sign(message: Data) throws -> Data {
        try key.signature(for: message).rawRepresentation
    }
}

private final class DeviceSyncTestURLProtocol: URLProtocol {
    nonisolated(unsafe) private static var responder: ((URLRequest) throws -> (HTTPURLResponse, Data))?
    nonisolated(unsafe) private static var requests = [URLRequest]()
    private static let lock = NSLock()

    static func install(_ responder: @escaping (URLRequest) throws -> (HTTPURLResponse, Data)) {
        lock.lock()
        self.responder = responder
        requests.removeAll()
        lock.unlock()
    }

    static func capturedRequests() -> [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return requests
    }

    override class func canInit(with request: URLRequest) -> Bool { request.url?.scheme == "https" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?
        Self.lock.lock()
        Self.requests.append(request)
        handler = Self.responder
        Self.lock.unlock()
        do {
            guard let handler else { throw NSError(domain: "DeviceSyncTestURLProtocol", code: 1) }
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if !data.isEmpty { client?.urlProtocol(self, didLoad: data) }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "DeviceSyncTestURLProtocol", code: 2))
        }
    }

    override func stopLoading() {}
}

@Suite(.serialized)
struct NativeDeviceSyncHTTPTransportTests {
    private func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [DeviceSyncTestURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    private func transport(
        signer: TransportTestSigner,
        session: URLSession? = nil,
        baseURL: URL? = URL(string: "https://api.example.test/v1")!
    ) throws -> NativeDeviceSyncHTTPTransport {
        guard let baseURL else { throw NativeDeviceSyncHTTPTransportError.invalidConfiguration }
        return try NativeDeviceSyncHTTPTransport(
            baseURL: baseURL,
            organizationID: transportOrganizationID,
            deviceID: transportDeviceID,
            signer: signer,
            session: session ?? self.session(),
            nowMilliseconds: { transportNow },
            nonceBytes: { Data(repeating: 7, count: 32) }
        )
    }

    private func response(for request: URLRequest, status: Int = 200, headers: [String: String] = ["Content-Type": "application/json"], body: Data = Data()) -> (HTTPURLResponse, Data) {
        (HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!, body)
    }

    private func requestBody(_ request: URLRequest) throws -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { throw NativeDeviceSyncHTTPTransportError.invalidRequest }
        stream.open()
        defer { stream.close() }
        var result = Data()
        let bufferSize = 16 * 1024
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: bufferSize)
            if count < 0 { throw NativeDeviceSyncHTTPTransportError.invalidRequest }
            if count == 0 { break }
            result.append(buffer, count: count)
            guard result.count <= NativeDeviceSyncHTTPTransport.maximumAcknowledgementBytes else {
                throw NativeDeviceSyncHTTPTransportError.responseTooLarge
            }
        }
        return result
    }

    private func refreshHintResponse() throws -> Data {
        let fixtureRoot = ProcessInfo.processInfo.environment["AGENTPASS_TEST_CONTRACTS_ROOT"].map(URL.init(fileURLWithPath:))
            ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../../contracts", isDirectory: true).standardizedFileURL
        let fixtureURL = fixtureRoot.appendingPathComponent("fixtures/refresh-hint.valid.json")
        var object = try JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as! [String: Any]
        object["organization_id"] = transportOrganizationID
        object["device_id"] = transportDeviceID
        return try NativeStrictJSON.data(["hint": object])
    }

    private func bundleResponse() throws -> Data {
        let bundle = Data(#"{"format_epoch":2,"issuer":"agentpass-cloud","organization_id":"11111111-1111-4111-8111-111111111111","device_id":"22222222-2222-4222-8222-222222222222","audience":{"organization_id":"11111111-1111-4111-8111-111111111111","device_id":"22222222-2222-4222-8222-222222222222"},"issued_at":"2026-08-12T00:00:00.000Z","expires_at":"2026-08-12T00:01:00.000Z","sequence":7,"policy_scope":{"operations":["git.commit.sign"],"repositories":["/work/project"],"branches":{"allow":["feature/*"],"deny":["main"]},"remotes":{"allow":["git@github.com:org/repo.git"]}},"global_revoked":false,"revoked_devices":[],"revoked_agents":[],"revoked_capabilities":[],"offline_ttl_ms":120000,"key_id":"control-v2","signature":"NCLDRc0wp4gCKnQeTZdf2dSlyMKoR8VeN7fTc5yJfhCke64orZuw/4NGCiKc92EP3nlJE0KmiaAzX7TktVV7Bg=="}"#.utf8)
        let object = try NativeStrictJSON.object(from: bundle, maxBytes: NativeControlBundleV2Codec.maxBytes, maxDepth: NativeControlBundleV2Codec.maxDepth)
        return try NativeStrictJSON.data(["bundle": object, "desired_generation": 7])
    }

    private func acknowledgement(signer: TransportTestSigner) throws -> NativeBundleAcknowledgement {
        try NativeBundleAcknowledgementSigner.create(
            organizationID: transportOrganizationID,
            deviceID: transportDeviceID,
            deviceKeyEpoch: 3,
            sequence: 7,
            statementHash: String(repeating: "a", count: 64),
            result: .applied,
            observedAtMilliseconds: transportNow,
            nonce: "AAAAAAAAAAAAAAAAAAAAAA",
            signer: signer
        )
    }

    private func auditEvent() throws -> NativeDeviceAuditEvent {
        try NativeDeviceAuditEvent(
            eventID: "33333333-3333-4333-8333-333333333333",
            requestID: "44444444-4444-4444-8444-444444444444",
            agentID: "55555555-5555-4555-8555-555555555555",
            decision: "allow",
            reason: "allowed",
            policySequence: 7,
            capabilitySequence: 9,
            repository: "/Users/agent/repository",
            branch: "refs/heads/main",
            remote: "origin",
            payloadDigest: String(repeating: "a", count: 64),
            deviceTimestamp: "2026-08-20T05:00:00.000Z",
            previousHash: String(repeating: "0", count: 64)
        )
    }

    @Test func pollAuthenticatesEveryRequestAndUsesTheExactOpenAPITarget() async throws {
        let signer = TransportTestSigner()
        let hintBody = try refreshHintResponse()
        DeviceSyncTestURLProtocol.install { request in
            #expect(request.httpMethod == "GET")
            return self.response(for: request, body: hintBody)
        }
        let client = try transport(signer: signer)

        let result = try await client.pollControlRefresh(afterGeneration: 7, waitMilliseconds: 30_000)
        #expect(result.hint?.organizationID == transportOrganizationID)
        #expect(result.hint?.deviceID == transportDeviceID)

        let request = try #require(DeviceSyncTestURLProtocol.capturedRequests().first)
        #expect(request.url?.absoluteString == "https://api.example.test/v1/organizations/11111111-1111-4111-8111-111111111111/devices/22222222-2222-4222-8222-222222222222/refresh?after_generation=7&wait_ms=30000")
        #expect(request.httpBody == nil)
        #expect(request.value(forHTTPHeaderField: "Accept") == "application/json")
        #expect(request.value(forHTTPHeaderField: "Cache-Control") == "no-store")
        #expect(request.value(forHTTPHeaderField: "AgentPass-Device") == transportDeviceID)
        #expect(request.value(forHTTPHeaderField: "AgentPass-Timestamp") == String(transportNow))
        #expect(request.value(forHTTPHeaderField: "AgentPass-Nonce") != nil)
        #expect(request.value(forHTTPHeaderField: "AgentPass-Content-SHA256") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        let nonce = try #require(request.value(forHTTPHeaderField: "AgentPass-Nonce"))
        let signature = try #require(request.value(forHTTPHeaderField: "AgentPass-Signature"))
        let canonical = [
            "GET",
            "/v1/organizations/11111111-1111-4111-8111-111111111111/devices/22222222-2222-4222-8222-222222222222/refresh",
            "after_generation=7&wait_ms=30000",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            String(transportNow),
            nonce
        ].joined(separator: "\n")
        let publicKey = try P256.Signing.PublicKey(x963Representation: signer.publicKeyX963)
        let rawSignature = try #require(Data(base64Encoded: signature))
        #expect(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: rawSignature), for: Data(canonical.utf8)))
    }

    @Test func fetchAndAcknowledgementAreTypedAndUseBoundedCanonicalBodies() async throws {
        let signer = TransportTestSigner()
        let bundleBody = try bundleResponse()
        let ackResponse = Data(#"{"accepted":true,"duplicate":false,"observed_generation":8,"refresh_state":"applied"}"#.utf8)
        DeviceSyncTestURLProtocol.install { request in
            if request.url?.path.hasSuffix("/acknowledgements") == true {
                #expect(request.httpMethod == "POST")
                #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
                let requestBody = try self.requestBody(request)
                _ = try NativeBundleAcknowledgementCodec.decode(requestBody)
                return self.response(for: request, status: 202, body: ackResponse)
            }
            #expect(request.httpMethod == "GET")
            return self.response(for: request, headers: ["Content-Type": "application/json", "Cache-Control": "no-store"], body: bundleBody)
        }
        let client = try transport(signer: signer)
        let fetched = try await client.fetchControlBundle()
        #expect(fetched.desiredGeneration == 7)
        #expect(fetched.bundle.sequence == 7)
        #expect(fetched.bundleData.count < NativeDeviceSyncHTTPTransport.maximumBundleResponseBytes)

        let acknowledgement = try acknowledgement(signer: signer)
        let submitted = try await client.acknowledgeControlBundle(acknowledgement)
        #expect(submitted.accepted)
        #expect(!submitted.duplicate)
        #expect(submitted.observedGeneration == 8)
        #expect(submitted.refreshState == .applied)

        let requests = DeviceSyncTestURLProtocol.capturedRequests()
        #expect(requests.count == 2)
        #expect(requests[0].url?.absoluteString == "https://api.example.test/v1/organizations/11111111-1111-4111-8111-111111111111/bundles/22222222-2222-4222-8222-222222222222")
        #expect(requests[1].url?.absoluteString == "https://api.example.test/v1/organizations/11111111-1111-4111-8111-111111111111/bundles/22222222-2222-4222-8222-222222222222/acknowledgements")
        #expect(try requestBody(requests[1]).count <= NativeDeviceSyncHTTPTransport.maximumAcknowledgementBytes)
        for request in requests {
            #expect(request.value(forHTTPHeaderField: "AgentPass-Device") == transportDeviceID)
            #expect(request.value(forHTTPHeaderField: "AgentPass-Timestamp") == String(transportNow))
            #expect(request.value(forHTTPHeaderField: "AgentPass-Signature") != nil)
        }
    }

    @Test func auditUploadUsesDeviceAuthAndDecodesTheBoundedIngestionEnvelope() async throws {
        let signer = TransportTestSigner()
        let event = try auditEvent()
        let batch = try NativeDeviceAuditBatch(events: [event])
        let responseBody = try NativeStrictJSON.data([
            "ingestion": [
                "device_id": transportDeviceID,
                "accepted": [event.eventID],
                "duplicates": [],
                "gaps": [],
                "head": [
                    "last_hash": event.eventHash,
                    "last_event_id": event.eventID,
                    "chain_status": "continuous",
                    "gap_count": 0
                ]
            ]
        ])
        DeviceSyncTestURLProtocol.install { request in
            #expect(request.httpMethod == "POST")
            #expect(request.url?.absoluteString == "https://api.example.test/v1/organizations/11111111-1111-4111-8111-111111111111/audit/events")
            #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
            let body = try self.requestBody(request)
            let decoded = try NativeDeviceAuditBatch.decode(body)
            #expect(decoded == batch)
            return self.response(for: request, status: 202, body: responseBody)
        }
        let client = try transport(signer: signer)

        let result = try await client.uploadAuditBatch(batch)
        #expect(result.deviceID == transportDeviceID)
        #expect(result.acceptedEventIDs == [event.eventID])
        #expect(result.duplicateEventIDs.isEmpty)
        #expect(result.gapCount == 0)
        #expect(result.headHash == event.eventHash)
        #expect(result.headEventID == event.eventID)
        #expect(result.chainStatus == "continuous")
        let request = try #require(DeviceSyncTestURLProtocol.capturedRequests().first)
        #expect(request.value(forHTTPHeaderField: "AgentPass-Device") == transportDeviceID)
        #expect(request.value(forHTTPHeaderField: "AgentPass-Signature") != nil)
        #expect(try requestBody(request).count <= NativeDeviceAuditEvent.maxBytes * NativeDeviceAuditBatch.maxEvents)
    }

    @Test func poll204IsNoChangeAndDoesNotAcceptAResponseBody() async throws {
        let signer = TransportTestSigner()
        DeviceSyncTestURLProtocol.install { request in
            self.response(for: request, status: 204, headers: [:], body: Data())
        }
        let client = try transport(signer: signer)
        let result = try await client.pollControlRefresh()
        #expect(result.hint == nil)

        DeviceSyncTestURLProtocol.install { request in
            self.response(for: request, status: 204, headers: [:], body: Data("{}".utf8))
        }
        await #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            try await client.pollControlRefresh()
        }
    }

    @Test func constructorAndArgumentsRejectCredentialsQueriesUnboundedWaitAndCrossDeviceAck() async throws {
        let signer = TransportTestSigner()
        DeviceSyncTestURLProtocol.install { request in
            self.response(for: request, body: try self.refreshHintResponse())
        }
        #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            _ = try transport(signer: signer, baseURL: URL(string: "http://api.example.test/v1"))
        }
        #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            _ = try transport(signer: signer, baseURL: URL(string: "https://user:secret@api.example.test/v1"))
        }
        #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            _ = try transport(signer: signer, baseURL: URL(string: "https://api.example.test/v1?token=secret"))
        }
        let client = try transport(signer: signer)
        await #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            try await client.pollControlRefresh(afterGeneration: -1)
        }
        await #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            try await client.pollControlRefresh(waitMilliseconds: 30_001)
        }
        let foreign = NativeBundleAcknowledgement(
            organizationID: "33333333-3333-4333-8333-333333333333",
            deviceID: transportDeviceID,
            deviceKeyEpoch: 1,
            sequence: 1,
            statementHash: String(repeating: "a", count: 64),
            result: .blocked,
            reasonCode: .internalError,
            observedAt: "2026-08-12T00:00:00.000Z",
            nonce: "AAAAAAAAAAAAAAAAAAAAAA",
            signature: String(repeating: "A", count: 86)
        )
        await #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            try await client.acknowledgeControlBundle(foreign)
        }
        #expect(DeviceSyncTestURLProtocol.capturedRequests().isEmpty)
    }

    @Test func redirectsOriginsContentTypesAndOversizedBodiesFailWithoutRedactingSecrets() async throws {
        let signer = TransportTestSigner()
        let client = try transport(signer: signer)
        let secretBody = Data(#"{"token":"token-secret","nonce":"nonce-secret","signature":"signature-secret","device_id":"22222222-2222-4222-8222-222222222222"}"#.utf8)

        DeviceSyncTestURLProtocol.install { request in
            self.response(for: request, status: 302, headers: ["Location": "https://evil.example/v1/redirect"], body: secretBody)
        }
        let redirectError = await #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            try await client.pollControlRefresh()
        }
        #expect(String(describing: redirectError).contains("token-secret") == false)
        #expect(String(describing: redirectError).contains("nonce-secret") == false)
        #expect(String(describing: redirectError).contains("signature-secret") == false)
        #expect(String(describing: redirectError).contains("22222222-2222-4222-8222-222222222222") == false)

        DeviceSyncTestURLProtocol.install { request in
            (HTTPURLResponse(url: URL(string: "https://evil.example/v1/organizations/\(transportOrganizationID)/devices/\(transportDeviceID)/refresh")!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!, secretBody)
        }
        await #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            try await client.pollControlRefresh()
        }

        DeviceSyncTestURLProtocol.install { request in
            self.response(for: request, headers: ["Content-Type": "application/json; charset=utf-8"], body: secretBody)
        }
        await #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            try await client.pollControlRefresh()
        }

        DeviceSyncTestURLProtocol.install { request in
            self.response(for: request, body: Data(repeating: 0x7b, count: NativeDeviceSyncHTTPTransport.maximumPollResponseBytes + 1))
        }
        await #expect(throws: NativeDeviceSyncHTTPTransportError.self) {
            try await client.pollControlRefresh()
        }
    }

    @Test func injectedSessionTemplateKeepsEphemeralNoCookieNoCacheAndSingleConnectionSettings() async throws {
        let configuration = URLSessionConfiguration.default
        configuration.httpMaximumConnectionsPerHost = 8
        configuration.httpShouldSetCookies = true
        configuration.urlCache = URLCache()
        configuration.protocolClasses = [DeviceSyncTestURLProtocol.self]
        let injected = URLSession(configuration: configuration)
        let client = try transport(signer: TransportTestSigner(), session: injected)
        DeviceSyncTestURLProtocol.install { request in
            self.response(for: request, body: try self.refreshHintResponse())
        }
        let result = try await client.pollControlRefresh()
        #expect(result.hint != nil)
        let request = try #require(DeviceSyncTestURLProtocol.capturedRequests().first)
        #expect(request.value(forHTTPHeaderField: "Cookie") == nil)
    }
}
