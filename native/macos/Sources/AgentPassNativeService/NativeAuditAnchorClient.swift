import AgentPassNativeCore
import AgentPassNativeServiceSupport
import CoreFoundation
import Foundation
import Security

private func serviceClientExactBoolean(_ value: Any?) -> Bool? {
    guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
    return number.boolValue
}

final class NativeAuditAnchorClient: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate, NativeAuditPruneExternalReceiptPositionProvider, @unchecked Sendable {
    private static let maximumBytes = 512 * 1024
    private let tenant: String
    private let checkpointEndpoint: URL
    private let keyTransitionEndpoint: URL
    private let auditPruneEndpoint: URL
    private let auditPruneHeadEndpoint: URL
    private let auditPruneLeaseEndpoint: URL
    private let auditPruneLeaseReleaseEndpoint: URL
    private let auditPruneHeadVerifier: NativeAuditPruneReceiptHeadVerifier
    private let auditPruneLeaseVerifier: NativeAuditPruneLeaseVerifier
    private let auditSigner: any P256MessageSigner
    private let lock = NSLock()
    private var session: URLSession!
    private var task: URLSessionDataTask?
    private var responseData = Data()
    private var responseFailure: String?
    private var pending: PendingRequest?

    private final class NativeAuditPruneHeadResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var result: Result<Data, Error>?
        func set(_ value: Result<Data, Error>) { lock.lock(); result = value; lock.unlock() }
        func get() -> Result<Data, Error>? { lock.lock(); defer { lock.unlock() }; return result }
    }

    private enum PendingRequest {
        case checkpoint(endpoint: URL, completion: (Result<Data, Error>) -> Void)
        case keyTransition(
            endpoint: URL,
            transition: NativeAuditKeyTransition,
            verifier: NativeAuditKeyTransitionReceiptVerifier,
            expectedTransitionIndex: Int,
            completion: (Result<NativeAuditKeyTransitionReceipt, Error>) -> Void
        )
        case rawKeyTransition(endpoint: URL, completion: (Result<Data, Error>) -> Void)
        case auditPrune(endpoint: URL, completion: (Result<Data, Error>) -> Void)
        case auditPruneHead(endpoint: URL, completion: (Result<Data, Error>) -> Void)
        case auditPruneLeaseAcquire(endpoint: URL, completion: (Result<Data, Error>) -> Void)
        case auditPruneLeaseRelease(endpoint: URL, completion: (Result<Data, Error>) -> Void)

        var endpoint: URL {
            switch self {
            case .checkpoint(let endpoint, _), .keyTransition(let endpoint, _, _, _, _), .rawKeyTransition(let endpoint, _), .auditPrune(let endpoint, _), .auditPruneHead(let endpoint, _), .auditPruneLeaseAcquire(let endpoint, _), .auditPruneLeaseRelease(let endpoint, _): endpoint
            }
        }
    }

    init(url: URL, tenant: String, anchorPublicKeyPEM: String, auditSigner: any P256MessageSigner) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false), components.scheme?.lowercased() == "https",
              components.host?.isEmpty == false, components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              tenant.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Native audit anchor requires a credential-free HTTPS URL and valid tenant")
        }
        self.tenant = tenant
        self.auditSigner = auditSigner
        var checkpointEndpoint = url
        checkpointEndpoint.appendPathComponent("v1")
        checkpointEndpoint.appendPathComponent("checkpoints")
        checkpointEndpoint.appendPathComponent(tenant)
        self.checkpointEndpoint = checkpointEndpoint
        var keyTransitionEndpoint = url
        keyTransitionEndpoint.appendPathComponent("v1")
        keyTransitionEndpoint.appendPathComponent("key-transitions")
        keyTransitionEndpoint.appendPathComponent(tenant)
        self.keyTransitionEndpoint = keyTransitionEndpoint
        var auditPruneEndpoint = url
        auditPruneEndpoint.appendPathComponent("v1")
        auditPruneEndpoint.appendPathComponent("audit-prunes")
        auditPruneEndpoint.appendPathComponent(tenant)
        self.auditPruneEndpoint = auditPruneEndpoint
        var auditPruneHeadEndpoint = auditPruneEndpoint
        auditPruneHeadEndpoint.appendPathComponent("head")
        self.auditPruneHeadEndpoint = auditPruneHeadEndpoint
        var auditPruneLeaseEndpoint = auditPruneEndpoint
        auditPruneLeaseEndpoint.appendPathComponent("leases")
        self.auditPruneLeaseEndpoint = auditPruneLeaseEndpoint
        var auditPruneLeaseReleaseEndpoint = auditPruneLeaseEndpoint
        auditPruneLeaseReleaseEndpoint.appendPathComponent("release")
        self.auditPruneLeaseReleaseEndpoint = auditPruneLeaseReleaseEndpoint
        auditPruneHeadVerifier = try NativeAuditPruneReceiptHeadVerifier(tenant: tenant, anchorPublicKeyPEM: anchorPublicKeyPEM)
        auditPruneLeaseVerifier = try NativeAuditPruneLeaseVerifier(tenant: tenant, anchorPublicKeyPEM: anchorPublicKeyPEM, principalPublicKeyX963: auditSigner.publicKeyX963)
        super.init()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        let queue = OperationQueue()
        queue.name = "dev.agentpass.native-audit-anchor"
        queue.maxConcurrentOperationCount = 1
        session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
    }

    func post(checkpoint: NativeAuditCheckpoint, completion: @escaping (Result<Data, Error>) -> Void) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let checkpointData = try encoder.encode(checkpoint)
        guard checkpointData.count <= Self.maximumBytes else { throw AgentPassNativeError.invalidConfiguration("Native audit checkpoint is too large") }
        let object = try JSONSerialization.jsonObject(with: checkpointData)
        let body = try JSONSerialization.data(withJSONObject: ["checkpoint": object], options: [.sortedKeys, .withoutEscapingSlashes])
        try start(body: body, pending: .checkpoint(endpoint: checkpointEndpoint, completion: completion))
    }

    /// Submits an exact canonical transition and verifies the returned Ed25519
    /// receipt before exposing it to the service. The caller must durably persist
    /// the returned receipt before activating the replacement lifecycle key.
    func post(
        transition: NativeAuditKeyTransition,
        retiringPublicKeyX963: Data,
        expectedTransitionIndex: Int,
        anchorPublicKeyPEM: String,
        completion: @escaping (Result<NativeAuditKeyTransitionReceipt, Error>) -> Void
    ) throws {
        guard transition.tenant == tenant,
              expectedTransitionIndex > 0,
              expectedTransitionIndex <= NativeAuditKeyTransitionStatement.maximumSafeInteger else {
            throw AgentPassNativeError.invalidConfiguration("Native audit key transition does not match the configured anchor tenant or index")
        }
        try transition.verify(retiringPublicKeyX963: retiringPublicKeyX963)
        let verifier = try NativeAuditKeyTransitionReceiptVerifier(tenant: transition.tenant, anchorPublicKeyPEM: anchorPublicKeyPEM)
        let transitionData = try transition.canonicalData()
        let object = try JSONSerialization.jsonObject(with: transitionData)
        let body = try JSONSerialization.data(withJSONObject: ["transition": object], options: [.sortedKeys, .withoutEscapingSlashes])
        try start(
            body: body,
            pending: .keyTransition(
                endpoint: keyTransitionEndpoint,
                transition: transition,
                verifier: verifier,
                expectedTransitionIndex: expectedTransitionIndex,
                completion: completion
            )
        )
    }

    /// Submits canonical transition bytes and returns canonical receipt bytes. Verification and
    /// durable acceptance are performed by `NativeAuditKeyTransitionStore`, allowing the caller
    /// to retain and retry the exact request across process restarts.
    func postTransitionData(_ transitionData: Data, completion: @escaping (Result<Data, Error>) -> Void) throws {
        let transition = try NativeAuditKeyTransition.decodeCanonical(transitionData)
        guard transition.tenant == tenant, try transition.canonicalData() == transitionData else {
            throw AgentPassNativeError.invalidSignature("Native audit transition bytes are noncanonical or belong to another tenant")
        }
        let object = try JSONSerialization.jsonObject(with: transitionData)
        let body = try JSONSerialization.data(withJSONObject: ["transition": object], options: [.sortedKeys, .withoutEscapingSlashes])
        try start(body: body, pending: .rawKeyTransition(endpoint: keyTransitionEndpoint, completion: completion))
    }

    func postAuditPruneData(_ authorizationData: Data, externalLeaseData: Data, completion: @escaping (Result<Data, Error>) -> Void) throws {
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
        guard authorization.tenant == tenant, try authorization.canonicalData() == authorizationData else {
            throw AgentPassNativeError.invalidSignature("Native audit prune bytes are noncanonical or belong to another tenant")
        }
        let object = try JSONSerialization.jsonObject(with: authorizationData)
        let leaseObject = try JSONSerialization.jsonObject(with: externalLeaseData)
        let body = try JSONSerialization.data(withJSONObject: ["authorization": object, "lease": leaseObject], options: [.sortedKeys, .withoutEscapingSlashes])
        try start(body: body, pending: .auditPrune(endpoint: auditPruneEndpoint, completion: completion))
    }

    func readAuditPruneReceiptHead() throws -> NativeAuditPruneExternalReceiptHead {
        let nonce = try randomNonce()
        let challenge = try NativeAuditPruneReceiptHeadRequest(baseEndpoint: auditPruneHeadEndpoint, nonce: nonce)
        let semaphore = DispatchSemaphore(value: 0)
        let box = NativeAuditPruneHeadResultBox()
        try start(body: nil, pending: .auditPruneHead(endpoint: challenge.endpoint) { result in
            box.set(result)
            semaphore.signal()
        })
        guard semaphore.wait(timeout: .now() + 21) == .success, let result = box.get() else {
            throw AgentPassNativeError.invalidSignature("Native audit prune head request timed out")
        }
        return try auditPruneHeadVerifier.verify(result.get(), requestNonce: challenge.nonce, now: Date())
    }

    func acquireAuditPruneReceiptLease(purpose: NativeAuditPruneExternalObservationPurpose, operationID: String, expected: NativeAuditPruneExternalReceiptPosition?) throws -> NativeAuditPruneExternalReceiptLease {
        let nonce = try randomNonce()
        let requestData = try NativeAuditPruneLeaseProtocol.acquisitionRequest(tenant: tenant, nonce: nonce, purpose: purpose, operationID: operationID, expected: expected, issuedAt: Date(), signer: auditSigner)
        let requestObject = try JSONSerialization.jsonObject(with: requestData)
        let body = try JSONSerialization.data(withJSONObject: ["request": requestObject], options: [.sortedKeys, .withoutEscapingSlashes])
        let data = try synchronousRaw(body: body, pending: { .auditPruneLeaseAcquire(endpoint: auditPruneLeaseEndpoint, completion: $0) }, timeoutMessage: "Native audit prune lease acquisition timed out")
        return try auditPruneLeaseVerifier.verify(data, requestNonce: nonce, purpose: purpose, operationID: operationID, expected: expected)
    }

    func releaseAuditPruneReceiptLease(_ lease: NativeAuditPruneExternalReceiptLease) throws {
        let leaseObject = try JSONSerialization.jsonObject(with: lease.canonicalData)
        let requestData = try NativeAuditPruneLeaseProtocol.releaseRequest(tenant: tenant, nonce: randomNonce(), lease: lease, issuedAt: Date(), signer: auditSigner)
        let requestObject = try JSONSerialization.jsonObject(with: requestData)
        let body = try JSONSerialization.data(withJSONObject: ["lease": leaseObject, "request": requestObject], options: [.sortedKeys, .withoutEscapingSlashes])
        let data = try synchronousRaw(body: body, pending: { .auditPruneLeaseRelease(endpoint: auditPruneLeaseReleaseEndpoint, completion: $0) }, timeoutMessage: "Native audit prune lease release timed out")
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(value.keys) == ["lease_id", "released"], value["lease_id"] as? String == lease.leaseID,
              serviceClientExactBoolean(value["released"]) == true else {
            throw AgentPassNativeError.invalidSignature("Native audit prune lease release response is invalid")
        }
    }

    private func randomNonce() throws -> String {
        var bytes = Data(count: 32)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else { throw AgentPassNativeError.invalidConfiguration("Native audit prune nonce generation failed") }
        return bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func synchronousRaw(body: Data, pending: (@escaping (Result<Data, Error>) -> Void) -> PendingRequest, timeoutMessage: String) throws -> Data {
        let semaphore = DispatchSemaphore(value: 0); let box = NativeAuditPruneHeadResultBox()
        try start(body: body, pending: pending { box.set($0); semaphore.signal() })
        guard semaphore.wait(timeout: .now() + 21) == .success, let result = box.get() else { throw AgentPassNativeError.invalidSignature(timeoutMessage) }
        return try result.get()
    }

    private func start(body: Data?, pending: PendingRequest) throws {
        guard body == nil || (!body!.isEmpty && body!.count <= Self.maximumBytes) else {
            throw AgentPassNativeError.invalidConfiguration("Native audit anchor request is too large")
        }
        lock.lock()
        guard task == nil else { lock.unlock(); throw AgentPassNativeError.invalidConfiguration("Native audit anchor push is already in progress") }
        responseData = Data()
        responseFailure = nil
        self.pending = pending
        var request = URLRequest(url: pending.endpoint, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15)
        request.httpMethod = body == nil ? "GET" : "POST"
        request.httpBody = body
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let newTask = session.dataTask(with: request)
        task = newTask
        lock.unlock()
        newTask.resume()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        lock.lock(); responseFailure = "Native audit anchor redirects are not allowed"; lock.unlock()
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        let expectedEndpoint = pending?.endpoint
        lock.unlock()
        guard let response = response as? HTTPURLResponse, response.statusCode == 200,
              response.url == expectedEndpoint,
              response.mimeType?.lowercased() == "application/json" else {
            lock.lock(); responseFailure = "Native audit anchor returned an unexpected status or URL"; lock.unlock()
            completionHandler(.cancel)
            return
        }
        if response.expectedContentLength > Self.maximumBytes {
            lock.lock(); responseFailure = "Native audit anchor response is too large"; lock.unlock()
            completionHandler(.cancel)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        if data.count > Self.maximumBytes - responseData.count {
            responseFailure = "Native audit anchor response is too large"
            lock.unlock()
            dataTask.cancel()
            return
        }
        responseData.append(data)
        lock.unlock()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        lock.lock()
        let data = responseData
        let failure = responseFailure ?? error?.localizedDescription
        let current = pending
        self.task = nil
        responseData = Data()
        responseFailure = nil
        pending = nil
        lock.unlock()
        guard let current else { return }
        if let failure {
            finish(current, result: .failure(AgentPassNativeError.invalidSignature(failure)))
            return
        }
        if case .auditPruneHead = current {
            finish(current, result: .success(data))
            return
        }
        if case .auditPruneLeaseAcquire = current {
            finish(current, result: .success(data)); return
        }
        if case .auditPruneLeaseRelease = current {
            finish(current, result: .success(data))
            return
        }
        do {
            guard data.count > 0, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == ["receipt"],
                  let receipt = object["receipt"] as? [String: Any], JSONSerialization.isValidJSONObject(receipt) else {
                throw AgentPassNativeError.invalidSignature("Native audit anchor response is invalid")
            }
            let receiptData = try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys, .withoutEscapingSlashes])
            finish(current, result: .success(receiptData))
        } catch { finish(current, result: .failure(error)) }
    }

    private func finish(_ pending: PendingRequest, result: Result<Data, Error>) {
        switch pending {
        case .checkpoint(_, let completion):
            completion(result)
        case .rawKeyTransition(_, let completion):
            completion(result)
        case .auditPrune(_, let completion):
            do {
                let data = try result.get()
                let receipt = try NativeAuditPruneReceipt.decodeCanonical(data)
                guard try receipt.canonicalData() == data else { throw AgentPassNativeError.invalidSignature("Native audit prune receipt is noncanonical") }
                completion(.success(data))
            } catch { completion(.failure(error)) }
        case .auditPruneHead(_, let completion):
            completion(result)
        case .auditPruneLeaseAcquire(_, let completion):
            completion(result)
        case .auditPruneLeaseRelease(_, let completion):
            completion(result)
        case .keyTransition(_, let transition, let verifier, let expectedTransitionIndex, let completion):
            do {
                let receiptData = try result.get()
                completion(.success(try verifier.verify(
                    receiptData: receiptData,
                    transition: transition,
                    expectedTransitionIndex: expectedTransitionIndex
                )))
            } catch {
                completion(.failure(error))
            }
        }
    }

}

/// Bounded synchronous adapter used only inside the serialized management activation path.
/// URLSession still performs network work asynchronously; the adapter bounds the wait below the
/// session resource timeout so a management call cannot block indefinitely.
final class NativeAuditKeyTransitionHTTPTransport: NativeAuditKeyTransitionTransport, NativeAuditKeyRecoveryTransitionTransport, NativeAuditPruneTransport, @unchecked Sendable {
    private final class ResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var result: Result<Data, Error>?
        func set(_ value: Result<Data, Error>) { lock.lock(); result = value; lock.unlock() }
        func get() -> Result<Data, Error>? { lock.lock(); defer { lock.unlock() }; return result }
    }

    private let client: NativeAuditAnchorClient

    init(client: NativeAuditAnchorClient) { self.client = client }

    func submit(transitionData: Data) throws -> Data {
        let semaphore = DispatchSemaphore(value: 0)
        let box = ResultBox()
        try client.postTransitionData(transitionData) { result in
            box.set(result)
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + 21) == .success, let result = box.get() else {
            throw AgentPassNativeError.invalidSignature("Native audit anchor transition request timed out")
        }
        return try result.get()
    }

    func submitRecoveryTransition(transitionData: Data) throws -> Data {
        try submit(transitionData: transitionData)
    }

    func submitAuditPrune(tenant: String, authorizationData: Data) throws -> Data {
        throw AgentPassNativeError.invalidConfiguration("Audit prune submission requires an external Node lease")
    }

    func submitAuditPrune(tenant: String, authorizationData: Data, externalLeaseData: Data?) throws -> Data {
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
        guard authorization.tenant == tenant else { throw AgentPassNativeError.invalidSignature("Audit prune transport tenant mismatch") }
        let semaphore = DispatchSemaphore(value: 0)
        let box = ResultBox()
        guard let externalLeaseData else { throw AgentPassNativeError.invalidSignature("Audit prune submission lease is missing") }
        try client.postAuditPruneData(authorizationData, externalLeaseData: externalLeaseData) { result in box.set(result); semaphore.signal() }
        guard semaphore.wait(timeout: .now() + 21) == .success, let result = box.get() else {
            throw AgentPassNativeError.invalidSignature("Native audit prune anchor request timed out")
        }
        return try result.get()
    }
}
