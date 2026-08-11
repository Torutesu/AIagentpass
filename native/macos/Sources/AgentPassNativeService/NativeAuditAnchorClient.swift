import AgentPassNativeCore
import Foundation

final class NativeAuditAnchorClient: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private static let maximumBytes = 512 * 1024
    private let endpoint: URL
    private let lock = NSLock()
    private var session: URLSession!
    private var task: URLSessionDataTask?
    private var responseData = Data()
    private var responseFailure: String?
    private var completion: ((Result<Data, Error>) -> Void)?

    init(url: URL, tenant: String) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false), components.scheme?.lowercased() == "https",
              components.host?.isEmpty == false, components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              tenant.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            throw AgentPassNativeError.invalidConfiguration("Native audit anchor requires a credential-free HTTPS URL and valid tenant")
        }
        var endpoint = url
        endpoint.appendPathComponent("v1")
        endpoint.appendPathComponent("checkpoints")
        endpoint.appendPathComponent(tenant)
        self.endpoint = endpoint
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
        lock.lock()
        guard task == nil else { lock.unlock(); throw AgentPassNativeError.invalidConfiguration("Native audit anchor push is already in progress") }
        responseData = Data()
        responseFailure = nil
        self.completion = completion
        var request = URLRequest(url: endpoint, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
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
        guard let response = response as? HTTPURLResponse, response.statusCode == 200, response.url == endpoint else {
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
        if responseData.count + data.count > Self.maximumBytes {
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
        let callback = completion
        self.task = nil
        responseData = Data()
        responseFailure = nil
        completion = nil
        lock.unlock()
        guard let callback else { return }
        if let failure {
            callback(.failure(AgentPassNativeError.invalidSignature(failure)))
            return
        }
        do {
            guard data.count > 0, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == ["receipt"],
                  let receipt = object["receipt"] as? [String: Any], JSONSerialization.isValidJSONObject(receipt) else {
                throw AgentPassNativeError.invalidSignature("Native audit anchor response is invalid")
            }
            callback(.success(try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys, .withoutEscapingSlashes])))
        } catch { callback(.failure(error)) }
    }
}
