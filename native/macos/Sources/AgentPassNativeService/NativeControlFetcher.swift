import Foundation

enum NativeControlFetchOutcome: Sendable {
    case success(Data)
    case failure(String)
}

struct NativeControlFetchStatus: Sendable {
    let configured: Bool
    let sourceURL: String?
    let inFlight: Bool
    let lastAttemptAt: String?
    let lastSuccessAt: String?
    let lastError: String?
}

final class NativeControlFetcher: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private static let maximumBytes = 256 * 1024
    private let sourceURL: URL
    private let refreshSeconds: Int
    private let handler: @Sendable (NativeControlFetchOutcome) throws -> Void
    private let stateLock = NSLock()
    private var session: URLSession!
    private var timer: DispatchSourceTimer?
    private var task: URLSessionDataTask?
    private var responseData = Data()
    private var responseFailure: String?
    private var lastAttemptAt: String?
    private var lastSuccessAt: String?
    private var lastError: String?
    private var lastTransportFailure: String?
    private var lastFailureReportAt: Date?

    init(sourceURL: URL, refreshSeconds: Int, handler: @escaping @Sendable (NativeControlFetchOutcome) throws -> Void) {
        self.sourceURL = sourceURL
        self.refreshSeconds = refreshSeconds
        self.handler = handler
        super.init()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpMaximumConnectionsPerHost = 1
        let delegateQueue = OperationQueue()
        delegateQueue.name = "dev.agentpass.native-control-fetch"
        delegateQueue.maxConcurrentOperationCount = 1
        session = URLSession(configuration: configuration, delegate: self, delegateQueue: delegateQueue)
    }

    func start() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "dev.agentpass.native-control-timer"))
        timer.schedule(deadline: .now(), repeating: .seconds(refreshSeconds), leeway: .seconds(min(5, refreshSeconds / 4)))
        timer.setEventHandler { [weak self] in self?.fetch() }
        self.timer = timer
        timer.resume()
    }

    func status() -> NativeControlFetchStatus {
        stateLock.lock()
        defer { stateLock.unlock() }
        return NativeControlFetchStatus(configured: true, sourceURL: sourceURL.absoluteString, inFlight: task != nil, lastAttemptAt: lastAttemptAt, lastSuccessAt: lastSuccessAt, lastError: lastError)
    }

    private func fetch() {
        stateLock.lock()
        guard task == nil else { stateLock.unlock(); return }
        responseData = Data()
        responseFailure = nil
        lastAttemptAt = timestamp()
        var request = URLRequest(url: sourceURL, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let newTask = session.dataTask(with: request)
        task = newTask
        stateLock.unlock()
        newTask.resume()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        stateLock.lock()
        responseFailure = "Native control fetch redirects are not allowed"
        stateLock.unlock()
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let response = response as? HTTPURLResponse, response.statusCode == 200, response.url == sourceURL else {
            stateLock.lock()
            responseFailure = "Native control fetch returned an unexpected status or URL"
            stateLock.unlock()
            completionHandler(.cancel)
            return
        }
        if response.expectedContentLength > Self.maximumBytes {
            stateLock.lock()
            responseFailure = "Native control fetch response is too large"
            stateLock.unlock()
            completionHandler(.cancel)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        stateLock.lock()
        if responseData.count + data.count > Self.maximumBytes {
            responseFailure = "Native control fetch response is too large"
            stateLock.unlock()
            dataTask.cancel()
            return
        }
        responseData.append(data)
        stateLock.unlock()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        stateLock.lock()
        let data = responseData
        let failure = responseFailure ?? error?.localizedDescription
        self.task = nil
        responseData = Data()
        responseFailure = nil
        stateLock.unlock()

        if let failure {
            stateLock.lock()
            let shouldReport = lastTransportFailure != failure || lastFailureReportAt.map { Date().timeIntervalSince($0) >= 3600 } ?? true
            if shouldReport {
                lastTransportFailure = failure
                lastFailureReportAt = Date()
            }
            stateLock.unlock()
            guard shouldReport else { return }
            var recordedFailure = failure
            do { try handler(.failure(failure)) }
            catch { recordedFailure += "; audit failure: \(error.localizedDescription)" }
            stateLock.lock()
            lastError = recordedFailure
            stateLock.unlock()
            return
        }
        do {
            try handler(.success(data))
            stateLock.lock()
            lastSuccessAt = timestamp()
            lastError = nil
            lastTransportFailure = nil
            lastFailureReportAt = nil
            stateLock.unlock()
        } catch {
            stateLock.lock()
            lastError = error.localizedDescription
            stateLock.unlock()
        }
    }
}

private func timestamp() -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date())
}
