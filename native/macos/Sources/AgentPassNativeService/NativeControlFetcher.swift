import AgentPassNativeCore
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
    let nextAttemptAt: String?
    let consecutiveFailures: Int
}

final class NativeControlFetcher: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private static let maximumBytes = 256 * 1024
    private let sourceURL: URL
    private let handler: @Sendable (NativeControlFetchOutcome) throws -> Void
    private let stateLock = NSLock()
    private let timerQueue = DispatchQueue(label: "dev.agentpass.native-control-timer")
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
    private var retrySchedule: NativeControlRetrySchedule

    init(sourceURL: URL, refreshSeconds: Int, handler: @escaping @Sendable (NativeControlFetchOutcome) throws -> Void) throws {
        self.sourceURL = sourceURL
        self.handler = handler
        retrySchedule = try NativeControlRetrySchedule(refreshSeconds: refreshSeconds)
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
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.setEventHandler { [weak self] in self?.fetch() }
        self.timer = timer
        timer.resume()
        scheduleNext(after: 0)
    }

    func status() -> NativeControlFetchStatus {
        stateLock.lock()
        defer { stateLock.unlock() }
        return NativeControlFetchStatus(configured: true, sourceURL: sourceURL.absoluteString, inFlight: task != nil, lastAttemptAt: lastAttemptAt, lastSuccessAt: lastSuccessAt, lastError: lastError, nextAttemptAt: nextAttemptAt, consecutiveFailures: retrySchedule.consecutiveFailures)
    }

    private func fetch() {
        stateLock.lock()
        guard task == nil else { stateLock.unlock(); return }
        responseData = Data()
        responseFailure = nil
        lastAttemptAt = timestamp()
        nextAttemptAt = nil
        var request = URLRequest(url: sourceURL, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let newTask = session.dataTask(with: request)
        task = newTask
        stateLock.unlock()
        newTask.resume()
    }

    private var nextAttemptAt: String?

    private func scheduleNext(after delay: TimeInterval) {
        let boundedDelay = max(0, delay)
        stateLock.lock()
        nextAttemptAt = timestamp(Date().addingTimeInterval(boundedDelay))
        let timer = self.timer
        stateLock.unlock()
        timer?.schedule(deadline: .now() + boundedDelay, leeway: .milliseconds(min(5_000, max(250, Int(boundedDelay * 100)))))
    }

    private func scheduleAfterSuccess() {
        stateLock.lock()
        let delay = retrySchedule.successDelay(randomUnit: Double.random(in: 0...1))
        stateLock.unlock()
        scheduleNext(after: delay)
    }

    private func scheduleAfterFailure() {
        stateLock.lock()
        let delay = retrySchedule.failureDelay(randomUnit: Double.random(in: 0...1))
        stateLock.unlock()
        scheduleNext(after: delay)
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
            guard shouldReport else { scheduleAfterFailure(); return }
            var recordedFailure = failure
            do { try handler(.failure(failure)) }
            catch { recordedFailure += "; audit failure: \(error.localizedDescription)" }
            stateLock.lock()
            lastError = recordedFailure
            stateLock.unlock()
            scheduleAfterFailure()
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
            scheduleAfterSuccess()
        } catch {
            stateLock.lock()
            lastError = error.localizedDescription
            stateLock.unlock()
            scheduleAfterFailure()
        }
    }
}

private func timestamp(_ date: Date = Date()) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
}
