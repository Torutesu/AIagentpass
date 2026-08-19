import AgentPassNativeCore
import Foundation

public protocol NativeDeviceAuditBatchUploading: Sendable {
    func uploadAuditBatch(_ batch: NativeDeviceAuditBatch) async throws -> NativeDeviceAuditIngestionResponse
}

extension NativeDeviceSyncHTTPTransport: NativeDeviceAuditBatchUploading {}

/// Bridges the durable Core outbox to the authenticated Device transport.
/// Upload failures deliberately leave every event on disk.  A caller may run
/// `flush` again after connectivity returns; retrying the same bytes is safe
/// because Cloud ingestion is idempotent by event ID and hash.
public final class NativeDeviceAuditUploadCoordinator: @unchecked Sendable {
    private let outbox: NativeDeviceAuditOutbox
    private let transport: any NativeDeviceAuditBatchUploading

    public init(outbox: NativeDeviceAuditOutbox, transport: any NativeDeviceAuditBatchUploading) {
        self.outbox = outbox
        self.transport = transport
    }

    /// Attempts at most `maximumAttempts` exact batch submissions.  There is
    /// no unbounded background retry hidden in this method; the service owns
    /// scheduling and may call it again from its supervised loop.
    @discardableResult
    public func flush(maximumAttempts: Int = 1) async throws -> Int {
        guard (1...8).contains(maximumAttempts) else {
            throw AgentPassNativeError.invalidConfiguration("Device audit upload attempt bound is invalid")
        }
        var uploaded = 0
        for _ in 0..<maximumAttempts {
            let events = try outbox.pending()
            guard !events.isEmpty else { return uploaded }
            let batch = try NativeDeviceAuditBatch(batchID: UUID().uuidString.lowercased(), events: events)
            do {
                let response = try await transport.uploadAuditBatch(batch)
                try outbox.acknowledge(response)
                uploaded += response.acceptedEventIDs.count + response.duplicateEventIDs.count
            } catch let error as NativeDeviceSyncHTTPTransportError {
                // Response loss and an unavailable endpoint are retryable. A
                // malformed envelope, redirect, origin, or body is a trust
                // failure and must not be retried as if it were connectivity.
                switch error {
                case .transportFailure, .unexpectedStatusCode:
                    if maximumAttempts == 1 { throw error }
                default:
                    throw error
                }
            } catch {
                // Outbox acknowledgement and filesystem failures are never
                // silently converted into a retry loop. The exact batch stays
                // durable and the supervisor receives the error.
                throw error
            }
        }
        return uploaded
    }
}
