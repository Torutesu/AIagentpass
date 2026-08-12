import AgentPassNativeCore
import Foundation

/// Performs the potentially slow, independently authenticated Node head read before minting
/// a short-lived local capability. Callers must invoke this outside Service/coordinator locks.
public struct NativeAuditPruneExternalObservationFetcher: Sendable {
    private let provider: any NativeAuditPruneExternalReceiptPositionProvider
    private let trustSource: NativeAuditPruneServiceTrustSource

    public init(provider: any NativeAuditPruneExternalReceiptPositionProvider, trustSource: NativeAuditPruneServiceTrustSource) {
        self.provider = provider
        self.trustSource = trustSource
    }

    public func fetch(
        purpose: NativeAuditPruneExternalObservationPurpose,
        operationID: String? = nil
    ) throws -> NativeAuditPruneExternalReceiptObservation {
        let boundOperationID: String?
        if let operationID { boundOperationID = operationID }
        else if let current = try trustSource.currentAuditPruneOperationID() { boundOperationID = current }
        else if purpose == .reconcile { boundOperationID = "reconcile-\(UUID().uuidString.lowercased())" }
        else { boundOperationID = nil }
        let head = try provider.readAuditPruneReceiptHead()
        if purpose == .status {
            return try trustSource.issueAuditPruneExternalReceiptObservation(
                position: head.position, purpose: purpose, operationID: boundOperationID
            )
        }
        guard let boundOperationID else {
            throw AgentPassNativeError.invalidSignature("Mutating audit prune observation requires an operation binding")
        }
        let lease = try provider.acquireAuditPruneReceiptLease(purpose: purpose, operationID: boundOperationID, expected: head.position)
        do {
            return try trustSource.issueAuditPruneExternalReceiptObservation(
                position: head.position, lease: lease, purpose: purpose, operationID: boundOperationID
            )
        } catch {
            try? provider.releaseAuditPruneReceiptLease(lease)
            throw error
        }
    }
}

/// Exact challenge URL used by the production GET client. Keeping construction here lets tests
/// assert that the nonce is neither omitted nor encoded into a different request target.
public struct NativeAuditPruneReceiptHeadRequest: Equatable, Sendable {
    public let endpoint: URL
    public let nonce: String

    public init(baseEndpoint: URL, nonce: String) throws {
        guard nonce.wholeMatch(of: /^[A-Za-z0-9_-]{43}$/) != nil,
              var components = URLComponents(url: baseEndpoint, resolvingAgainstBaseURL: false),
              components.query == nil, components.fragment == nil else {
            throw AgentPassNativeError.invalidConfiguration("Native audit prune head challenge is invalid")
        }
        components.queryItems = [URLQueryItem(name: "nonce", value: nonce)]
        guard let endpoint = components.url else {
            throw AgentPassNativeError.invalidConfiguration("Native audit prune head endpoint is invalid")
        }
        self.endpoint = endpoint
        self.nonce = nonce
    }
}
