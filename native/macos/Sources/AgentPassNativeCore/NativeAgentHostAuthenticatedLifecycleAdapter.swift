import Foundation

/// The bounded child-side lifecycle handoff used by the authenticated Host
/// transport. The returned client remains connection-owned by the child
/// supervisor so attach and close use the same prepared XPC session.
internal protocol NativeAgentHostAuthenticatedLaunchPreparationAdapter: Sendable {
    func prepareForChild(
        launchNonce: Data
    ) throws -> any NativeAgentHostAuthenticatedXPCClientProtocol
}

/// Production preparation adapter. It is intentionally limited to the Host
/// XPC prepare operation; service bootstrap and the complete
/// `NativeAgentSessionBinding` remain a separate, higher-level handoff.
///
/// Tests inject the narrow client factory below, while production constructs
/// the existing connection-owned `NativeAgentAuthenticatedHostXPCClient`.
internal struct NativeAgentAuthenticatedHostLaunchPreparationAdapter:
    NativeAgentHostAuthenticatedLaunchPreparationAdapter,
    Sendable
{
    private let clientFactory: @Sendable () -> any NativeAgentHostAuthenticatedXPCClientProtocol

    init(
        clientFactory: @escaping @Sendable () -> any NativeAgentHostAuthenticatedXPCClientProtocol = {
            NativeAgentAuthenticatedHostXPCClient()
        }
    ) {
        self.clientFactory = clientFactory
    }

    func prepareForChild(
        launchNonce: Data
    ) throws -> any NativeAgentHostAuthenticatedXPCClientProtocol {
        let client = clientFactory()
        do {
            try client.prepareForChild(launchNonce: launchNonce)
            return client
        } catch {
            // A prepared session is never handed to the supervisor after a
            // failed prepare. Close is best-effort because the public result
            // is the single bounded launchFailed outcome.
            try? client.closeForChild(reason: .cancelled)
            throw NativeAgentHostChildSupervisorError.launchFailed
        }
    }
}
