import Foundation

/// Composes the fixed Git signer protocol with one qualified Host lifecycle.
///
/// The runner owns no alternate transport or authority. It delegates to the
/// Coordinator, which re-observes authority and closes the child/session on
/// every terminal bridge path. The one-use reservation here prevents a Host
/// event loop from accidentally scheduling a second serve attempt.
public final class NativeAgentHostGitBridgeRunner: @unchecked Sendable {
    private let coordinator: NativeAgentHostLifecycleCoordinator
    private let signer: any NativeAgentGitCommitSigning
    private let lock = NSLock()
    private var attempted = false

    public init(
        coordinator: NativeAgentHostLifecycleCoordinator,
        signer: any NativeAgentGitCommitSigning
    ) {
        self.coordinator = coordinator
        self.signer = signer
    }

    public func serveOne() throws {
        lock.lock()
        guard !attempted else {
            lock.unlock()
            throw NativeAgentHostPrivateGitBridgeError.alreadyAttempted
        }
        attempted = true
        lock.unlock()

        try coordinator.servePrivateGitBridge { [signer] payload in
            try signer.signGitCommitPayload(payload)
        }
    }
}
