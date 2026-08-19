import Foundation
import Security

internal enum NativeAgentHostLaunchNonce {
    static func make() -> Data {
        var nonce = Data(repeating: 0, count: 32)
        let status = nonce.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
        }
        return status == errSecSuccess ? nonce : Data()
    }
}

/// Narrow Host-side seam for the authenticated child lifecycle.  The concrete
/// XPC client remains the only production implementation; tests can replace
/// this seam without creating a Mach service.
internal protocol NativeAgentHostAuthenticatedXPCClientProtocol: AnyObject, Sendable {
    func prepareForChild(launchNonce: Data) throws
    func attachForChild(
        childPID: Int,
        childPIDVersion: Int64,
        executableIdentityDigest: Data,
        ancestryBindingDigest: Data,
        worktreeBindingDigest: Data
    ) throws
    func closeForChild(reason: AgentPassHostXPCContract.CloseReason) throws
}

/// The complete child observation consumed by the Host attach request. Both
/// values are obtained independently of the launch request and are immutable
/// after the observer returns.
internal struct NativeAgentHostChildObservation: Sendable {
    let identity: NativeProcessIdentity
    let worktreeBindingDigest: Data

    init(identity: NativeProcessIdentity, worktreeBindingDigest: Data) throws {
        guard AgentPassHostXPCContract.isDigest(worktreeBindingDigest) else {
            throw NativeProcessIdentityError.invalidObservation("invalid worktree binding digest")
        }
        self.identity = identity
        self.worktreeBindingDigest = worktreeBindingDigest
    }
}

internal protocol NativeAgentHostChildObserver: Sendable {
    func observe(pid: Int32) throws -> NativeAgentHostChildObservation
}

/// Production child observer. The process identity and Git worktree binding
/// are sampled from the spawned PID, never from the request or parent state.
internal struct NativeAgentHostDarwinChildObserver: NativeAgentHostChildObserver, Sendable {
    private let processSource: NativeDarwinProcessObservationSource
    private let worktreeSource: NativeDarwinGitWorktreeObserver

    init(
        processSource: NativeDarwinProcessObservationSource = NativeDarwinProcessObservationSource(),
        worktreeSource: NativeDarwinGitWorktreeObserver = NativeDarwinGitWorktreeObserver()
    ) {
        self.processSource = processSource
        self.worktreeSource = worktreeSource
    }

    func observe(pid: Int32) throws -> NativeAgentHostChildObservation {
        let observation = try processSource.observe(pid: pid)
        let identity = NativeProcessIdentity(observation: observation)
        let worktree = try worktreeSource.observe(pid: pid, expectedUserID: identity.uid)
        return try NativeAgentHostChildObservation(
            identity: identity,
            worktreeBindingDigest: worktree.binding.digest
        )
    }
}

/// Converts the existing canonical SHA-256 hex projections into the exact
/// 32-byte payload required by the Host XPC DTO. This deliberately decodes the
/// canonical digest; it does not hash the printable hexadecimal form again.
internal extension NativeProcessIdentity {
    var canonicalBindingDigestData: Data {
        get throws {
            try NativeAgentHostCanonicalDigestData.decode(canonicalBindingHash)
        }
    }

    var canonicalAncestryBindingDigestData: Data {
        get throws {
            try NativeAgentHostCanonicalDigestData.decode(canonicalAncestryBindingHash)
        }
    }
}

private enum NativeAgentHostCanonicalDigestData {
    static func decode(_ value: String) throws -> Data {
        guard value.utf8.count == AgentPassHostXPCContract.digestBytes * 2 else {
            throw NativeProcessIdentityError.invalidObservation("invalid canonical digest length")
        }
        var result = Data(capacity: AgentPassHostXPCContract.digestBytes)
        var highNibble: UInt8?
        for byte in value.utf8 {
            let nibble: UInt8
            switch byte {
            case 48...57: nibble = byte - 48
            case 65...70: nibble = byte - 55
            case 97...102: nibble = byte - 87
            default:
                throw NativeProcessIdentityError.invalidObservation("invalid canonical digest encoding")
            }
            if let high = highNibble {
                result.append((high << 4) | nibble)
                highNibble = nil
            } else {
                highNibble = nibble
            }
        }
        guard result.count == AgentPassHostXPCContract.digestBytes else {
            throw NativeProcessIdentityError.invalidObservation("invalid canonical digest bytes")
        }
        return result
    }
}
