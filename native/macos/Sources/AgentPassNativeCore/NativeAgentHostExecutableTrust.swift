import Darwin
import Foundation

/// The metadata used to bind a fixed Host executable to an inode. No launch
/// request can provide or modify this value.
internal struct NativeAgentHostExecutableSelection: Equatable, Sendable {
    let path: String
    let device: UInt64
    let inode: UInt64

    init(path: String, device: UInt64, inode: UInt64) {
        self.path = path
        self.device = device
        self.inode = inode
    }
}

internal enum NativeAgentHostExecutableTrustError: Error, Equatable, Sendable {
    case noTrustedCandidate
    case identityChanged
}

/// These hooks are internal and exist only to make the filesystem policy
/// deterministic in unit tests. The production Host initializer never
/// accepts a trust hook and always uses `system`.
internal struct NativeAgentHostExecutableTrustHooks: @unchecked Sendable {
    typealias LStatClosure = @Sendable (String) throws -> NativeAgentHostExecutableMetadata
    typealias AccessClosure = @Sendable (String) -> Bool

    let lstat: LStatClosure
    let isExecutable: AccessClosure
    let isWritable: AccessClosure

    static let system = Self(
        lstat: { path in
            var info = stat()
            guard path.withCString({ Darwin.lstat($0, &info) }) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            return NativeAgentHostExecutableMetadata(
                device: UInt64(info.st_dev),
                inode: UInt64(info.st_ino),
                ownerUID: UInt32(info.st_uid),
                mode: UInt32(info.st_mode)
            )
        },
        isExecutable: { path in
            path.withCString { Darwin.access($0, X_OK) == 0 }
        },
        isWritable: { path in
            // A root supervisor is already the trusted owner of the launch
            // boundary. For the normal user Host, access(2) also accounts for
            // macOS ACL grants that are invisible in st_mode's 022 bits.
            guard geteuid() != 0 else { return false }
            return path.withCString { Darwin.access($0, W_OK) == 0 }
        }
    )
}

internal struct NativeAgentHostExecutableMetadata: Equatable, Sendable {
    let device: UInt64
    let inode: UInt64
    let ownerUID: UInt32
    let mode: UInt32

    var fileType: UInt32 { mode & UInt32(S_IFMT) }
}

/// Trust policy for fixed Cursor executables.
///
/// A candidate is accepted only when every parent component is a root-owned,
/// non-group/world-writable directory observed with `lstat`, and the final
/// object is a root-owned, non-group/world-writable regular executable file.
/// `lstat` makes symlink candidates and symlink parents fail closed.
///
/// Standard Homebrew `bin` entries are commonly symlinks into a Cellar and
/// are intentionally rejected. A direct administrator-installed root-owned
/// file at a reviewed system path can still be accepted; if none qualifies,
/// Cursor launch fails closed.
internal enum NativeAgentHostExecutableTrust {
    // Keep this list closed. Adding a path is a security-review change.
    static let cursorExecutableCandidates = [
        "/Applications/Cursor.app/Contents/Resources/app/bin/code",
        "/Applications/Cursor.app/Contents/Resources/app/bin/cursor",
        "/opt/cursor-agent",
        "/opt/homebrew/bin/cursor-agent",
        "/usr/local/bin/cursor-agent"
    ]

    static func resolveCursorExecutable() throws -> NativeAgentHostExecutableSelection {
        try resolveCursorExecutable(candidates: cursorExecutableCandidates, hooks: .system)
    }

    /// Test-only resolver entry point. It is internal so production callers
    /// cannot replace the trust policy or candidate list through the public
    /// API.
    static func resolveCursorExecutable(
        candidates: [String],
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws -> NativeAgentHostExecutableSelection {
        for candidate in candidates {
            guard cursorExecutableCandidates.contains(candidate) else {
                continue
            }
            if let selection = try? validate(candidate, hooks: hooks) {
                return selection
            }
        }
        throw NativeAgentHostExecutableTrustError.noTrustedCandidate
    }

    static func revalidate(_ selection: NativeAgentHostExecutableSelection) throws {
        try revalidate(selection, hooks: .system)
    }

    /// Rechecks the same fixed path immediately before `posix_spawn`.
    ///
    /// The current `posix_spawn(path, ...)` API does not make lstat and exec
    /// atomic. A privileged/root actor could still swap the file after this
    /// check. Root ownership and non-writable ancestors do prevent an
    /// unprivileged agent user from performing that substitution.
    static func revalidate(
        _ selection: NativeAgentHostExecutableSelection,
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws {
        let current = try validate(selection.path, hooks: hooks)
        guard current.device == selection.device,
              current.inode == selection.inode else {
            throw NativeAgentHostExecutableTrustError.identityChanged
        }
    }

    private static func validate(
        _ candidate: String,
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws -> NativeAgentHostExecutableSelection {
        guard isReviewedAbsolutePath(candidate) else {
            throw NativeAgentHostExecutableTrustError.noTrustedCandidate
        }

        let components = candidate.split(separator: "/", omittingEmptySubsequences: true)
        guard !components.isEmpty else {
            throw NativeAgentHostExecutableTrustError.noTrustedCandidate
        }

        var current = "/"
        try validateDirectory(current, hooks: hooks)
        for (index, component) in components.enumerated() {
            current = current == "/" ? "/\(component)" : "\(current)/\(component)"
            if index == components.count - 1 {
                let metadata = try hooks.lstat(current)
                guard metadata.fileType == UInt32(S_IFREG),
                      metadata.ownerUID == 0,
                      metadata.mode & 0o022 == 0,
                      metadata.mode & 0o111 != 0,
                      hooks.isExecutable(current),
                      !hooks.isWritable(current) else {
                    throw NativeAgentHostExecutableTrustError.noTrustedCandidate
                }
                return NativeAgentHostExecutableSelection(
                    path: candidate,
                    device: metadata.device,
                    inode: metadata.inode
                )
            }
            try validateDirectory(current, hooks: hooks)
        }

        throw NativeAgentHostExecutableTrustError.noTrustedCandidate
    }

    private static func validateDirectory(
        _ path: String,
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws {
        let metadata = try hooks.lstat(path)
        guard metadata.fileType == UInt32(S_IFDIR),
              metadata.ownerUID == 0,
              metadata.mode & 0o022 == 0,
              !hooks.isWritable(path) else {
            throw NativeAgentHostExecutableTrustError.noTrustedCandidate
        }
    }

    private static func isReviewedAbsolutePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"),
              !path.hasSuffix("/"),
              !path.contains("\0"),
              !path.contains("//") else {
            return false
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        return components.dropFirst().allSatisfy { $0 != "." && $0 != ".." && !$0.isEmpty }
    }
}
