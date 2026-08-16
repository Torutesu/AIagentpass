import CryptoKit
import Darwin
import Foundation
import Security

/// Fixed AgentPass-managed Cursor Agent materialization layout.
///
/// The official Cursor shell launcher is intentionally not part of this
/// layout. It can install or execute a user-home `cursor-agent`, so the Host
/// launches the sibling Node runtime directly with the sibling index file.
internal enum NativeCursorAgentRuntimeSpec {
    static let runtimeRoot = "/Library/Application Support/AgentPass/CursorAgent/runtime"
    static let nodePath = runtimeRoot + "/node"
    static let indexPath = runtimeRoot + "/index.js"
    static let nodeRelativePath = "node"
    static let indexRelativePath = "index.js"
    static let requiredRelativePaths = [nodeRelativePath, indexRelativePath]
    static let requiredPaths = [nodePath, indexPath]
    static let fixedArguments = ["--use-system-ca", indexPath]
    static let invokedAsEnvironmentKey = "CURSOR_INVOKED_AS"
    static let invokedAsEnvironmentValue = "cursor-agent"
    static let fixedEnvironment = [
        invokedAsEnvironmentKey: invokedAsEnvironmentValue
    ]
}

/// Bounds are policy limits, not release metadata. They leave room for the
/// current multi-file runtime while preventing an unbounded traversal or
/// digest workload.
internal enum NativeCursorAgentRuntimePolicy {
    static let maximumFileCount = 4_096
    static let maximumDirectoryCount = 4_096
    static let maximumInventoryEntryCount = maximumFileCount + maximumDirectoryCount
    static let maximumFileSize: UInt64 = 256 * 1024 * 1024
    static let maximumTotalSize: UInt64 = 512 * 1024 * 1024
}

internal struct NativeCursorAgentRuntimeCodeIdentityClaim: Equatable, Sendable {
    let identifier: String
    let teamIdentifier: String
    let designatedRequirement: String
}

/// One closed-inventory file entry supplied by the trusted materializer.
/// `isRegularFile` is retained in the wire contract so a malformed manifest
/// cannot silently turn a directory or special file into a runtime member.
internal struct NativeCursorAgentRuntimeManifestEntry: Equatable, Sendable {
    let relativePath: String
    let sha256: String
    let size: UInt64
    let isExecutable: Bool
    let isRegularFile: Bool

    init(
        relativePath: String,
        sha256: String,
        size: UInt64,
        isExecutable: Bool,
        isRegularFile: Bool = true
    ) throws {
        guard Self.isCanonicalRelativePath(relativePath),
              Self.isSHA256(sha256),
              isRegularFile,
              size <= NativeCursorAgentRuntimePolicy.maximumFileSize else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }
        self.relativePath = relativePath
        self.sha256 = sha256.lowercased()
        self.size = size
        self.isExecutable = isExecutable
        self.isRegularFile = isRegularFile
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.utf8.count == 64
            && value.range(of: "^[0-9a-fA-F]{64}$", options: .regularExpression) != nil
    }

    static func isCanonicalRelativePath(_ path: String) -> Bool {
        guard !path.isEmpty,
              !path.contains("\0"),
              !path.hasPrefix("/"),
              !path.hasSuffix("/"),
              !path.contains("//") else {
            return false
        }
        return path.split(separator: "/", omittingEmptySubsequences: false)
            .allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }
}

/// A filesystem item returned by the injected recursive runtime enumerator.
/// The production enumerator uses lstat and never follows a symlink.
internal struct NativeCursorAgentRuntimeObservedFile: Equatable, Sendable {
    let relativePath: String
    let metadata: NativeAgentHostExecutableMetadata
}

/// Release materialization contract for the complete fixed runtime.
///
/// The trusted provisioner must enumerate every runtime file. A missing,
/// extra, duplicate, malformed, or non-regular item is a denial. No release
/// digest is embedded in this source tree; a missing manifest is a production
/// denial. The optional identity claim applies only to the Node entrypoint;
/// tree closure and per-file digests remain mandatory for every entry.
internal struct NativeCursorAgentRuntimeManifest: Equatable, Sendable {
    let entries: [NativeCursorAgentRuntimeManifestEntry]
    let nodeCodeIdentity: NativeCursorAgentRuntimeCodeIdentityClaim?

    init(
        entries: [NativeCursorAgentRuntimeManifestEntry],
        nodeCodeIdentity: NativeCursorAgentRuntimeCodeIdentityClaim? = nil
    ) throws {
        guard !entries.isEmpty,
              entries.count <= NativeCursorAgentRuntimePolicy.maximumFileCount else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }

        var paths = Set<String>()
        var totalSize: UInt64 = 0
        for entry in entries {
            guard paths.insert(entry.relativePath).inserted,
                  entry.isRegularFile,
                  entry.size <= NativeCursorAgentRuntimePolicy.maximumFileSize,
                  totalSize <= NativeCursorAgentRuntimePolicy.maximumTotalSize - entry.size else {
                throw NativeCursorAgentRuntimeTrustError.invalidManifest
            }
            totalSize += entry.size
        }

        guard NativeCursorAgentRuntimeSpec.requiredRelativePaths.allSatisfy(paths.contains),
              entries.first(where: { $0.relativePath == NativeCursorAgentRuntimeSpec.nodeRelativePath })?.isExecutable == true else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }

        self.entries = entries.sorted { $0.relativePath < $1.relativePath }
        self.nodeCodeIdentity = nodeCodeIdentity
    }

    func entry(for relativePath: String) -> NativeCursorAgentRuntimeManifestEntry? {
        entries.first { $0.relativePath == relativePath }
    }
}

internal enum NativeCursorAgentRuntimeTrustError: Error, Equatable, Sendable {
    case manifestUnavailable
    case invalidManifest
    case artifactUnavailable
    case artifactInvalid
    case inventoryUnavailable
    case inventoryMismatch
    case digestUnavailable
    case digestMismatch
    case codeIdentityMismatch
}

/// Security.framework verifier for an identity claim provisioned with the
/// runtime manifest. This is never called with caller-provided identity data.
internal enum NativeCursorSystemCodeIdentityVerifier {
    private static let strictValidationFlags = SecCSFlags(
        rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode
    )

    static func verify(
        path: String,
        claim: NativeCursorAgentRuntimeCodeIdentityClaim
    ) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            URL(fileURLWithPath: path).standardizedFileURL as CFURL,
            [],
            &code
        ) == errSecSuccess,
        let code else {
            throw NativeCursorAgentRuntimeTrustError.artifactUnavailable
        }

        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            claim.designatedRequirement as CFString,
            [],
            &requirement
        ) == errSecSuccess,
        let requirement,
        SecStaticCodeCheckValidity(code, strictValidationFlags, requirement) == errSecSuccess else {
            throw NativeCursorAgentRuntimeTrustError.codeIdentityMismatch
        }

        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
        let rawInformation,
        let information = rawInformation as? [String: Any],
        information[kSecCodeInfoIdentifier as String] as? String == claim.identifier,
        information[kSecCodeInfoTeamIdentifier as String] as? String == claim.teamIdentifier else {
            throw NativeCursorAgentRuntimeTrustError.codeIdentityMismatch
        }

        guard let rawDesignatedRequirement = information[
            kSecCodeInfoDesignatedRequirement as String
        ],
        CFGetTypeID(rawDesignatedRequirement as CFTypeRef) == SecRequirementGetTypeID() else {
            throw NativeCursorAgentRuntimeTrustError.codeIdentityMismatch
        }
        let designatedRequirement = unsafeBitCast(
            rawDesignatedRequirement as CFTypeRef,
            to: SecRequirement.self
        )
        guard let actual = requirementString(designatedRequirement),
              let expected = requirementString(requirement),
              actual == expected else {
            throw NativeCursorAgentRuntimeTrustError.codeIdentityMismatch
        }
    }

    private static func requirementString(_ requirement: SecRequirement) -> String? {
        var output: CFString?
        guard SecRequirementCopyString(requirement, SecCSFlags(), &output) == errSecSuccess,
              let output else {
            return nil
        }
        return output as String
    }
}

internal enum NativeCursorAgentRuntimeDigest {
    static func sha256(path: String) throws -> String {
        let descriptor = path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw NativeCursorAgentRuntimeTrustError.digestUnavailable
        }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard fstat(descriptor, &before) == 0,
              UInt32(before.st_mode) & UInt32(S_IFMT) == UInt32(S_IFREG),
              before.st_size >= 0,
              UInt64(before.st_size) <= NativeCursorAgentRuntimePolicy.maximumFileSize else {
            throw NativeCursorAgentRuntimeTrustError.digestUnavailable
        }

        var hasher = SHA256()
        var total: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            guard count > 0 else {
                if errno == EINTR { continue }
                throw NativeCursorAgentRuntimeTrustError.digestUnavailable
            }
            guard total <= NativeCursorAgentRuntimePolicy.maximumFileSize - UInt64(count) else {
                throw NativeCursorAgentRuntimeTrustError.digestUnavailable
            }
            total += UInt64(count)
            hasher.update(data: Data(buffer[0..<Int(count)]))
        }

        var after = stat()
        guard fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              total == UInt64(before.st_size) else {
            throw NativeCursorAgentRuntimeTrustError.digestUnavailable
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
