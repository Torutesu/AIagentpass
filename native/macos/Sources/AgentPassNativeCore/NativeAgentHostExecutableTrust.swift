import Darwin
import Foundation

internal struct NativeCursorAgentRuntimeFileIdentity: Equatable, Sendable {
    let relativePath: String
    let device: UInt64
    let inode: UInt64
    let size: UInt64
}

/// Identity of the complete runtime tree retained between initial resolution
/// and the spawn-adjacent revalidation.
internal struct NativeCursorAgentRuntimeSelection: Equatable, Sendable {
    let nodePath: String
    let indexPath: String
    let fileIdentities: [NativeCursorAgentRuntimeFileIdentity]
    let manifest: NativeCursorAgentRuntimeManifest

    var nodeDevice: UInt64 {
        fileIdentities.first { $0.relativePath == NativeCursorAgentRuntimeSpec.nodeRelativePath }?.device ?? 0
    }

    var nodeInode: UInt64 {
        fileIdentities.first { $0.relativePath == NativeCursorAgentRuntimeSpec.nodeRelativePath }?.inode ?? 0
    }

    var indexDevice: UInt64 {
        fileIdentities.first { $0.relativePath == NativeCursorAgentRuntimeSpec.indexRelativePath }?.device ?? 0
    }

    var indexInode: UInt64 {
        fileIdentities.first { $0.relativePath == NativeCursorAgentRuntimeSpec.indexRelativePath }?.inode ?? 0
    }

    var path: String { nodePath }
    var device: UInt64 { nodeDevice }
    var inode: UInt64 { nodeInode }
}

internal enum NativeAgentHostExecutableTrustError: Error, Equatable, Sendable {
    case noTrustedCandidate
    case identityChanged
}

/// Internal OS seams for deterministic runtime trust tests. Production code
/// obtains all of these closures from `system`; no launch request can provide
/// a runtime path, manifest, digest, or code identity.
internal struct NativeAgentHostExecutableTrustHooks: @unchecked Sendable {
    typealias LStatClosure = @Sendable (String) throws -> NativeAgentHostExecutableMetadata
    typealias AccessClosure = @Sendable (String) -> Bool
    typealias EnumerateClosure = @Sendable () throws -> [NativeCursorAgentRuntimeObservedFile]
    typealias DigestClosure = @Sendable (String) throws -> String
    typealias ManifestClosure = @Sendable () throws -> NativeCursorAgentRuntimeManifest
    typealias CodeIdentityClosure = @Sendable (String, NativeCursorAgentRuntimeCodeIdentityClaim) throws -> Void

    let lstat: LStatClosure
    let isExecutable: AccessClosure
    let isReadable: AccessClosure
    let isWritable: AccessClosure
    let hasExtendedACL: AccessClosure
    let enumerateRuntimeFiles: EnumerateClosure
    let digest: DigestClosure
    let loadRuntimeManifest: ManifestClosure
    let verifyCodeIdentity: CodeIdentityClosure

    init(
        lstat: @escaping LStatClosure,
        isExecutable: @escaping AccessClosure,
        isWritable: @escaping AccessClosure,
        hasExtendedACL: @escaping AccessClosure = { _ in false },
        isReadable: @escaping AccessClosure = { _ in true },
        enumerateRuntimeFiles: @escaping EnumerateClosure = {
            throw NativeCursorAgentRuntimeTrustError.inventoryUnavailable
        },
        digest: @escaping DigestClosure = { _ in
            throw NativeCursorAgentRuntimeTrustError.manifestUnavailable
        },
        loadRuntimeManifest: @escaping ManifestClosure = {
            throw NativeCursorAgentRuntimeTrustError.manifestUnavailable
        },
        verifyCodeIdentity: @escaping CodeIdentityClosure = { _, _ in }
    ) {
        self.lstat = lstat
        self.isExecutable = isExecutable
        self.isReadable = isReadable
        self.isWritable = isWritable
        self.hasExtendedACL = hasExtendedACL
        self.enumerateRuntimeFiles = enumerateRuntimeFiles
        self.digest = digest
        self.loadRuntimeManifest = loadRuntimeManifest
        self.verifyCodeIdentity = verifyCodeIdentity
    }

    static let system = Self(
        lstat: { path in
            var info = stat()
            guard path.withCString({ Darwin.lstat($0, &info) }) == 0 else {
                throw NativeCursorAgentRuntimeTrustError.artifactUnavailable
            }
            return NativeAgentHostExecutableMetadata(
                device: UInt64(info.st_dev),
                inode: UInt64(info.st_ino),
                ownerUID: UInt32(info.st_uid),
                mode: UInt32(info.st_mode),
                size: info.st_size >= 0 ? UInt64(info.st_size) : 0,
                linkCount: UInt64(info.st_nlink)
            )
        },
        isExecutable: { path in
            path.withCString { Darwin.access($0, X_OK) == 0 }
        },
        isWritable: { path in
            // A root supervisor owns the launch boundary. For a normal user,
            // access(2) also accounts for ACL grants hidden by st_mode.
            guard geteuid() != 0 else { return false }
            return path.withCString { Darwin.access($0, W_OK) == 0 }
        },
        hasExtendedACL: { path in
            NativeCursorAgentRuntimeACL.hasEntries(path: path)
        },
        isReadable: { path in
            path.withCString { Darwin.access($0, R_OK) == 0 }
        },
        enumerateRuntimeFiles: {
            try NativeCursorAgentRuntimeSystemEnumerator.enumerate()
        },
        digest: { path in
            try NativeCursorAgentRuntimeDigest.sha256(path: path)
        },
        loadRuntimeManifest: {
            try NativeCursorAgentRuntimeManifestLoader.load()
        },
        verifyCodeIdentity: { path, claim in
            try NativeCursorSystemCodeIdentityVerifier.verify(path: path, claim: claim)
        }
    )
}

internal struct NativeAgentHostExecutableMetadata: Equatable, Sendable {
    let device: UInt64
    let inode: UInt64
    let ownerUID: UInt32
    let mode: UInt32
    let size: UInt64
    let linkCount: UInt64

    init(
        device: UInt64,
        inode: UInt64,
        ownerUID: UInt32,
        mode: UInt32,
        size: UInt64 = 0,
        linkCount: UInt64 = 1
    ) {
        self.device = device
        self.inode = inode
        self.ownerUID = ownerUID
        self.mode = mode
        self.size = size
        self.linkCount = linkCount
    }

    var fileType: UInt32 { mode & UInt32(S_IFMT) }
}

/// The production recursive enumerator uses lstat for every item and only
/// descends after observing a real directory. Symlinks and other special
/// files are returned as observations so the trust layer can reject them;
/// they are never followed.
private enum NativeCursorAgentRuntimeSystemEnumerator {
    static func enumerate() throws -> [NativeCursorAgentRuntimeObservedFile] {
        var pending: [(path: String, relativePath: String)] = [
            (NativeCursorAgentRuntimeSpec.runtimeRoot, "")
        ]
        var observed: [NativeCursorAgentRuntimeObservedFile] = []

        while let directory = pending.popLast() {
            let directoryMetadata = try metadata(at: directory.path)
            try validateDirectory(directoryMetadata, path: directory.path)
            let names: [String]
            do {
                names = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
            } catch {
                throw NativeCursorAgentRuntimeTrustError.inventoryUnavailable
            }

            for name in names {
                let relativePath = directory.relativePath.isEmpty
                    ? name
                    : directory.relativePath + "/" + name
                guard NativeCursorAgentRuntimeManifestEntry.isCanonicalRelativePath(relativePath) else {
                    throw NativeCursorAgentRuntimeTrustError.inventoryMismatch
                }
                let path = NativeCursorAgentRuntimeSpec.runtimeRoot + "/" + relativePath
                let itemMetadata = try metadata(at: path)
                if itemMetadata.fileType == UInt32(S_IFDIR) {
                    observed.append(
                        NativeCursorAgentRuntimeObservedFile(
                            relativePath: relativePath,
                            metadata: itemMetadata
                        )
                    )
                    pending.append((path, relativePath))
                } else {
                    observed.append(
                        NativeCursorAgentRuntimeObservedFile(
                            relativePath: relativePath,
                            metadata: itemMetadata
                        )
                    )
                }
                guard observed.count <= NativeCursorAgentRuntimePolicy.maximumInventoryEntryCount else {
                    throw NativeCursorAgentRuntimeTrustError.inventoryMismatch
                }
            }
        }
        return observed
    }

    private static func metadata(at path: String) throws -> NativeAgentHostExecutableMetadata {
        var info = stat()
        guard path.withCString({ Darwin.lstat($0, &info) }) == 0 else {
            throw NativeCursorAgentRuntimeTrustError.inventoryUnavailable
        }
        return NativeAgentHostExecutableMetadata(
            device: UInt64(info.st_dev),
            inode: UInt64(info.st_ino),
            ownerUID: UInt32(info.st_uid),
            mode: UInt32(info.st_mode),
            size: info.st_size >= 0 ? UInt64(info.st_size) : 0,
            linkCount: UInt64(info.st_nlink)
        )
    }

    private static func validateDirectory(
        _ metadata: NativeAgentHostExecutableMetadata,
        path: String
    ) throws {
        guard metadata.fileType == UInt32(S_IFDIR),
              metadata.ownerUID == 0,
              metadata.mode & 0o022 == 0,
              !NativeCursorAgentRuntimeACL.hasEntries(path: path),
              !isWritable(path) else {
            throw NativeCursorAgentRuntimeTrustError.artifactInvalid
        }
    }

    private static func isWritable(_ path: String) -> Bool {
        guard geteuid() != 0 else { return false }
        return path.withCString { Darwin.access($0, W_OK) == 0 }
    }
}

/// Filesystem, inventory, digest, and manifest trust for the fixed AgentPass
/// runtime. The manifest and the observed tree must be exactly equal; every
/// file is checked before the Host can spawn the fixed node entrypoint.
internal enum NativeCursorAgentRuntimeTrust {
    static func resolve() throws -> NativeCursorAgentRuntimeSelection {
        try resolve(hooks: .system)
    }

    static func resolve(
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws -> NativeCursorAgentRuntimeSelection {
        let manifest = try hooks.loadRuntimeManifest()
        let observed = try hooks.enumerateRuntimeFiles()
        guard observed.count <= NativeCursorAgentRuntimePolicy.maximumInventoryEntryCount else {
            throw NativeCursorAgentRuntimeTrustError.inventoryMismatch
        }

        var observedByPath: [String: NativeCursorAgentRuntimeObservedFile] = [:]
        var observedDirectories = Set<String>()
        var allObservedPaths = Set<String>()
        for item in observed {
            guard NativeCursorAgentRuntimeManifestEntry.isCanonicalRelativePath(item.relativePath),
                  allObservedPaths.insert(item.relativePath).inserted else {
                throw NativeCursorAgentRuntimeTrustError.inventoryMismatch
            }
            let path = absolutePath(for: item.relativePath)
            if item.metadata.fileType == UInt32(S_IFDIR) {
                guard item.metadata.ownerUID == 0,
                      item.metadata.mode & 0o022 == 0,
                      !hooks.hasExtendedACL(path),
                      !hooks.isWritable(path),
                      observedDirectories.insert(item.relativePath).inserted,
                      observedDirectories.count <= NativeCursorAgentRuntimePolicy.maximumDirectoryCount else {
                    throw NativeCursorAgentRuntimeTrustError.inventoryMismatch
                }
            } else {
                guard item.metadata.fileType == UInt32(S_IFREG),
                      item.metadata.ownerUID == 0,
                      item.metadata.mode & 0o022 == 0,
                      item.metadata.size <= NativeCursorAgentRuntimePolicy.maximumFileSize,
                      item.metadata.linkCount == 1,
                      !hooks.hasExtendedACL(path),
                      !hooks.isWritable(path),
                      observedByPath[item.relativePath] == nil,
                      observedByPath.count < NativeCursorAgentRuntimePolicy.maximumFileCount else {
                    throw NativeCursorAgentRuntimeTrustError.inventoryMismatch
                }
                observedByPath[item.relativePath] = item
            }
        }

        guard Set(observedByPath.keys) == Set(manifest.entries.map(\.relativePath)),
              observedDirectories == expectedDirectories(for: manifest.entries) else {
            throw NativeCursorAgentRuntimeTrustError.inventoryMismatch
        }

        var totalSize: UInt64 = 0
        var identities: [NativeCursorAgentRuntimeFileIdentity] = []
        for entry in manifest.entries {
            guard let observed = observedByPath[entry.relativePath],
                  observed.metadata.fileType == UInt32(S_IFREG),
                  observed.metadata.size == entry.size,
                  (observed.metadata.mode & 0o111 != 0) == entry.isExecutable,
                  totalSize <= NativeCursorAgentRuntimePolicy.maximumTotalSize - entry.size else {
                throw NativeCursorAgentRuntimeTrustError.inventoryMismatch
            }

            let path = absolutePath(for: entry.relativePath)
            let metadata = try validateFile(
                path,
                expected: entry,
                hooks: hooks
            )
            try verifyArtifact(
                path: path,
                expectedDigest: entry.sha256,
                codeIdentity: entry.relativePath == NativeCursorAgentRuntimeSpec.nodeRelativePath
                    ? manifest.nodeCodeIdentity
                    : nil,
                hooks: hooks
            )
            totalSize += entry.size
            identities.append(
                NativeCursorAgentRuntimeFileIdentity(
                    relativePath: entry.relativePath,
                    device: metadata.device,
                    inode: metadata.inode,
                    size: metadata.size
                )
            )
        }

        return NativeCursorAgentRuntimeSelection(
            nodePath: NativeCursorAgentRuntimeSpec.nodePath,
            indexPath: NativeCursorAgentRuntimeSpec.indexPath,
            fileIdentities: identities,
            manifest: manifest
        )
    }

    static func revalidate(
        _ selection: NativeCursorAgentRuntimeSelection,
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws {
        let current = try resolve(hooks: hooks)
        guard current.manifest == selection.manifest,
              current.fileIdentities == selection.fileIdentities else {
            throw NativeAgentHostExecutableTrustError.identityChanged
        }
    }

    private static func verifyArtifact(
        path: String,
        expectedDigest: String,
        codeIdentity: NativeCursorAgentRuntimeCodeIdentityClaim?,
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws {
        guard try hooks.digest(path).lowercased() == expectedDigest.lowercased() else {
            throw NativeCursorAgentRuntimeTrustError.digestMismatch
        }
        if let codeIdentity {
            try hooks.verifyCodeIdentity(path, codeIdentity)
        }
    }

    private static func validateFile(
        _ path: String,
        expected: NativeCursorAgentRuntimeManifestEntry,
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws -> NativeAgentHostExecutableMetadata {
        guard isCanonicalAbsolutePath(path) else {
            throw NativeCursorAgentRuntimeTrustError.artifactInvalid
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        guard !components.isEmpty else {
            throw NativeCursorAgentRuntimeTrustError.artifactInvalid
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
                      metadata.size == expected.size,
                      metadata.linkCount == 1,
                      !hooks.hasExtendedACL(current),
                      !hooks.isWritable(current),
                      hooks.isReadable(current) else {
                    throw NativeCursorAgentRuntimeTrustError.artifactInvalid
                }
                if expected.isExecutable {
                    guard metadata.mode & 0o111 != 0,
                          hooks.isExecutable(current) else {
                        throw NativeCursorAgentRuntimeTrustError.artifactInvalid
                    }
                } else {
                    guard metadata.mode & 0o111 == 0 else {
                        throw NativeCursorAgentRuntimeTrustError.artifactInvalid
                    }
                }
                return metadata
            }
            try validateDirectory(current, hooks: hooks)
        }
        throw NativeCursorAgentRuntimeTrustError.artifactInvalid
    }

    private static func validateDirectory(
        _ path: String,
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws {
        let metadata = try hooks.lstat(path)
        guard metadata.fileType == UInt32(S_IFDIR),
              metadata.ownerUID == 0,
              metadata.mode & 0o022 == 0,
              !hooks.hasExtendedACL(path),
              !hooks.isWritable(path) else {
            throw NativeCursorAgentRuntimeTrustError.artifactInvalid
        }
    }

    private static func absolutePath(for relativePath: String) -> String {
        NativeCursorAgentRuntimeSpec.runtimeRoot + "/" + relativePath
    }

    private static func expectedDirectories(
        for entries: [NativeCursorAgentRuntimeManifestEntry]
    ) -> Set<String> {
        var result = Set<String>()
        for entry in entries {
            let components = entry.relativePath.split(separator: "/")
            guard components.count > 1 else { continue }
            for count in 1..<components.count {
                result.insert(components.prefix(count).joined(separator: "/"))
            }
        }
        return result
    }

    private static func isCanonicalAbsolutePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"),
              !path.hasSuffix("/"),
              !path.contains("\0"),
              !path.contains("//") else {
            return false
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        return components.first?.isEmpty == true
            && components.dropFirst().allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }
}

/// Compatibility-named internal boundary used by the Host. Its candidate set
/// is now exactly the managed runtime entrypoints, never Cursor launchers.
internal enum NativeAgentHostExecutableTrust {
    static let cursorExecutableCandidates = NativeCursorAgentRuntimeSpec.requiredPaths

    static func resolveCursorExecutable() throws -> NativeCursorAgentRuntimeSelection {
        do {
            return try NativeCursorAgentRuntimeTrust.resolve()
        } catch {
            throw NativeAgentHostExecutableTrustError.noTrustedCandidate
        }
    }

    static func resolveCursorExecutable(
        candidates: [String],
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws -> NativeCursorAgentRuntimeSelection {
        guard candidates == cursorExecutableCandidates else {
            throw NativeAgentHostExecutableTrustError.noTrustedCandidate
        }
        do {
            return try NativeCursorAgentRuntimeTrust.resolve(hooks: hooks)
        } catch {
            throw NativeAgentHostExecutableTrustError.noTrustedCandidate
        }
    }

    static func revalidate(_ selection: NativeCursorAgentRuntimeSelection) throws {
        do {
            try NativeCursorAgentRuntimeTrust.revalidate(selection, hooks: .system)
        } catch NativeAgentHostExecutableTrustError.identityChanged {
            throw NativeAgentHostExecutableTrustError.identityChanged
        } catch {
            throw NativeAgentHostExecutableTrustError.noTrustedCandidate
        }
    }

    static func revalidate(
        _ selection: NativeCursorAgentRuntimeSelection,
        hooks: NativeAgentHostExecutableTrustHooks
    ) throws {
        do {
            try NativeCursorAgentRuntimeTrust.revalidate(selection, hooks: hooks)
        } catch NativeAgentHostExecutableTrustError.identityChanged {
            throw NativeAgentHostExecutableTrustError.identityChanged
        } catch {
            throw NativeAgentHostExecutableTrustError.noTrustedCandidate
        }
    }
}

private enum NativeCursorAgentRuntimeACL {
    static func hasEntries(path: String) -> Bool {
        let acl = path.withCString { acl_get_file($0, ACL_TYPE_EXTENDED) }
        guard let acl else {
            // ENOENT/ENOATTR means this path has no extended ACL. Any other
            // inspection failure is not proof that no write grant exists.
            return errno != ENOENT && errno != ENOATTR
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        return acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == 0
    }
}
