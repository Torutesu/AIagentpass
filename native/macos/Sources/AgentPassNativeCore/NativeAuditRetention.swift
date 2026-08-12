import CryptoKit
import Darwin
import Foundation

/// Immutable evidence for one independently archived audit/checkpoint/receipt set.
/// Files are names, never paths: callers must resolve them inside already trusted archive roots.
public struct NativeAuditRetentionSegment: Codable, Equatable, Sendable {
    public let segmentID: String
    public let auditArchiveFile: String
    public let auditArchiveSHA256: String
    public let firstEventIndex: Int
    public let lastEventIndex: Int
    public let previousEventHash: String
    public let terminalEventHash: String
    public let checkpointArchiveFile: String
    public let checkpointArchiveSHA256: String
    public let firstCheckpointIndex: Int
    public let lastCheckpointIndex: Int
    public let previousCheckpointHash: String
    public let terminalCheckpointHash: String
    public let receiptArchiveFile: String
    public let receiptArchiveSHA256: String
    public let firstReceiptIndex: Int
    public let lastReceiptIndex: Int
    public let previousReceiptHash: String
    public let terminalReceiptHash: String
    public let anchoredEventIndex: Int
    public let anchoredEventHash: String
    public let sealedAt: String
    public let latestAnchorReceivedAt: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case segmentID = "segment_id"
        case auditArchiveFile = "audit_archive_file"
        case auditArchiveSHA256 = "audit_archive_sha256"
        case firstEventIndex = "first_event_index"
        case lastEventIndex = "last_event_index"
        case previousEventHash = "previous_event_hash"
        case terminalEventHash = "terminal_event_hash"
        case checkpointArchiveFile = "checkpoint_archive_file"
        case checkpointArchiveSHA256 = "checkpoint_archive_sha256"
        case firstCheckpointIndex = "first_checkpoint_index"
        case lastCheckpointIndex = "last_checkpoint_index"
        case previousCheckpointHash = "previous_checkpoint_hash"
        case terminalCheckpointHash = "terminal_checkpoint_hash"
        case receiptArchiveFile = "receipt_archive_file"
        case receiptArchiveSHA256 = "receipt_archive_sha256"
        case firstReceiptIndex = "first_receipt_index"
        case lastReceiptIndex = "last_receipt_index"
        case previousReceiptHash = "previous_receipt_hash"
        case terminalReceiptHash = "terminal_receipt_hash"
        case anchoredEventIndex = "anchored_event_index"
        case anchoredEventHash = "anchored_event_hash"
        case sealedAt = "sealed_at"
        case latestAnchorReceivedAt = "latest_anchor_received_at"
    }

    public init(segmentID: String, auditArchiveFile: String, auditArchiveSHA256: String, firstEventIndex: Int, lastEventIndex: Int, previousEventHash: String, terminalEventHash: String, checkpointArchiveFile: String, checkpointArchiveSHA256: String, firstCheckpointIndex: Int, lastCheckpointIndex: Int, previousCheckpointHash: String, terminalCheckpointHash: String, receiptArchiveFile: String, receiptArchiveSHA256: String, firstReceiptIndex: Int, lastReceiptIndex: Int, previousReceiptHash: String, terminalReceiptHash: String, anchoredEventIndex: Int, anchoredEventHash: String, sealedAt: String, latestAnchorReceivedAt: String) {
        self.segmentID = segmentID; self.auditArchiveFile = auditArchiveFile; self.auditArchiveSHA256 = auditArchiveSHA256
        self.firstEventIndex = firstEventIndex; self.lastEventIndex = lastEventIndex; self.previousEventHash = previousEventHash; self.terminalEventHash = terminalEventHash
        self.checkpointArchiveFile = checkpointArchiveFile; self.checkpointArchiveSHA256 = checkpointArchiveSHA256
        self.firstCheckpointIndex = firstCheckpointIndex; self.lastCheckpointIndex = lastCheckpointIndex; self.previousCheckpointHash = previousCheckpointHash; self.terminalCheckpointHash = terminalCheckpointHash
        self.receiptArchiveFile = receiptArchiveFile; self.receiptArchiveSHA256 = receiptArchiveSHA256
        self.firstReceiptIndex = firstReceiptIndex; self.lastReceiptIndex = lastReceiptIndex; self.previousReceiptHash = previousReceiptHash; self.terminalReceiptHash = terminalReceiptHash
        self.anchoredEventIndex = anchoredEventIndex; self.anchoredEventHash = anchoredEventHash; self.sealedAt = sealedAt; self.latestAnchorReceivedAt = latestAnchorReceivedAt
    }
}

public struct NativeAuditRetentionBoundary: Codable, Equatable, Sendable {
    public let lifecycleHeadHash: String
    public let auditKeyTransitionReceiptHash: String
    public let anchorEventIndex: Int
    public let anchorEventHash: String
    public let checkpointIndex: Int
    public let checkpointHash: String
    public let checkpointReceiptHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case lifecycleHeadHash = "lifecycle_head_hash"
        case auditKeyTransitionReceiptHash = "audit_key_transition_receipt_hash"
        case anchorEventIndex = "anchor_event_index"
        case anchorEventHash = "anchor_event_hash"
        case checkpointIndex = "checkpoint_index"
        case checkpointHash = "checkpoint_hash"
        case checkpointReceiptHash = "checkpoint_receipt_hash"
    }

    public init(lifecycleHeadHash: String, auditKeyTransitionReceiptHash: String, anchorEventIndex: Int, anchorEventHash: String, checkpointIndex: Int, checkpointHash: String, checkpointReceiptHash: String) {
        self.lifecycleHeadHash = lifecycleHeadHash; self.auditKeyTransitionReceiptHash = auditKeyTransitionReceiptHash
        self.anchorEventIndex = anchorEventIndex; self.anchorEventHash = anchorEventHash
        self.checkpointIndex = checkpointIndex; self.checkpointHash = checkpointHash; self.checkpointReceiptHash = checkpointReceiptHash
    }
}

public struct NativeAuditPruneAuthorization: Codable, Equatable, Sendable {
    public static let version = 1
    public let version: Int
    public let tenant: String
    public let operationID: String
    public let sequence: Int
    public let previousAuthorizationHash: String
    public let previousPruneReceiptHash: String
    public let previousManifestHash: String
    public let retentionSeconds: Int
    public let requestedAt: String
    public let boundary: NativeAuditRetentionBoundary
    public let segments: [NativeAuditRetentionSegment]
    public let signerFingerprint: String
    public let signature: String
    public let authorizationHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, tenant, sequence, segments, signature
        case operationID = "operation_id"
        case previousAuthorizationHash = "previous_authorization_hash"
        case previousPruneReceiptHash = "previous_prune_receipt_hash"
        case previousManifestHash = "previous_manifest_hash"
        case retentionSeconds = "retention_seconds"
        case requestedAt = "requested_at"
        case boundary
        case signerFingerprint = "signer_fingerprint"
        case authorizationHash = "authorization_hash"
    }

    public static func create(tenant: String, operationID: String, sequence: Int, previousAuthorizationHash: String = NativeAuditLog.zeroHash, previousPruneReceiptHash: String = NativeAuditLog.zeroHash, previousManifestHash: String = NativeAuditLog.zeroHash, retentionSeconds: Int, requestedAt: String, boundary: NativeAuditRetentionBoundary, segments: [NativeAuditRetentionSegment], signer: P256MessageSigner) throws -> Self {
        let fingerprint = NativeAuditCheckpoints.fingerprint(signer.publicKeyX963)
        var object = try NativeAuditRetentionCodec.authorizationObject(version: version, tenant: tenant, operationID: operationID, sequence: sequence, previousAuthorizationHash: previousAuthorizationHash, previousPruneReceiptHash: previousPruneReceiptHash, previousManifestHash: previousManifestHash, retentionSeconds: retentionSeconds, requestedAt: requestedAt, boundary: boundary, segments: segments, signerFingerprint: fingerprint)
        let signatureData = try NativeP256CanonicalSignature.canonicalized(signer.sign(message: NativeAuditLog.canonical(object)))
        guard signatureData.count == 64 else { throw AgentPassNativeError.invalidSignature("Audit prune authorization signature must be a raw P-256 signature") }
        let signature = signatureData.base64EncodedString()
        object["signature"] = signature
        let hash = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
        return Self(version: version, tenant: tenant, operationID: operationID, sequence: sequence, previousAuthorizationHash: previousAuthorizationHash, previousPruneReceiptHash: previousPruneReceiptHash, previousManifestHash: previousManifestHash, retentionSeconds: retentionSeconds, requestedAt: requestedAt, boundary: boundary, segments: segments, signerFingerprint: fingerprint, signature: signature, authorizationHash: hash)
    }

    public func canonicalData() throws -> Data { try NativeAuditRetentionCodec.encodeAuthorization(self) }

    public static func decodeCanonical(_ data: Data) throws -> Self {
        try NativeAuditRetentionCodec.decode(Self.self, data: data, keys: Set(CodingKeys.allCases.map(\.stringValue)), label: "Audit prune authorization") { try $0.canonicalData() }
    }
}

/// External-anchor acknowledgement. Its append-only chain is independent from local manifests.
public struct NativeAuditPruneReceipt: Codable, Equatable, Sendable {
    public static let version = 1
    public let version: Int
    public let tenant: String
    public let sequence: Int
    public let authorizationHash: String
    public let previousReceiptHash: String
    public let anchorEventIndex: Int
    public let previousAnchorEventHash: String
    public let receivedAt: String
    public let anchorKeyFingerprint: String
    public let signature: String
    public let receiptHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, tenant, sequence, signature
        case authorizationHash = "authorization_hash"
        case previousReceiptHash = "previous_receipt_hash"
        case anchorEventIndex = "anchor_event_index"
        case previousAnchorEventHash = "previous_anchor_event_hash"
        case receivedAt = "received_at"
        case anchorKeyFingerprint = "anchor_key_fingerprint"
        case receiptHash = "receipt_hash"
    }

    public func canonicalData() throws -> Data { try NativeAuditRetentionCodec.encodeReceipt(self) }
    public static func decodeCanonical(_ data: Data) throws -> Self {
        try NativeAuditRetentionCodec.decode(Self.self, data: data, keys: Set(CodingKeys.allCases.map(\.stringValue)), label: "Audit prune receipt") { try $0.canonicalData() }
    }
}

public struct NativeAuditPruneChainState: Equatable, Sendable {
    public let sequence: Int
    public let authorizationHash: String
    public let receiptHash: String
    public let manifestHash: String
    public let lastEventIndex: Int
    public let lastCheckpointIndex: Int
    public let lastReceiptIndex: Int
    public let lastEventHash: String
    public let lastCheckpointHash: String
    public let lastArchiveReceiptHash: String

    public init(sequence: Int = 0, authorizationHash: String = NativeAuditLog.zeroHash, receiptHash: String = NativeAuditLog.zeroHash, manifestHash: String = NativeAuditLog.zeroHash, lastEventIndex: Int = 0, lastCheckpointIndex: Int = 0, lastReceiptIndex: Int = 0, lastEventHash: String = NativeAuditLog.zeroHash, lastCheckpointHash: String = NativeAuditLog.zeroHash, lastArchiveReceiptHash: String = NativeAuditLog.zeroHash) {
        self.sequence = sequence; self.authorizationHash = authorizationHash; self.receiptHash = receiptHash; self.manifestHash = manifestHash
        self.lastEventIndex = lastEventIndex; self.lastCheckpointIndex = lastCheckpointIndex; self.lastReceiptIndex = lastReceiptIndex
        self.lastEventHash = lastEventHash; self.lastCheckpointHash = lastCheckpointHash; self.lastArchiveReceiptHash = lastArchiveReceiptHash
    }
}

/// A measured archive set. Construction proves that the bytes opened by the caller under its
/// trusted archive roots match all three hashes in `segment`; the raw bytes are not retained.
public struct NativeAuditRetentionArchiveObservation: Equatable, Sendable {
    public static let maximumArchiveBytes = 128 * 1024 * 1024
    public let segment: NativeAuditRetentionSegment
    public let auditArchiveBytes: Int
    public let checkpointArchiveBytes: Int
    public let receiptArchiveBytes: Int
    /// Present only when the observation was made from descriptor-relative filesystem reads.
    /// A deletion executor rejects legacy/data-only observations.
    public let fileIdentities: [NativeAuditRetentionFileIdentity]?

    public init(segment: NativeAuditRetentionSegment, auditArchiveData: Data, checkpointArchiveData: Data, receiptArchiveData: Data) throws {
        try NativeAuditRetentionCodec.validateSegment(segment)
        guard !auditArchiveData.isEmpty, !checkpointArchiveData.isEmpty, !receiptArchiveData.isEmpty,
              auditArchiveData.count <= Self.maximumArchiveBytes, checkpointArchiveData.count <= Self.maximumArchiveBytes, receiptArchiveData.count <= Self.maximumArchiveBytes,
              NativeAuditLog.hash(auditArchiveData) == segment.auditArchiveSHA256,
              NativeAuditLog.hash(checkpointArchiveData) == segment.checkpointArchiveSHA256,
              NativeAuditLog.hash(receiptArchiveData) == segment.receiptArchiveSHA256 else {
            throw AgentPassNativeError.invalidSignature("Observed audit archive bytes do not match their retention evidence")
        }
        self.segment = segment; auditArchiveBytes = auditArchiveData.count
        checkpointArchiveBytes = checkpointArchiveData.count; receiptArchiveBytes = receiptArchiveData.count
        fileIdentities = nil
    }

    public static func observe(archiveDirectory: String, segment: NativeAuditRetentionSegment) throws -> Self {
        try NativeAuditRetentionCodec.validateSegment(segment)
        let directory = try NativeAuditPruneFileSystem.openTrustedDirectory(archiveDirectory, label: "Audit archive")
        defer { close(directory.descriptor) }
        let specifications = [
            (segment.auditArchiveFile, segment.auditArchiveSHA256),
            (segment.checkpointArchiveFile, segment.checkpointArchiveSHA256),
            (segment.receiptArchiveFile, segment.receiptArchiveSHA256),
        ]
        let identities = try specifications.map {
            try NativeAuditPruneFileSystem.observeFile(directoryFD: directory.descriptor, name: $0.0, expectedHash: $0.1)
        }
        return Self(
            segment: segment,
            auditArchiveBytes: identities[0].size,
            checkpointArchiveBytes: identities[1].size,
            receiptArchiveBytes: identities[2].size,
            fileIdentities: identities
        )
    }

    private init(segment: NativeAuditRetentionSegment, auditArchiveBytes: Int, checkpointArchiveBytes: Int, receiptArchiveBytes: Int, fileIdentities: [NativeAuditRetentionFileIdentity]) {
        self.segment = segment
        self.auditArchiveBytes = auditArchiveBytes
        self.checkpointArchiveBytes = checkpointArchiveBytes
        self.receiptArchiveBytes = receiptArchiveBytes
        self.fileIdentities = fileIdentities
    }
}

public struct NativeAuditRetentionFileIdentity: Codable, Equatable, Sendable {
    public let name: String
    public let device: UInt64
    public let inode: UInt64
    public let mode: UInt32
    public let owner: UInt32
    public let group: UInt32
    public let linkCount: UInt64
    public let size: Int
    public let sha256: String
}

/// Pins the exact retained archive inodes used to authorize deletion of a retired audit key.
///
/// The directory and all three regular files stay open for the lifetime of this object.  A
/// caller must also invoke `revalidate()` immediately before and after the irreversible key
/// operation; that check proves both that the open bytes are unchanged and that every trusted
/// archive name still resolves to the same inode.  This closes the gap between bundle parsing
/// and Keychain deletion without following attacker-controlled links or refreshed paths.
public final class NativeAuditRetainedArchiveLease: @unchecked Sendable {
    private struct DirectoryIdentity {
        let device: UInt64
        let inode: UInt64
        let mode: UInt32
        let owner: UInt32
        let group: UInt32
        let linkCount: UInt64
    }

    private struct OpenDirectoryComponent {
        let descriptor: Int32
        /// Nil only for the fixed trust root (`/`).
        let basename: String?
        let identity: DirectoryIdentity
    }

    private struct OpenFile {
        let descriptor: Int32
        let identity: NativeAuditRetentionFileIdentity
    }

    private let directoryChain: [OpenDirectoryComponent]
    private let vnodeQueueDescriptor: Int32
    private let files: [OpenFile]
    public let pathChainHash: String
    private let lock = NSLock()
    private var topologyInvalidated = false

    private var directoryDescriptor: Int32 { directoryChain.last!.descriptor }

    public init(
        archiveDirectory: String,
        segment: NativeAuditRetentionSegment,
        expectedFileIdentities: [NativeAuditRetentionFileIdentity]
    ) throws {
        try NativeAuditRetentionCodec.validateSegment(segment)
        guard expectedFileIdentities.count == 3,
              expectedFileIdentities.map(\.name) == [
                segment.auditArchiveFile, segment.checkpointArchiveFile, segment.receiptArchiveFile,
              ],
              expectedFileIdentities.map(\.sha256) == [
                segment.auditArchiveSHA256, segment.checkpointArchiveSHA256, segment.receiptArchiveSHA256,
              ],
              Set(expectedFileIdentities.map(\.name)).count == 3 else {
            throw AgentPassNativeError.invalidSignature("Retained archive lease does not bind the exact retained segment")
        }

        let components = try Self.absoluteDirectoryComponents(archiveDirectory)
        let queue = kqueue()
        guard queue >= 0 else { throw Self.posixError() }
        var openedDirectories: [OpenDirectoryComponent] = []
        var opened: [OpenFile] = []
        do {
            let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0 else { throw Self.posixError() }
            let rootComponent = try Self.openDirectoryComponent(descriptor: root, basename: nil, parentDescriptor: nil)
            openedDirectories.append(rootComponent)
            try Self.monitorTopology(of: root, queue: queue)

            for basename in components {
                let parent = openedDirectories.last!.descriptor
                let descriptor = openat(parent, basename, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard descriptor >= 0 else { throw Self.posixError() }
                do {
                    let component = try Self.openDirectoryComponent(
                        descriptor: descriptor,
                        basename: basename,
                        parentDescriptor: parent
                    )
                    openedDirectories.append(component)
                    try Self.monitorTopology(of: descriptor, queue: queue)
                } catch {
                    close(descriptor)
                    throw error
                }
            }
            guard let archive = openedDirectories.last,
                  archive.identity.owner == geteuid(), archive.identity.mode & 0o077 == 0 else {
                throw AgentPassNativeError.invalidConfiguration("Retained audit archive must be a private service-owned directory")
            }
            for identity in expectedFileIdentities {
                let descriptor = openat(
                    archive.descriptor,
                    identity.name,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
                )
                guard descriptor >= 0 else { throw Self.posixError() }
                do {
                    let observed = try NativeAuditPruneFileSystem.observeDescriptor(
                        descriptor,
                        name: identity.name,
                        expectedHash: identity.sha256
                    )
                    guard observed == identity else {
                        throw AgentPassNativeError.invalidSignature("Retained audit archive identity changed before lease acquisition")
                    }
                    opened.append(OpenFile(descriptor: descriptor, identity: identity))
                } catch {
                    close(descriptor)
                    throw error
                }
            }
            directoryChain = openedDirectories
            vnodeQueueDescriptor = queue
            files = opened
            pathChainHash = try Self.pathChainHash(openedDirectories)
            try revalidateUnlocked()
        } catch {
            for file in opened { close(file.descriptor) }
            for directory in openedDirectories.reversed() { close(directory.descriptor) }
            close(queue)
            throw error
        }
    }

    deinit {
        for file in files { close(file.descriptor) }
        for directory in directoryChain.reversed() { close(directory.descriptor) }
        close(vnodeQueueDescriptor)
    }

    /// Re-hashes the pinned descriptors and checks each directory entry without following links.
    public func revalidate() throws {
        lock.lock()
        defer { lock.unlock() }
        try revalidateUnlocked()
    }

    func recoverySnapshot() throws -> [(identity: NativeAuditRetentionFileIdentity, data: Data)] {
        lock.lock()
        defer { lock.unlock() }
        try revalidateUnlocked()
        var result: [(NativeAuditRetentionFileIdentity, Data)] = []
        for file in files {
            guard lseek(file.descriptor, 0, SEEK_SET) == 0 else { throw Self.posixError() }
            var data = Data(); data.reserveCapacity(file.identity.size)
            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            while data.count < file.identity.size {
                let count = Darwin.read(file.descriptor, &buffer, min(buffer.count, file.identity.size - data.count))
                guard count > 0 else { throw Self.posixError() }
                data.append(buffer, count: count)
            }
            result.append((file.identity, data))
        }
        try revalidateUnlocked()
        return result
    }

    private func revalidateUnlocked() throws {
        try revalidateDirectoryChain()

        for file in files {
            guard lseek(file.descriptor, 0, SEEK_SET) == 0 else { throw Self.posixError() }
            let observed = try NativeAuditPruneFileSystem.observeDescriptor(
                file.descriptor,
                name: file.identity.name,
                expectedHash: file.identity.sha256
            )
            var path = stat()
            guard observed == file.identity,
                  fstatat(directoryDescriptor, file.identity.name, &path, AT_SYMLINK_NOFOLLOW) == 0,
                  (path.st_mode & S_IFMT) == S_IFREG,
                  UInt64(path.st_dev) == file.identity.device,
                  UInt64(path.st_ino) == file.identity.inode,
                  UInt32(path.st_mode) == file.identity.mode,
                  path.st_uid == file.identity.owner,
                  path.st_gid == file.identity.group,
                  UInt64(path.st_nlink) == file.identity.linkCount,
                  Int(path.st_size) == file.identity.size else {
                throw AgentPassNativeError.invalidSignature("Retained audit archive path changed while deletion was leased")
            }
        }
        // A second full pass prevents a long file re-hash from widening the ancestor-path race.
        try revalidateDirectoryChain()
    }

    private func revalidateDirectoryChain() throws {
        if !topologyInvalidated {
            var events = [kevent64_s](repeating: kevent64_s(), count: max(1, directoryChain.count))
            var timeout = timespec(tv_sec: 0, tv_nsec: 0)
            let count = events.withUnsafeMutableBufferPointer {
                kevent64(vnodeQueueDescriptor, nil, 0, $0.baseAddress, Int32($0.count), 0, &timeout)
            }
            guard count >= 0 else { throw Self.posixError() }
            topologyInvalidated = count > 0
        }
        guard !topologyInvalidated else {
            throw AgentPassNativeError.invalidSignature("Retained audit archive ancestor topology changed while deletion was leased")
        }

        for (index, component) in directoryChain.enumerated() {
            var descriptorInfo = stat()
            guard fstat(component.descriptor, &descriptorInfo) == 0,
                  Self.matches(descriptorInfo, component.identity) else {
                throw AgentPassNativeError.invalidSignature("Retained audit archive ancestor metadata changed while deletion was leased")
            }
            var pathInfo = stat()
            if index == 0 {
                let currentRoot = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard currentRoot >= 0 else { throw Self.posixError() }
                defer { close(currentRoot) }
                guard fstat(currentRoot, &pathInfo) == 0 else { throw Self.posixError() }
            } else {
                guard let basename = component.basename,
                      fstatat(directoryChain[index - 1].descriptor, basename, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0 else {
                    throw AgentPassNativeError.invalidSignature("Retained audit archive ancestor path disappeared while deletion was leased")
                }
            }
            guard Self.matches(pathInfo, component.identity),
                  pathInfo.st_nlink == descriptorInfo.st_nlink else {
                throw AgentPassNativeError.invalidSignature("Retained audit archive ancestor path changed while deletion was leased")
            }
        }
        guard let archive = directoryChain.last,
              archive.identity.owner == geteuid(), archive.identity.mode & 0o077 == 0 else {
            throw AgentPassNativeError.invalidSignature("Retained audit archive privacy changed while deletion was leased")
        }
        var archiveInfo = stat()
        guard fstat(archive.descriptor, &archiveInfo) == 0,
              UInt64(archiveInfo.st_nlink) == archive.identity.linkCount else {
            throw AgentPassNativeError.invalidSignature("Retained audit archive link count changed while deletion was leased")
        }
    }

    private static func absoluteDirectoryComponents(_ path: String) throws -> [String] {
        guard path.hasPrefix("/"), path != "/", !path.contains("//"), !path.utf8.contains(0) else {
            throw AgentPassNativeError.invalidConfiguration("Retained audit archive path must be a normalized absolute path below /")
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard !components.isEmpty,
              !components.contains(where: { $0 == "." || $0 == ".." }) else {
            throw AgentPassNativeError.invalidConfiguration("Retained audit archive path must be normalized")
        }
        return components
    }

    private static func openDirectoryComponent(
        descriptor: Int32,
        basename: String?,
        parentDescriptor: Int32?
    ) throws -> OpenDirectoryComponent {
        guard let basename, let parentDescriptor else {
            var descriptorInfo = stat()
            guard fstat(descriptor, &descriptorInfo) == 0,
                  (descriptorInfo.st_mode & S_IFMT) == S_IFDIR else { throw posixError() }
            return OpenDirectoryComponent(descriptor: descriptor, basename: nil, identity: identity(descriptorInfo))
        }

        // A shared ancestor such as /tmp can gain or lose an unrelated child
        // between fstat and fstatat, changing only its link count. Require one
        // stable before/path/after observation instead of treating that benign
        // concurrent churn as path substitution. Device/inode/type/ownership
        // must agree on every pass, so a replacement can never be stabilized.
        for _ in 0..<8 {
            var descriptorBefore = stat()
            guard fstat(descriptor, &descriptorBefore) == 0,
                  (descriptorBefore.st_mode & S_IFMT) == S_IFDIR else { throw posixError() }
            let observedIdentity = identity(descriptorBefore)
            var pathInfo = stat()
            guard fstatat(parentDescriptor, basename, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw AgentPassNativeError.invalidSignature("Retained audit archive ancestor changed during lease acquisition")
            }
            var descriptorAfter = stat()
            guard fstat(descriptor, &descriptorAfter) == 0 else { throw posixError() }
            if matches(pathInfo, observedIdentity), matches(descriptorAfter, observedIdentity),
               pathInfo.st_nlink == descriptorBefore.st_nlink,
               descriptorAfter.st_nlink == descriptorBefore.st_nlink {
                return OpenDirectoryComponent(
                    descriptor: descriptor,
                    basename: basename,
                    identity: observedIdentity
                )
            }
        }
        throw AgentPassNativeError.invalidSignature("Retained audit archive ancestor changed during lease acquisition")
    }

    private static func monitorTopology(of descriptor: Int32, queue: Int32) throws {
        var change = kevent64_s()
        change.ident = UInt64(descriptor)
        change.filter = Int16(EVFILT_VNODE)
        change.flags = UInt16(EV_ADD | EV_CLEAR)
        change.fflags = UInt32(NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)
        guard withUnsafePointer(to: &change, {
            kevent64(queue, $0, 1, nil, 0, 0, nil)
        }) == 0 else { throw posixError() }
    }

    private static func identity(_ value: stat) -> DirectoryIdentity {
        DirectoryIdentity(
            device: UInt64(value.st_dev), inode: UInt64(value.st_ino), mode: UInt32(value.st_mode),
            owner: value.st_uid, group: value.st_gid, linkCount: UInt64(value.st_nlink)
        )
    }

    private static func pathChainHash(_ chain: [OpenDirectoryComponent]) throws -> String {
        let value: [[String: Any]] = chain.map {
            [
                "basename": $0.basename ?? "/", "device": $0.identity.device,
                "inode": $0.identity.inode, "mode": $0.identity.mode,
                "owner": $0.identity.owner, "group": $0.identity.group,
            ]
        }
        return NativeAuditLog.hash(try NativeAuditLog.canonical(["version": 1, "components": value]))
    }

    private static func matches(_ value: stat, _ identity: DirectoryIdentity) -> Bool {
        (value.st_mode & S_IFMT) == S_IFDIR && UInt64(value.st_dev) == identity.device &&
            UInt64(value.st_ino) == identity.inode && UInt32(value.st_mode) == identity.mode &&
            value.st_uid == identity.owner && value.st_gid == identity.group
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}

/// Verified immutable input to a deletion executor. This type never deletes files.
public struct NativeAuditPrunePlan: Equatable, Sendable {
    public let authorizationData: Data
    public let receiptData: Data
    public let authorization: NativeAuditPruneAuthorization
    public let receipt: NativeAuditPruneReceipt
    public let eligibleAt: Date
    public let nextState: NativeAuditPruneChainState
    public let observedArchives: [NativeAuditRetentionArchiveObservation]
}

public struct NativeAuditPostPruneManifest: Codable, Equatable, Sendable {
    public static let version = 2
    public let version: Int
    public let tenant: String
    public let sequence: Int
    public let operationID: String
    public let authorizationHash: String
    public let pruneReceiptHash: String
    public let previousManifestHash: String
    public let lifecycleHeadHash: String
    public let auditKeyTransitionReceiptHash: String
    public let prunedSegmentsHash: String
    public let expectedNextRetainedHash: String
    public let retainedIdentityHash: String
    public let lastPrunedEventIndex: Int
    public let lastPrunedCheckpointIndex: Int
    public let lastPrunedReceiptIndex: Int
    public let nextRetainedEventIndex: Int
    public let nextRetainedCheckpointIndex: Int
    public let nextRetainedReceiptIndex: Int
    public let nextRetainedEventPreviousHash: String
    public let nextRetainedCheckpointPreviousHash: String
    public let nextRetainedReceiptPreviousHash: String
    public let intentCreatedAt: String
    /// Source compatibility only. Schema v2 deliberately records this as `intent_created_at`;
    /// actual completion is carried solely by the executor statement and completion proof.
    @available(*, deprecated, message: "Use intentCreatedAt; actual completedAt is in NativeAuditPruneCompletionProof")
    public var completedAt: String { intentCreatedAt }
    public let signerFingerprint: String
    public let signature: String
    public let manifestHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, tenant, sequence, signature
        case operationID = "operation_id"
        case authorizationHash = "authorization_hash"
        case pruneReceiptHash = "prune_receipt_hash"
        case previousManifestHash = "previous_manifest_hash"
        case lifecycleHeadHash = "lifecycle_head_hash"
        case auditKeyTransitionReceiptHash = "audit_key_transition_receipt_hash"
        case prunedSegmentsHash = "pruned_segments_hash"
        case expectedNextRetainedHash = "expected_next_retained_hash"
        case retainedIdentityHash = "retained_identity_hash"
        case lastPrunedEventIndex = "last_pruned_event_index"
        case lastPrunedCheckpointIndex = "last_pruned_checkpoint_index"
        case lastPrunedReceiptIndex = "last_pruned_receipt_index"
        case nextRetainedEventIndex = "next_retained_event_index"
        case nextRetainedCheckpointIndex = "next_retained_checkpoint_index"
        case nextRetainedReceiptIndex = "next_retained_receipt_index"
        case nextRetainedEventPreviousHash = "next_retained_event_previous_hash"
        case nextRetainedCheckpointPreviousHash = "next_retained_checkpoint_previous_hash"
        case nextRetainedReceiptPreviousHash = "next_retained_receipt_previous_hash"
        case intentCreatedAt = "intent_created_at"
        case signerFingerprint = "signer_fingerprint"
        case manifestHash = "manifest_hash"
    }

    public static func create(plan: NativeAuditPrunePlan, completedAt: String, nextRetainedEventIndex: Int, nextRetainedCheckpointIndex: Int, nextRetainedReceiptIndex: Int, nextRetainedEventPreviousHash: String, nextRetainedCheckpointPreviousHash: String, nextRetainedReceiptPreviousHash: String, expectedNextRetainedHash: String = NativeAuditLog.zeroHash, retainedIdentityHash: String = NativeAuditLog.zeroHash, signer: P256MessageSigner) throws -> Self {
        let a = plan.authorization
        let last = a.segments.last!
        let segmentsHash = try NativeAuditRetentionCodec.segmentsHash(a.segments)
        let fingerprint = NativeAuditCheckpoints.fingerprint(signer.publicKeyX963)
        var object = NativeAuditRetentionCodec.manifestObject(version: version, tenant: a.tenant, sequence: a.sequence, operationID: a.operationID, authorizationHash: a.authorizationHash, pruneReceiptHash: plan.receipt.receiptHash, previousManifestHash: a.previousManifestHash, lifecycleHeadHash: a.boundary.lifecycleHeadHash, auditKeyTransitionReceiptHash: a.boundary.auditKeyTransitionReceiptHash, prunedSegmentsHash: segmentsHash, expectedNextRetainedHash: expectedNextRetainedHash, retainedIdentityHash: retainedIdentityHash, lastPrunedEventIndex: last.lastEventIndex, lastPrunedCheckpointIndex: last.lastCheckpointIndex, lastPrunedReceiptIndex: last.lastReceiptIndex, nextRetainedEventIndex: nextRetainedEventIndex, nextRetainedCheckpointIndex: nextRetainedCheckpointIndex, nextRetainedReceiptIndex: nextRetainedReceiptIndex, nextRetainedEventPreviousHash: nextRetainedEventPreviousHash, nextRetainedCheckpointPreviousHash: nextRetainedCheckpointPreviousHash, nextRetainedReceiptPreviousHash: nextRetainedReceiptPreviousHash, intentCreatedAt: completedAt, signerFingerprint: fingerprint)
        let raw = try NativeP256CanonicalSignature.canonicalized(signer.sign(message: NativeAuditLog.canonical(object)))
        guard raw.count == 64 else { throw AgentPassNativeError.invalidSignature("Post-prune manifest signature must be a raw P-256 signature") }
        let signature = raw.base64EncodedString(); object["signature"] = signature
        let hash = NativeAuditLog.hash(try NativeAuditLog.canonical(object))
        return Self(version: version, tenant: a.tenant, sequence: a.sequence, operationID: a.operationID, authorizationHash: a.authorizationHash, pruneReceiptHash: plan.receipt.receiptHash, previousManifestHash: a.previousManifestHash, lifecycleHeadHash: a.boundary.lifecycleHeadHash, auditKeyTransitionReceiptHash: a.boundary.auditKeyTransitionReceiptHash, prunedSegmentsHash: segmentsHash, expectedNextRetainedHash: expectedNextRetainedHash, retainedIdentityHash: retainedIdentityHash, lastPrunedEventIndex: last.lastEventIndex, lastPrunedCheckpointIndex: last.lastCheckpointIndex, lastPrunedReceiptIndex: last.lastReceiptIndex, nextRetainedEventIndex: nextRetainedEventIndex, nextRetainedCheckpointIndex: nextRetainedCheckpointIndex, nextRetainedReceiptIndex: nextRetainedReceiptIndex, nextRetainedEventPreviousHash: nextRetainedEventPreviousHash, nextRetainedCheckpointPreviousHash: nextRetainedCheckpointPreviousHash, nextRetainedReceiptPreviousHash: nextRetainedReceiptPreviousHash, intentCreatedAt: completedAt, signerFingerprint: fingerprint, signature: signature, manifestHash: hash)
    }

    public func canonicalData() throws -> Data { try NativeAuditRetentionCodec.encodeManifest(self) }
    public static func decodeCanonical(_ data: Data) throws -> Self {
        try NativeAuditRetentionCodec.decode(Self.self, data: data, keys: Set(CodingKeys.allCases.map(\.stringValue)), label: "Post-prune manifest") { try $0.canonicalData() }
    }
}

public struct NativeAuditRetentionVerifier: Sendable {
    public static let maximumDocumentBytes = 1024 * 1024
    public static let maximumSegments = 4096
    public static let maximumSafeInteger = 9_007_199_254_740_991
    private let tenant: String
    private let authorizerKey: P256.Signing.PublicKey
    private let authorizerFingerprint: String
    private let anchorKey: Curve25519.Signing.PublicKey
    private let anchorFingerprint: String
    private let minimumRetentionSeconds: Int

    public init(tenant: String, authorizerPublicKeyX963: Data, anchorPublicKeyPEM: String, minimumRetentionSeconds: Int) throws {
        guard NativeAuditRetentionCodec.isSlug(tenant), minimumRetentionSeconds > 0, minimumRetentionSeconds <= Self.maximumSafeInteger else { throw AgentPassNativeError.invalidConfiguration("Audit retention policy is invalid") }
        authorizerKey = try P256.Signing.PublicKey(x963Representation: authorizerPublicKeyX963)
        authorizerFingerprint = NativeAuditCheckpoints.fingerprint(authorizerPublicKeyX963)
        let anchor = try NativeAuditRetentionCodec.anchorPublicKey(anchorPublicKeyPEM)
        anchorKey = anchor.key; anchorFingerprint = anchor.fingerprint; self.tenant = tenant; self.minimumRetentionSeconds = minimumRetentionSeconds
    }

    public func eligiblePlan(authorizationData: Data, receiptData: Data, observedArchives: [NativeAuditRetentionArchiveObservation], prior: NativeAuditPruneChainState, currentBoundary: NativeAuditRetentionBoundary, now: Date) throws -> NativeAuditPrunePlan {
        guard authorizationData.count <= Self.maximumDocumentBytes, receiptData.count <= Self.maximumDocumentBytes else { throw AgentPassNativeError.invalidSignature("Audit prune evidence exceeds its verification limit") }
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
        guard authorization.segments == observedArchives.map(\.segment) else { throw AgentPassNativeError.invalidSignature("Observed audit archives do not exactly match the prune authorization") }
        try verifyAuthorization(authorization, prior: prior, currentBoundary: currentBoundary, now: now)
        let receipt = try NativeAuditPruneReceipt.decodeCanonical(receiptData)
        try verifyReceipt(receipt, authorization: authorization)
        guard let requested = NativeAuditRetentionCodec.date(authorization.requestedAt), let received = NativeAuditRetentionCodec.date(receipt.receivedAt), received >= requested, received <= now else { throw AgentPassNativeError.invalidSignature("Audit prune receipt time is invalid") }
        let eligibleAt = authorization.segments.map { NativeAuditRetentionCodec.date($0.latestAnchorReceivedAt)!.addingTimeInterval(TimeInterval(authorization.retentionSeconds)) }.max()!
        guard now >= eligibleAt else { throw AgentPassNativeError.invalidConfiguration("Audit archive retention age has not elapsed") }
        let last = authorization.segments.last!
        let next = NativeAuditPruneChainState(sequence: authorization.sequence, authorizationHash: authorization.authorizationHash, receiptHash: receipt.receiptHash, manifestHash: prior.manifestHash, lastEventIndex: last.lastEventIndex, lastCheckpointIndex: last.lastCheckpointIndex, lastReceiptIndex: last.lastReceiptIndex, lastEventHash: last.terminalEventHash, lastCheckpointHash: last.terminalCheckpointHash, lastArchiveReceiptHash: last.terminalReceiptHash)
        return NativeAuditPrunePlan(authorizationData: authorizationData, receiptData: receiptData, authorization: authorization, receipt: receipt, eligibleAt: eligibleAt, nextState: next, observedArchives: observedArchives)
    }

    fileprivate func revalidateExecutablePlan(_ plan: NativeAuditPrunePlan, currentBoundary: NativeAuditRetentionBoundary, now: Date) throws {
        guard plan.authorization.sequence > 0,
              let first = plan.authorization.segments.first,
              plan.observedArchives.count == plan.authorization.segments.count,
              plan.observedArchives.allSatisfy({ $0.fileIdentities?.count == 3 }) else {
            throw AgentPassNativeError.invalidSignature("Audit prune plan lacks verified filesystem observations")
        }
        let prior = NativeAuditPruneChainState(
            sequence: plan.authorization.sequence - 1,
            authorizationHash: plan.authorization.previousAuthorizationHash,
            receiptHash: plan.authorization.previousPruneReceiptHash,
            manifestHash: plan.authorization.previousManifestHash,
            lastEventIndex: first.firstEventIndex - 1,
            lastCheckpointIndex: first.firstCheckpointIndex - 1,
            lastReceiptIndex: first.firstReceiptIndex - 1,
            lastEventHash: first.previousEventHash,
            lastCheckpointHash: first.previousCheckpointHash,
            lastArchiveReceiptHash: first.previousReceiptHash
        )
        let verified = try eligiblePlan(
            authorizationData: plan.authorizationData,
            receiptData: plan.receiptData,
            observedArchives: plan.observedArchives,
            prior: prior,
            currentBoundary: currentBoundary,
            now: now
        )
        guard verified.authorization == plan.authorization,
              verified.receipt == plan.receipt,
              verified.eligibleAt == plan.eligibleAt,
              verified.nextState == plan.nextState else {
            throw AgentPassNativeError.invalidSignature("Audit prune plan is partial or was modified after verification")
        }
    }

    /// Rehydrates an already durable executor capability without consulting the current wall
    /// clock. The original receipt, authorization and retention timestamps still verify; only
    /// a backwards local clock is ignored after the executor intent has been fsynced.
    /// Recovery-only API for a plan whose exact executor intent is already durable.
    /// Callers must first prove that intent exists and pass journal-persisted identities.
    func persistedExecutablePlan(
        authorizationData: Data,
        receiptData: Data,
        observedArchives: [NativeAuditRetentionArchiveObservation],
        prior: NativeAuditPruneChainState,
        currentBoundary: NativeAuditRetentionBoundary
    ) throws -> NativeAuditPrunePlan {
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
        let receipt = try NativeAuditPruneReceipt.decodeCanonical(receiptData)
        guard let requested = NativeAuditRetentionCodec.date(authorization.requestedAt),
              let received = NativeAuditRetentionCodec.date(receipt.receivedAt) else {
            throw AgentPassNativeError.invalidSignature("Durable audit prune timestamps are invalid")
        }
        let eligible = authorization.segments.compactMap {
            NativeAuditRetentionCodec.date($0.latestAnchorReceivedAt)?.addingTimeInterval(TimeInterval(authorization.retentionSeconds))
        }.max() ?? requested
        return try eligiblePlan(
            authorizationData: authorizationData,
            receiptData: receiptData,
            observedArchives: observedArchives,
            prior: prior,
            currentBoundary: currentBoundary,
            now: max(requested, received, eligible)
        )
    }

    fileprivate func revalidatePersistedExecutablePlan(_ plan: NativeAuditPrunePlan, currentBoundary: NativeAuditRetentionBoundary) throws {
        guard let first = plan.authorization.segments.first else {
            throw AgentPassNativeError.invalidSignature("Durable audit prune plan has no segment")
        }
        let prior = NativeAuditPruneChainState(
            sequence: plan.authorization.sequence - 1,
            authorizationHash: plan.authorization.previousAuthorizationHash,
            receiptHash: plan.authorization.previousPruneReceiptHash,
            manifestHash: plan.authorization.previousManifestHash,
            lastEventIndex: first.firstEventIndex - 1,
            lastCheckpointIndex: first.firstCheckpointIndex - 1,
            lastReceiptIndex: first.firstReceiptIndex - 1,
            lastEventHash: first.previousEventHash,
            lastCheckpointHash: first.previousCheckpointHash,
            lastArchiveReceiptHash: first.previousReceiptHash
        )
        let restored = try persistedExecutablePlan(
            authorizationData: plan.authorizationData,
            receiptData: plan.receiptData,
            observedArchives: plan.observedArchives,
            prior: prior,
            currentBoundary: currentBoundary
        )
        guard restored.authorization == plan.authorization,
              restored.receipt == plan.receipt,
              restored.eligibleAt == plan.eligibleAt,
              restored.nextState == plan.nextState else {
            throw AgentPassNativeError.invalidSignature("Durable audit prune plan was modified after executor intent")
        }
    }

    public func verifyPostPruneManifest(_ data: Data, plan: NativeAuditPrunePlan, currentBoundary: NativeAuditRetentionBoundary, expectedNextRetained: NativeAuditRetentionSegment?, expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity]? = nil, now: Date) throws -> NativeAuditPruneChainState {
        let value = try NativeAuditPostPruneManifest.decodeCanonical(data)
        let a = plan.authorization; let last = a.segments.last!
        guard value.version == NativeAuditPostPruneManifest.version, value.tenant == tenant, value.sequence == a.sequence, value.operationID == a.operationID,
              value.authorizationHash == a.authorizationHash, value.pruneReceiptHash == plan.receipt.receiptHash, value.previousManifestHash == a.previousManifestHash,
              value.lifecycleHeadHash == currentBoundary.lifecycleHeadHash, value.auditKeyTransitionReceiptHash == currentBoundary.auditKeyTransitionReceiptHash,
              value.lifecycleHeadHash == a.boundary.lifecycleHeadHash, value.auditKeyTransitionReceiptHash == a.boundary.auditKeyTransitionReceiptHash,
              value.prunedSegmentsHash == (try NativeAuditRetentionCodec.segmentsHash(a.segments)),
              NativeAuditRetentionCodec.isHash(value.expectedNextRetainedHash), NativeAuditRetentionCodec.isHash(value.retainedIdentityHash),
              value.lastPrunedEventIndex == last.lastEventIndex, value.lastPrunedCheckpointIndex == last.lastCheckpointIndex, value.lastPrunedReceiptIndex == last.lastReceiptIndex,
              value.signerFingerprint == authorizerFingerprint,
              let created = NativeAuditRetentionCodec.date(value.intentCreatedAt), created >= NativeAuditRetentionCodec.date(plan.receipt.receivedAt)!, created <= now else { throw AgentPassNativeError.invalidSignature("Post-prune manifest does not match its authorized plan") }
        if let retained = expectedNextRetained {
            try NativeAuditRetentionCodec.validateSegment(retained)
            if value.expectedNextRetainedHash != NativeAuditLog.zeroHash || value.retainedIdentityHash != NativeAuditLog.zeroHash {
                guard value.expectedNextRetainedHash == (try NativeAuditRetentionCodec.retainedSegmentHash(retained)),
                      let retainedIdentities = expectedNextRetainedFileIdentities,
                      retainedIdentities.count == 3,
                      value.retainedIdentityHash == (try NativeAuditRetentionCodec.fileIdentityHash(retainedIdentities)) else { throw AgentPassNativeError.invalidSignature("Post-prune retained capability hash is invalid") }
            }
            guard retained.firstEventIndex == last.lastEventIndex + 1, retained.firstCheckpointIndex == last.lastCheckpointIndex + 1, retained.firstReceiptIndex == last.lastReceiptIndex + 1,
                  value.nextRetainedEventIndex == retained.firstEventIndex, value.nextRetainedCheckpointIndex == retained.firstCheckpointIndex, value.nextRetainedReceiptIndex == retained.firstReceiptIndex,
                  value.nextRetainedEventPreviousHash == last.terminalEventHash, value.nextRetainedCheckpointPreviousHash == last.terminalCheckpointHash, value.nextRetainedReceiptPreviousHash == last.terminalReceiptHash,
                  retained.previousEventHash == last.terminalEventHash, retained.previousCheckpointHash == last.terminalCheckpointHash, retained.previousReceiptHash == last.terminalReceiptHash else { throw AgentPassNativeError.invalidSignature("Post-prune retained boundary has a gap, overlap, or substitution") }
        } else {
            guard value.expectedNextRetainedHash == NativeAuditLog.zeroHash, value.retainedIdentityHash == NativeAuditLog.zeroHash, expectedNextRetainedFileIdentities == nil else { throw AgentPassNativeError.invalidSignature("Post-prune manifest has a substituted null retained boundary") }
            guard value.nextRetainedEventIndex == last.lastEventIndex + 1, value.nextRetainedCheckpointIndex == last.lastCheckpointIndex + 1, value.nextRetainedReceiptIndex == last.lastReceiptIndex + 1,
                  value.nextRetainedEventPreviousHash == last.terminalEventHash, value.nextRetainedCheckpointPreviousHash == last.terminalCheckpointHash, value.nextRetainedReceiptPreviousHash == last.terminalReceiptHash else { throw AgentPassNativeError.invalidSignature("Post-prune empty retained boundary is invalid") }
        }
        try verifyP256(signature: value.signature, fingerprint: value.signerFingerprint, message: NativeAuditRetentionCodec.manifestObject(value), hash: value.manifestHash, label: "Post-prune manifest")
        return NativeAuditPruneChainState(sequence: a.sequence, authorizationHash: a.authorizationHash, receiptHash: plan.receipt.receiptHash, manifestHash: value.manifestHash, lastEventIndex: last.lastEventIndex, lastCheckpointIndex: last.lastCheckpointIndex, lastReceiptIndex: last.lastReceiptIndex, lastEventHash: last.terminalEventHash, lastCheckpointHash: last.terminalCheckpointHash, lastArchiveReceiptHash: last.terminalReceiptHash)
    }

    /// Verifies schema-v2 deletion evidence after the authorized archive targets are gone.
    /// This path deliberately accepts no filesystem observations and never opens an archive.
    public func verifyCompletedPruneEvidence(
        authorizationData: Data,
        receiptData: Data,
        manifestData: Data,
        completionProofData: Data,
        completionStatementData: Data,
        quarantinedMarkerData: Data,
        manifestCommitMarkerData: Data,
        prior: NativeAuditPruneChainState,
        currentBoundary: NativeAuditRetentionBoundary,
        expectedNextRetained: NativeAuditRetentionSegment?,
        expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity]?
    ) throws -> NativeAuditPruneChainState {
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(authorizationData)
        let receipt = try NativeAuditPruneReceipt.decodeCanonical(receiptData)
        guard let requested = NativeAuditRetentionCodec.date(authorization.requestedAt),
              let received = NativeAuditRetentionCodec.date(receipt.receivedAt), received >= requested else {
            throw AgentPassNativeError.invalidSignature("Completed audit prune evidence timestamps are invalid")
        }
        let eligible = authorization.segments.compactMap {
            NativeAuditRetentionCodec.date($0.latestAnchorReceivedAt)?.addingTimeInterval(TimeInterval(authorization.retentionSeconds))
        }.max() ?? requested
        let logicalAuthorizationTime = max(requested, received, eligible)
        try verifyAuthorization(authorization, prior: prior, currentBoundary: currentBoundary, now: logicalAuthorizationTime)
        try verifyReceipt(receipt, authorization: authorization)
        let last = authorization.segments.last!
        let preManifestState = NativeAuditPruneChainState(sequence: authorization.sequence, authorizationHash: authorization.authorizationHash, receiptHash: receipt.receiptHash, manifestHash: prior.manifestHash, lastEventIndex: last.lastEventIndex, lastCheckpointIndex: last.lastCheckpointIndex, lastReceiptIndex: last.lastReceiptIndex, lastEventHash: last.terminalEventHash, lastCheckpointHash: last.terminalCheckpointHash, lastArchiveReceiptHash: last.terminalReceiptHash)
        let plan = NativeAuditPrunePlan(authorizationData: authorizationData, receiptData: receiptData, authorization: authorization, receipt: receipt, eligibleAt: eligible, nextState: preManifestState, observedArchives: [])
        guard let retained = expectedNextRetained, let retainedIdentities = expectedNextRetainedFileIdentities, retainedIdentities.count == 3 else { throw AgentPassNativeError.invalidSignature("Completed audit prune evidence requires an exact non-null retained capability") }
        let manifest = try NativeAuditPostPruneManifest.decodeCanonical(manifestData)
        guard let manifestTime = NativeAuditRetentionCodec.date(manifest.intentCreatedAt) else {
            throw AgentPassNativeError.invalidSignature("Completed audit prune manifest time is invalid")
        }
        let next = try verifyPostPruneManifest(manifestData, plan: plan, currentBoundary: currentBoundary, expectedNextRetained: retained, expectedNextRetainedFileIdentities: retainedIdentities, now: manifestTime)
        let completion = try NativeAuditPruneExecutorCompletionStatement.verifyCanonicalPhaseChain(
            quarantinedMarkerData: quarantinedMarkerData,
            manifestCommitMarkerData: manifestCommitMarkerData,
            completionStatementData: completionStatementData,
            operationID: authorization.operationID,
            manifestHash: manifest.manifestHash
        )
        let proof = try NativeAuditPruneCompletionProof.decodeCanonical(completionProofData)
        try verifyCompletionProof(proof, plan: plan, manifest: manifest, completion: completion, completionStatementData: completionStatementData)
        return next
    }

    /// Internal source-compatibility trap. A completion statement without the exact durable
    /// executor phase-chain bytes is never deletion or key-retirement authority.
    func verifyCompletedPruneEvidence(
        authorizationData: Data, receiptData: Data, manifestData: Data, completionProofData: Data,
        completionStatementData: Data, prior: NativeAuditPruneChainState,
        currentBoundary: NativeAuditRetentionBoundary, expectedNextRetained: NativeAuditRetentionSegment?,
        expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity]
    ) throws -> NativeAuditPruneChainState {
        throw AgentPassNativeError.invalidConfiguration("Completion evidence without exact executor phase-chain bytes is not deletion authority")
    }

    /// Source-compatibility trap. Evidence without the exact durable executor phase chain can
    /// never authorize deletion or key retirement.
    @available(*, deprecated, message: "Unavailable as deletion authority; use exact phase-chain overload")
    public func verifyCompletedPruneEvidence(
        authorizationData: Data, receiptData: Data, manifestData: Data, completionProofData: Data,
        prior: NativeAuditPruneChainState, currentBoundary: NativeAuditRetentionBoundary,
        expectedNextRetained: NativeAuditRetentionSegment?
    ) throws -> NativeAuditPruneChainState {
        throw AgentPassNativeError.invalidConfiguration("Completion evidence without exact executor phase-chain bytes is not deletion authority")
    }

    private func verifyCompletionProof(_ value: NativeAuditPruneCompletionProof, plan: NativeAuditPrunePlan, manifest: NativeAuditPostPruneManifest, completion: NativeAuditPruneExecutorCompletionStatement, completionStatementData: Data) throws {
        guard value.version == NativeAuditPruneCompletionProof.version,
              value.tenant == tenant, value.operationID == plan.authorization.operationID,
              value.sequence == plan.authorization.sequence,
              value.authorizationHash == plan.authorization.authorizationHash,
              value.anchorPruneReceiptHash == plan.receipt.receiptHash,
              value.manifestHash == manifest.manifestHash,
              value.prunedSegmentsHash == (try NativeAuditPruneCompletionProof.segmentsHash(plan.authorization.segments)),
              value.executorCompletionHash == NativeAuditLog.hash(completionStatementData),
              value.expectedNextRetainedHash == manifest.expectedNextRetainedHash,
              value.retainedIdentityHash == manifest.retainedIdentityHash,
              value.completedAt == completion.completedAt,
              completion.operationID == value.operationID, completion.authorizationHash == value.authorizationHash,
              completion.receiptHash == value.anchorPruneReceiptHash, completion.manifestHash == value.manifestHash,
              completion.expectedNextRetainedHash == value.expectedNextRetainedHash,
              completion.retainedIdentityHash == value.retainedIdentityHash,
              completion.intentCreatedAt == manifest.intentCreatedAt,
              value.signerFingerprint == authorizerFingerprint else {
            throw AgentPassNativeError.invalidSignature("Audit prune completion proof does not bind the completed executor operation")
        }
        try verifyP256(signature: value.signature, fingerprint: value.signerFingerprint, message: NativeAuditPruneCompletionProof.signingObject(value), hash: value.proofHash, label: "Audit prune completion proof")
    }

    private func verifyAuthorization(_ value: NativeAuditPruneAuthorization, prior: NativeAuditPruneChainState, currentBoundary: NativeAuditRetentionBoundary, now: Date) throws {
        guard prior.sequence >= 0, prior.sequence < Self.maximumSafeInteger,
              prior.lastEventIndex >= 0, prior.lastEventIndex < Self.maximumSafeInteger,
              prior.lastCheckpointIndex >= 0, prior.lastCheckpointIndex < Self.maximumSafeInteger,
              prior.lastReceiptIndex >= 0, prior.lastReceiptIndex < Self.maximumSafeInteger,
              NativeAuditRetentionCodec.isHash(prior.authorizationHash), NativeAuditRetentionCodec.isHash(prior.receiptHash), NativeAuditRetentionCodec.isHash(prior.manifestHash),
              NativeAuditRetentionCodec.isHash(prior.lastEventHash), NativeAuditRetentionCodec.isHash(prior.lastCheckpointHash), NativeAuditRetentionCodec.isHash(prior.lastArchiveReceiptHash),
              (prior.sequence == 0
                ? prior.authorizationHash == NativeAuditLog.zeroHash && prior.receiptHash == NativeAuditLog.zeroHash && prior.manifestHash == NativeAuditLog.zeroHash && prior.lastEventIndex == 0 && prior.lastCheckpointIndex == 0 && prior.lastReceiptIndex == 0 && prior.lastEventHash == NativeAuditLog.zeroHash && prior.lastCheckpointHash == NativeAuditLog.zeroHash && prior.lastArchiveReceiptHash == NativeAuditLog.zeroHash
                : prior.authorizationHash != NativeAuditLog.zeroHash && prior.receiptHash != NativeAuditLog.zeroHash && prior.manifestHash != NativeAuditLog.zeroHash && prior.lastEventIndex > 0 && prior.lastCheckpointIndex > 0 && prior.lastReceiptIndex > 0),
              value.version == NativeAuditPruneAuthorization.version, value.tenant == tenant, NativeAuditRetentionCodec.isSlug(value.operationID), value.sequence == prior.sequence + 1, value.sequence <= Self.maximumSafeInteger,
              value.previousAuthorizationHash == prior.authorizationHash, value.previousPruneReceiptHash == prior.receiptHash, value.previousManifestHash == prior.manifestHash,
              value.retentionSeconds >= minimumRetentionSeconds, value.retentionSeconds <= Self.maximumSafeInteger, !value.segments.isEmpty, value.segments.count <= Self.maximumSegments,
              value.boundary == currentBoundary, value.signerFingerprint == authorizerFingerprint,
              let requested = NativeAuditRetentionCodec.date(value.requestedAt), requested <= now else { throw AgentPassNativeError.invalidSignature("Audit prune authorization chain or boundary is invalid") }
        try NativeAuditRetentionCodec.validateBoundary(value.boundary)
        var event = prior.lastEventIndex + 1, checkpoint = prior.lastCheckpointIndex + 1, receipt = prior.lastReceiptIndex + 1
        var eventHash = prior.lastEventHash
        var checkpointHash = prior.lastCheckpointHash
        var receiptHash = prior.lastArchiveReceiptHash
        var identifiers = Set<String>(); var files = Set<String>()
        for segment in value.segments {
            try NativeAuditRetentionCodec.validateSegment(segment)
            guard identifiers.insert(segment.segmentID).inserted,
                  files.insert(segment.auditArchiveFile).inserted, files.insert(segment.checkpointArchiveFile).inserted, files.insert(segment.receiptArchiveFile).inserted,
                  segment.firstEventIndex == event, segment.firstCheckpointIndex == checkpoint, segment.firstReceiptIndex == receipt,
                  segment.previousEventHash == eventHash, segment.previousCheckpointHash == checkpointHash, segment.previousReceiptHash == receiptHash,
                  segment.lastCheckpointIndex == segment.lastReceiptIndex, segment.firstCheckpointIndex == segment.firstReceiptIndex,
                  segment.anchoredEventIndex == segment.lastEventIndex, segment.anchoredEventHash == segment.terminalEventHash,
                  let sealed = NativeAuditRetentionCodec.date(segment.sealedAt), let anchored = NativeAuditRetentionCodec.date(segment.latestAnchorReceivedAt), anchored >= sealed, requested >= anchored,
                  now.timeIntervalSince(anchored) >= TimeInterval(value.retentionSeconds) else { throw AgentPassNativeError.invalidSignature("Audit prune segment has a gap, overlap, substitution, or insufficient age") }
            guard segment.lastEventIndex < Self.maximumSafeInteger, segment.lastCheckpointIndex < Self.maximumSafeInteger, segment.lastReceiptIndex < Self.maximumSafeInteger else { throw AgentPassNativeError.invalidSignature("Audit prune segment range is too large") }
            event = segment.lastEventIndex + 1; checkpoint = segment.lastCheckpointIndex + 1; receipt = segment.lastReceiptIndex + 1
            eventHash = segment.terminalEventHash; checkpointHash = segment.terminalCheckpointHash; receiptHash = segment.terminalReceiptHash
        }
        let last = value.segments.last!
        guard value.boundary.anchorEventIndex >= last.lastReceiptIndex, value.boundary.checkpointIndex >= last.lastCheckpointIndex else { throw AgentPassNativeError.invalidSignature("Audit prune segment is not covered by current external anchor evidence") }
        try verifyP256(signature: value.signature, fingerprint: value.signerFingerprint, message: try NativeAuditRetentionCodec.authorizationObject(value), hash: value.authorizationHash, label: "Audit prune authorization")
    }

    private func verifyReceipt(_ value: NativeAuditPruneReceipt, authorization: NativeAuditPruneAuthorization) throws {
        guard value.version == NativeAuditPruneReceipt.version, value.tenant == tenant, value.sequence == authorization.sequence, value.authorizationHash == authorization.authorizationHash,
              value.previousReceiptHash == authorization.previousPruneReceiptHash, value.anchorEventIndex == authorization.boundary.anchorEventIndex + 1,
              value.previousAnchorEventHash == authorization.boundary.anchorEventHash, value.anchorKeyFingerprint == anchorFingerprint,
              NativeAuditRetentionCodec.isHash(value.receiptHash), let signature = NativeAuditRetentionCodec.signature(value.signature) else { throw AgentPassNativeError.invalidSignature("Audit prune receipt statement is invalid") }
        let statement = NativeAuditRetentionCodec.receiptObject(value, includeSignature: false, includeHash: false)
        guard anchorKey.isValidSignature(signature, for: try NativeAuditLog.canonical(statement)) else { throw AgentPassNativeError.invalidSignature("Audit prune receipt signature is invalid") }
        let unhashed = NativeAuditRetentionCodec.receiptObject(value, includeSignature: true, includeHash: false)
        guard value.receiptHash == NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)) else { throw AgentPassNativeError.invalidSignature("Audit prune receipt hash is invalid") }
    }

    private func verifyP256(signature: String, fingerprint: String, message: [String: Any], hash: String, label: String) throws {
        guard fingerprint == authorizerFingerprint, let raw = NativeAuditRetentionCodec.signature(signature), NativeP256CanonicalSignature.isCanonicalLowS(raw), let sig = try? P256.Signing.ECDSASignature(rawRepresentation: raw), authorizerKey.isValidSignature(sig, for: try NativeAuditLog.canonical(message)) else { throw AgentPassNativeError.invalidSignature("\(label) signature is invalid or noncanonical high-S") }
        var signed = message; signed["signature"] = signature
        guard hash == NativeAuditLog.hash(try NativeAuditLog.canonical(signed)) else { throw AgentPassNativeError.invalidSignature("\(label) hash is invalid") }
    }
}

private enum NativeAuditRetentionCodec {
    static func decode<T: Decodable>(_ type: T.Type, data: Data, keys: Set<String>, label: String, encode: (T) throws -> Data) throws -> T {
        guard !data.isEmpty, data.count <= NativeAuditRetentionVerifier.maximumDocumentBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys else { throw AgentPassNativeError.invalidSignature("\(label) schema is invalid") }
        let value = try JSONDecoder().decode(type, from: data)
        guard try encode(value) == data else { throw AgentPassNativeError.invalidSignature("\(label) is not canonical") }
        return value
    }

    static func authorizationObject(version: Int, tenant: String, operationID: String, sequence: Int, previousAuthorizationHash: String, previousPruneReceiptHash: String, previousManifestHash: String, retentionSeconds: Int, requestedAt: String, boundary: NativeAuditRetentionBoundary, segments: [NativeAuditRetentionSegment], signerFingerprint: String) throws -> [String: Any] {
        ["version": version, "tenant": tenant, "operation_id": operationID, "sequence": sequence, "previous_authorization_hash": previousAuthorizationHash, "previous_prune_receipt_hash": previousPruneReceiptHash, "previous_manifest_hash": previousManifestHash, "retention_seconds": retentionSeconds, "requested_at": requestedAt, "boundary": try json(boundary), "segments": try segments.map(json), "signer_fingerprint": signerFingerprint]
    }
    static func authorizationObject(_ v: NativeAuditPruneAuthorization) throws -> [String: Any] { try authorizationObject(version: v.version, tenant: v.tenant, operationID: v.operationID, sequence: v.sequence, previousAuthorizationHash: v.previousAuthorizationHash, previousPruneReceiptHash: v.previousPruneReceiptHash, previousManifestHash: v.previousManifestHash, retentionSeconds: v.retentionSeconds, requestedAt: v.requestedAt, boundary: v.boundary, segments: v.segments, signerFingerprint: v.signerFingerprint) }
    static func encodeAuthorization(_ v: NativeAuditPruneAuthorization) throws -> Data { var o = try authorizationObject(v); o["signature"] = v.signature; o["authorization_hash"] = v.authorizationHash; return try NativeAuditLog.canonical(o) }

    static func receiptObject(_ v: NativeAuditPruneReceipt, includeSignature: Bool, includeHash: Bool) -> [String: Any] { var o: [String: Any] = ["version": v.version, "tenant": v.tenant, "sequence": v.sequence, "authorization_hash": v.authorizationHash, "previous_receipt_hash": v.previousReceiptHash, "anchor_event_index": v.anchorEventIndex, "previous_anchor_event_hash": v.previousAnchorEventHash, "received_at": v.receivedAt]; if includeSignature { o["anchor_key_fingerprint"] = v.anchorKeyFingerprint; o["signature"] = v.signature }; if includeHash { o["receipt_hash"] = v.receiptHash }; return o }
    static func encodeReceipt(_ v: NativeAuditPruneReceipt) throws -> Data { try NativeAuditLog.canonical(receiptObject(v, includeSignature: true, includeHash: true)) }

    static func manifestObject(version: Int, tenant: String, sequence: Int, operationID: String, authorizationHash: String, pruneReceiptHash: String, previousManifestHash: String, lifecycleHeadHash: String, auditKeyTransitionReceiptHash: String, prunedSegmentsHash: String, expectedNextRetainedHash: String, retainedIdentityHash: String, lastPrunedEventIndex: Int, lastPrunedCheckpointIndex: Int, lastPrunedReceiptIndex: Int, nextRetainedEventIndex: Int, nextRetainedCheckpointIndex: Int, nextRetainedReceiptIndex: Int, nextRetainedEventPreviousHash: String, nextRetainedCheckpointPreviousHash: String, nextRetainedReceiptPreviousHash: String, intentCreatedAt: String, signerFingerprint: String) -> [String: Any] { ["version": version, "tenant": tenant, "sequence": sequence, "operation_id": operationID, "authorization_hash": authorizationHash, "prune_receipt_hash": pruneReceiptHash, "previous_manifest_hash": previousManifestHash, "lifecycle_head_hash": lifecycleHeadHash, "audit_key_transition_receipt_hash": auditKeyTransitionReceiptHash, "pruned_segments_hash": prunedSegmentsHash, "expected_next_retained_hash": expectedNextRetainedHash, "retained_identity_hash": retainedIdentityHash, "last_pruned_event_index": lastPrunedEventIndex, "last_pruned_checkpoint_index": lastPrunedCheckpointIndex, "last_pruned_receipt_index": lastPrunedReceiptIndex, "next_retained_event_index": nextRetainedEventIndex, "next_retained_checkpoint_index": nextRetainedCheckpointIndex, "next_retained_receipt_index": nextRetainedReceiptIndex, "next_retained_event_previous_hash": nextRetainedEventPreviousHash, "next_retained_checkpoint_previous_hash": nextRetainedCheckpointPreviousHash, "next_retained_receipt_previous_hash": nextRetainedReceiptPreviousHash, "intent_created_at": intentCreatedAt, "signer_fingerprint": signerFingerprint] }
    static func manifestObject(_ v: NativeAuditPostPruneManifest) -> [String: Any] { manifestObject(version: v.version, tenant: v.tenant, sequence: v.sequence, operationID: v.operationID, authorizationHash: v.authorizationHash, pruneReceiptHash: v.pruneReceiptHash, previousManifestHash: v.previousManifestHash, lifecycleHeadHash: v.lifecycleHeadHash, auditKeyTransitionReceiptHash: v.auditKeyTransitionReceiptHash, prunedSegmentsHash: v.prunedSegmentsHash, expectedNextRetainedHash: v.expectedNextRetainedHash, retainedIdentityHash: v.retainedIdentityHash, lastPrunedEventIndex: v.lastPrunedEventIndex, lastPrunedCheckpointIndex: v.lastPrunedCheckpointIndex, lastPrunedReceiptIndex: v.lastPrunedReceiptIndex, nextRetainedEventIndex: v.nextRetainedEventIndex, nextRetainedCheckpointIndex: v.nextRetainedCheckpointIndex, nextRetainedReceiptIndex: v.nextRetainedReceiptIndex, nextRetainedEventPreviousHash: v.nextRetainedEventPreviousHash, nextRetainedCheckpointPreviousHash: v.nextRetainedCheckpointPreviousHash, nextRetainedReceiptPreviousHash: v.nextRetainedReceiptPreviousHash, intentCreatedAt: v.intentCreatedAt, signerFingerprint: v.signerFingerprint) }
    static func encodeManifest(_ v: NativeAuditPostPruneManifest) throws -> Data { var o = manifestObject(v); o["signature"] = v.signature; o["manifest_hash"] = v.manifestHash; return try NativeAuditLog.canonical(o) }

    static func segmentsHash(_ segments: [NativeAuditRetentionSegment]) throws -> String { NativeAuditLog.hash(try NativeAuditLog.canonical(["segments": try segments.map(json)])) }
    static func retainedSegmentHash(_ segment: NativeAuditRetentionSegment) throws -> String { NativeAuditLog.hash(try NativeAuditLog.canonical(["expected_next_retained": try json(segment)])) }
    static func fileIdentityHash(_ identities: [NativeAuditRetentionFileIdentity]) throws -> String { NativeAuditLog.hash(try NativeAuditLog.canonical(["retained_file_identities": try identities.map(json)])) }
    static func json<T: Encodable>(_ value: T) throws -> Any { try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) }
    static func isHash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
    static func isFingerprint(_ value: String) -> Bool { value.range(of: "^SHA256:[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil }
    static func isSlug(_ value: String) -> Bool { value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", options: .regularExpression) != nil }
    static func isFile(_ value: String) -> Bool { !value.isEmpty && value.utf8.count <= 255 && value != "." && value != ".." && !value.contains("/") && !value.contains("\\") && value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]*$", options: .regularExpression) != nil }
    static func date(_ value: String) -> Date? { guard value.utf8.count <= 64 else { return nil }; let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; if let d = f.date(from: value) { return d }; let b = ISO8601DateFormatter(); return b.date(from: value) }
    static func signature(_ value: String) -> Data? { guard value.utf8.count <= 128, let d = Data(base64Encoded: value), d.count == 64, d.base64EncodedString() == value else { return nil }; return d }
    static func validateBoundary(_ v: NativeAuditRetentionBoundary) throws { guard isHash(v.lifecycleHeadHash), isHash(v.auditKeyTransitionReceiptHash), v.anchorEventIndex > 0, v.anchorEventIndex <= NativeAuditRetentionVerifier.maximumSafeInteger, isHash(v.anchorEventHash), v.checkpointIndex > 0, v.checkpointIndex <= NativeAuditRetentionVerifier.maximumSafeInteger, isHash(v.checkpointHash), isHash(v.checkpointReceiptHash) else { throw AgentPassNativeError.invalidSignature("Audit retention boundary is invalid") } }
    static func validateSegment(_ v: NativeAuditRetentionSegment) throws { guard isSlug(v.segmentID), isFile(v.auditArchiveFile), isFile(v.checkpointArchiveFile), isFile(v.receiptArchiveFile), Set([v.auditArchiveFile, v.checkpointArchiveFile, v.receiptArchiveFile]).count == 3, isHash(v.auditArchiveSHA256), isHash(v.checkpointArchiveSHA256), isHash(v.receiptArchiveSHA256), v.firstEventIndex > 0, v.lastEventIndex >= v.firstEventIndex, v.firstCheckpointIndex > 0, v.lastCheckpointIndex >= v.firstCheckpointIndex, v.firstReceiptIndex > 0, v.lastReceiptIndex >= v.firstReceiptIndex, isHash(v.previousEventHash), isHash(v.terminalEventHash), isHash(v.previousCheckpointHash), isHash(v.terminalCheckpointHash), isHash(v.previousReceiptHash), isHash(v.terminalReceiptHash), v.anchoredEventIndex > 0, isHash(v.anchoredEventHash), date(v.sealedAt) != nil, date(v.latestAnchorReceivedAt) != nil else { throw AgentPassNativeError.invalidSignature("Audit retention segment is invalid") } }
    static func anchorPublicKey(_ pem: String) throws -> (key: Curve25519.Signing.PublicKey, fingerprint: String) { let lines = pem.split(whereSeparator: \.isNewline).map(String.init); guard pem.utf8.count <= 4096, lines.first == "-----BEGIN PUBLIC KEY-----", lines.last == "-----END PUBLIC KEY-----", let der = Data(base64Encoded: lines.dropFirst().dropLast().joined()), der.count == 44, der.prefix(12) == Data([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]) else { throw AgentPassNativeError.invalidKey("Audit retention anchor key must be Ed25519 SPKI PEM") }; let fp = "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: ""); return (try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)), fp) }
}

public enum NativeAuditDeletionEvidenceHash {
    public static func canonicalData(_ value: Data) -> String { NativeAuditLog.hash(value) }
    public static func retainedSegment(_ value: NativeAuditRetentionSegment) throws -> String {
        try NativeAuditRetentionCodec.retainedSegmentHash(value)
    }
    public static func retainedIdentities(_ value: [NativeAuditRetentionFileIdentity]) throws -> String {
        try NativeAuditRetentionCodec.fileIdentityHash(value)
    }
}

public enum NativeAuditPruneExecutionCrashPoint: Equatable, Sendable {
    case beforeIntentRename
    case afterIntentSynced
    case afterFileQuarantined(Int)
    case afterQuarantineSynced
    case afterManifestCommitted
    case afterFileUnlinked(Int)
    case afterCompletionSynced
}

/// Exact fsynced executor statement written only after every target unlink and quarantine fsync.
/// It is deliberately unsigned; the signed completion proof binds the SHA-256 of these bytes.
public struct NativeAuditPruneExecutorCompletionStatement: Codable, Equatable, Sendable {
    public static let version = 2
    public let version: Int
    public let operationID: String
    public let authorizationHash: String
    public let receiptHash: String
    public let manifestHash: String
    public let expectedNextRetainedHash: String
    public let retainedIdentityHash: String
    public let intentCreatedAt: String
    public let completedAt: String
    public let previousPhaseHash: String
    public let targetsAbsent: Bool
    public let quarantineEmpty: Bool
    public let completionState: String
    public let statementHash: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case operationID = "operation_id"
        case authorizationHash = "authorization_hash"
        case receiptHash = "receipt_hash"
        case manifestHash = "manifest_hash"
        case expectedNextRetainedHash = "expected_next_retained_hash"
        case retainedIdentityHash = "retained_identity_hash"
        case intentCreatedAt = "intent_created_at"
        case completedAt = "completed_at"
        case previousPhaseHash = "previous_phase_hash"
        case targetsAbsent = "targets_absent"
        case quarantineEmpty = "quarantine_empty"
        case completionState = "completion_state"
        case statementHash = "statement_hash"
    }

    fileprivate static func create(intent: NativeAuditPruneExecutionIntent, completedAt: String, previousPhaseHash: String) throws -> Self {
        var object = object(version: version, operationID: intent.operationID, authorizationHash: intent.authorizationHash, receiptHash: intent.receiptHash, manifestHash: intent.manifestHash, expectedNextRetainedHash: intent.expectedNextRetainedHash, retainedIdentityHash: intent.retainedIdentityHash, intentCreatedAt: intent.intentCreatedAt, completedAt: completedAt, previousPhaseHash: previousPhaseHash, targetsAbsent: true, quarantineEmpty: true, completionState: "post-unlink-fsynced")
        let hash = NativeAuditLog.hash(try NativeAuditLog.canonical(object)); object["statement_hash"] = hash
        return Self(version: version, operationID: intent.operationID, authorizationHash: intent.authorizationHash, receiptHash: intent.receiptHash, manifestHash: intent.manifestHash, expectedNextRetainedHash: intent.expectedNextRetainedHash, retainedIdentityHash: intent.retainedIdentityHash, intentCreatedAt: intent.intentCreatedAt, completedAt: completedAt, previousPhaseHash: previousPhaseHash, targetsAbsent: true, quarantineEmpty: true, completionState: "post-unlink-fsynced", statementHash: hash)
    }

    public func canonicalData() throws -> Data { var value = Self.object(self); value["statement_hash"] = statementHash; return try NativeAuditLog.canonical(value) }
    public static func decodeCanonical(_ data: Data) throws -> Self {
        guard data.count <= 4096, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == Set(CodingKeys.allCases.map(\.stringValue)), let value = try? JSONDecoder().decode(Self.self, from: data), try value.canonicalData() == data else { throw AgentPassNativeError.invalidSignature("Audit prune executor completion statement is not exact canonical schema") }
        var unhashed = object; unhashed.removeValue(forKey: "statement_hash")
        guard value.version == version, NativeAuditRetentionCodec.isSlug(value.operationID), NativeAuditRetentionCodec.isHash(value.authorizationHash), NativeAuditRetentionCodec.isHash(value.receiptHash), NativeAuditRetentionCodec.isHash(value.manifestHash), NativeAuditRetentionCodec.isHash(value.expectedNextRetainedHash), NativeAuditRetentionCodec.isHash(value.retainedIdentityHash), NativeAuditRetentionCodec.date(value.intentCreatedAt) != nil, let completed = NativeAuditRetentionCodec.date(value.completedAt), let created = NativeAuditRetentionCodec.date(value.intentCreatedAt), completed >= created, NativeAuditRetentionCodec.isHash(value.previousPhaseHash), value.targetsAbsent, value.quarantineEmpty, value.completionState == "post-unlink-fsynced", value.statementHash == NativeAuditLog.hash(try NativeAuditLog.canonical(unhashed)) else { throw AgentPassNativeError.invalidSignature("Audit prune executor completion statement is invalid") }
        return value
    }
    private static func object(_ value: Self) -> [String: Any] { object(version: value.version, operationID: value.operationID, authorizationHash: value.authorizationHash, receiptHash: value.receiptHash, manifestHash: value.manifestHash, expectedNextRetainedHash: value.expectedNextRetainedHash, retainedIdentityHash: value.retainedIdentityHash, intentCreatedAt: value.intentCreatedAt, completedAt: value.completedAt, previousPhaseHash: value.previousPhaseHash, targetsAbsent: value.targetsAbsent, quarantineEmpty: value.quarantineEmpty, completionState: value.completionState) }
    private static func object(version: Int, operationID: String, authorizationHash: String, receiptHash: String, manifestHash: String, expectedNextRetainedHash: String, retainedIdentityHash: String, intentCreatedAt: String, completedAt: String, previousPhaseHash: String, targetsAbsent: Bool, quarantineEmpty: Bool, completionState: String) -> [String: Any] { ["version": version, "operation_id": operationID, "authorization_hash": authorizationHash, "receipt_hash": receiptHash, "manifest_hash": manifestHash, "expected_next_retained_hash": expectedNextRetainedHash, "retained_identity_hash": retainedIdentityHash, "intent_created_at": intentCreatedAt, "completed_at": completedAt, "previous_phase_hash": previousPhaseHash, "targets_absent": targetsAbsent, "quarantine_empty": quarantineEmpty, "completion_state": completionState] }

    /// Recomputes the complete canonical executor phase chain without filesystem access.
    static func verifyCanonicalPhaseChain(quarantinedMarkerData: Data, manifestCommitMarkerData: Data, completionStatementData: Data, operationID: String, manifestHash: String) throws -> Self {
        let quarantined = try NativeAuditPruneExecutorPhaseStatement.decodeCanonical(quarantinedMarkerData)
        let committed = try NativeAuditPruneExecutorPhaseStatement.decodeCanonical(manifestCommitMarkerData)
        let completion = try decodeCanonical(completionStatementData)
        guard quarantined.phase == "01-quarantined.json", quarantined.operationID == operationID,
              quarantined.manifestHash == manifestHash, quarantined.previousPhaseHash == NativeAuditLog.zeroHash,
              committed.phase == "02-manifest-committed.json", committed.operationID == operationID,
              committed.manifestHash == manifestHash, committed.previousPhaseHash == NativeAuditLog.hash(quarantinedMarkerData),
              completion.operationID == operationID, completion.manifestHash == manifestHash,
              completion.previousPhaseHash == NativeAuditLog.hash(manifestCommitMarkerData) else {
            throw AgentPassNativeError.invalidSignature("Audit prune offline executor phase chain is invalid")
        }
        return completion
    }
}

struct NativeAuditPruneExecutorPhaseStatement: Codable, Equatable, Sendable {
    let version: Int
    let operationID: String
    let manifestHash: String
    let previousPhaseHash: String
    let phase: String
    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, phase
        case operationID = "operation_id"
        case manifestHash = "manifest_hash"
        case previousPhaseHash = "previous_phase_hash"
    }
    func canonicalData() throws -> Data { try NativeAuditLog.canonical(["version": version, "operation_id": operationID, "manifest_hash": manifestHash, "previous_phase_hash": previousPhaseHash, "phase": phase]) }
    static func decodeCanonical(_ data: Data) throws -> Self {
        guard data.count <= 4096, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == Set(CodingKeys.allCases.map(\.stringValue)), let value = try? JSONDecoder().decode(Self.self, from: data), value.version == 1, NativeAuditRetentionCodec.isSlug(value.operationID), NativeAuditRetentionCodec.isHash(value.manifestHash), NativeAuditRetentionCodec.isHash(value.previousPhaseHash), ["01-quarantined.json", "02-manifest-committed.json"].contains(value.phase), try value.canonicalData() == data else { throw AgentPassNativeError.invalidSignature("Audit prune executor phase statement is not exact canonical schema") }
        return value
    }
}

public struct NativeAuditPruneExecutionResult: Equatable, Sendable {
    public let manifest: NativeAuditPostPruneManifest
    public let manifestData: Data
    /// SHA-256 of the exact fsynced `03-completed.json` executor marker.
    public let durableCompletionHash: String
    public let completionStatementData: Data
    /// Exact canonical fsynced phase-chain predecessors (`01` then `02`).
    public let quarantinedMarkerData: Data
    public let manifestCommitMarkerData: Data
    public let completedAt: String
    public let recovered: Bool
}

/// Executes an already verified prune capability. Every destructive target is one exact,
/// descriptor-relative filename; there is deliberately no directory-delete API.
public final class NativeAuditPruneExecutor: @unchecked Sendable {
    private static let stateDirectoryName = ".agentpass-prune-transactions"
    private static let intentName = "intent.json"
    private static let manifestName = "post-prune-manifest.json"
    private static let quarantineName = "quarantine"
    private static let quarantinedMarker = "01-quarantined.json"
    private static let manifestMarker = "02-manifest-committed.json"
    private static let completedMarker = "03-completed.json"

    private let archivePath: String
    private let archiveDescriptor: Int32
    private let archiveDevice: UInt64
    private let archiveInode: UInt64
    private let stateDescriptor: Int32
    private let fault: @Sendable (NativeAuditPruneExecutionCrashPoint) throws -> Void
    private let processLock = NSLock()

    public init(archiveDirectory: String, faultInjector: @escaping @Sendable (NativeAuditPruneExecutionCrashPoint) throws -> Void = { _ in }) throws {
        let archive = try NativeAuditPruneFileSystem.openTrustedDirectory(archiveDirectory, label: "Audit archive")
        archivePath = archive.path
        archiveDescriptor = archive.descriptor
        archiveDevice = UInt64(archive.info.st_dev)
        archiveInode = UInt64(archive.info.st_ino)
        fault = faultInjector
        do {
            if mkdirat(archiveDescriptor, Self.stateDirectoryName, 0o700) != 0, errno != EEXIST {
                throw Self.posixError()
            }
            let state = openat(archiveDescriptor, Self.stateDirectoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard state >= 0 else { throw Self.posixError() }
            var stateInfo = stat()
            guard fstat(state, &stateInfo) == 0,
                  (stateInfo.st_mode & S_IFMT) == S_IFDIR,
                  stateInfo.st_uid == geteuid(), stateInfo.st_mode & 0o077 == 0,
                  UInt64(stateInfo.st_dev) == archiveDevice else {
                close(state)
                throw AgentPassNativeError.invalidConfiguration("Audit prune state must be a private directory on the archive filesystem")
            }
            stateDescriptor = state
            try Self.removeValidatedTemporaryOperations(stateDescriptor: state, archiveDevice: archiveDevice)
            guard fsync(archiveDescriptor) == 0 else { throw Self.posixError() }
        } catch {
            close(archiveDescriptor)
            throw error
        }
    }

    deinit {
        close(stateDescriptor)
        close(archiveDescriptor)
    }

    public func verifyKnownOperations(_ operationIDs: Set<String>) throws {
        try withLock {
            try validateRoots()
            let expected = Set(operationIDs.map(Self.operationDirectoryName))
            let actual = Set(try Self.names(stateDescriptor))
            guard actual.isSubset(of: expected) else {
                throw AgentPassNativeError.invalidSignature("Audit prune executor contains an operation absent from the trusted journal")
            }
        }
    }

    public func hasDurableIntent(operationID: String) throws -> Bool {
        try withLock {
            try validateRoots()
            return try Self.entryExists(stateDescriptor, Self.operationDirectoryName(operationID))
        }
    }

    public func execute(
        plan: NativeAuditPrunePlan,
        verifier: NativeAuditRetentionVerifier,
        currentBoundary: NativeAuditRetentionBoundary,
        expectedNextRetained: NativeAuditRetentionSegment?,
        expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity]? = nil,
        completedAt: String,
        now: Date,
        signer: P256MessageSigner,
        completionNow: @escaping @Sendable () -> Date = Date.init,
        beforeDurableIntent: () throws -> Void = {},
        beforeIrreversibleUnlink: () throws -> Void = {}
    ) throws -> NativeAuditPruneExecutionResult {
        try verifier.revalidateExecutablePlan(plan, currentBoundary: currentBoundary, now: now)
        let manifest = try Self.makeManifest(plan: plan, retained: expectedNextRetained, retainedIdentities: expectedNextRetainedFileIdentities, completedAt: completedAt, signer: signer)
        let manifestData = try manifest.canonicalData()
        _ = try verifier.verifyPostPruneManifest(manifestData, plan: plan, currentBoundary: currentBoundary, expectedNextRetained: expectedNextRetained, expectedNextRetainedFileIdentities: expectedNextRetainedFileIdentities, now: now)
        return try withLock {
            try validateRoots()
            try beforeDurableIntent()
            let name = Self.operationDirectoryName(plan.authorization.operationID)
            guard try !Self.entryExists(stateDescriptor, name) else {
                throw AgentPassNativeError.invalidSignature("Audit prune operation ID has already been used")
            }
            try createOperation(name: name, plan: plan, manifestData: manifestData, retained: expectedNextRetained, retainedIdentities: expectedNextRetainedFileIdentities, intentCreatedAt: completedAt)
            try fault(.afterIntentSynced)
            return try resume(name: name, plan: plan, verifier: verifier, boundary: currentBoundary, retained: expectedNextRetained, retainedIdentities: expectedNextRetainedFileIdentities, now: now, completionNow: completionNow, recovered: false, beforeIrreversibleUnlink: beforeIrreversibleUnlink)
        }
    }

    /// Resumes only an existing exact operation. It never creates a new deletion intent and is
    /// idempotent after completion, while `execute` rejects operation reuse.
    public func recover(
        plan: NativeAuditPrunePlan,
        verifier: NativeAuditRetentionVerifier,
        currentBoundary: NativeAuditRetentionBoundary,
        expectedNextRetained: NativeAuditRetentionSegment?,
        expectedNextRetainedFileIdentities: [NativeAuditRetentionFileIdentity]? = nil,
        completionNow: @escaping @Sendable () -> Date = Date.init,
        now: Date,
        beforeIrreversibleUnlink: () throws -> Void = {}
    ) throws -> NativeAuditPruneExecutionResult {
        try verifier.revalidatePersistedExecutablePlan(plan, currentBoundary: currentBoundary)
        return try withLock {
            try validateRoots()
            let name = Self.operationDirectoryName(plan.authorization.operationID)
            guard try Self.entryExists(stateDescriptor, name) else {
                throw AgentPassNativeError.invalidSignature("Audit prune recovery has no durable execution intent")
            }
            return try resume(name: name, plan: plan, verifier: verifier, boundary: currentBoundary, retained: expectedNextRetained, retainedIdentities: expectedNextRetainedFileIdentities, now: now, completionNow: completionNow, recovered: true, beforeIrreversibleUnlink: beforeIrreversibleUnlink)
        }
    }

    private func createOperation(name: String, plan: NativeAuditPrunePlan, manifestData: Data, retained: NativeAuditRetentionSegment?, retainedIdentities: [NativeAuditRetentionFileIdentity]?, intentCreatedAt: String) throws {
        let temporary = ".tmp-\(name)-\(UUID().uuidString.lowercased())"
        guard mkdirat(stateDescriptor, temporary, 0o700) == 0 else { throw Self.posixError() }
        var renamed = false
        var preserveTemporary = false
        defer {
            if !renamed && !preserveTemporary {
                // Exact, bounded cleanup only; never recurse and never touch archive data.
                let temporaryFD = openat(stateDescriptor, temporary, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                if temporaryFD >= 0 {
                    _ = unlinkat(temporaryFD, Self.intentName, 0)
                    _ = unlinkat(temporaryFD, Self.manifestName, 0)
                    _ = unlinkat(temporaryFD, Self.quarantineName, AT_REMOVEDIR)
                    close(temporaryFD)
                }
                _ = unlinkat(stateDescriptor, temporary, AT_REMOVEDIR)
            }
        }
        let operationFD = openat(stateDescriptor, temporary, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard operationFD >= 0 else { throw Self.posixError() }
        defer { close(operationFD) }
        guard mkdirat(operationFD, Self.quarantineName, 0o700) == 0 else { throw Self.posixError() }
        let identities = try Self.executionIdentities(plan)
        let manifest = try NativeAuditPostPruneManifest.decodeCanonical(manifestData)
        let retainedData = try retained.map { try NativeAuditLog.canonical(["expected_next_retained": NativeAuditRetentionCodec.json($0)]) }
        let durableRetainedIdentities = retainedIdentities ?? []
        let legacyUnbound = manifest.expectedNextRetainedHash == NativeAuditLog.zeroHash && manifest.retainedIdentityHash == NativeAuditLog.zeroHash
        let expectedRetainedHash = try retained.map(NativeAuditRetentionCodec.retainedSegmentHash) ?? NativeAuditLog.zeroHash
        let expectedIdentityHash = try retained.map { _ in try NativeAuditRetentionCodec.fileIdentityHash(durableRetainedIdentities) } ?? NativeAuditLog.zeroHash
        guard legacyUnbound || (((retained == nil && durableRetainedIdentities.isEmpty) || (retained != nil && durableRetainedIdentities.count == 3)) &&
              manifest.expectedNextRetainedHash == expectedRetainedHash &&
              manifest.retainedIdentityHash == expectedIdentityHash) else {
            throw AgentPassNativeError.invalidSignature("Audit prune retained capability is not bound to its authorization")
        }
        let intent = NativeAuditPruneExecutionIntent(
            version: 2,
            operationID: plan.authorization.operationID,
            authorizationData: plan.authorizationData,
            receiptData: plan.receiptData,
            authorizationHash: plan.authorization.authorizationHash,
            receiptHash: plan.receipt.receiptHash,
            manifestHash: manifest.manifestHash,
            files: identities,
            expectedNextRetainedData: retainedData,
            retainedFiles: durableRetainedIdentities,
            expectedNextRetainedHash: manifest.expectedNextRetainedHash,
            retainedIdentityHash: manifest.retainedIdentityHash,
            intentCreatedAt: intentCreatedAt
        )
        try Self.writeImmutable(directoryFD: operationFD, name: Self.intentName, data: try intent.canonicalData())
        try Self.writeImmutable(directoryFD: operationFD, name: Self.manifestName, data: manifestData)
        let quarantineFD = openat(operationFD, Self.quarantineName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard quarantineFD >= 0 else { throw Self.posixError() }
        guard fsync(quarantineFD) == 0 else { close(quarantineFD); throw Self.posixError() }
        close(quarantineFD)
        guard fsync(operationFD) == 0 else { throw Self.posixError() }
        do { try fault(.beforeIntentRename) } catch { preserveTemporary = true; throw error }
        guard renameatx_np(stateDescriptor, temporary, stateDescriptor, name, UInt32(RENAME_EXCL)) == 0,
              fsync(stateDescriptor) == 0 else { throw Self.posixError() }
        renamed = true
    }

    private func resume(name: String, plan: NativeAuditPrunePlan, verifier: NativeAuditRetentionVerifier, boundary: NativeAuditRetentionBoundary, retained: NativeAuditRetentionSegment?, retainedIdentities: [NativeAuditRetentionFileIdentity]?, now: Date, completionNow: @escaping @Sendable () -> Date, recovered: Bool, beforeIrreversibleUnlink: () throws -> Void) throws -> NativeAuditPruneExecutionResult {
        let operationFD = openat(stateDescriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard operationFD >= 0 else { throw Self.posixError() }
        defer { close(operationFD) }
        try Self.validateDirectory(operationFD, device: archiveDevice, label: "Audit prune operation")
        let allowed = Set([Self.intentName, Self.manifestName, Self.quarantineName, Self.quarantinedMarker, Self.manifestMarker, Self.completedMarker])
        guard Set(try Self.names(operationFD)).isSubset(of: allowed) else {
            throw AgentPassNativeError.invalidSignature("Audit prune operation contains an unknown file")
        }
        let intentData = try Self.readImmutable(directoryFD: operationFD, name: Self.intentName, maximum: NativeAuditRetentionVerifier.maximumDocumentBytes * 4)
        let intent = try NativeAuditPruneExecutionIntent.decodeCanonical(intentData)
        let expected = try Self.executionIdentities(plan)
        let retainedData = try retained.map { try NativeAuditLog.canonical(["expected_next_retained": NativeAuditRetentionCodec.json($0)]) }
        let durableRetained = retainedIdentities ?? []
        let retainedSegmentHash = try retained.map(NativeAuditRetentionCodec.retainedSegmentHash) ?? NativeAuditLog.zeroHash
        let retainedFilesHash = try retained.map { _ in try NativeAuditRetentionCodec.fileIdentityHash(durableRetained) } ?? NativeAuditLog.zeroHash
        guard intent.operationID == plan.authorization.operationID,
              intent.authorizationData == plan.authorizationData,
              intent.receiptData == plan.receiptData,
              intent.authorizationHash == plan.authorization.authorizationHash,
              intent.receiptHash == plan.receipt.receiptHash,
              intent.files == expected,
              intent.expectedNextRetainedData == retainedData,
              intent.retainedFiles == durableRetained,
              (intent.expectedNextRetainedHash == retainedSegmentHash || intent.expectedNextRetainedHash == NativeAuditLog.zeroHash),
              (intent.retainedIdentityHash == retainedFilesHash || intent.retainedIdentityHash == NativeAuditLog.zeroHash) else {
            throw AgentPassNativeError.invalidSignature("Audit prune recovery plan equivocates with its durable intent")
        }
        try Self.requireRetained(directoryFD: archiveDescriptor, identities: intent.retainedFiles)
        let manifestData = try Self.readImmutable(directoryFD: operationFD, name: Self.manifestName, maximum: NativeAuditRetentionVerifier.maximumDocumentBytes)
        guard (try NativeAuditPostPruneManifest.decodeCanonical(manifestData)).manifestHash == intent.manifestHash else {
            throw AgentPassNativeError.invalidSignature("Audit prune manifest differs from its durable intent")
        }
        let manifest = try NativeAuditPostPruneManifest.decodeCanonical(manifestData)
        guard manifest.expectedNextRetainedHash == intent.expectedNextRetainedHash, manifest.retainedIdentityHash == intent.retainedIdentityHash else { throw AgentPassNativeError.invalidSignature("Audit prune manifest retained capability differs from durable intent") }
        let manifestVerificationNow: Date
        if recovered, let created = NativeAuditRetentionCodec.date(manifest.intentCreatedAt) {
            manifestVerificationNow = max(now, created)
        } else {
            manifestVerificationNow = now
        }
        _ = try verifier.verifyPostPruneManifest(manifestData, plan: plan, currentBoundary: boundary, expectedNextRetained: retained, expectedNextRetainedFileIdentities: retainedIdentities, now: manifestVerificationNow)
        let quarantineFD = openat(operationFD, Self.quarantineName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard quarantineFD >= 0 else { throw Self.posixError() }
        defer { close(quarantineFD) }
        try Self.validateDirectory(quarantineFD, device: archiveDevice, label: "Audit prune quarantine")
        let expectedNames = Set(expected.map(\.name))
        guard Set(try Self.names(quarantineFD)).isSubset(of: expectedNames) else {
            throw AgentPassNativeError.invalidSignature("Audit prune quarantine contains an unknown file")
        }

        if try Self.entryExists(operationFD, Self.completedMarker) {
            try Self.validateMarkers(operationFD: operationFD, operationID: intent.operationID, manifestHash: intent.manifestHash, requireCompleted: true)
            guard try Self.names(quarantineFD).isEmpty else {
                throw AgentPassNativeError.invalidSignature("Completed audit prune operation still has a target file")
            }
            for identity in expected where try Self.entryExists(archiveDescriptor, identity.name) {
                throw AgentPassNativeError.invalidSignature("Completed audit prune operation still has a target file")
            }
            let completionData = try Self.readImmutable(directoryFD: operationFD, name: Self.completedMarker, maximum: 4096)
            let completion = try NativeAuditPruneExecutorCompletionStatement.decodeCanonical(completionData)
            try Self.validateCompletion(completion, intent: intent, manifest: manifest)
            try Self.requireRetained(directoryFD: archiveDescriptor, identities: intent.retainedFiles)
            let quarantinedData = try Self.readImmutable(directoryFD: operationFD, name: Self.quarantinedMarker, maximum: 4096)
            let manifestCommitData = try Self.readImmutable(directoryFD: operationFD, name: Self.manifestMarker, maximum: 4096)
            return NativeAuditPruneExecutionResult(manifest: manifest, manifestData: manifestData, durableCompletionHash: NativeAuditLog.hash(completionData), completionStatementData: completionData, quarantinedMarkerData: quarantinedData, manifestCommitMarkerData: manifestCommitData, completedAt: completion.completedAt, recovered: recovered)
        }

        let manifestCommitted = try Self.entryExists(operationFD, Self.manifestMarker)
        for (index, identity) in expected.enumerated() {
            let source = try Self.entryExists(archiveDescriptor, identity.name)
            let quarantined = try Self.entryExists(quarantineFD, identity.name)
            guard !(source && quarantined) else {
                throw AgentPassNativeError.invalidSignature("Audit prune target exists in both archive and quarantine")
            }
            if source {
                guard !manifestCommitted else {
                    throw AgentPassNativeError.invalidSignature("Audit prune source reappeared after manifest commit")
                }
                try NativeAuditPruneFileSystem.reobserveAndMove(
                    sourceDirectoryFD: archiveDescriptor,
                    destinationDirectoryFD: quarantineFD,
                    identity: identity
                )
                guard fsync(archiveDescriptor) == 0, fsync(quarantineFD) == 0 else { throw Self.posixError() }
                try fault(.afterFileQuarantined(index))
            } else if quarantined {
                try NativeAuditPruneFileSystem.requireExact(directoryFD: quarantineFD, identity: identity)
            } else if !manifestCommitted {
                throw AgentPassNativeError.invalidSignature("Audit prune target disappeared before irreversible deletion was authorized")
            }
        }

        if try !Self.entryExists(operationFD, Self.quarantinedMarker) {
            guard Set(try Self.names(quarantineFD)) == expectedNames else {
                throw AgentPassNativeError.invalidSignature("Audit prune quarantine is incomplete")
            }
            try Self.writeMarker(operationFD: operationFD, name: Self.quarantinedMarker, operationID: intent.operationID, manifestHash: intent.manifestHash, previousHash: NativeAuditLog.zeroHash)
            try fault(.afterQuarantineSynced)
        }
        if try !Self.entryExists(operationFD, Self.manifestMarker) {
            let previous = try Self.fileHash(operationFD, Self.quarantinedMarker)
            try Self.writeMarker(operationFD: operationFD, name: Self.manifestMarker, operationID: intent.operationID, manifestHash: intent.manifestHash, previousHash: previous)
            try fault(.afterManifestCommitted)
        }
        try Self.validateMarkers(operationFD: operationFD, operationID: intent.operationID, manifestHash: intent.manifestHash, requireCompleted: false)

        for (index, identity) in expected.enumerated() {
            try Self.requireRetained(directoryFD: archiveDescriptor, identities: intent.retainedFiles)
            if try Self.entryExists(quarantineFD, identity.name) {
                try NativeAuditPruneFileSystem.requireExact(directoryFD: quarantineFD, identity: identity)
                try beforeIrreversibleUnlink()
                guard unlinkat(quarantineFD, identity.name, 0) == 0, fsync(quarantineFD) == 0 else { throw Self.posixError() }
                try fault(.afterFileUnlinked(index))
            }
        }
        guard try Self.names(quarantineFD).isEmpty else {
            throw AgentPassNativeError.invalidSignature("Audit prune quarantine did not become empty")
        }
        try Self.requireRetained(directoryFD: archiveDescriptor, identities: intent.retainedFiles)
        if try !Self.entryExists(operationFD, Self.completedMarker) {
            let previous = try Self.fileHash(operationFD, Self.manifestMarker)
            let created = NativeAuditRetentionCodec.date(intent.intentCreatedAt)!
            let completed = max(completionNow(), created)
            let statement = try NativeAuditPruneExecutorCompletionStatement.create(intent: intent, completedAt: Self.timestamp(completed), previousPhaseHash: previous)
            try Self.writeImmutable(directoryFD: operationFD, name: Self.completedMarker, data: try statement.canonicalData())
            try fault(.afterCompletionSynced)
        }
        try Self.validateMarkers(operationFD: operationFD, operationID: intent.operationID, manifestHash: intent.manifestHash, requireCompleted: true)
        let completionData = try Self.readImmutable(directoryFD: operationFD, name: Self.completedMarker, maximum: 4096)
        let completion = try NativeAuditPruneExecutorCompletionStatement.decodeCanonical(completionData)
        try Self.validateCompletion(completion, intent: intent, manifest: manifest)
        let quarantinedData = try Self.readImmutable(directoryFD: operationFD, name: Self.quarantinedMarker, maximum: 4096)
        let manifestCommitData = try Self.readImmutable(directoryFD: operationFD, name: Self.manifestMarker, maximum: 4096)
        return NativeAuditPruneExecutionResult(manifest: manifest, manifestData: manifestData, durableCompletionHash: NativeAuditLog.hash(completionData), completionStatementData: completionData, quarantinedMarkerData: quarantinedData, manifestCommitMarkerData: manifestCommitData, completedAt: completion.completedAt, recovered: recovered)
    }

    private static func makeManifest(plan: NativeAuditPrunePlan, retained: NativeAuditRetentionSegment?, retainedIdentities: [NativeAuditRetentionFileIdentity]?, completedAt: String, signer: P256MessageSigner) throws -> NativeAuditPostPruneManifest {
        let last = plan.authorization.segments.last!
        let retainedHash: String
        let identityHash: String
        if let retained, let retainedIdentities {
            retainedHash = try NativeAuditRetentionCodec.retainedSegmentHash(retained)
            identityHash = try NativeAuditRetentionCodec.fileIdentityHash(retainedIdentities)
        } else {
            // Compatibility for low-level non-production executor tests. The coordinator
            // rejects a null/unmeasured retained capability before signing or anchor contact.
            retainedHash = NativeAuditLog.zeroHash
            identityHash = NativeAuditLog.zeroHash
        }
        if let retained {
            let deleted = Set(plan.authorization.segments.flatMap { [$0.auditArchiveFile, $0.checkpointArchiveFile, $0.receiptArchiveFile] })
            guard deleted.isDisjoint(with: [retained.auditArchiveFile, retained.checkpointArchiveFile, retained.receiptArchiveFile]) else {
                throw AgentPassNativeError.invalidSignature("Audit prune plan attempts to delete the retained boundary")
            }
            return try .create(plan: plan, completedAt: completedAt, nextRetainedEventIndex: retained.firstEventIndex, nextRetainedCheckpointIndex: retained.firstCheckpointIndex, nextRetainedReceiptIndex: retained.firstReceiptIndex, nextRetainedEventPreviousHash: retained.previousEventHash, nextRetainedCheckpointPreviousHash: retained.previousCheckpointHash, nextRetainedReceiptPreviousHash: retained.previousReceiptHash, expectedNextRetainedHash: retainedHash, retainedIdentityHash: identityHash, signer: signer)
        }
        return try .create(plan: plan, completedAt: completedAt, nextRetainedEventIndex: last.lastEventIndex + 1, nextRetainedCheckpointIndex: last.lastCheckpointIndex + 1, nextRetainedReceiptIndex: last.lastReceiptIndex + 1, nextRetainedEventPreviousHash: last.terminalEventHash, nextRetainedCheckpointPreviousHash: last.terminalCheckpointHash, nextRetainedReceiptPreviousHash: last.terminalReceiptHash, expectedNextRetainedHash: retainedHash, retainedIdentityHash: identityHash, signer: signer)
    }

    private static func executionIdentities(_ plan: NativeAuditPrunePlan) throws -> [NativeAuditRetentionFileIdentity] {
        var result: [NativeAuditRetentionFileIdentity] = []
        for (segment, observation) in zip(plan.authorization.segments, plan.observedArchives) {
            guard observation.segment == segment, let identities = observation.fileIdentities, identities.count == 3,
                  identities.map(\.name) == [segment.auditArchiveFile, segment.checkpointArchiveFile, segment.receiptArchiveFile],
                  identities.map(\.sha256) == [segment.auditArchiveSHA256, segment.checkpointArchiveSHA256, segment.receiptArchiveSHA256] else {
                throw AgentPassNativeError.invalidSignature("Audit prune plan has partial or mismatched filesystem observations")
            }
            result.append(contentsOf: identities)
        }
        guard Set(result.map(\.name)).count == result.count else {
            throw AgentPassNativeError.invalidSignature("Audit prune plan repeats a filesystem target")
        }
        return result
    }

    private func validateRoots() throws {
        var info = stat()
        guard fstat(archiveDescriptor, &info) == 0, UInt64(info.st_dev) == archiveDevice, UInt64(info.st_ino) == archiveInode,
              (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
            throw AgentPassNativeError.invalidConfiguration("Audit archive directory identity changed")
        }
        let allowed = try Self.names(stateDescriptor)
        guard allowed.allSatisfy({ $0.hasPrefix("op-") && $0.count == 67 }) else {
            throw AgentPassNativeError.invalidSignature("Audit prune state contains an unknown entry")
        }
    }

    private static func removeValidatedTemporaryOperations(stateDescriptor: Int32, archiveDevice: UInt64) throws {
        let temporaryPattern = /^\.tmp-op-[0-9a-f]{64}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
        for name in try names(stateDescriptor) where name.hasPrefix(".tmp-") {
            guard name.wholeMatch(of: temporaryPattern) != nil else { throw AgentPassNativeError.invalidSignature("Audit prune state contains an unrecognized temporary operation") }
            let descriptor = openat(stateDescriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw posixError() }
            defer { close(descriptor) }
            try validateDirectory(descriptor, device: archiveDevice, label: "Audit prune temporary operation")
            guard Set(try names(descriptor)) == Set([intentName, manifestName, quarantineName]) else { throw AgentPassNativeError.invalidSignature("Audit prune temporary operation is not an exact pre-rename remnant") }
            let intentData = try readImmutable(directoryFD: descriptor, name: intentName, maximum: NativeAuditRetentionVerifier.maximumDocumentBytes * 4)
            let intent = try NativeAuditPruneExecutionIntent.decodeCanonical(intentData)
            let manifestData = try readImmutable(directoryFD: descriptor, name: manifestName, maximum: NativeAuditRetentionVerifier.maximumDocumentBytes)
            guard try NativeAuditPostPruneManifest.decodeCanonical(manifestData).manifestHash == intent.manifestHash else { throw AgentPassNativeError.invalidSignature("Audit prune temporary manifest is not bound to intent") }
            let quarantine = openat(descriptor, quarantineName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard quarantine >= 0 else { throw posixError() }
            defer { close(quarantine) }
            try validateDirectory(quarantine, device: archiveDevice, label: "Audit prune temporary quarantine")
            guard try names(quarantine).isEmpty else { throw AgentPassNativeError.invalidSignature("Audit prune temporary quarantine is not empty") }
            guard unlinkat(descriptor, intentName, 0) == 0, unlinkat(descriptor, manifestName, 0) == 0,
                  unlinkat(descriptor, quarantineName, AT_REMOVEDIR) == 0, fsync(descriptor) == 0,
                  unlinkat(stateDescriptor, name, AT_REMOVEDIR) == 0, fsync(stateDescriptor) == 0 else { throw posixError() }
        }
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        processLock.lock(); defer { processLock.unlock() }
        guard flock(stateDescriptor, LOCK_EX) == 0 else { throw Self.posixError() }
        defer { flock(stateDescriptor, LOCK_UN) }
        return try body()
    }

    private static func operationDirectoryName(_ operationID: String) -> String {
        "op-" + NativeAuditLog.hash(Data(operationID.utf8))
    }

    private static func writeMarker(operationFD: Int32, name: String, operationID: String, manifestHash: String, previousHash: String) throws {
        let data = try NativeAuditLog.canonical(["version": 1, "operation_id": operationID, "manifest_hash": manifestHash, "previous_phase_hash": previousHash, "phase": name])
        try writeImmutable(directoryFD: operationFD, name: name, data: data)
        guard fsync(operationFD) == 0 else { throw posixError() }
    }

    private static func validateMarkers(operationFD: Int32, operationID: String, manifestHash: String, requireCompleted: Bool) throws {
        let chain = [quarantinedMarker, manifestMarker]
        var previous = NativeAuditLog.zeroHash
        for name in chain {
            let data = try readImmutable(directoryFD: operationFD, name: name, maximum: 4096)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(object.keys) == Set(["version", "operation_id", "manifest_hash", "previous_phase_hash", "phase"]),
                  object["version"] as? Int == 1, object["operation_id"] as? String == operationID,
                  object["manifest_hash"] as? String == manifestHash, object["previous_phase_hash"] as? String == previous,
                  object["phase"] as? String == name, try NativeAuditLog.canonical(object) == data else {
                throw AgentPassNativeError.invalidSignature("Audit prune phase journal is invalid")
            }
            previous = NativeAuditLog.hash(data)
        }
        if requireCompleted {
            let data = try readImmutable(directoryFD: operationFD, name: completedMarker, maximum: 4096)
            let statement = try NativeAuditPruneExecutorCompletionStatement.decodeCanonical(data)
            guard statement.operationID == operationID, statement.manifestHash == manifestHash, statement.previousPhaseHash == previous else { throw AgentPassNativeError.invalidSignature("Audit prune completion statement breaks the durable phase chain") }
        }
    }

    private static func validateCompletion(_ value: NativeAuditPruneExecutorCompletionStatement, intent: NativeAuditPruneExecutionIntent, manifest: NativeAuditPostPruneManifest) throws {
        guard value.operationID == intent.operationID, value.authorizationHash == intent.authorizationHash,
              value.receiptHash == intent.receiptHash, value.manifestHash == intent.manifestHash,
              value.expectedNextRetainedHash == intent.expectedNextRetainedHash,
              value.retainedIdentityHash == intent.retainedIdentityHash,
              value.intentCreatedAt == intent.intentCreatedAt, manifest.intentCreatedAt == intent.intentCreatedAt else {
            throw AgentPassNativeError.invalidSignature("Audit prune completion statement is not bound to its durable intent")
        }
    }

    private static func requireRetained(directoryFD: Int32, identities: [NativeAuditRetentionFileIdentity]) throws {
        do {
            for identity in identities { try NativeAuditPruneFileSystem.requireExact(directoryFD: directoryFD, identity: identity) }
        } catch {
            throw AgentPassNativeError.invalidSignature("Audit prune retained capability disappeared or changed after durable intent")
        }
    }

    private static func timestamp(_ value: Date) -> String {
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: value)
    }

    private static func fileHash(_ directoryFD: Int32, _ name: String) throws -> String {
        NativeAuditLog.hash(try readImmutable(directoryFD: directoryFD, name: name, maximum: 4096))
    }

    private static func writeImmutable(directoryFD: Int32, name: String, data: Data) throws {
        let temporary = ".tmp-\(UUID().uuidString.lowercased())"
        let fd = openat(directoryFD, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw posixError() }
        var keep = false
        defer { close(fd); if !keep { _ = unlinkat(directoryFD, temporary, 0) } }
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                guard count > 0 else { throw posixError() }
                offset += count
            }
        }
        guard fchmod(fd, 0o400) == 0, fsync(fd) == 0,
              renameatx_np(directoryFD, temporary, directoryFD, name, UInt32(RENAME_EXCL)) == 0,
              fsync(directoryFD) == 0 else { throw posixError() }
        keep = true
    }

    private static func readImmutable(directoryFD: Int32, name: String, maximum: Int) throws -> Data {
        let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posixError() }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG,
              before.st_uid == geteuid(), before.st_mode & 0o777 == 0o400, before.st_nlink == 1,
              before.st_size > 0, before.st_size <= maximum else {
            throw AgentPassNativeError.invalidSignature("Audit prune state file is not immutable")
        }
        var data = Data(); data.reserveCapacity(Int(before.st_size)); var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            guard count >= 0 else { throw posixError() }
            if count == 0 { break }
            data.append(buffer, count: count)
        }
        var after = stat()
        guard data.count == Int(before.st_size), fstat(fd, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino, before.st_size == after.st_size,
              before.st_mode == after.st_mode, before.st_uid == after.st_uid, before.st_nlink == after.st_nlink else {
            throw AgentPassNativeError.invalidSignature("Audit prune state changed while being read")
        }
        return data
    }

    private static func names(_ directoryFD: Int32) throws -> [String] {
        // `dup` shares a directory offset with the original descriptor. Open `.` instead so
        // repeated validation always starts at offset zero.
        let duplicate = openat(directoryFD, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard duplicate >= 0, let stream = fdopendir(duplicate) else { if duplicate >= 0 { close(duplicate) }; throw posixError() }
        defer { closedir(stream) }
        var result: [String] = []
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { result.append(name) }
        }
        return result.sorted()
    }

    private static func entryExists(_ directoryFD: Int32, _ name: String) throws -> Bool {
        var info = stat()
        if fstatat(directoryFD, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        if errno == ENOENT { return false }
        throw posixError()
    }

    private static func validateDirectory(_ descriptor: Int32, device: UInt64, label: String) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0, UInt64(info.st_dev) == device else {
            throw AgentPassNativeError.invalidConfiguration("\(label) is not a private directory on the archive filesystem")
        }
    }

    private static func posixError() -> Error { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}

fileprivate struct NativeAuditPruneExecutionIntent: Codable, Equatable {
    let version: Int
    let operationID: String
    let authorizationData: Data
    let receiptData: Data
    let authorizationHash: String
    let receiptHash: String
    let manifestHash: String
    let files: [NativeAuditRetentionFileIdentity]
    let expectedNextRetainedData: Data?
    let retainedFiles: [NativeAuditRetentionFileIdentity]
    let expectedNextRetainedHash: String
    let retainedIdentityHash: String
    let intentCreatedAt: String

    func canonicalData() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = try encoder.encode(self)
        guard let object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any] else {
            throw AgentPassNativeError.invalidSignature("Audit prune execution intent schema is invalid")
        }
        return try NativeAuditLog.canonical(object)
    }

    static func decodeCanonical(_ data: Data) throws -> Self {
        guard data.count <= NativeAuditRetentionVerifier.maximumDocumentBytes * 4 else {
            throw AgentPassNativeError.invalidSignature("Audit prune execution intent is too large")
        }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.version == 2, NativeAuditRetentionCodec.isSlug(value.operationID),
              NativeAuditRetentionCodec.isHash(value.authorizationHash), NativeAuditRetentionCodec.isHash(value.receiptHash), NativeAuditRetentionCodec.isHash(value.manifestHash), !value.files.isEmpty,
              NativeAuditRetentionCodec.isHash(value.expectedNextRetainedHash), NativeAuditRetentionCodec.isHash(value.retainedIdentityHash), NativeAuditRetentionCodec.date(value.intentCreatedAt) != nil,
              (value.expectedNextRetainedHash == NativeAuditLog.zeroHash && value.retainedIdentityHash == NativeAuditLog.zeroHash || (value.expectedNextRetainedData == nil ? value.retainedFiles.isEmpty : value.retainedFiles.count == 3)),
              try value.canonicalData() == data else {
            throw AgentPassNativeError.invalidSignature("Audit prune execution intent is invalid")
        }
        return value
    }
}

private enum NativeAuditPruneFileSystem {
    struct TrustedDirectory { let path: String; let descriptor: Int32; let info: stat }

    static func openTrustedDirectory(_ path: String, label: String) throws -> TrustedDirectory {
        guard path.hasPrefix("/") else { throw AgentPassNativeError.invalidConfiguration("\(label) path must be absolute") }
        guard !path.contains("//"), !path.split(separator: "/", omittingEmptySubsequences: true).contains(where: { $0 == "." || $0 == ".." }) else {
            throw AgentPassNativeError.invalidConfiguration("\(label) path must be normalized")
        }
        guard let resolved = realpath(path, nil) else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { free(resolved) }
        let canonical = String(cString: resolved)
        guard path == canonical else { throw AgentPassNativeError.invalidConfiguration("\(label) path must not contain symbolic links") }
        let fd = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
            close(fd)
            throw AgentPassNativeError.invalidConfiguration("\(label) must be a private service-owned directory")
        }
        return TrustedDirectory(path: canonical, descriptor: fd, info: info)
    }

    static func observeFile(directoryFD: Int32, name: String, expectedHash: String) throws -> NativeAuditRetentionFileIdentity {
        guard NativeAuditRetentionCodec.isFile(name), NativeAuditRetentionCodec.isHash(expectedHash) else {
            throw AgentPassNativeError.invalidSignature("Audit prune filename or hash is invalid")
        }
        let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(fd) }
        return try observeDescriptor(fd, name: name, expectedHash: expectedHash)
    }

    fileprivate static func observeDescriptor(_ fd: Int32, name: String, expectedHash: String) throws -> NativeAuditRetentionFileIdentity {
        var before = stat()
        guard fstat(fd, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG,
              before.st_uid == geteuid(), before.st_mode & 0o077 == 0, before.st_nlink == 1,
              before.st_size > 0, before.st_size <= NativeAuditRetentionArchiveObservation.maximumArchiveBytes else {
            throw AgentPassNativeError.invalidSignature("Audit prune target must be a private, singly-linked regular file")
        }
        var hasher = SHA256(); var total = 0; var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            guard count >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            if count == 0 { break }
            hasher.update(data: Data(buffer[0..<count])); total += count
        }
        guard fsync(fd) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var after = stat()
        let hash = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        guard fstat(fd, &after) == 0, total == Int(before.st_size), hash == expectedHash,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino, before.st_mode == after.st_mode,
              before.st_uid == after.st_uid, before.st_gid == after.st_gid, before.st_nlink == after.st_nlink, before.st_size == after.st_size else {
            throw AgentPassNativeError.invalidSignature("Audit prune target changed while being observed")
        }
        return NativeAuditRetentionFileIdentity(name: name, device: UInt64(before.st_dev), inode: UInt64(before.st_ino), mode: UInt32(before.st_mode), owner: before.st_uid, group: before.st_gid, linkCount: UInt64(before.st_nlink), size: total, sha256: hash)
    }

    static func requireExact(directoryFD: Int32, identity: NativeAuditRetentionFileIdentity) throws {
        let observed = try observeFile(directoryFD: directoryFD, name: identity.name, expectedHash: identity.sha256)
        guard observed == identity else { throw AgentPassNativeError.invalidSignature("Audit prune target identity changed after verification") }
    }

    static func reobserveAndMove(sourceDirectoryFD: Int32, destinationDirectoryFD: Int32, identity: NativeAuditRetentionFileIdentity) throws {
        let fd = openat(sourceDirectoryFD, identity.name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(fd) }
        guard try observeDescriptor(fd, name: identity.name, expectedHash: identity.sha256) == identity else {
            throw AgentPassNativeError.invalidSignature("Audit prune target identity changed immediately before quarantine")
        }
        var sourcePath = stat()
        guard fstatat(sourceDirectoryFD, identity.name, &sourcePath, AT_SYMLINK_NOFOLLOW) == 0,
              UInt64(sourcePath.st_dev) == identity.device, UInt64(sourcePath.st_ino) == identity.inode,
              UInt64(sourcePath.st_nlink) == identity.linkCount else {
            throw AgentPassNativeError.invalidSignature("Audit prune source path was swapped before quarantine")
        }
        guard renameatx_np(sourceDirectoryFD, identity.name, destinationDirectoryFD, identity.name, UInt32(RENAME_EXCL)) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var descriptorInfo = stat(), destinationPath = stat()
        guard fstat(fd, &descriptorInfo) == 0,
              fstatat(destinationDirectoryFD, identity.name, &destinationPath, AT_SYMLINK_NOFOLLOW) == 0,
              UInt64(descriptorInfo.st_dev) == identity.device, UInt64(descriptorInfo.st_ino) == identity.inode,
              UInt64(descriptorInfo.st_nlink) == identity.linkCount,
              destinationPath.st_dev == descriptorInfo.st_dev, destinationPath.st_ino == descriptorInfo.st_ino,
              destinationPath.st_mode == descriptorInfo.st_mode, destinationPath.st_uid == descriptorInfo.st_uid,
              destinationPath.st_gid == descriptorInfo.st_gid, destinationPath.st_size == descriptorInfo.st_size else {
            throw AgentPassNativeError.invalidSignature("Audit prune path was swapped during quarantine")
        }
    }
}
