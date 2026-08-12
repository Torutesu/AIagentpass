import CryptoKit
import Darwin
import Foundation

/// The store deliberately receives a descriptor and bytes that have already been
/// validated by the ControlBundle verifier.  It does not parse or verify signatures;
/// it only binds the descriptor to the exact bytes that it durably installs.
public struct NativeAtomicControlBundleDescriptor: Equatable, Sendable {
    public let generation: Int64
    public let sequence: Int64
    public let statementHash: String
    public let contentHash: String

    public init(generation: Int64, sequence: Int64, statementHash: String, contentHash: String) throws {
        guard generation > 0, sequence > 0 else {
            throw NativeAtomicControlBundleStoreError(.invalidDescriptor, "generation and sequence must be positive")
        }
        guard NativeAtomicControlBundleStoreSupport.isHash(statementHash), NativeAtomicControlBundleStoreSupport.isHash(contentHash) else {
            throw NativeAtomicControlBundleStoreError(.invalidDescriptor, "descriptor hashes must be lowercase SHA-256 hex")
        }
        self.generation = generation
        self.sequence = sequence
        self.statementHash = statementHash
        self.contentHash = contentHash
    }
}

public struct NativeAtomicControlBundleSnapshot: Equatable, Sendable {
    public let descriptor: NativeAtomicControlBundleDescriptor
    public let canonicalBytes: Data

    public init(descriptor: NativeAtomicControlBundleDescriptor, canonicalBytes: Data) {
        self.descriptor = descriptor
        self.canonicalBytes = canonicalBytes
    }
}

public enum NativeAtomicControlBundleStoreReason: String, Sendable {
    case invalidRoot
    case rootNotFound
    case unsafeRoot
    case unsafePath
    case unsafeNode
    case invalidConfiguration
    case invalidDescriptor
    case bundleTooLarge
    case contentHashMismatch
    case statementConflict
    case sequenceRollback
    case generationRollback
    case pointerCorrupt
    case bundleCorrupt
    case activationVerificationFailed
    case ioFailure
    case failpoint
}

public struct NativeAtomicControlBundleStoreError: LocalizedError, Equatable, Sendable {
    public let reason: NativeAtomicControlBundleStoreReason
    public let message: String

    public init(_ reason: NativeAtomicControlBundleStoreReason, _ message: String? = nil) {
        self.reason = reason
        self.message = message ?? reason.rawValue
    }

    public var errorDescription: String? { "\(reason.rawValue): \(message)" }
}

public enum NativeAtomicControlBundleNodeKind: Equatable, Sendable {
    case regular
    case directory
    case symlink
    case other
}

public struct NativeAtomicControlBundleFileMetadata: Equatable, Sendable {
    public let kind: NativeAtomicControlBundleNodeKind
    public let ownerUID: UInt32
    public let mode: UInt16
    public let linkCount: UInt64
    public let size: Int64

    public init(kind: NativeAtomicControlBundleNodeKind, ownerUID: UInt32, mode: UInt16, linkCount: UInt64, size: Int64) {
        self.kind = kind
        self.ownerUID = ownerUID
        self.mode = mode
        self.linkCount = linkCount
        self.size = size
    }
}

/// The deliberately small filesystem surface makes every durability boundary
/// injectable.  Production uses the POSIX implementation below; tests can model
/// power loss without touching the host filesystem.
public protocol NativeAtomicControlBundleFileSystem: Sendable {
    func metadata(at path: String) throws -> NativeAtomicControlBundleFileMetadata?
    func listDirectory(at path: String) throws -> [String]
    func createDirectory(at path: String, mode: UInt16) throws
    func createExclusive(at path: String, mode: UInt16) throws -> Int32
    func write(_ data: Data, to descriptor: Int32) throws
    func setMode(_ mode: UInt16, for descriptor: Int32) throws
    func synchronize(_ descriptor: Int32) throws
    func close(_ descriptor: Int32) throws
    func read(at path: String) throws -> Data
    func linkNoReplace(from: String, to: String) throws
    func replaceAtomically(from: String, to: String) throws
    func remove(at path: String) throws
    func synchronizeDirectory(at path: String) throws
}

public enum NativeAtomicControlBundleStoreFailpoint: String, CaseIterable, Sendable {
    case beforeStageCreate
    case afterStageWrite
    case afterStageFileSync
    case afterStageMode
    case afterStageModeSync
    case afterStageClose
    case beforeStageRead
    case afterStageRead
    case beforeBundleLink
    case afterBundleLink
    case afterBundlesDirectorySync
    case beforeStageRemove
    case afterStageRemove
    case afterStagingDirectorySync
    case beforePointerCreate
    case afterPointerWrite
    case afterPointerFileSync
    case afterPointerMode
    case afterPointerModeSync
    case afterPointerClose
    case beforePointerRead
    case afterPointerRead
    case beforePointerReplace
    case afterPointerReplace
    case afterRootDirectorySync
}

public protocol NativeAtomicControlBundleStoreFailpointHandler: Sendable {
    func check(_ point: NativeAtomicControlBundleStoreFailpoint) throws
}

public struct NativeAtomicControlBundleStoreNoFailpoint: NativeAtomicControlBundleStoreFailpointHandler, Sendable {
    public init() {}
    public func check(_ point: NativeAtomicControlBundleStoreFailpoint) throws {}
}

public struct NativeAtomicControlBundlePOSIXFileSystem: NativeAtomicControlBundleFileSystem, Sendable {
    public init() {}

    public func metadata(at path: String) throws -> NativeAtomicControlBundleFileMetadata? {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            if errno == ENOENT { return nil }
            throw Self.posixError()
        }
        let type = info.st_mode & S_IFMT
        let kind: NativeAtomicControlBundleNodeKind
        if type == S_IFREG {
            kind = .regular
        } else if type == S_IFDIR {
            kind = .directory
        } else if type == S_IFLNK {
            kind = .symlink
        } else {
            kind = .other
        }
        return NativeAtomicControlBundleFileMetadata(
            kind: kind,
            ownerUID: UInt32(info.st_uid),
            mode: UInt16(info.st_mode & 0o777),
            linkCount: UInt64(info.st_nlink),
            size: Int64(info.st_size)
        )
    }

    public func listDirectory(at path: String) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: path).sorted()
    }

    public func createDirectory(at path: String, mode: UInt16) throws {
        guard mkdir(path, mode_t(mode)) == 0 else {
            if errno == EEXIST { return }
            throw Self.posixError()
        }
        guard chmod(path, mode_t(mode)) == 0 else { throw Self.posixError() }
    }

    public func createExclusive(at path: String, mode: UInt16) throws -> Int32 {
        let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(mode))
        guard descriptor >= 0 else { throw Self.posixError() }
        return descriptor
    }

    public func write(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard var base = rawBuffer.baseAddress else { return }
            var remaining = rawBuffer.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, base, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw Self.posixError()
                }
                guard written > 0 else { throw POSIXError(.EIO) }
                remaining -= written
                base = base.advanced(by: written)
            }
        }
    }

    public func setMode(_ mode: UInt16, for descriptor: Int32) throws {
        guard fchmod(descriptor, mode_t(mode)) == 0 else { throw Self.posixError() }
    }

    public func synchronize(_ descriptor: Int32) throws {
        guard fsync(descriptor) == 0 else { throw Self.posixError() }
    }

    public func close(_ descriptor: Int32) throws {
        guard Darwin.close(descriptor) == 0 else { throw Self.posixError() }
    }

    public func read(at path: String) throws -> Data {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        var result = Data()
        do {
            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let count = buffer.withUnsafeMutableBytes { bytes in
                    Darwin.read(descriptor, bytes.baseAddress, bytes.count)
                }
                if count < 0 {
                    if errno == EINTR { continue }
                    throw Self.posixError()
                }
                if count == 0 { break }
                result.append(buffer, count: count)
            }
            try close(descriptor)
            return result
        } catch {
            try? close(descriptor)
            throw error
        }
    }

    public func linkNoReplace(from: String, to: String) throws {
        guard link(from, to) == 0 else { throw Self.posixError() }
    }

    public func replaceAtomically(from: String, to: String) throws {
        guard Darwin.rename(from, to) == 0 else { throw Self.posixError() }
    }

    public func remove(at path: String) throws {
        guard unlink(path) == 0 else {
            if errno == ENOENT { return }
            throw Self.posixError()
        }
    }

    public func synchronizeDirectory(at path: String) throws {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.posixError() }
        do {
            try synchronize(descriptor)
            try close(descriptor)
        } catch {
            try? close(descriptor)
            throw error
        }
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}

public final class NativeAtomicControlBundleStore: @unchecked Sendable {
    public static let defaultMaximumBundleBytes = 256 * 1024
    public static let absoluteMaximumBundleBytes = 16 * 1024 * 1024
    private static let maximumPointerBytes = 2 * 1024

    public let rootPath: String
    public let maximumBundleBytes: Int

    private let fileSystem: any NativeAtomicControlBundleFileSystem
    private let failpoint: any NativeAtomicControlBundleStoreFailpointHandler
    private let lock = NSLock()
    private let bundlesPath: String
    private let stagingPath: String
    private let activePointerPath: String

    public init(
        rootURL: URL,
        maximumBundleBytes: Int = NativeAtomicControlBundleStore.defaultMaximumBundleBytes,
        fileSystem: any NativeAtomicControlBundleFileSystem = NativeAtomicControlBundlePOSIXFileSystem(),
        failpoint: any NativeAtomicControlBundleStoreFailpointHandler = NativeAtomicControlBundleStoreNoFailpoint()
    ) throws {
        guard rootURL.isFileURL else {
            throw NativeAtomicControlBundleStoreError(.invalidRoot, "store root must be a file URL")
        }
        let rawPath = rootURL.path
        guard rawPath.hasPrefix("/"), !rawPath.isEmpty else {
            throw NativeAtomicControlBundleStoreError(.invalidRoot, "store root must be absolute")
        }
        guard !rawPath.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }) else {
            throw NativeAtomicControlBundleStoreError(.unsafePath, "store root contains traversal components")
        }
        let standardized = URL(fileURLWithPath: rawPath).standardizedFileURL.path
        guard standardized == rawPath || standardized == rawPath + "/" else {
            throw NativeAtomicControlBundleStoreError(.unsafePath, "store root is not canonical")
        }
        guard maximumBundleBytes > 0, maximumBundleBytes <= Self.absoluteMaximumBundleBytes else {
            throw NativeAtomicControlBundleStoreError(.invalidConfiguration, "maximum bundle size is outside the supported bound")
        }

        self.rootPath = standardized == "/" ? "/" : standardized.trimmingCharacters(in: CharacterSet(charactersIn: "/")) == "" ? "/" : standardized
        self.maximumBundleBytes = maximumBundleBytes
        self.fileSystem = fileSystem
        self.failpoint = failpoint
        self.bundlesPath = self.rootPath == "/" ? "/bundles" : self.rootPath + "/bundles"
        self.stagingPath = self.rootPath == "/" ? "/staging" : self.rootPath + "/staging"
        self.activePointerPath = self.rootPath == "/" ? "/active.pointer" : self.rootPath + "/active.pointer"

        try validateRootPathComponents()
        try validateRootAndPrepare()
        try recoverAndValidate()
    }

    public func active() throws -> NativeAtomicControlBundleSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        return try loadActive()
    }

    @discardableResult
    public func install(descriptor: NativeAtomicControlBundleDescriptor, canonicalBytes: Data) throws -> NativeAtomicControlBundleSnapshot {
        lock.lock()
        defer { lock.unlock() }

        do {
            try validate(descriptor: descriptor, bytes: canonicalBytes)
            let evidence = try scanBundleEvidence()
            let current = try loadActive()
            try enforceOrdering(descriptor: descriptor, current: current, evidence: evidence)

            let finalName = Self.bundleFileName(descriptor)
            let finalPath = bundlesPath + "/" + finalName
            let finalMetadata = try fileSystem.metadata(at: finalPath)
            if let finalMetadata {
                try validateImmutableFile(finalMetadata, path: finalPath, allowTransientLink: false)
                let existing = try readAndVerify(path: finalPath, expectedHash: descriptor.contentHash, allowTransientLink: false)
                guard existing == canonicalBytes else {
                    throw NativeAtomicControlBundleStoreError(.contentHashMismatch, "immutable bundle path contains different bytes")
                }
            } else {
                try publishImmutableBundle(descriptor: descriptor, bytes: canonicalBytes, finalPath: finalPath)
            }

            if let current, current.descriptor == descriptor {
                guard current.canonicalBytes == canonicalBytes else {
                    throw NativeAtomicControlBundleStoreError(.contentHashMismatch, "same descriptor was supplied with different bytes")
                }
                return current
            }

            try activate(descriptor: descriptor, finalName: finalName)
            guard let activated = try loadActive(), activated.descriptor == descriptor, activated.canonicalBytes == canonicalBytes else {
                throw NativeAtomicControlBundleStoreError(.activationVerificationFailed, "active pointer did not bind the installed bytes")
            }
            return activated
        } catch let error as NativeAtomicControlBundleStoreError {
            throw error
        } catch {
            throw NativeAtomicControlBundleStoreError(.ioFailure, error.localizedDescription)
        }
    }

    private func validateRootAndPrepare() throws {
        guard let root = try fileSystem.metadata(at: rootPath) else {
            throw NativeAtomicControlBundleStoreError(.rootNotFound, "service-owned root does not exist")
        }
        try requireDirectory(root, path: rootPath, exactMode: 0o700, label: "store root")

        for (path, label) in [(bundlesPath, "bundle directory"), (stagingPath, "staging directory")] {
            if let metadata = try fileSystem.metadata(at: path) {
                try requireDirectory(metadata, path: path, exactMode: 0o700, label: label)
            } else {
                try fileSystem.createDirectory(at: path, mode: 0o700)
                guard let created = try fileSystem.metadata(at: path) else {
                    throw NativeAtomicControlBundleStoreError(.unsafeNode, "\(label) was not created")
                }
                try requireDirectory(created, path: path, exactMode: 0o700, label: label)
                try fileSystem.synchronizeDirectory(at: rootPath)
            }
        }
    }

    private func recoverAndValidate() throws {
        try cleanupTemporaryFiles()

        let rootEntries = try fileSystem.listDirectory(at: rootPath)
        for name in rootEntries {
            guard name == "active.pointer" || name == "bundles" || name == "staging" else {
                throw NativeAtomicControlBundleStoreError(.unsafePath, "unexpected entry in store root: \(name)")
            }
            guard !name.contains("/") && name != "." && name != ".." else {
                throw NativeAtomicControlBundleStoreError(.unsafePath, "path traversal entry in store root")
            }
        }
        _ = try scanBundleEvidence()
        if let metadata = try fileSystem.metadata(at: activePointerPath) {
            try validatePrivateRegular(metadata, path: activePointerPath, expectedMode: 0o600, label: "active pointer")
            guard metadata.size >= 0, metadata.size <= Int64(Self.maximumPointerBytes) else {
                throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer size is invalid")
            }
            _ = try loadActive(injectFailpoint: false)
        }
    }

    private func validateRootPathComponents() throws {
        guard rootPath != "/" else { return }
        var current = ""
        for component in rootPath.split(separator: "/") {
            current += "/" + component
            guard let metadata = try fileSystem.metadata(at: current) else {
                throw NativeAtomicControlBundleStoreError(.rootNotFound, "root path component does not exist: \(current)")
            }
            guard metadata.kind == .directory else {
                throw NativeAtomicControlBundleStoreError(.unsafeRoot, "root path component is not a directory: \(current)")
            }
            guard metadata.kind != .symlink else {
                throw NativeAtomicControlBundleStoreError(.unsafeRoot, "root path component is a symlink: \(current)")
            }
        }
    }

    private func cleanupTemporaryFiles() throws {
        var removedRoot = false
        for name in try fileSystem.listDirectory(at: rootPath) {
            guard !name.contains("/") && name != "." && name != ".." else {
                throw NativeAtomicControlBundleStoreError(.unsafePath, "invalid root entry")
            }
            if Self.isPointerTemporaryName(name) {
                let path = rootPath + "/" + name
                guard let metadata = try fileSystem.metadata(at: path) else { continue }
                try validatePrivateRegular(metadata, path: path, expectedMode: 0o600, label: "pointer temporary")
                try fileSystem.remove(at: path)
                removedRoot = true
            }
        }
        if removedRoot { try fileSystem.synchronizeDirectory(at: rootPath) }

        var removedStaging = false
        for name in try fileSystem.listDirectory(at: stagingPath) {
            guard !name.contains("/") && name != "." && name != ".." else {
                throw NativeAtomicControlBundleStoreError(.unsafePath, "invalid staging entry")
            }
            if Self.isStageTemporaryName(name) {
                let path = stagingPath + "/" + name
                guard let metadata = try fileSystem.metadata(at: path) else { continue }
                try validateTemporary(metadata, path: path, label: "staging temporary")
                try fileSystem.remove(at: path)
                removedStaging = true
            } else {
                throw NativeAtomicControlBundleStoreError(.unsafePath, "unexpected staging entry: \(name)")
            }
        }
        if removedStaging { try fileSystem.synchronizeDirectory(at: stagingPath) }
    }

    private func scanBundleEvidence() throws -> [String: NativeAtomicControlBundleDescriptor] {
        var evidence: [String: NativeAtomicControlBundleDescriptor] = [:]
        for name in try fileSystem.listDirectory(at: bundlesPath) {
            guard !name.contains("/") && name != "." && name != ".." else {
                throw NativeAtomicControlBundleStoreError(.unsafePath, "invalid bundle entry")
            }
            guard let descriptor = Self.descriptor(fromBundleFileName: name) else {
                throw NativeAtomicControlBundleStoreError(.unsafePath, "unexpected bundle filename: \(name)")
            }
            let path = bundlesPath + "/" + name
            guard let metadata = try fileSystem.metadata(at: path) else {
                throw NativeAtomicControlBundleStoreError(.bundleCorrupt, "bundle disappeared while scanning")
            }
            try validateImmutableFile(metadata, path: path, allowTransientLink: false)
            _ = try readAndVerify(path: path, expectedHash: descriptor.contentHash, allowTransientLink: false)
            let key = Self.orderingKey(descriptor)
            if let previous = evidence[key], previous != descriptor {
                throw NativeAtomicControlBundleStoreError(.statementConflict, "bundle evidence equivocates at generation and sequence")
            }
            evidence[key] = descriptor
        }
        return evidence
    }

    private func enforceOrdering(
        descriptor: NativeAtomicControlBundleDescriptor,
        current: NativeAtomicControlBundleSnapshot?,
        evidence: [String: NativeAtomicControlBundleDescriptor]
    ) throws {
        if let prior = evidence[Self.orderingKey(descriptor)], prior != descriptor {
            throw NativeAtomicControlBundleStoreError(.statementConflict, "same generation and sequence has a different statement hash")
        }
        var priorDescriptors = Array(evidence.values)
        if let currentDescriptor = current?.descriptor { priorDescriptors.append(currentDescriptor) }
        guard let highest = priorDescriptors.max(by: Self.compare) else {
            return
        }
        if descriptor.generation < highest.generation {
            throw NativeAtomicControlBundleStoreError(.generationRollback, "bundle generation rolled back")
        }
        if descriptor.sequence < highest.sequence || (descriptor.generation > highest.generation && descriptor.sequence == highest.sequence) {
            throw NativeAtomicControlBundleStoreError(.sequenceRollback, "bundle sequence rolled back")
        }
        if descriptor.sequence == highest.sequence, descriptor.statementHash != highest.statementHash {
            throw NativeAtomicControlBundleStoreError(.statementConflict, "same sequence has a different statement hash")
        }
    }

    private func publishImmutableBundle(descriptor: NativeAtomicControlBundleDescriptor, bytes: Data, finalPath: String) throws {
        let stageName = ".bundle-\(UUID().uuidString).stage"
        let stagePath = stagingPath + "/" + stageName
        var descriptorFD: Int32 = -1
        var stageExists = false
        defer {
            if descriptorFD >= 0 { try? fileSystem.close(descriptorFD) }
            if stageExists { try? fileSystem.remove(at: stagePath) }
        }

        try failpoint.check(.beforeStageCreate)
        descriptorFD = try fileSystem.createExclusive(at: stagePath, mode: 0o600)
        stageExists = true
        try fileSystem.write(bytes, to: descriptorFD)
        try failpoint.check(.afterStageWrite)
        try fileSystem.synchronize(descriptorFD)
        try failpoint.check(.afterStageFileSync)
        try fileSystem.setMode(0o400, for: descriptorFD)
        try failpoint.check(.afterStageMode)
        try fileSystem.synchronize(descriptorFD)
        try failpoint.check(.afterStageModeSync)
        try fileSystem.close(descriptorFD)
        descriptorFD = -1
        try failpoint.check(.afterStageClose)

        try failpoint.check(.beforeStageRead)
        let staged = try readAndVerify(path: stagePath, expectedHash: descriptor.contentHash, allowTransientLink: false)
        try failpoint.check(.afterStageRead)
        guard staged == bytes else {
            throw NativeAtomicControlBundleStoreError(.contentHashMismatch, "staged bytes changed before publication")
        }

        try failpoint.check(.beforeBundleLink)
        try fileSystem.linkNoReplace(from: stagePath, to: finalPath)
        try failpoint.check(.afterBundleLink)
        try fileSystem.synchronizeDirectory(at: bundlesPath)
        try failpoint.check(.afterBundlesDirectorySync)

        try failpoint.check(.beforeStageRemove)
        try fileSystem.remove(at: stagePath)
        stageExists = false
        try failpoint.check(.afterStageRemove)
        try fileSystem.synchronizeDirectory(at: stagingPath)
        try failpoint.check(.afterStagingDirectorySync)

        guard let finalMetadata = try fileSystem.metadata(at: finalPath) else {
            throw NativeAtomicControlBundleStoreError(.bundleCorrupt, "published bundle disappeared")
        }
        try validateImmutableFile(finalMetadata, path: finalPath, allowTransientLink: false)
        _ = try readAndVerify(path: finalPath, expectedHash: descriptor.contentHash, allowTransientLink: false)
    }

    private func activate(descriptor: NativeAtomicControlBundleDescriptor, finalName: String) throws {
        let pointerName = ".active.pointer.\(UUID().uuidString).tmp"
        let pointerPath = rootPath + "/" + pointerName
        let data = Self.pointerData(descriptor: descriptor, fileName: finalName)
        var descriptorFD: Int32 = -1
        var pointerExists = false
        defer {
            if descriptorFD >= 0 { try? fileSystem.close(descriptorFD) }
            if pointerExists { try? fileSystem.remove(at: pointerPath) }
        }

        do {
            try failpoint.check(.beforePointerCreate)
            descriptorFD = try fileSystem.createExclusive(at: pointerPath, mode: 0o600)
            pointerExists = true
            try fileSystem.write(data, to: descriptorFD)
            try failpoint.check(.afterPointerWrite)
            try fileSystem.synchronize(descriptorFD)
            try failpoint.check(.afterPointerFileSync)
            try fileSystem.setMode(0o600, for: descriptorFD)
            try failpoint.check(.afterPointerMode)
            try fileSystem.synchronize(descriptorFD)
            try failpoint.check(.afterPointerModeSync)
            try fileSystem.close(descriptorFD)
            descriptorFD = -1
            try failpoint.check(.afterPointerClose)
            try failpoint.check(.beforePointerRead)
            guard try fileSystem.read(at: pointerPath) == data else {
                throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "pointer temporary changed before activation")
            }
            try failpoint.check(.afterPointerRead)
            try failpoint.check(.beforePointerReplace)
            try fileSystem.replaceAtomically(from: pointerPath, to: activePointerPath)
            pointerExists = false
            try failpoint.check(.afterPointerReplace)
            try fileSystem.synchronizeDirectory(at: rootPath)
            try failpoint.check(.afterRootDirectorySync)
        } catch {
            // A failed rename leaves the old pointer in place.  If rename has
            // already succeeded, the new pointer is complete and points only at
            // a fully fsynced, hash-verified immutable file.  Never overwrite it
            // with an unverified rollback during error handling.
            throw error
        }
    }

    private func loadActive(injectFailpoint: Bool = true) throws -> NativeAtomicControlBundleSnapshot? {
        guard let metadata = try fileSystem.metadata(at: activePointerPath) else { return nil }
        try validatePrivateRegular(metadata, path: activePointerPath, expectedMode: 0o600, label: "active pointer")
        guard metadata.size >= 0, metadata.size <= Int64(Self.maximumPointerBytes) else {
            throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer size is invalid")
        }
        if injectFailpoint { try failpoint.check(.beforePointerRead) }
        let data = try fileSystem.read(at: activePointerPath)
        if injectFailpoint { try failpoint.check(.afterPointerRead) }
        let pointer = try Self.decodePointer(data)
        let finalPath = bundlesPath + "/" + pointer.fileName
        guard let finalMetadata = try fileSystem.metadata(at: finalPath) else {
            throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer references a missing bundle")
        }
        try validateImmutableFile(finalMetadata, path: finalPath, allowTransientLink: false)
        let bytes = try readAndVerify(path: finalPath, expectedHash: pointer.descriptor.contentHash, allowTransientLink: false)
        return NativeAtomicControlBundleSnapshot(descriptor: pointer.descriptor, canonicalBytes: bytes)
    }

    private func readPointerDataIfPresent() throws -> Data? {
        guard let metadata = try fileSystem.metadata(at: activePointerPath) else { return nil }
        try validatePrivateRegular(metadata, path: activePointerPath, expectedMode: 0o600, label: "active pointer")
        guard metadata.size >= 0, metadata.size <= Int64(Self.maximumPointerBytes) else {
            throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer size is invalid")
        }
        return try fileSystem.read(at: activePointerPath)
    }

    private func validate(descriptor: NativeAtomicControlBundleDescriptor, bytes: Data) throws {
        guard bytes.count <= maximumBundleBytes else {
            throw NativeAtomicControlBundleStoreError(.bundleTooLarge, "bundle exceeds maximum size")
        }
        guard bytes.count > 0 else {
            throw NativeAtomicControlBundleStoreError(.invalidDescriptor, "bundle bytes must not be empty")
        }
        guard Self.sha256Hex(bytes) == descriptor.contentHash else {
            throw NativeAtomicControlBundleStoreError(.contentHashMismatch, "descriptor content hash does not match bytes")
        }
    }

    private func validateImmutableFile(_ metadata: NativeAtomicControlBundleFileMetadata, path: String, allowTransientLink: Bool) throws {
        try validatePrivateRegular(metadata, path: path, expectedMode: 0o400, label: "immutable bundle")
        let validLinkCount = metadata.linkCount == 1 || (allowTransientLink && metadata.linkCount == 2)
        guard validLinkCount else {
            throw NativeAtomicControlBundleStoreError(.unsafeNode, "immutable bundle must have exactly one hard link")
        }
        guard metadata.size >= 0, metadata.size <= Int64(maximumBundleBytes) else {
            throw NativeAtomicControlBundleStoreError(.bundleTooLarge, "stored bundle exceeds maximum size")
        }
    }

    private func validatePrivateRegular(_ metadata: NativeAtomicControlBundleFileMetadata, path: String, expectedMode: UInt16, label: String) throws {
        guard metadata.kind == .regular, metadata.ownerUID == UInt32(geteuid()), metadata.linkCount == 1, metadata.mode == expectedMode else {
            throw NativeAtomicControlBundleStoreError(.unsafeNode, "\(label) is not a private service-owned regular file: \(path)")
        }
    }

    private func validateTemporary(_ metadata: NativeAtomicControlBundleFileMetadata, path: String, label: String) throws {
        let validLinks = metadata.linkCount == 1 || (metadata.linkCount == 2 && metadata.mode == 0o400)
        guard metadata.kind == .regular, metadata.ownerUID == UInt32(geteuid()), validLinks, metadata.mode == 0o600 || metadata.mode == 0o400 else {
            throw NativeAtomicControlBundleStoreError(.unsafeNode, "\(label) is not a private service-owned regular file: \(path)")
        }
    }

    private func readAndVerify(path: String, expectedHash: String, allowTransientLink: Bool) throws -> Data {
        guard let metadata = try fileSystem.metadata(at: path) else {
            throw NativeAtomicControlBundleStoreError(.bundleCorrupt, "file disappeared: \(path)")
        }
        if allowTransientLink {
            guard metadata.kind == .regular, metadata.ownerUID == UInt32(geteuid()), metadata.mode == 0o400, (metadata.linkCount == 1 || metadata.linkCount == 2) else {
                throw NativeAtomicControlBundleStoreError(.unsafeNode, "file is not a safe immutable regular file")
            }
        } else {
            try validatePrivateRegular(metadata, path: path, expectedMode: 0o400, label: "stored file")
        }
        guard metadata.size >= 0, metadata.size <= Int64(maximumBundleBytes) else {
            throw NativeAtomicControlBundleStoreError(.bundleTooLarge, "file exceeds maximum size")
        }
        let bytes = try fileSystem.read(at: path)
        guard bytes.count == metadata.size else {
            throw NativeAtomicControlBundleError.bundleCorruptSize
        }
        guard Self.sha256Hex(bytes) == expectedHash else {
            throw NativeAtomicControlBundleStoreError(.contentHashMismatch, "stored bytes do not match descriptor hash")
        }
        return bytes
    }
}

private enum NativeAtomicControlBundleStoreSupport {
    static func isHash(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
    }
}

private extension NativeAtomicControlBundleStore {
    struct Pointer {
        let descriptor: NativeAtomicControlBundleDescriptor
        let fileName: String
    }

    static func sha256Hex(_ data: Data) -> String {
        Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
    }

    static func bundleFileName(_ descriptor: NativeAtomicControlBundleDescriptor) -> String {
        "bundle-g\(descriptor.generation)-s\(descriptor.sequence)-sh\(descriptor.statementHash)-ch\(descriptor.contentHash).bundle"
    }

    static func orderingKey(_ descriptor: NativeAtomicControlBundleDescriptor) -> String {
        "\(descriptor.generation):\(descriptor.sequence)"
    }

    static func compare(_ left: NativeAtomicControlBundleDescriptor, _ right: NativeAtomicControlBundleDescriptor) -> Bool {
        if left.generation != right.generation { return left.generation < right.generation }
        if left.sequence != right.sequence { return left.sequence < right.sequence }
        if left.statementHash != right.statementHash { return left.statementHash < right.statementHash }
        return left.contentHash < right.contentHash
    }

    static func pointerData(descriptor: NativeAtomicControlBundleDescriptor, fileName: String) -> Data {
        Data([
            "version=1",
            "generation=\(descriptor.generation)",
            "sequence=\(descriptor.sequence)",
            "statement_hash=\(descriptor.statementHash)",
            "content_hash=\(descriptor.contentHash)",
            "file=\(fileName)"
        ].joined(separator: "\n").appending("\n").utf8)
    }

    static func decodePointer(_ data: Data) throws -> Pointer {
        guard let string = String(data: data, encoding: .utf8) else {
            throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer is not UTF-8")
        }
        let lines = string.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard lines.count == 7, lines.last == "", lines[0] == "version=1" else {
            throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer has a non-canonical shape")
        }
        func value(_ prefix: String, at index: Int) throws -> String {
            guard lines[index].hasPrefix(prefix) else {
                throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer field order is invalid")
            }
            let result = String(lines[index].dropFirst(prefix.count))
            guard !result.isEmpty, !result.contains("\n"), !result.contains("/") else {
                throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer field is invalid")
            }
            return result
        }
        guard let generation = Int64(try value("generation=", at: 1)), generation > 0,
              let sequence = Int64(try value("sequence=", at: 2)), sequence > 0 else {
            throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer counters are invalid")
        }
        let statementHash = try value("statement_hash=", at: 3)
        let contentHash = try value("content_hash=", at: 4)
        guard NativeAtomicControlBundleStoreSupport.isHash(statementHash), NativeAtomicControlBundleStoreSupport.isHash(contentHash) else {
            throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer hashes are invalid")
        }
        let fileName = try value("file=", at: 5)
        let descriptor = try NativeAtomicControlBundleDescriptor(generation: generation, sequence: sequence, statementHash: statementHash, contentHash: contentHash)
        guard fileName == bundleFileName(descriptor), data == pointerData(descriptor: descriptor, fileName: fileName) else {
            throw NativeAtomicControlBundleStoreError(.pointerCorrupt, "active pointer is not canonically bound to its descriptor")
        }
        return Pointer(descriptor: descriptor, fileName: fileName)
    }

    static func descriptor(fromBundleFileName name: String) -> NativeAtomicControlBundleDescriptor? {
        guard name.hasPrefix("bundle-g"), name.hasSuffix(".bundle") else { return nil }
        let body = String(name.dropFirst("bundle-g".count).dropLast(".bundle".count))
        let parts = body.split(separator: "-", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 4, parts[1].hasPrefix("s"), parts[2].hasPrefix("sh"), parts[3].hasPrefix("ch") else { return nil }
        guard let generation = Int64(parts[0]), let sequence = Int64(String(parts[1].dropFirst())),
              let descriptor = try? NativeAtomicControlBundleDescriptor(
                generation: generation,
                sequence: sequence,
                statementHash: String(parts[2].dropFirst(2)),
                contentHash: String(parts[3].dropFirst(2))
              ), bundleFileName(descriptor) == name else { return nil }
        return descriptor
    }

    static func isUUID(_ value: String) -> Bool {
        value.range(of: "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$", options: .regularExpression) != nil
    }

    static func isPointerTemporaryName(_ value: String) -> Bool {
        guard value.hasPrefix(".active.pointer."), value.hasSuffix(".tmp") else { return false }
        let uuid = String(value.dropFirst(".active.pointer.".count).dropLast(".tmp".count))
        return isUUID(uuid)
    }

    static func isStageTemporaryName(_ value: String) -> Bool {
        guard value.hasPrefix(".bundle-"), value.hasSuffix(".stage") else { return false }
        let uuid = String(value.dropFirst(".bundle-".count).dropLast(".stage".count))
        return isUUID(uuid)
    }

    func requireDirectory(_ metadata: NativeAtomicControlBundleFileMetadata, path: String, exactMode: UInt16, label: String) throws {
        guard metadata.kind == .directory, metadata.ownerUID == UInt32(geteuid()), metadata.mode == exactMode, metadata.linkCount >= 1 else {
            throw NativeAtomicControlBundleStoreError(path == rootPath ? .unsafeRoot : .unsafeNode, "\(label) is not a private service-owned directory: \(path)")
        }
    }
}

private enum NativeAtomicControlBundleError {
    static let bundleCorruptSize = NativeAtomicControlBundleStoreError(.bundleCorrupt, "stored file size changed while reading")
}
