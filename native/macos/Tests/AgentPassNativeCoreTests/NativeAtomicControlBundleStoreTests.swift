import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private final class AtomicStoreMemoryFileSystem: NativeAtomicControlBundleFileSystem, @unchecked Sendable {
    private final class Node {
        var kind: NativeAtomicControlBundleNodeKind
        var ownerUID: UInt32
        var mode: UInt16
        var data: Data
        var linkCount: UInt64

        init(kind: NativeAtomicControlBundleNodeKind, ownerUID: UInt32, mode: UInt16, data: Data = Data(), linkCount: UInt64 = 1) {
            self.kind = kind
            self.ownerUID = ownerUID
            self.mode = mode
            self.data = data
            self.linkCount = linkCount
        }
    }

    private struct OpenHandle {
        let node: Node
    }

    let root: String
    private let ownerUID = UInt32(geteuid())
    private let lock = NSLock()
    private var nodes: [String: Node] = [:]
    private var openHandles: [Int32: OpenHandle] = [:]
    private var nextDescriptor: Int32 = 100

    init(root: String = "/agentpass-memory-root") {
        self.root = root
        nodes[root] = Node(kind: .directory, ownerUID: ownerUID, mode: 0o700)
    }

    func metadata(at path: String) throws -> NativeAtomicControlBundleFileMetadata? {
        lock.lock()
        defer { lock.unlock() }
        guard let node = nodes[path] else { return nil }
        let size = node.kind == .regular ? Int64(node.data.count) : 0
        return NativeAtomicControlBundleFileMetadata(kind: node.kind, ownerUID: node.ownerUID, mode: node.mode, linkCount: node.linkCount, size: size)
    }

    func listDirectory(at path: String) throws -> [String] {
        lock.lock()
        defer { lock.unlock() }
        let prefix = path == "/" ? "/" : path + "/"
        var children = Set<String>()
        for key in nodes.keys where key.hasPrefix(prefix) {
            let suffix = String(key.dropFirst(prefix.count))
            guard !suffix.isEmpty, !suffix.contains("/") else { continue }
            children.insert(suffix)
        }
        return children.sorted()
    }

    func createDirectory(at path: String, mode: UInt16) throws {
        lock.lock()
        defer { lock.unlock() }
        if nodes[path] != nil { return }
        guard let parent = parent(of: path), nodes[parent]?.kind == .directory else { throw POSIXError(.ENOENT) }
        nodes[path] = Node(kind: .directory, ownerUID: ownerUID, mode: mode)
    }

    func createExclusive(at path: String, mode: UInt16) throws -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        guard nodes[path] == nil else { throw POSIXError(.EEXIST) }
        guard let parent = parent(of: path), nodes[parent]?.kind == .directory else { throw POSIXError(.ENOENT) }
        let node = Node(kind: .regular, ownerUID: ownerUID, mode: mode)
        nodes[path] = node
        let descriptor = nextDescriptor
        nextDescriptor += 1
        openHandles[descriptor] = OpenHandle(node: node)
        return descriptor
    }

    func write(_ data: Data, to descriptor: Int32) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let handle = openHandles[descriptor], handle.node.kind == .regular else { throw POSIXError(.EBADF) }
        handle.node.data.append(data)
    }

    func setMode(_ mode: UInt16, for descriptor: Int32) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let handle = openHandles[descriptor] else { throw POSIXError(.EBADF) }
        handle.node.mode = mode
    }

    func synchronize(_ descriptor: Int32) throws {
        lock.lock()
        defer { lock.unlock() }
        guard openHandles[descriptor] != nil else { throw POSIXError(.EBADF) }
    }

    func close(_ descriptor: Int32) throws {
        lock.lock()
        defer { lock.unlock() }
        guard openHandles.removeValue(forKey: descriptor) != nil else { throw POSIXError(.EBADF) }
    }

    func read(at path: String) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        guard let node = nodes[path], node.kind == .regular else { throw POSIXError(.ELOOP) }
        return node.data
    }

    func linkNoReplace(from: String, to: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard nodes[to] == nil else { throw POSIXError(.EEXIST) }
        guard let source = nodes[from], source.kind == .regular else { throw POSIXError(.ENOENT) }
        source.linkCount += 1
        nodes[to] = source
    }

    func replaceAtomically(from: String, to: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let source = nodes.removeValue(forKey: from) else { throw POSIXError(.ENOENT) }
        if let destination = nodes.removeValue(forKey: to) {
            destination.linkCount = max(destination.linkCount - 1, 0)
        }
        nodes[to] = source
    }

    func remove(at path: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let node = nodes.removeValue(forKey: path) else { return }
        node.linkCount = max(node.linkCount - 1, 0)
    }

    func synchronizeDirectory(at path: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard nodes[path]?.kind == .directory else { throw POSIXError(.ENOTDIR) }
    }

    func addSymlink(at path: String) {
        lock.lock()
        defer { lock.unlock() }
        nodes[path] = Node(kind: .symlink, ownerUID: ownerUID, mode: 0o777)
    }

    func addHardLink(from sourcePath: String, to destinationPath: String) throws {
        try linkNoReplace(from: sourcePath, to: destinationPath)
    }

    func addRegularFile(at path: String, data: Data, mode: UInt16 = 0o600) {
        lock.lock()
        defer { lock.unlock() }
        nodes[path] = Node(kind: .regular, ownerUID: ownerUID, mode: mode, data: data)
    }

    func mutateRegularFile(at path: String, data: Data) {
        lock.lock()
        defer { lock.unlock() }
        nodes[path]?.data = data
    }

    func nodeNames(in directory: String) throws -> [String] {
        try listDirectory(at: directory)
    }

    private func parent(of path: String) -> String? {
        guard let slash = path.lastIndex(of: "/"), slash > path.startIndex else { return "/" }
        return String(path[..<slash])
    }
}

private final class AtomicStoreOneShotFailpoint: NativeAtomicControlBundleStoreFailpointHandler, @unchecked Sendable {
    let target: NativeAtomicControlBundleStoreFailpoint
    private let lock = NSLock()
    private var fired = false

    init(_ target: NativeAtomicControlBundleStoreFailpoint) {
        self.target = target
    }

    func check(_ point: NativeAtomicControlBundleStoreFailpoint) throws {
        lock.lock()
        defer { lock.unlock() }
        guard point == target, !fired else { return }
        fired = true
        throw NativeAtomicControlBundleStoreError(.failpoint, point.rawValue)
    }
}

private enum AtomicStoreTestSupport {
    static func contentHash(_ data: Data) -> String {
        Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
    }

    static func descriptor(generation: Int64, sequence: Int64, statementByte: UInt8, bytes: Data) throws -> NativeAtomicControlBundleDescriptor {
        try NativeAtomicControlBundleDescriptor(
            generation: generation,
            sequence: sequence,
            statementHash: String(repeating: String(format: "%02x", statementByte), count: 32),
            contentHash: contentHash(bytes)
        )
    }

    static func store(root: String, fileSystem: AtomicStoreMemoryFileSystem, failpoint: any NativeAtomicControlBundleStoreFailpointHandler = NativeAtomicControlBundleStoreNoFailpoint()) throws -> NativeAtomicControlBundleStore {
        try NativeAtomicControlBundleStore(rootURL: URL(fileURLWithPath: root), fileSystem: fileSystem, failpoint: failpoint)
    }

    static func fileName(_ descriptor: NativeAtomicControlBundleDescriptor) -> String {
        "bundle-g\(descriptor.generation)-s\(descriptor.sequence)-sh\(descriptor.statementHash)-ch\(descriptor.contentHash).bundle"
    }
}

@Test func atomicControlBundleStoreInstallsExactBytesAndSurvivesRestart() throws {
    let fs = AtomicStoreMemoryFileSystem()
    let bytes = Data(#"{"format_epoch":2,"sequence":1}"#.utf8)
    let descriptor = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 1, statementByte: 0x11, bytes: bytes)
    let store = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs)

    let installed = try store.install(descriptor: descriptor, canonicalBytes: bytes)
    #expect(installed == NativeAtomicControlBundleSnapshot(descriptor: descriptor, canonicalBytes: bytes))
    #expect(try store.active() == installed)

    let restarted = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs)
    #expect(try restarted.active() == installed)
    let bundlePath = fs.root + "/bundles/" + AtomicStoreTestSupport.fileName(descriptor)
    #expect(try fs.metadata(at: bundlePath)?.mode == 0o400)
    #expect(try fs.metadata(at: bundlePath)?.linkCount == 1)
    #expect(try fs.metadata(at: fs.root + "/active.pointer")?.mode == 0o600)
    #expect(try fs.nodeNames(in: fs.root + "/staging").isEmpty)
}

@Test func atomicControlBundleStoreRejectsHashRollbackAndEquivocation() throws {
    let fs = AtomicStoreMemoryFileSystem()
    let store = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs)
    let firstBytes = Data("first".utf8)
    let secondBytes = Data("second".utf8)
    let first = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 1, statementByte: 0x11, bytes: firstBytes)
    let second = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 2, statementByte: 0x22, bytes: secondBytes)
    _ = try store.install(descriptor: first, canonicalBytes: firstBytes)
    _ = try store.install(descriptor: second, canonicalBytes: secondBytes)

    let rollback = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 1, statementByte: 0x11, bytes: firstBytes)
    #expect(throws: NativeAtomicControlBundleStoreError.self) {
        _ = try store.install(descriptor: rollback, canonicalBytes: firstBytes)
    }
    let equivocationBytes = Data("equivocation".utf8)
    let equivocation = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 2, statementByte: 0x33, bytes: equivocationBytes)
    #expect(throws: NativeAtomicControlBundleStoreError.self) {
        _ = try store.install(descriptor: equivocation, canonicalBytes: equivocationBytes)
    }
    let crossGenerationRollbackBytes = Data("cross-generation-sequence-rollback".utf8)
    let crossGenerationRollback = try AtomicStoreTestSupport.descriptor(generation: 2, sequence: 1, statementByte: 0x44, bytes: crossGenerationRollbackBytes)
    #expect(throws: NativeAtomicControlBundleStoreError.self) {
        _ = try store.install(descriptor: crossGenerationRollback, canonicalBytes: crossGenerationRollbackBytes)
    }
    let nextGenerationBytes = Data("next-generation".utf8)
    let nextGeneration = try AtomicStoreTestSupport.descriptor(generation: 2, sequence: 3, statementByte: 0x44, bytes: nextGenerationBytes)
    _ = try store.install(descriptor: nextGeneration, canonicalBytes: nextGenerationBytes)
    let generationRollbackBytes = Data("old-generation".utf8)
    let generationRollback = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 4, statementByte: 0x55, bytes: generationRollbackBytes)
    #expect(throws: NativeAtomicControlBundleStoreError.self) {
        _ = try store.install(descriptor: generationRollback, canonicalBytes: generationRollbackBytes)
    }
}

@Test func atomicControlBundleStoreFailsClosedAcrossEveryDurableBoundary() throws {
    for point in NativeAtomicControlBundleStoreFailpoint.allCases {
        let fs = AtomicStoreMemoryFileSystem(root: "/agentpass-memory-\(point.rawValue)")
        let oldBytes = Data("old-bundle".utf8)
        let newBytes = Data("new-bundle".utf8)
        let old = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 1, statementByte: 0x11, bytes: oldBytes)
        let new = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 2, statementByte: 0x22, bytes: newBytes)
        _ = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs).install(descriptor: old, canonicalBytes: oldBytes)

        let failing = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs, failpoint: AtomicStoreOneShotFailpoint(point))
        #expect(throws: NativeAtomicControlBundleStoreError.self) {
            _ = try failing.install(descriptor: new, canonicalBytes: newBytes)
        }

        let recovered = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs)
        let active = try #require(try recovered.active())
        #expect(active.descriptor == old || active.descriptor == new, "failpoint \(point.rawValue) left an invalid active state")
        #expect(active.canonicalBytes == oldBytes || active.canonicalBytes == newBytes)
        #expect(try fs.nodeNames(in: fs.root + "/staging").isEmpty)
    }
}

@Test func atomicControlBundleStoreDeterministicallyCleansCrashTemporaries() throws {
    let fs = AtomicStoreMemoryFileSystem()
    let bytes = Data("durable".utf8)
    let descriptor = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 1, statementByte: 0x11, bytes: bytes)
    _ = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs).install(descriptor: descriptor, canonicalBytes: bytes)
    fs.addRegularFile(at: fs.root + "/.active.pointer.12345678-1234-1234-1234-123456789abc.tmp", data: Data("partial".utf8))
    fs.addRegularFile(at: fs.root + "/staging/.bundle-12345678-1234-1234-1234-123456789abc.stage", data: bytes, mode: 0o400)

    let recovered = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs)
    #expect(try recovered.active()?.descriptor == descriptor)
    #expect(try fs.nodeNames(in: fs.root + "/staging").isEmpty)
    #expect(!(try fs.nodeNames(in: fs.root)).contains { $0.hasSuffix(".tmp") })
}

@Test func atomicControlBundleStoreRepairsCrashAfterHardLinkPublication() throws {
    let fs = AtomicStoreMemoryFileSystem()
    _ = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs)
    let bytes = Data("published-before-stage-cleanup".utf8)
    let descriptor = try AtomicStoreTestSupport.descriptor(
        generation: 1,
        sequence: 1,
        statementByte: 0x11,
        bytes: bytes
    )
    let stagePath = fs.root + "/staging/.bundle-12345678-1234-1234-1234-123456789abc.stage"
    let finalPath = fs.root + "/bundles/" + AtomicStoreTestSupport.fileName(descriptor)
    fs.addRegularFile(at: stagePath, data: bytes, mode: 0o400)
    try fs.addHardLink(from: stagePath, to: finalPath)
    #expect(try fs.metadata(at: stagePath)?.linkCount == 2)

    let recovered = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs)
    #expect(try recovered.active() == nil)
    #expect(try fs.metadata(at: stagePath) == nil)
    #expect(try fs.metadata(at: finalPath)?.linkCount == 1)
    #expect(try fs.read(at: finalPath) == bytes)
}

@Test func atomicControlBundleStoreRejectsSymlinkHardlinkAndTraversalState() throws {
    let symlinkFS = AtomicStoreMemoryFileSystem()
    symlinkFS.addSymlink(at: symlinkFS.root + "/bundles/bundle-g1-s1-sh" + String(repeating: "1", count: 64) + "-ch" + String(repeating: "2", count: 64) + ".bundle")
    #expect(throws: NativeAtomicControlBundleStoreError.self) {
        _ = try AtomicStoreTestSupport.store(root: symlinkFS.root, fileSystem: symlinkFS)
    }

    let hardlinkFS = AtomicStoreMemoryFileSystem()
    let bytes = Data("hardlink".utf8)
    let descriptor = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 1, statementByte: 0x11, bytes: bytes)
    _ = try AtomicStoreTestSupport.store(root: hardlinkFS.root, fileSystem: hardlinkFS).install(descriptor: descriptor, canonicalBytes: bytes)
    let bundlePath = hardlinkFS.root + "/bundles/" + AtomicStoreTestSupport.fileName(descriptor)
    try hardlinkFS.addHardLink(from: bundlePath, to: hardlinkFS.root + "/bundles/foreign")
    #expect(throws: NativeAtomicControlBundleStoreError.self) {
        _ = try AtomicStoreTestSupport.store(root: hardlinkFS.root, fileSystem: hardlinkFS)
    }

    #expect(throws: NativeAtomicControlBundleStoreError.self) {
        _ = try NativeAtomicControlBundleStore(rootURL: URL(fileURLWithPath: "/private/../agentpass"))
    }
}

@Test func atomicControlBundleStoreRejectsTamperedBytesBeforeActivation() throws {
    let fs = AtomicStoreMemoryFileSystem()
    let bytes = Data("original".utf8)
    let descriptor = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 1, statementByte: 0x11, bytes: bytes)
    _ = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs).install(descriptor: descriptor, canonicalBytes: bytes)
    let path = fs.root + "/bundles/" + AtomicStoreTestSupport.fileName(descriptor)
    fs.mutateRegularFile(at: path, data: Data("tampered".utf8))
    #expect(throws: NativeAtomicControlBundleStoreError.self) {
        _ = try AtomicStoreTestSupport.store(root: fs.root, fileSystem: fs)
    }
}

@Test func atomicControlBundleStoreRealPOSIXIntegration() throws {
    let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        .appendingPathComponent(".agentpass-atomic-store-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let fileSystem = NativeAtomicControlBundlePOSIXFileSystem()
    let firstBytes = Data("posix-first".utf8)
    let secondBytes = Data("posix-second".utf8)
    let first = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 1, statementByte: 0x11, bytes: firstBytes)
    let second = try AtomicStoreTestSupport.descriptor(generation: 1, sequence: 2, statementByte: 0x22, bytes: secondBytes)
    let store = try NativeAtomicControlBundleStore(rootURL: root, fileSystem: fileSystem)
    _ = try store.install(descriptor: first, canonicalBytes: firstBytes)
    _ = try store.install(descriptor: second, canonicalBytes: secondBytes)
    let restarted = try NativeAtomicControlBundleStore(rootURL: root, fileSystem: fileSystem)
    #expect(try restarted.active()?.descriptor == second)
    let finalPath = root.path + "/bundles/" + AtomicStoreTestSupport.fileName(second)
    #expect(try fileSystem.metadata(at: finalPath)?.kind == .regular)
    #expect(try fileSystem.metadata(at: finalPath)?.mode == 0o400)
    #expect(try fileSystem.metadata(at: finalPath)?.linkCount == 1)
}
