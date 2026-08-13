import CryptoKit
import Darwin
import Foundation
import zlib

internal enum NativeGitObjectStoreError: String, Error, Equatable, Sendable {
  case invalidCommonGitDirectory
  case unsafeFilesystemObject
  case filesystemRace
  case objectNotFound
  case invalidObjectID
  case malformedLooseObject
  case malformedPackIndex
  case malformedPack
  case unsupportedPackVersion
  case unsupportedObjectType
  case objectHashMismatch
  case objectSizeMismatch
  case invalidDelta
  case resourceLimitExceeded
}

internal enum NativeGitObjectType: String, Equatable, Sendable {
  case commit
  case tree
  case blob
  case tag
}

internal struct NativeGitObject: Equatable, Sendable {
  let type: NativeGitObjectType
  let payload: Data
}

internal struct NativeGitTreeEntry: Equatable, Sendable {
  let mode: String
  let name: String
  let oid: String
}

/// A descriptor-anchored reader for the common Git object database.
///
/// The store does not invoke Git or any other process. `commonGitDirectoryPath`
/// must be an absolute, canonical path to the common `.git` directory, and all
/// objects are accepted only when owned by `expectedUserID`.
internal struct NativeGitObjectStore: Sendable {
  private let commonGitDirectoryPath: String
  private let expectedUserID: UInt32

  init(commonGitDirectoryPath: String, expectedUserID: UInt32) throws {
    guard Self.isCanonicalAbsolutePath(commonGitDirectoryPath), expectedUserID > 0 else {
      throw NativeGitObjectStoreError.invalidCommonGitDirectory
    }
    self.commonGitDirectoryPath = commonGitDirectoryPath
    self.expectedUserID = expectedUserID
  }

  init(commonGitDirectoryPath: String, expectedUID: UInt32) throws {
    try self.init(commonGitDirectoryPath: commonGitDirectoryPath, expectedUserID: expectedUID)
  }

  func readObject(oid: String) throws -> NativeGitObject {
    let objectID = try ObjectID(oid)
    let common = try SecureGitDirectory.open(
      commonGitDirectoryPath, expectedUserID: expectedUserID)
    defer { common.close() }
    guard let objects = try common.openDirectory("objects", missingError: .malformedPack)
    else { throw NativeGitObjectStoreError.malformedPack }
    defer { objects.close() }
    let context = LookupContext(objectsDirectory: objects)
    return try resolve(objectID, context: context, depth: 0)
  }

  func readCommitTreeOID(oid: String) throws -> String {
    let object = try readObject(oid: oid)
    return try Self.commitTreeOID(from: object, expectedHashLength: oid.count / 2)
  }

  func readCommitRootTree(oid: String) throws -> NativeGitObject {
    let objectID = try ObjectID(oid)
    let commit = try readObject(oid: oid)
    let treeOID = try Self.commitTreeOID(from: commit, expectedHashLength: objectID.hashLength)
    let tree = try readObject(oid: treeOID)
    guard tree.type == .tree else { throw NativeGitObjectStoreError.unsupportedObjectType }
    let entries = try Self.parseTree(tree.payload, hashLength: objectID.hashLength)
    try validateRootTreeChildren(entries)
    return tree
  }

  func readCommitRootTreeEntries(oid: String) throws -> [NativeGitTreeEntry] {
    let objectID = try ObjectID(oid)
    let commit = try readObject(oid: oid)
    let treeOID = try Self.commitTreeOID(from: commit, expectedHashLength: objectID.hashLength)
    let tree = try readObject(oid: treeOID)
    guard tree.type == .tree else { throw NativeGitObjectStoreError.unsupportedObjectType }
    let entries = try Self.parseTree(tree.payload, hashLength: objectID.hashLength)
    try validateRootTreeChildren(entries)
    return entries
  }

  private func validateRootTreeChildren(_ entries: [NativeGitTreeEntry]) throws {
    guard entries.count <= Limits.maximumRootTreeEntries else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    for entry in entries where entry.mode != "160000" {
      let child = try readObject(oid: entry.oid)
      let expected: NativeGitObjectType = entry.mode == "040000" ? .tree : .blob
      guard child.type == expected else {
        throw NativeGitObjectStoreError.unsupportedObjectType
      }
    }
  }

  static func commitTreeOID(from object: NativeGitObject) throws -> String {
    try commitTreeOID(from: object, expectedHashLength: nil)
  }

  private static func commitTreeOID(
    from object: NativeGitObject, expectedHashLength: Int?
  ) throws -> String {
    guard object.type == .commit else { throw NativeGitObjectStoreError.unsupportedObjectType }
    guard object.type == .commit, let text = String(data: object.payload, encoding: .utf8) else {
      throw NativeGitObjectStoreError.malformedLooseObject
    }
    guard let separator = text.range(of: "\n\n") else {
      throw NativeGitObjectStoreError.malformedLooseObject
    }
    let header = text[..<separator.lowerBound]
    var tree: String?
    var author = false
    var committer = false
    var previousHeader = false
    for line in header.split(separator: "\n", omittingEmptySubsequences: false) {
      if line.first == " " {
        guard previousHeader else { throw NativeGitObjectStoreError.malformedLooseObject }
        continue
      }
      guard !line.isEmpty, let space = line.firstIndex(of: " "), space > line.startIndex else {
        throw NativeGitObjectStoreError.malformedLooseObject
      }
      let key = line[..<space]
      let value = line[line.index(after: space)...]
      guard !value.isEmpty, key.allSatisfy({ $0.isASCII && $0 != " " && $0 != "\t" }) else {
        throw NativeGitObjectStoreError.malformedLooseObject
      }
      previousHeader = true
      switch key {
      case "tree":
        guard tree == nil else { throw NativeGitObjectStoreError.malformedLooseObject }
        tree = String(value)
      case "author":
        guard !author else { throw NativeGitObjectStoreError.malformedLooseObject }
        author = true
      case "committer":
        guard !committer else { throw NativeGitObjectStoreError.malformedLooseObject }
        committer = true
      case "parent":
        guard Self.isObjectID(String(value), expectedHashLength: expectedHashLength) else {
          throw NativeGitObjectStoreError.malformedLooseObject
        }
      default:
        break
      }
    }
    guard author, committer, let value = tree,
      Self.isObjectID(String(value), expectedHashLength: expectedHashLength)
    else { throw NativeGitObjectStoreError.malformedLooseObject }
    if let expectedHashLength, value.count != expectedHashLength * 2 {
      throw NativeGitObjectStoreError.malformedLooseObject
    }
    return value
  }

  private static func isObjectID(_ value: String, expectedHashLength: Int?) -> Bool {
    guard value.count == 40 || value.count == 64,
      value.allSatisfy({ $0.isHexDigit && $0.isLowercaseHexDigit })
    else { return false }
    return expectedHashLength == nil || value.count == expectedHashLength! * 2
  }

  private static func parseTree(_ data: Data, hashLength: Int) throws -> [NativeGitTreeEntry] {
    var cursor = 0
    var result: [NativeGitTreeEntry] = []
    var seen = Set<String>()
    var previousSortKey: [UInt8]?
    while cursor < data.count {
      guard let space = data[cursor...].firstIndex(of: 0x20), space > cursor,
        space - cursor <= 6
      else { throw NativeGitObjectStoreError.malformedLooseObject }
      let mode = String(decoding: data[cursor..<space], as: UTF8.self)
      guard ["040000", "100644", "100755", "120000", "160000"].contains(mode) else {
        throw NativeGitObjectStoreError.malformedLooseObject
      }
      cursor = space + 1
      guard let nul = data[cursor...].firstIndex(of: 0), nul > cursor else {
        throw NativeGitObjectStoreError.malformedLooseObject
      }
      let nameBytes = Data(data[cursor..<nul])
      guard nameBytes.count <= 255, !nameBytes.contains(0), !nameBytes.contains(0x2f),
        let name = String(data: nameBytes, encoding: .utf8), name != ".", name != "..",
        !seen.contains(name)
      else { throw NativeGitObjectStoreError.malformedLooseObject }
      seen.insert(name)
      cursor = nul + 1
      guard cursor + hashLength <= data.count else {
        throw NativeGitObjectStoreError.malformedLooseObject
      }
      let oidData = Data(data[cursor..<(cursor + hashLength)])
      cursor += hashLength
      let oid = try ObjectID(bytes: oidData, hashLength: hashLength).value
      let sortKey = Array(nameBytes) + (mode == "040000" ? [0x2f] : [])
      if let previousSortKey, !Self.lexicographicallyPrecedes(previousSortKey, sortKey) {
        throw NativeGitObjectStoreError.malformedLooseObject
      }
      previousSortKey = sortKey
      result.append(NativeGitTreeEntry(mode: mode, name: name, oid: oid))
      guard result.count <= Limits.maximumRootTreeEntries else {
        throw NativeGitObjectStoreError.resourceLimitExceeded
      }
    }
    return result
  }

  private static func lexicographicallyPrecedes(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
    for (left, right) in zip(lhs, rhs) {
      if left != right { return left < right }
    }
    return lhs.count < rhs.count
  }

  fileprivate final class LookupContext: @unchecked Sendable {
    let objectsDirectory: SecureGitDirectory
    var oidStack = Set<String>()
    var packStack = Set<PackVisit>()

    init(objectsDirectory: SecureGitDirectory) {
      self.objectsDirectory = objectsDirectory
    }
  }

  private func resolve(
    _ objectID: ObjectID, context: LookupContext, depth: Int
  ) throws -> NativeGitObject {
    guard depth <= Limits.maximumDeltaDepth else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    guard context.oidStack.insert(objectID.value).inserted else {
      throw NativeGitObjectStoreError.malformedPack
    }
    defer { context.oidStack.remove(objectID.value) }

    if let loose = try readLoose(objectID, objectsDirectory: context.objectsDirectory) {
      try Self.validateHash(objectID, object: loose)
      return loose
    }

    let packDirectory = try context.objectsDirectory.openDirectory(
      "pack", missingError: .objectNotFound, allowMissing: true)
    guard let packDirectory else { throw NativeGitObjectStoreError.objectNotFound }
    defer { packDirectory.close() }
    let indexNames = try packDirectory.indexNames()
    guard indexNames.count <= Limits.maximumPackFiles else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    for indexName in indexNames {
      let index = try PackIndex.open(
        indexName: indexName, directory: packDirectory, hashLength: objectID.hashLength)
      guard let offset = index.offset(for: objectID) else { continue }
      let packName = String(indexName.dropLast(4)) + ".pack"
      guard let pack = try packDirectory.openFile(packName) else {
        throw NativeGitObjectStoreError.malformedPack
      }
      defer { pack.close() }
      let reader = try PackReader(
        name: packName, descriptor: pack.descriptor, snapshot: pack.snapshot,
        hashLength: objectID.hashLength, expectedObjectCount: index.objectCount,
        expectedPackChecksum: index.packChecksum)
      let object = try reader.readObject(
        at: offset, context: context,
        resolver: { baseID, nextDepth in
          try self.resolve(baseID, context: context, depth: nextDepth)
        }, depth: depth)
      guard descriptorSnapshot(pack.descriptor) == pack.snapshot else {
        throw NativeGitObjectStoreError.filesystemRace
      }
      try Self.validateHash(objectID, object: object)
      return object
    }
    throw NativeGitObjectStoreError.objectNotFound
  }

  private func readLoose(
    _ objectID: ObjectID, objectsDirectory: SecureGitDirectory
  ) throws -> NativeGitObject? {
    let fanout = String(objectID.value.prefix(2))
    let directory = try objectsDirectory.openDirectory(
      fanout, missingError: .objectNotFound, allowMissing: true)
    guard let directory else { return nil }
    defer { directory.close() }
    let name = String(objectID.value.dropFirst(2))
    guard let file = try directory.openFile(name, allowMissing: true) else { return nil }
    defer { file.close() }
    guard file.snapshot.size <= Limits.maximumCompressedBytes else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    let compressed = try file.readAll(maximum: Limits.maximumCompressedBytes)
    let inflated = try Zlib.inflate(compressed, maximumOutput: Limits.maximumObjectBytes)
    let object = try Self.parseLoose(inflated)
    guard file.matchesCurrentSnapshot() else { throw NativeGitObjectStoreError.filesystemRace }
    return object
  }

  private static func parseLoose(_ data: Data) throws -> NativeGitObject {
    guard let nul = data.firstIndex(of: 0), nul > 1, nul <= Limits.maximumHeaderBytes else {
      throw NativeGitObjectStoreError.malformedLooseObject
    }
    let header = data.prefix(upTo: nul)
    guard let headerText = String(data: header, encoding: .ascii) else {
      throw NativeGitObjectStoreError.malformedLooseObject
    }
    let fields = headerText.split(separator: " ", omittingEmptySubsequences: false)
    guard fields.count == 2, let type = NativeGitObjectType(rawValue: String(fields[0])),
      let declaredSize = UInt64(fields[1]), declaredSize <= UInt64(Limits.maximumObjectBytes)
    else { throw NativeGitObjectStoreError.malformedLooseObject }
    let payload = data.suffix(from: data.index(after: nul))
    guard payload.count == Int(declaredSize) else {
      throw NativeGitObjectStoreError.objectSizeMismatch
    }
    return NativeGitObject(type: type, payload: Data(payload))
  }

  private static func validateHash(_ objectID: ObjectID, object: NativeGitObject) throws {
    var input = Data("\(object.type.rawValue) \(object.payload.count)\0".utf8)
    input.append(object.payload)
    let digest: Data
    if objectID.hashLength == 20 {
      digest = Data(Insecure.SHA1.hash(data: input))
    } else {
      digest = Data(SHA256.hash(data: input))
    }
    guard digest.map({ String(format: "%02x", $0) }).joined() == objectID.value else {
      throw NativeGitObjectStoreError.objectHashMismatch
    }
  }

  private static func isCanonicalAbsolutePath(_ path: String) -> Bool {
    path.hasPrefix("/") && path != "/" && !path.hasSuffix("/") && path.utf8.count < MAXPATHLEN
      && !path.contains("\0")
      && !path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().contains {
        $0.isEmpty || $0 == "." || $0 == ".."
      }
  }
}

private enum Limits {
  static let maximumObjectBytes = 64 * 1024 * 1024
  static let maximumCompressedBytes = 128 * 1024 * 1024
  static let maximumHeaderBytes = 256
  static let maximumDeltaDepth = 64
  static let maximumPackFiles = 128
  static let maximumRootTreeEntries = 4_096
  static let maximumObjectsPerPack: UInt32 = 4_000_000
  static let maximumIndexBytes = 256 * 1024 * 1024
  static let maximumPackBytes: off_t = 8 * 1024 * 1024 * 1024
}

private enum GitObjectDigest {
  static func hash(_ data: Data, hashLength: Int) -> Data {
    if hashLength == 20 {
      return Data(Insecure.SHA1.hash(data: data))
    }
    return Data(SHA256.hash(data: data))
  }

  static func file(descriptor: Int32, snapshot: FileSnapshot, hashLength: Int) throws -> Data {
    guard snapshot.size >= off_t(hashLength), snapshot.size <= Limits.maximumPackBytes else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    var sha1 = Insecure.SHA1()
    var sha256 = SHA256()
    var offset: off_t = 0
    let end = snapshot.size - off_t(hashLength)
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while offset < end {
      let count = Int(min(off_t(buffer.count), end - offset))
      let actual = buffer.withUnsafeMutableBytes { rawBuffer -> Int in
        guard let base = rawBuffer.baseAddress else { return -1 }
        return Darwin.pread(descriptor, base, count, offset)
      }
      guard actual == count else { throw NativeGitObjectStoreError.malformedPack }
      let data = Data(buffer.prefix(count))
      if hashLength == 20 { sha1.update(data: data) } else { sha256.update(data: data) }
      offset += off_t(count)
    }
    guard descriptorSnapshot(descriptor) == snapshot else {
      throw NativeGitObjectStoreError.filesystemRace
    }
    return hashLength == 20 ? Data(sha1.finalize()) : Data(sha256.finalize())
  }
}

private func descriptorSnapshot(_ descriptor: Int32) -> FileSnapshot? {
  var info = stat()
  guard fstat(descriptor, &info) == 0 else { return nil }
  return FileSnapshot(info)
}

private struct ObjectID: Hashable, Sendable {
  let value: String
  let hashLength: Int

  init(_ value: String) throws {
    guard value.count == 40 || value.count == 64,
      value.allSatisfy({ $0.isHexDigit && $0.isLowercaseHexDigit })
    else { throw NativeGitObjectStoreError.invalidObjectID }
    self.value = value
    self.hashLength = value.count / 2
  }

  init(bytes: Data, hashLength: Int) throws {
    guard bytes.count == hashLength else { throw NativeGitObjectStoreError.invalidObjectID }
    self.value = bytes.map { String(format: "%02x", $0) }.joined()
    self.hashLength = hashLength
  }
}

private struct FileSnapshot: Equatable, Sendable {
  let device: dev_t
  let inode: ino_t
  let generation: UInt32
  let size: off_t
  let mode: mode_t
  let owner: uid_t
  let links: nlink_t
  let modificationSeconds: time_t
  let modificationNanoseconds: Int64
  let changeSeconds: time_t
  let changeNanoseconds: Int64

  init(_ info: stat) {
    device = info.st_dev
    inode = info.st_ino
    generation = info.st_gen
    size = info.st_size
    mode = info.st_mode
    owner = info.st_uid
    links = info.st_nlink
    modificationSeconds = info.st_mtimespec.tv_sec
    modificationNanoseconds = Int64(info.st_mtimespec.tv_nsec)
    changeSeconds = info.st_ctimespec.tv_sec
    changeNanoseconds = Int64(info.st_ctimespec.tv_nsec)
  }
}

private final class SecureGitFile: @unchecked Sendable {
  let descriptor: Int32
  let snapshot: FileSnapshot
  private var closed = false

  init(descriptor: Int32, snapshot: FileSnapshot) {
    self.descriptor = descriptor
    self.snapshot = snapshot
  }

  func close() {
    guard !closed else { return }
    _ = Darwin.close(descriptor)
    closed = true
  }

  func matchesCurrentSnapshot() -> Bool {
    var info = stat()
    return fstat(descriptor, &info) == 0 && FileSnapshot(info) == snapshot
  }

  func readAll(maximum: Int) throws -> Data {
    guard snapshot.size >= 0, snapshot.size <= off_t(maximum) else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    var result = Data()
    result.reserveCapacity(Int(snapshot.size))
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while true {
      let count = Darwin.read(descriptor, &buffer, buffer.count)
      guard count >= 0 else { throw NativeGitObjectStoreError.malformedLooseObject }
      if count == 0 { break }
      guard result.count + count <= maximum else {
        throw NativeGitObjectStoreError.resourceLimitExceeded
      }
      result.append(contentsOf: buffer.prefix(count))
    }
    guard result.count == Int(snapshot.size), matchesCurrentSnapshot() else {
      throw NativeGitObjectStoreError.filesystemRace
    }
    return result
  }

  func read(at offset: off_t, count: Int) throws -> Data {
    guard offset >= 0, count >= 0, offset <= snapshot.size,
      off_t(count) <= snapshot.size - offset
    else { throw NativeGitObjectStoreError.malformedPack }
    var data = Data(count: count)
    let readCount = data.withUnsafeMutableBytes { rawBuffer -> Int in
      guard let base = rawBuffer.baseAddress else { return count == 0 ? 0 : -1 }
      return Darwin.pread(descriptor, base, count, offset)
    }
    guard readCount == count else { throw NativeGitObjectStoreError.malformedPack }
    return data
  }
}

private final class SecureGitDirectory: @unchecked Sendable {
  let descriptor: Int32
  private let snapshot: FileSnapshot
  private let expectedUserID: UInt32
  private var closed = false

  private init(descriptor: Int32, snapshot: FileSnapshot, expectedUserID: UInt32) {
    self.descriptor = descriptor
    self.snapshot = snapshot
    self.expectedUserID = expectedUserID
  }

  func close() {
    guard !closed else { return }
    _ = Darwin.close(descriptor)
    closed = true
  }

  static func open(_ path: String, expectedUserID: UInt32) throws -> SecureGitDirectory {
    var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw NativeGitObjectStoreError.unsafeFilesystemObject }
    let components = path.split(separator: "/").map(String.init)
    for (index, component) in components.enumerated() {
      let next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      _ = Darwin.close(fd)
      guard next >= 0 else { throw NativeGitObjectStoreError.unsafeFilesystemObject }
      fd = next
      var info = stat()
      guard fstat(fd, &info) == 0,
        Self.safeDirectory(
          FileSnapshot(info), expectedUserID: expectedUserID,
          allowRootOwner: index + 1 < components.count)
      else {
        _ = Darwin.close(fd)
        throw NativeGitObjectStoreError.unsafeFilesystemObject
      }
    }
    var info = stat()
    guard fstat(fd, &info) == 0,
      Self.safeDirectory(FileSnapshot(info), expectedUserID: expectedUserID)
    else {
      _ = Darwin.close(fd)
      throw NativeGitObjectStoreError.unsafeFilesystemObject
    }
    return SecureGitDirectory(
      descriptor: fd, snapshot: FileSnapshot(info), expectedUserID: expectedUserID)
  }

  func openDirectory(
    _ name: String, missingError: NativeGitObjectStoreError, allowMissing: Bool = false
  ) throws -> SecureGitDirectory? {
    guard Self.safeName(name) else { throw NativeGitObjectStoreError.unsafeFilesystemObject }
    let fd = openat(descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 {
      if allowMissing && errno == ENOENT { return nil }
      throw missingError
    }
    var info = stat()
    guard fstat(fd, &info) == 0,
      Self.safeDirectory(FileSnapshot(info), expectedUserID: expectedUserID)
    else {
      _ = Darwin.close(fd)
      throw NativeGitObjectStoreError.unsafeFilesystemObject
    }
    return SecureGitDirectory(
      descriptor: fd, snapshot: FileSnapshot(info), expectedUserID: expectedUserID)
  }

  func openFile(_ name: String, allowMissing: Bool = false) throws -> SecureGitFile? {
    guard Self.safeName(name) else { throw NativeGitObjectStoreError.unsafeFilesystemObject }
    let fd = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 {
      if allowMissing && errno == ENOENT { return nil }
      throw NativeGitObjectStoreError.unsafeFilesystemObject
    }
    var info = stat()
    guard fstat(fd, &info) == 0, Self.safeFile(FileSnapshot(info), expectedUserID: expectedUserID)
    else {
      _ = Darwin.close(fd)
      throw NativeGitObjectStoreError.unsafeFilesystemObject
    }
    return SecureGitFile(descriptor: fd, snapshot: FileSnapshot(info))
  }

  func indexNames() throws -> [String] {
    var before = stat()
    guard fstat(descriptor, &before) == 0 else { throw NativeGitObjectStoreError.filesystemRace }
    let duplicate = Darwin.dup(descriptor)
    guard duplicate >= 0, let directory = fdopendir(duplicate) else {
      if duplicate >= 0 { _ = Darwin.close(duplicate) }
      throw NativeGitObjectStoreError.malformedPack
    }
    defer { closedir(directory) }
    var indexNames: [String] = []
    var packNames: [String] = []
    while let entry = readdir(directory) {
      let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN)) {
          String(cString: $0)
        }
      }
      guard name == "." || name == ".." || Self.safeName(name) else {
        throw NativeGitObjectStoreError.unsafeFilesystemObject
      }
      guard name == "." || name == ".." || Self.isAllowedPackDirectoryName(name) else {
        throw NativeGitObjectStoreError.malformedPack
      }
      guard !name.hasSuffix(".promisor") else {
        throw NativeGitObjectStoreError.malformedPack
      }
      if name.hasSuffix(".idx") {
        indexNames.append(name)
        guard indexNames.count <= Limits.maximumPackFiles else {
          throw NativeGitObjectStoreError.resourceLimitExceeded
        }
      } else if name.hasSuffix(".pack") {
        packNames.append(name)
        guard packNames.count <= Limits.maximumPackFiles else {
          throw NativeGitObjectStoreError.resourceLimitExceeded
        }
      }
    }
    var after = stat()
    guard fstat(descriptor, &after) == 0, FileSnapshot(before) == FileSnapshot(after) else {
      throw NativeGitObjectStoreError.filesystemRace
    }
    guard
      Set(indexNames.map { String($0.dropLast(4)) })
        == Set(packNames.map { String($0.dropLast(5)) })
    else {
      throw NativeGitObjectStoreError.malformedPack
    }
    return indexNames.sorted()
  }

  private static func safeName(_ value: String) -> Bool {
    !value.isEmpty && value != "." && value != ".." && !value.contains("/") && !value.contains("\0")
  }

  private static func isAllowedPackDirectoryName(_ value: String) -> Bool {
    guard value.hasPrefix("pack-") else {
      return ["multi-pack-index"].contains(value)
    }
    return value.hasSuffix(".idx") || value.hasSuffix(".pack")
      || value.hasSuffix(".keep") || value.hasSuffix(".bitmap") || value.hasSuffix(".rev")
      || value.hasSuffix(".mtimes") || value.hasSuffix(".promisor")
  }

  private static func safeDirectory(
    _ file: FileSnapshot, expectedUserID: UInt32, allowRootOwner: Bool = false
  ) -> Bool {
    file.device > 0 && file.inode > 0
      && (file.owner == expectedUserID || (allowRootOwner && file.owner == 0)) && file.links >= 1
      && file.mode & S_IFMT == S_IFDIR && file.mode & 0o022 == 0
  }

  private static func safeFile(_ file: FileSnapshot, expectedUserID: UInt32) -> Bool {
    file.owner == expectedUserID && file.links == 1 && file.mode & S_IFMT == S_IFREG
      && file.mode & 0o022 == 0 && file.size >= 0
  }
}

private struct PackIndex {
  private let bytes: Data
  private let count: Int
  private let hashLength: Int
  private let oidStart: Int
  private let offsetStart: Int
  private let largeOffsetStart: Int
  let objectCount: UInt32
  let packChecksum: Data

  static func open(indexName: String, directory: SecureGitDirectory, hashLength: Int) throws
    -> PackIndex
  {
    guard let file = try directory.openFile(indexName) else {
      throw NativeGitObjectStoreError.malformedPackIndex
    }
    defer { file.close() }
    guard file.snapshot.size <= off_t(Limits.maximumIndexBytes) else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    let bytes = try file.readAll(maximum: Limits.maximumIndexBytes)
    guard bytes.count >= 8 + 256 * 4 + hashLength * 2,
      bytes.prefix(4).elementsEqual([0xff, 0x74, 0x4f, 0x63]),
      readUInt32(bytes, at: 4) == 2
    else { throw NativeGitObjectStoreError.malformedPackIndex }
    let countValue = readUInt32(bytes, at: 8 + 255 * 4)
    guard countValue <= Limits.maximumObjectsPerPack else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    let count = Int(countValue)
    var previousFanout: UInt32 = 0
    for index in 0..<256 {
      let fanout = readUInt32(bytes, at: 8 + index * 4)
      guard fanout >= previousFanout, fanout <= countValue else {
        throw NativeGitObjectStoreError.malformedPackIndex
      }
      previousFanout = fanout
    }
    let oidStart = 8 + 256 * 4
    let offsetStart = oidStart + count * hashLength + count * 4
    let largeOffsetStart = offsetStart + count * 4
    let remaining = bytes.count - largeOffsetStart - (hashLength * 2)
    guard remaining >= 0, remaining % 8 == 0 else {
      throw NativeGitObjectStoreError.malformedPackIndex
    }
    let largeOffsetCount = remaining / 8
    let expected = largeOffsetStart + largeOffsetCount * 8 + (hashLength * 2)
    guard expected == bytes.count else { throw NativeGitObjectStoreError.malformedPackIndex }
    let checksumStart = bytes.count - hashLength
    let actualChecksum = GitObjectDigest.hash(Data(bytes[..<checksumStart]), hashLength: hashLength)
    guard Data(bytes[checksumStart...]) == actualChecksum else {
      throw NativeGitObjectStoreError.malformedPackIndex
    }
    let packChecksumStart = checksumStart - hashLength
    return PackIndex(
      bytes: bytes, count: count, hashLength: hashLength, oidStart: oidStart,
      offsetStart: offsetStart, largeOffsetStart: largeOffsetStart,
      objectCount: countValue, packChecksum: Data(bytes[packChecksumStart..<checksumStart]))
  }

  func offset(for objectID: ObjectID) -> off_t? {
    guard objectID.hashLength == hashLength else { return nil }
    var low = 0
    var high = count
    while low < high {
      let middle = (low + high) / 2
      if compareOID(at: middle, with: objectID) < 0 { low = middle + 1 } else { high = middle }
    }
    guard low < count, compareOID(at: low, with: objectID) == 0 else { return nil }
    let raw = Self.readUInt32(bytes, at: offsetStart + low * 4)
    if raw & 0x8000_0000 == 0 { return off_t(raw) }
    let index = Int(raw & 0x7fff_ffff)
    guard index * 8 + 8 <= bytes.count - largeOffsetStart else { return nil }
    let highPart = UInt64(Self.readUInt32(bytes, at: largeOffsetStart + index * 8))
    let lowPart = UInt64(Self.readUInt32(bytes, at: largeOffsetStart + index * 8 + 4))
    let value = (highPart << 32) | lowPart
    guard value <= UInt64(Int64.max) else { return nil }
    return off_t(value)
  }

  private func compareOID(at index: Int, with objectID: ObjectID) -> Int {
    let start = oidStart + index * hashLength
    for position in 0..<hashLength {
      let lhs = bytes[start + position]
      let rhs = Self.hexByte(objectID.value, at: position)
      if lhs != rhs { return lhs < rhs ? -1 : 1 }
    }
    return 0
  }

  private static func hexByte(_ value: String, at index: Int) -> UInt8 {
    let start = value.index(value.startIndex, offsetBy: index * 2)
    let end = value.index(start, offsetBy: 2)
    return UInt8(value[start..<end], radix: 16)!
  }

  private static func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
    UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16
      | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
  }
}

private struct PackVisit: Hashable {
  let name: String
  let offset: off_t
}

private struct PackReader {
  let name: String
  let descriptor: Int32
  let snapshot: FileSnapshot
  let hashLength: Int

  init(
    name: String, descriptor: Int32, snapshot: FileSnapshot, hashLength: Int,
    expectedObjectCount: UInt32, expectedPackChecksum: Data
  ) throws {
    guard snapshot.size >= 12, snapshot.size <= Limits.maximumPackBytes else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    let header = try Self.read(descriptor: descriptor, snapshot: snapshot, offset: 0, count: 12)
    guard header.prefix(4).elementsEqual([0x50, 0x41, 0x43, 0x4b]) else {
      throw NativeGitObjectStoreError.malformedPack
    }
    let version = Self.readUInt32(header, at: 4)
    guard version == 2 || version == 3 else {
      throw NativeGitObjectStoreError.unsupportedPackVersion
    }
    guard Self.readUInt32(header, at: 8) <= Limits.maximumObjectsPerPack,
      Self.readUInt32(header, at: 8) == expectedObjectCount
    else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    guard snapshot.size >= off_t(12 + hashLength) else {
      throw NativeGitObjectStoreError.malformedPack
    }
    let trailer = try Self.read(
      descriptor: descriptor, snapshot: snapshot, offset: snapshot.size - off_t(hashLength),
      count: hashLength)
    guard trailer == expectedPackChecksum,
      try GitObjectDigest.file(descriptor: descriptor, snapshot: snapshot, hashLength: hashLength)
        == trailer
    else { throw NativeGitObjectStoreError.malformedPack }
    self.name = name
    self.descriptor = descriptor
    self.snapshot = snapshot
    self.hashLength = hashLength
  }

  func readObject(
    at offset: off_t, context: NativeGitObjectStore.LookupContext,
    resolver: (ObjectID, Int) throws -> NativeGitObject, depth: Int
  ) throws -> NativeGitObject {
    guard offset >= 12, offset < snapshot.size else {
      throw NativeGitObjectStoreError.malformedPack
    }
    let visit = PackVisit(name: name, offset: offset)
    guard context.packStack.insert(visit).inserted else {
      throw NativeGitObjectStoreError.malformedPack
    }
    defer { context.packStack.remove(visit) }
    var cursor = offset
    let first = try readByte(at: cursor)
    cursor += 1
    let typeBits = (first >> 4) & 0x07
    var declaredSize = UInt64(first & 0x0f)
    var shift: UInt64 = 4
    var byte = first
    var headerBytes = 1
    while byte & 0x80 != 0 {
      guard headerBytes < 10 else { throw NativeGitObjectStoreError.malformedPack }
      byte = try readByte(at: cursor)
      cursor += 1
      headerBytes += 1
      guard shift < 64 else { throw NativeGitObjectStoreError.resourceLimitExceeded }
      declaredSize |= UInt64(byte & 0x7f) << shift
      shift += 7
    }
    guard declaredSize <= UInt64(Limits.maximumObjectBytes) else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    switch typeBits {
    case 1, 2, 3, 4:
      let type = try NativeGitObjectType(packType: typeBits)
      let payload = try inflatePack(at: cursor, maximumOutput: Int(declaredSize))
      guard payload.count == Int(declaredSize) else {
        throw NativeGitObjectStoreError.objectSizeMismatch
      }
      return NativeGitObject(type: type, payload: payload)
    case 6:
      let baseOffset = try readOFSDeltaBase(at: &cursor, objectOffset: offset)
      let delta = try inflatePack(at: cursor, maximumOutput: Limits.maximumObjectBytes)
      let base = try readObject(
        at: baseOffset, context: context, resolver: resolver, depth: depth + 1)
      return try applyDelta(delta, to: base)
    case 7:
      let baseBytes = try Self.read(
        descriptor: descriptor, snapshot: snapshot, offset: cursor, count: hashLength)
      cursor += off_t(hashLength)
      let baseID = try ObjectID(bytes: baseBytes, hashLength: hashLength)
      let delta = try inflatePack(at: cursor, maximumOutput: Limits.maximumObjectBytes)
      let base = try resolver(baseID, depth + 1)
      return try applyDelta(delta, to: base)
    default:
      throw NativeGitObjectStoreError.unsupportedObjectType
    }
  }

  private func readOFSDeltaBase(at cursor: inout off_t, objectOffset: off_t) throws -> off_t {
    let first = try readByte(at: cursor)
    cursor += 1
    var value = UInt64(first & 0x7f)
    var byte = first
    var count = 1
    while byte & 0x80 != 0 {
      guard count < 10 else { throw NativeGitObjectStoreError.malformedPack }
      byte = try readByte(at: cursor)
      cursor += 1
      count += 1
      guard value <= (UInt64.max >> 7) else { throw NativeGitObjectStoreError.malformedPack }
      value = ((value + 1) << 7) | UInt64(byte & 0x7f)
    }
    guard value < UInt64(objectOffset), value <= UInt64(objectOffset - 12) else {
      throw NativeGitObjectStoreError.malformedPack
    }
    let base = UInt64(objectOffset) - value
    guard base <= UInt64(Int64.max) else { throw NativeGitObjectStoreError.malformedPack }
    return off_t(base)
  }

  private func inflatePack(at offset: off_t, maximumOutput: Int) throws -> Data {
    try Zlib.inflate(
      descriptor: descriptor, start: offset, end: snapshot.size,
      maximumOutput: maximumOutput, maximumCompressed: Limits.maximumCompressedBytes)
  }

  private func readByte(at offset: off_t) throws -> UInt8 {
    try Self.read(descriptor: descriptor, snapshot: snapshot, offset: offset, count: 1)[0]
  }

  private static func read(descriptor: Int32, snapshot: FileSnapshot, offset: off_t, count: Int)
    throws -> Data
  {
    guard offset >= 0, count >= 0, offset <= snapshot.size, off_t(count) <= snapshot.size - offset
    else {
      throw NativeGitObjectStoreError.malformedPack
    }
    var result = Data(count: count)
    let actual = result.withUnsafeMutableBytes { rawBuffer -> Int in
      guard let base = rawBuffer.baseAddress else { return count == 0 ? 0 : -1 }
      return Darwin.pread(descriptor, base, count, offset)
    }
    guard actual == count else { throw NativeGitObjectStoreError.malformedPack }
    return result
  }

  private static func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
    UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16
      | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
  }
}

extension NativeGitObjectType {
  fileprivate init(packType: UInt8) throws {
    switch packType {
    case 1: self = .commit
    case 2: self = .tree
    case 3: self = .blob
    case 4: self = .tag
    default: throw NativeGitObjectStoreError.unsupportedObjectType
    }
  }
}

private func applyDelta(_ delta: Data, to base: NativeGitObject) throws -> NativeGitObject {
  var cursor = 0
  let baseSize = try readDeltaVarint(delta, cursor: &cursor)
  let resultSize = try readDeltaVarint(delta, cursor: &cursor)
  guard baseSize == base.payload.count, resultSize <= UInt64(Limits.maximumObjectBytes) else {
    throw NativeGitObjectStoreError.invalidDelta
  }
  var result = Data()
  result.reserveCapacity(Int(resultSize))
  while cursor < delta.count {
    let opcode = delta[cursor]
    cursor += 1
    if opcode & 0x80 == 0 {
      let count = Int(opcode)
      guard count > 0, cursor + count <= delta.count, result.count + count <= Int(resultSize) else {
        throw NativeGitObjectStoreError.invalidDelta
      }
      result.append(delta[cursor..<(cursor + count)])
      cursor += count
      continue
    }
    var offset: UInt64 = 0
    var size: UInt64 = 0
    if opcode & 0x01 != 0 { offset |= UInt64(try nextDeltaByte(delta, cursor: &cursor)) }
    if opcode & 0x02 != 0 { offset |= UInt64(try nextDeltaByte(delta, cursor: &cursor)) << 8 }
    if opcode & 0x04 != 0 { offset |= UInt64(try nextDeltaByte(delta, cursor: &cursor)) << 16 }
    if opcode & 0x08 != 0 { offset |= UInt64(try nextDeltaByte(delta, cursor: &cursor)) << 24 }
    if opcode & 0x10 != 0 { size |= UInt64(try nextDeltaByte(delta, cursor: &cursor)) }
    if opcode & 0x20 != 0 { size |= UInt64(try nextDeltaByte(delta, cursor: &cursor)) << 8 }
    if opcode & 0x40 != 0 { size |= UInt64(try nextDeltaByte(delta, cursor: &cursor)) << 16 }
    if size == 0 { size = 0x1_0000 }
    guard offset <= UInt64(base.payload.count), size <= UInt64(base.payload.count) - offset,
      size <= UInt64(Int(resultSize) - result.count)
    else { throw NativeGitObjectStoreError.invalidDelta }
    let start = base.payload.index(base.payload.startIndex, offsetBy: Int(offset))
    let end = base.payload.index(start, offsetBy: Int(size))
    result.append(base.payload[start..<end])
  }
  guard result.count == Int(resultSize) else { throw NativeGitObjectStoreError.invalidDelta }
  return NativeGitObject(type: base.type, payload: result)
}

private func readDeltaVarint(_ data: Data, cursor: inout Int) throws -> UInt64 {
  var value: UInt64 = 0
  var shift: UInt64 = 0
  for _ in 0..<10 {
    let byte = try nextDeltaByte(data, cursor: &cursor)
    guard shift < 64, UInt64(byte & 0x7f) <= (UInt64.max >> shift) else {
      throw NativeGitObjectStoreError.invalidDelta
    }
    value |= UInt64(byte & 0x7f) << shift
    if byte & 0x80 == 0 { return value }
    shift += 7
  }
  throw NativeGitObjectStoreError.invalidDelta
}

private func nextDeltaByte(_ data: Data, cursor: inout Int) throws -> UInt8 {
  guard cursor < data.count else { throw NativeGitObjectStoreError.invalidDelta }
  defer { cursor += 1 }
  return data[cursor]
}

private enum Zlib {
  static func inflate(_ data: Data, maximumOutput: Int) throws -> Data {
    guard data.count <= Limits.maximumCompressedBytes else {
      throw NativeGitObjectStoreError.resourceLimitExceeded
    }
    let (result, consumed) = try inflateBytes(
      data, start: 0, end: data.count, maximumOutput: maximumOutput)
    guard consumed == data.count else { throw NativeGitObjectStoreError.malformedLooseObject }
    return result
  }

  static func inflate(
    descriptor: Int32, start: off_t, end: off_t, maximumOutput: Int, maximumCompressed: Int
  ) throws -> Data {
    guard start >= 0, end >= start else { throw NativeGitObjectStoreError.malformedPack }
    var stream = z_stream()
    let initResult = inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
    guard initResult == Z_OK else { throw NativeGitObjectStoreError.malformedPack }
    defer { inflateEnd(&stream) }
    var result = Data()
    var position = start
    var consumed: Int = 0
    var finished = false
    while position < end && !finished {
      let count = Int(min(off_t(64 * 1024), end - position))
      guard consumed + count <= maximumCompressed else {
        throw NativeGitObjectStoreError.resourceLimitExceeded
      }
      var input = Data(count: count)
      let readCount = input.withUnsafeMutableBytes { rawBuffer -> Int in
        guard let base = rawBuffer.baseAddress else { return -1 }
        return Darwin.pread(descriptor, base, count, position)
      }
      guard readCount == count else { throw NativeGitObjectStoreError.malformedPack }
      let (produced, used, ended) = try inflateChunk(
        input, stream: &stream, maximumOutput: maximumOutput - result.count)
      result.append(produced)
      position += off_t(used)
      consumed += used
      finished = ended
      guard used > 0 || ended else { throw NativeGitObjectStoreError.malformedPack }
      if used < count && !ended { throw NativeGitObjectStoreError.malformedPack }
    }
    guard finished else { throw NativeGitObjectStoreError.malformedPack }
    return result
  }

  private static func inflateBytes(
    _ data: Data, start: Int, end: Int, maximumOutput: Int
  ) throws -> (Data, Int) {
    var stream = z_stream()
    let initResult = inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
    guard initResult == Z_OK else { throw NativeGitObjectStoreError.malformedLooseObject }
    defer { inflateEnd(&stream) }
    var result = Data()
    let slice = Data(data[start..<end])
    var input = Array(slice)
    var used = 0
    var ended = false
    let inputCount = input.count
    let outcome: Void = try input.withUnsafeMutableBytes { inputBytes in
      stream.next_in = inputBytes.bindMemory(to: UInt8.self).baseAddress
      stream.avail_in = uInt(inputCount)
      while !ended {
        let (produced, status) = try inflateOnce(
          &stream, maximumOutput: maximumOutput - result.count)
        result.append(produced)
        guard status == Z_OK || status == Z_STREAM_END else {
          throw NativeGitObjectStoreError.malformedLooseObject
        }
        ended = status == Z_STREAM_END
        if !ended && stream.avail_in == 0 { break }
        if !ended && produced.isEmpty && stream.avail_in > 0 {
          throw NativeGitObjectStoreError.malformedLooseObject
        }
      }
      used = inputCount - Int(stream.avail_in)
    }
    _ = outcome
    guard ended else { throw NativeGitObjectStoreError.malformedLooseObject }
    return (result, used)
  }

  private static func inflateChunk(
    _ input: Data, stream: inout z_stream, maximumOutput: Int
  ) throws -> (Data, Int, Bool) {
    var input = Array(input)
    var result = Data()
    var status: Int32 = Z_OK
    let inputCount = input.count
    input.withUnsafeMutableBytes { inputBytes in
      stream.next_in = inputBytes.bindMemory(to: UInt8.self).baseAddress
      stream.avail_in = uInt(inputCount)
      while stream.avail_in > 0 && status != Z_STREAM_END {
        do {
          let outcome = try inflateOnce(&stream, maximumOutput: maximumOutput - result.count)
          result.append(outcome.0)
          status = outcome.1
        } catch {
          status = Z_DATA_ERROR
        }
      }
    }
    guard status == Z_OK || status == Z_STREAM_END else {
      throw NativeGitObjectStoreError.malformedPack
    }
    return (result, inputCount - Int(stream.avail_in), status == Z_STREAM_END)
  }

  private static func inflateOnce(
    _ stream: inout z_stream, maximumOutput: Int
  ) throws -> (Data, Int32) {
    guard maximumOutput >= 0 else { throw NativeGitObjectStoreError.resourceLimitExceeded }
    var buffer = [UInt8](repeating: 0, count: min(64 * 1024, max(1, maximumOutput)))
    let bufferCount = buffer.count
    let status = buffer.withUnsafeMutableBytes { outputBytes -> Int32 in
      stream.next_out = outputBytes.bindMemory(to: UInt8.self).baseAddress
      stream.avail_out = uInt(bufferCount)
      return zlib.inflate(&stream, Z_NO_FLUSH)
    }
    let produced = bufferCount - Int(stream.avail_out)
    guard produced <= maximumOutput else { throw NativeGitObjectStoreError.resourceLimitExceeded }
    return (Data(buffer.prefix(produced)), status)
  }
}

extension Character {
  fileprivate var isLowercaseHexDigit: Bool {
    (self >= "0" && self <= "9") || (self >= "a" && self <= "f")
  }
}
