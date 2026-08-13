import CryptoKit
import Darwin
import Foundation

/// Stable, secret-free errors for the N3-E qualification fired boundary.
///
/// These errors intentionally do not contain a path, POSIX description, or
/// caller-provided value. The qualification controller may safely reduce them
/// to a closed error code at a process boundary.
public enum NativeAgentQualificationDurableReceiptStoreError: String, Error, Equatable, Sendable {
  case invalidPath = "invalid_path"
  case invalidBinding = "invalid_binding"
  case invalidState = "invalid_state"
  case conflict = "conflict"
  case ioFailure = "io_failure"
}

/// The identity tuple which authorizes one durable fired receipt.
///
/// Every value is a digest or a closed enum. In particular, the raw run ID,
/// proof, repository path, PID, and secret material never enter this type.
public struct NativeAgentQualificationDurableReceiptBinding: Equatable, Sendable {
  public let candidateDigest: Data
  public let sourceCommitDigest: Data
  public let codeIdentityDigest: Data
  public let runIDDigest: Data
  public let scenario: NativeAgentQualificationFaultScenario
  public let phase: NativeAgentQualificationFaultPhase

  public init(
    candidateDigest: Data,
    sourceCommitDigest: Data,
    codeIdentityDigest: Data,
    runIDDigest: Data,
    scenario: NativeAgentQualificationFaultScenario,
    phase: NativeAgentQualificationFaultPhase
  ) throws {
    guard Self.isDigest(candidateDigest), Self.isDigest(sourceCommitDigest),
      Self.isDigest(codeIdentityDigest), Self.isDigest(runIDDigest),
      scenario.phase == phase
    else {
      throw NativeAgentQualificationDurableReceiptStoreError.invalidBinding
    }
    self.candidateDigest = Data(candidateDigest)
    self.sourceCommitDigest = Data(sourceCommitDigest)
    self.codeIdentityDigest = Data(codeIdentityDigest)
    self.runIDDigest = Data(runIDDigest)
    self.scenario = scenario
    self.phase = phase
  }

  fileprivate static func isDigest(_ value: Data) -> Bool {
    value.count == 32 && value.contains(where: { $0 != 0 })
  }
}

/// The exact closed record committed after a matching fault is consumed.
public struct NativeAgentQualificationDurableReceipt: Equatable, Sendable {
  public static let schemaVersion = 1
  public static let kind = "agentpass-n3e-fired-receipt"

  public let binding: NativeAgentQualificationDurableReceiptBinding
  public let generation: UInt64
  public let outcome: NativeAgentQualificationFaultOutcome
  public let armedReceiptDigest: Data

  fileprivate init(
    binding: NativeAgentQualificationDurableReceiptBinding,
    generation: UInt64,
    outcome: NativeAgentQualificationFaultOutcome,
    armedReceiptDigest: Data
  ) throws {
    guard generation > 0, generation <= NativeAgentQualificationFaultController.maximumGeneration,
      outcome == .injected,
      NativeAgentQualificationDurableReceiptBinding.isDigest(armedReceiptDigest),
      armedReceiptDigest == NativeAgentQualificationDurableReceiptStore.armedReceiptDigest(
        candidateDigest: binding.candidateDigest,
        sourceCommitDigest: binding.sourceCommitDigest,
        codeIdentityDigest: binding.codeIdentityDigest,
        runIDDigest: binding.runIDDigest,
        phase: binding.phase,
        generation: generation)
    else {
      throw NativeAgentQualificationDurableReceiptStoreError.invalidBinding
    }
    self.binding = binding
    self.generation = generation
    self.outcome = outcome
    self.armedReceiptDigest = armedReceiptDigest
  }
}

/// Durable hand-off for the N3-E fired boundary.
///
/// Production always uses the fixed root-owned directory below. The internal
/// test initializer exists only to exercise the same descriptor-relative
/// implementation against an isolated fixture.
public final class NativeAgentQualificationDurableReceiptStore: @unchecked Sendable {
  public static let productionRootPath = "/private/var/db/agentpass-qualification"
  public static let receiptFileName = "fired-receipt.json"
  public static let productionReceiptPath =
    "\(productionRootPath)/\(receiptFileName)"
  public static let maximumRecordBytes = 4 * 1024

  private static let receiptDomain = Data("AgentPassQualificationReceipt/v1\0".utf8)

  private let rootPath: String
  private let rootDescriptor: Int32
  private let rootDevice: dev_t
  private let rootInode: ino_t
  private let owner: uid_t
  private let isProductionPath: Bool
  private let lock = NSLock()

  public convenience init() throws {
    try self.init(rootPath: Self.productionRootPath, productionPath: true)
  }

  private init(rootPath: String, productionPath: Bool) throws {
    guard Self.isLexicalAbsolutePath(rootPath) else {
      throw NativeAgentQualificationDurableReceiptStoreError.invalidPath
    }
    if productionPath {
      guard rootPath == Self.productionRootPath else {
        throw NativeAgentQualificationDurableReceiptStoreError.invalidPath
      }
      owner = 0
    } else {
      owner = geteuid()
    }
    self.rootPath = rootPath
    isProductionPath = productionPath

    let descriptor = try Self.openDirectory(
      path: rootPath, expectedOwner: owner, requireProtectedAncestors: productionPath)
    var info = stat()
    guard fstat(descriptor, &info) == 0,
      info.st_uid == owner,
      (info.st_mode & S_IFMT) == S_IFDIR,
      (info.st_mode & 0o7777) == 0o700
    else {
      close(descriptor)
      throw NativeAgentQualificationDurableReceiptStoreError.invalidState
    }
    rootDescriptor = descriptor
    rootDevice = info.st_dev
    rootInode = info.st_ino
  }

  /// Test-only construction. It keeps all production checks and only changes
  /// the fixture root and its expected owner.
  internal convenience init(testRootPath: String) throws {
    try self.init(rootPath: testRootPath, productionPath: false)
  }

  deinit {
    close(rootDescriptor)
  }

  /// The receipt digest returned by the existing qualification endpoint when a
  /// fault is armed. Keeping this calculation here lets durable readers prove
  /// that the record is the same arm receipt, without persisting the run ID.
  public static func armedReceiptDigest(
    candidateDigest: Data,
    sourceCommitDigest: Data,
    codeIdentityDigest: Data,
    runIDDigest: Data,
    phase: NativeAgentQualificationFaultPhase,
    generation: UInt64
  ) -> Data {
    var material = receiptDomain
    material.append(candidateDigest)
    material.append(sourceCommitDigest)
    material.append(codeIdentityDigest)
    material.append(runIDDigest)
    material.append(Data(SHA256.hash(data: Data(phase.rawValue.utf8))))
    material.append(contentsOf: withUnsafeBytes(of: generation.bigEndian) { Array($0) })
    return Data(SHA256.hash(data: material))
  }

  /// Commits one injected receipt. A byte-identical existing record is
  /// idempotently accepted; any other existing record is a substitution or
  /// stale-run conflict and is rejected.
  @discardableResult
  public func writeInjected(
    binding: NativeAgentQualificationDurableReceiptBinding,
    generation: UInt64
  ) throws -> NativeAgentQualificationDurableReceipt {
    let receipt = try NativeAgentQualificationDurableReceipt(
      binding: binding,
      generation: generation,
      outcome: .injected,
      armedReceiptDigest: Self.armedReceiptDigest(
        candidateDigest: binding.candidateDigest,
        sourceCommitDigest: binding.sourceCommitDigest,
        codeIdentityDigest: binding.codeIdentityDigest,
        runIDDigest: binding.runIDDigest,
        phase: binding.phase,
        generation: generation))
    let data = try Self.encode(receipt)
    lock.lock()
    defer { lock.unlock() }
    try validateRootIdentity()
    if let existing = try readIfPresentLocked() {
      guard existing == receipt else {
        throw NativeAgentQualificationDurableReceiptStoreError.conflict
      }
      return existing
    }
    try atomicWriteLocked(data)
    return receipt
  }

  /// Reads and validates the durable record against the exact expected run.
  public func read(
    expected binding: NativeAgentQualificationDurableReceiptBinding? = nil
  ) throws -> NativeAgentQualificationDurableReceipt? {
    lock.lock()
    defer { lock.unlock() }
    try validateRootIdentity()
    guard let receipt = try readIfPresentLocked() else { return nil }
    if let binding, receipt.binding != binding {
      throw NativeAgentQualificationDurableReceiptStoreError.conflict
    }
    return receipt
  }

  /// Removes the receipt only after exact identity and armed-receipt digest
  /// validation. This is the recovery/cleanup boundary; callers cannot ask it
  /// to delete an arbitrary path or a record belonging to another run.
  @discardableResult
  public func remove(
    expected binding: NativeAgentQualificationDurableReceiptBinding
  ) throws -> Bool {
    lock.lock()
    defer { lock.unlock() }
    try validateRootIdentity()
    guard let receipt = try readIfPresentLocked() else { return false }
    guard receipt.binding == binding else {
      throw NativeAgentQualificationDurableReceiptStoreError.conflict
    }
    guard unlinkat(rootDescriptor, Self.receiptFileName, 0) == 0 else {
      throw Self.ioError()
    }
    guard fsync(rootDescriptor) == 0 else { throw Self.ioError() }
    return true
  }

  // MARK: - Closed canonical encoding

  private static func encode(_ receipt: NativeAgentQualificationDurableReceipt) throws -> Data {
    let object: [String: Any] = [
      "armed_receipt_sha256": hex(receipt.armedReceiptDigest),
      "candidate_sha256": hex(receipt.binding.candidateDigest),
      "code_identity_sha256": hex(receipt.binding.codeIdentityDigest),
      "generation": receipt.generation,
      "kind": NativeAgentQualificationDurableReceipt.kind,
      "outcome": receipt.outcome.rawValue,
      "phase": receipt.binding.phase.rawValue,
      "run_id_sha256": hex(receipt.binding.runIDDigest),
      "scenario": receipt.binding.scenario.rawValue,
      "schema_version": NativeAgentQualificationDurableReceipt.schemaVersion,
      "source_commit_sha256": hex(receipt.binding.sourceCommitDigest),
    ]
    let payload = try NativeStrictJSON.data(object)
    guard payload.count + 1 <= maximumRecordBytes else {
      throw NativeAgentQualificationDurableReceiptStoreError.invalidState
    }
    return payload + Data([0x0a])
  }

  private static func decode(_ data: Data) throws -> NativeAgentQualificationDurableReceipt {
    guard data.last == 0x0a, data.count <= maximumRecordBytes else {
      throw NativeAgentQualificationDurableReceiptStoreError.invalidState
    }
    let payload = Data(data.dropLast())
    let object: [String: Any]
    do {
      object = try NativeStrictJSON.object(from: payload, maxBytes: maximumRecordBytes, maxDepth: 4)
      guard try NativeStrictJSON.data(object) == payload else {
        throw NativeAgentQualificationDurableReceiptStoreError.invalidState
      }
    } catch let error as NativeAgentQualificationDurableReceiptStoreError {
      throw error
    } catch {
      throw NativeAgentQualificationDurableReceiptStoreError.invalidState
    }
    let keys: Set<String> = [
      "armed_receipt_sha256", "candidate_sha256", "code_identity_sha256", "generation", "kind",
      "outcome", "phase", "run_id_sha256", "scenario", "schema_version", "source_commit_sha256",
    ]
    guard Set(object.keys) == keys,
      integer(object["schema_version"]) == UInt64(NativeAgentQualificationDurableReceipt.schemaVersion),
      object["kind"] as? String == NativeAgentQualificationDurableReceipt.kind,
      object["outcome"] as? String == NativeAgentQualificationFaultOutcome.injected.rawValue,
      let scenarioText = object["scenario"] as? String,
      let scenario = NativeAgentQualificationFaultScenario(rawValue: scenarioText),
      let phaseText = object["phase"] as? String,
      let phase = NativeAgentQualificationFaultPhase(rawValue: phaseText),
      let generation = integer(object["generation"]),
      let candidate = digest(object["candidate_sha256"]),
      let source = digest(object["source_commit_sha256"]),
      let code = digest(object["code_identity_sha256"]),
      let run = digest(object["run_id_sha256"]),
      let armed = digest(object["armed_receipt_sha256"])
    else { throw NativeAgentQualificationDurableReceiptStoreError.invalidState }
    let binding = try NativeAgentQualificationDurableReceiptBinding(
      candidateDigest: candidate,
      sourceCommitDigest: source,
      codeIdentityDigest: code,
      runIDDigest: run,
      scenario: scenario,
      phase: phase)
    return try NativeAgentQualificationDurableReceipt(
      binding: binding,
      generation: generation,
      outcome: .injected,
      armedReceiptDigest: armed)
  }

  private func readIfPresentLocked() throws -> NativeAgentQualificationDurableReceipt? {
    var metadata = stat()
    if fstatat(rootDescriptor, Self.receiptFileName, &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
      guard errno == ENOENT else { throw Self.invalidStateError() }
      return nil
    }
    try Self.validateFileMetadata(metadata, owner: owner)
    let descriptor = openat(rootDescriptor, Self.receiptFileName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw Self.invalidStateError() }
    defer { close(descriptor) }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 1024)
    while true {
      let count = buffer.withUnsafeMutableBytes { bytes in
        Darwin.read(descriptor, bytes.baseAddress, bytes.count)
      }
      if count < 0 {
        if errno == EINTR { continue }
        throw Self.invalidStateError()
      }
      if count == 0 { break }
      guard data.count <= Self.maximumRecordBytes - count else { throw Self.invalidStateError() }
      data.append(buffer, count: count)
    }
    var after = stat()
    var pathInfo = stat()
    guard fstat(descriptor, &after) == 0,
      fstatat(rootDescriptor, Self.receiptFileName, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
      after.st_dev == metadata.st_dev, after.st_ino == metadata.st_ino,
      after.st_uid == metadata.st_uid, after.st_gid == metadata.st_gid,
      after.st_mode == metadata.st_mode, after.st_nlink == metadata.st_nlink,
      after.st_size == metadata.st_size, data.count == Int(metadata.st_size),
      pathInfo.st_dev == after.st_dev, pathInfo.st_ino == after.st_ino
    else { throw Self.invalidStateError() }
    return try Self.decode(data)
  }

  private func atomicWriteLocked(_ data: Data) throws {
    try validateRootIdentity()
    let temporary = ".fired-receipt.\(UUID().uuidString.lowercased()).tmp"
    let descriptor = openat(
      rootDescriptor, temporary,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      mode_t(0o600))
    guard descriptor >= 0 else { throw Self.ioError() }
    var committed = false
    defer {
      close(descriptor)
      if !committed { unlinkat(rootDescriptor, temporary, 0) }
    }
    try Self.writeAll(data, descriptor: descriptor)
    guard fchmod(descriptor, mode_t(0o600)) == 0,
      fchown(descriptor, owner, gid_t.max) == 0,
      fsync(descriptor) == 0
    else { throw Self.ioError() }
    var temporaryInfo = stat()
    guard fstat(descriptor, &temporaryInfo) == 0,
      temporaryInfo.st_uid == owner, (temporaryInfo.st_mode & 0o7777) == 0o600,
      temporaryInfo.st_nlink == 1
    else { throw Self.invalidStateError() }
    guard renameatx_np(
      rootDescriptor, temporary, rootDescriptor, Self.receiptFileName,
      UInt32(RENAME_EXCL)) == 0
    else { throw Self.ioError() }
    committed = true
    guard fsync(rootDescriptor) == 0 else { throw Self.ioError() }
  }

  private func validateRootIdentity() throws {
    var current = stat()
    var pathInfo = stat()
    guard fstat(rootDescriptor, &current) == 0,
      fstatat(rootDescriptor, ".", &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
      current.st_dev == rootDevice, current.st_ino == rootInode,
      pathInfo.st_dev == rootDevice, pathInfo.st_ino == rootInode,
      current.st_uid == owner, (current.st_mode & S_IFMT) == S_IFDIR,
      (current.st_mode & 0o7777) == 0o700
    else { throw Self.invalidStateError() }
    if isProductionPath { try Self.validateAncestors(rootPath, owner: owner) }
  }

  private static func openDirectory(
    path: String, expectedOwner: uid_t, requireProtectedAncestors: Bool
  ) throws -> Int32 {
    var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw Self.invalidPathError() }
    do {
      if requireProtectedAncestors { try validateAncestors(path, owner: expectedOwner) }
      for component in path.split(separator: "/", omittingEmptySubsequences: true) {
        let next = openat(
          descriptor, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard next >= 0 else { throw Self.invalidPathError() }
        close(descriptor)
        descriptor = next
      }
      return descriptor
    } catch {
      close(descriptor)
      throw error
    }
  }

  private static func validateAncestors(_ path: String, owner: uid_t) throws {
    var current = URL(fileURLWithPath: path, isDirectory: true)
    while true {
      var info = stat()
      guard lstat(current.path, &info) == 0,
        (info.st_mode & S_IFMT) == S_IFDIR,
        info.st_uid == owner,
        (info.st_mode & 0o022) == 0
      else { throw Self.invalidStateError() }
      if current.path == "/" { break }
      current.deleteLastPathComponent()
    }
  }

  private static func isLexicalAbsolutePath(_ path: String) -> Bool {
    guard path.hasPrefix("/"), !path.hasPrefix("//"), path != "/", !path.hasSuffix("/") else {
      return false
    }
    let components = path.split(separator: "/", omittingEmptySubsequences: false)
    guard components.first?.isEmpty == true, components.count > 1 else { return false }
    return components.dropFirst().allSatisfy { component in
      !component.isEmpty && component != "." && component != ".."
    }
  }

  private static func validateFileMetadata(_ info: stat, owner: uid_t) throws {
    guard (info.st_mode & S_IFMT) == S_IFREG,
      info.st_uid == owner,
      (info.st_mode & 0o7777) == 0o600,
      info.st_nlink == 1,
      info.st_size > 0,
      info.st_size <= off_t(maximumRecordBytes)
    else { throw Self.invalidStateError() }
  }

  private static func writeAll(_ data: Data, descriptor: Int32) throws {
    try data.withUnsafeBytes { bytes in
      guard let base = bytes.baseAddress else { throw Self.ioError() }
      var offset = 0
      while offset < bytes.count {
        let count = Darwin.write(descriptor, base.advanced(by: offset), bytes.count - offset)
        if count < 0 {
          if errno == EINTR { continue }
          throw Self.ioError()
        }
        guard count > 0 else { throw Self.ioError() }
        offset += count
      }
    }
  }

  private static func digest(_ value: Any?) -> Data? {
    guard let text = value as? String, text.utf8.count == 64,
      text.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }),
      text.utf8.contains(where: { $0 != 48 })
    else { return nil }
    var result = Data(capacity: 32)
    var index = text.startIndex
    for _ in 0..<32 {
      let next = text.index(index, offsetBy: 2)
      guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
      result.append(byte)
      index = next
    }
    return result
  }

  private static func integer(_ value: Any?) -> UInt64? {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID()
    else { return nil }
    let value = number.doubleValue
    guard value.isFinite, value >= 0, value <= 9_007_199_254_740_991,
      value.rounded(.towardZero) == value else { return nil }
    return number.uint64Value
  }

  private static func hex(_ value: Data) -> String {
    value.map { String(format: "%02x", $0) }.joined()
  }

  private static func ioError() -> NativeAgentQualificationDurableReceiptStoreError { .ioFailure }
  private static func invalidStateError() -> NativeAgentQualificationDurableReceiptStoreError { .invalidState }
  private static func invalidPathError() -> NativeAgentQualificationDurableReceiptStoreError { .invalidPath }
}
