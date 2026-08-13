import CoreFoundation
import CryptoKit
import Darwin
import Foundation

/// Errors from the crash-recovery evidence store.  Values deliberately do not
/// contain paths, POSIX descriptions, or other caller-controlled diagnostics.
public enum NativeAgentSessionConsumeRecoveryStoreError: String, Error, Equatable, Sendable {
  case invalidPath = "invalid_path"
  case invalidEvidence = "invalid_evidence"
  case invalidState = "invalid_state"
  case conflict = "conflict"
  case capacityExceeded = "capacity_exceeded"
  case ioFailure = "io_failure"
}

/// The only durable input to consume recovery.
///
/// This is intentionally a digest-only record.  In particular, it has no
/// proof bytes, repository path, PID, process token, private key material, or
/// cloud credential.  A restarted service may use the tuple to identify an
/// exact retry candidate after obtaining the opaque proof again from its
/// trusted bootstrap source, and must reject every substitution.
public struct NativeAgentSessionConsumeRecoveryEvidence: Equatable, Sendable {
  public static let digestByteCount = 32

  public let organizationID: String
  public let deviceID: String
  public let agentID: String
  public let adapterKind: AgentPassAgentAdapterKind
  public let grantProofDigest: Data
  public let processBindingDigest: Data
  public let ancestryBindingDigest: Data
  public let worktreeBindingDigest: Data
  public let controlSequence: Int64
  public let authorityGeneration: Int64
  public let keyGeneration: Int64
  public let recoveryExpiresAtMilliseconds: Int64

  public init(
    organizationID: String,
    deviceID: String,
    agentID: String,
    adapterKind: AgentPassAgentAdapterKind,
    grantProofDigest: Data,
    processBindingDigest: Data,
    ancestryBindingDigest: Data,
    worktreeBindingDigest: Data,
    controlSequence: Int64,
    authorityGeneration: Int64,
    keyGeneration: Int64,
    recoveryExpiresAtMilliseconds: Int64
  ) throws {
    guard let organizationID = Self.uuid(organizationID),
      let deviceID = Self.uuid(deviceID),
      let agentID = Self.uuid(agentID),
      Self.digest(grantProofDigest),
      Self.digest(processBindingDigest),
      Self.digest(ancestryBindingDigest),
      Self.digest(worktreeBindingDigest),
      controlSequence >= 1,
      authorityGeneration >= 1,
      keyGeneration >= 1,
      recoveryExpiresAtMilliseconds > 0
    else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
    }
    self.organizationID = organizationID
    self.deviceID = deviceID
    self.agentID = agentID
    self.adapterKind = adapterKind
    self.grantProofDigest = grantProofDigest
    self.processBindingDigest = processBindingDigest
    self.ancestryBindingDigest = ancestryBindingDigest
    self.worktreeBindingDigest = worktreeBindingDigest
    self.controlSequence = controlSequence
    self.authorityGeneration = authorityGeneration
    self.keyGeneration = keyGeneration
    self.recoveryExpiresAtMilliseconds = recoveryExpiresAtMilliseconds
  }

  /// Constructs the recovery bound from bootstrap issuance and requested TTL.
  /// A verified Lease expiry, when available, may only shorten this bound.
  public init(
    organizationID: String,
    deviceID: String,
    agentID: String,
    adapterKind: AgentPassAgentAdapterKind,
    grantProofDigest: Data,
    processBindingDigest: Data,
    ancestryBindingDigest: Data,
    worktreeBindingDigest: Data,
    controlSequence: Int64,
    authorityGeneration: Int64,
    keyGeneration: Int64,
    bootstrapIssuedAtMilliseconds: Int64,
    requestedTTLSeconds: Int,
    leaseExpiresAtMilliseconds: Int64? = nil
  ) throws {
    let expiry = try Self.recoveryExpiry(
      bootstrapIssuedAtMilliseconds: bootstrapIssuedAtMilliseconds,
      requestedTTLSeconds: requestedTTLSeconds,
      leaseExpiresAtMilliseconds: leaseExpiresAtMilliseconds)
    try self.init(
      organizationID: organizationID, deviceID: deviceID, agentID: agentID,
      adapterKind: adapterKind, grantProofDigest: grantProofDigest,
      processBindingDigest: processBindingDigest,
      ancestryBindingDigest: ancestryBindingDigest,
      worktreeBindingDigest: worktreeBindingDigest,
      controlSequence: controlSequence, authorityGeneration: authorityGeneration,
      keyGeneration: keyGeneration, recoveryExpiresAtMilliseconds: expiry)
  }

  /// Computes the digest that may be put in an evidence record.  The proof is
  /// not retained by this type or by the store.
  public static func digest(of proof: Data) -> Data {
    Data(SHA256.hash(data: proof))
  }

  fileprivate var recoveryKey: String {
    grantProofDigest.map { String(format: "%02x", $0) }.joined()
  }

  fileprivate func matchesAuthority(
    _ other: NativeAgentSessionConsumeRecoveryEvidence
  ) -> Bool {
    organizationID == other.organizationID
      && deviceID == other.deviceID
      && agentID == other.agentID
      && adapterKind == other.adapterKind
      && grantProofDigest == other.grantProofDigest
      && processBindingDigest == other.processBindingDigest
      && ancestryBindingDigest == other.ancestryBindingDigest
      && worktreeBindingDigest == other.worktreeBindingDigest
      && controlSequence == other.controlSequence
      && authorityGeneration == other.authorityGeneration
      && keyGeneration == other.keyGeneration
  }

  public static func recoveryExpiry(
    bootstrapIssuedAtMilliseconds: Int64,
    requestedTTLSeconds: Int,
    leaseExpiresAtMilliseconds: Int64? = nil
  ) throws -> Int64 {
    guard bootstrapIssuedAtMilliseconds > 0,
      (60...28_800).contains(requestedTTLSeconds)
    else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence }
    let (lifetime, lifetimeOverflow) = Int64(requestedTTLSeconds)
      .multipliedReportingOverflow(by: 1_000)
    let (expiry, expiryOverflow) =
      bootstrapIssuedAtMilliseconds
      .addingReportingOverflow(lifetime)
    guard !lifetimeOverflow, !expiryOverflow, expiry > bootstrapIssuedAtMilliseconds else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
    }
    if let leaseExpiresAtMilliseconds {
      guard leaseExpiresAtMilliseconds > bootstrapIssuedAtMilliseconds else {
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
      }
      return min(expiry, leaseExpiresAtMilliseconds)
    }
    return expiry
  }

  private static func uuid(_ value: String) -> String? {
    guard value.utf8.count == 36,
      value.range(
        of: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        options: .regularExpression) != nil,
      UUID(uuidString: value) != nil
    else { return nil }
    return value.lowercased()
  }

  private static func digest(_ value: Data) -> Bool {
    value.count == digestByteCount
  }
}

/// The bounded record written before an activation audit is appended.
///
/// This is the durable hand-off between local activation and the audit
/// appender.  It contains only immutable authority evidence and fixed-size
/// digests.  In particular, it contains neither the audit payload nor any
/// session credential.  The canonical audit-evidence digest is what lets a
/// restarted coordinator find and reuse an exact append instead of emitting a
/// second audit event.
public struct NativeAgentSessionConsumeRecoveryPreparedRecord: Equatable, Sendable {
  public static let digestByteCount = NativeAgentSessionConsumeRecoveryEvidence.digestByteCount

  public let evidence: NativeAgentSessionConsumeRecoveryEvidence
  /// The public Cloud session identifier used to locate an exact audit event.
  /// This is not a local lease ID and carries no authority or credential.
  public let sessionID: String
  public let sessionDigest: Data
  public let resultDigest: Data
  public let auditEvidenceDigest: Data
  public let expiresAtMilliseconds: Int64

  public init(
    evidence: NativeAgentSessionConsumeRecoveryEvidence,
    sessionID: String,
    sessionDigest: Data,
    resultDigest: Data,
    auditEvidenceDigest: Data,
    expiresAtMilliseconds: Int64? = nil
  ) throws {
    let preparedExpiry = expiresAtMilliseconds ?? evidence.recoveryExpiresAtMilliseconds
    guard let sessionID = Self.uuid(sessionID),
      Self.digest(sessionDigest), Self.digest(resultDigest),
      Self.digest(auditEvidenceDigest),
      preparedExpiry > 0,
      preparedExpiry <= evidence.recoveryExpiresAtMilliseconds
    else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
    }
    self.evidence = evidence
    self.sessionID = sessionID
    self.sessionDigest = sessionDigest
    self.resultDigest = resultDigest
    self.auditEvidenceDigest = auditEvidenceDigest
    self.expiresAtMilliseconds = preparedExpiry
  }

  fileprivate func matchesExact(
    _ other: NativeAgentSessionConsumeRecoveryPreparedRecord
  ) -> Bool {
    evidence == other.evidence
      && sessionID == other.sessionID
      && sessionDigest == other.sessionDigest
      && resultDigest == other.resultDigest
      && auditEvidenceDigest == other.auditEvidenceDigest
      && expiresAtMilliseconds == other.expiresAtMilliseconds
  }

  private static func digest(_ value: Data) -> Bool {
    value.count == digestByteCount
  }

  private static func uuid(_ value: String) -> String? {
    guard value.utf8.count == 36,
      value.range(
        of: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        options: .regularExpression) != nil,
      UUID(uuidString: value) != nil
    else { return nil }
    return value.lowercased()
  }
}

/// The bounded terminal result retained after the local activation audit is
/// durable.  It is deliberately composed only of the prepared record and one
/// fixed-size durable audit-chain digest; it carries no session authority or
/// replayable secret.  The terminal expiry may shorten, but never extend, the
/// recovery tuple's expiry.
public struct NativeAgentSessionConsumeRecoveryAuditedRecord: Equatable, Sendable {
  public static let digestByteCount = NativeAgentSessionConsumeRecoveryEvidence.digestByteCount

  public let preparedRecord: NativeAgentSessionConsumeRecoveryPreparedRecord
  public let auditDigest: Data

  public var evidence: NativeAgentSessionConsumeRecoveryEvidence { preparedRecord.evidence }
  public var sessionID: String { preparedRecord.sessionID }
  public var sessionDigest: Data { preparedRecord.sessionDigest }
  public var resultDigest: Data { preparedRecord.resultDigest }
  public var auditEvidenceDigest: Data { preparedRecord.auditEvidenceDigest }
  public var expiresAtMilliseconds: Int64 { preparedRecord.expiresAtMilliseconds }

  public init(
    preparedRecord: NativeAgentSessionConsumeRecoveryPreparedRecord,
    auditDigest: Data
  ) throws {
    guard Self.digest(auditDigest) else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
    }
    self.preparedRecord = preparedRecord
    self.auditDigest = auditDigest
  }

  private static func digest(_ value: Data) -> Bool {
    value.count == digestByteCount
  }
}

/// Exact recovery lookup.  `auditPrepared` is the durable hand-off to the
/// audit appender and must be reconciled before another append is attempted.
/// `audited` is a terminal replay record and must not be treated as a missing
/// pending request.
public enum NativeAgentSessionConsumeRecoveryLookup: Equatable, Sendable {
  case missing
  case pending(NativeAgentSessionConsumeRecoveryEvidence)
  case auditPrepared(NativeAgentSessionConsumeRecoveryPreparedRecord)
  case audited(NativeAgentSessionConsumeRecoveryAuditedRecord)
}

public protocol NativeAgentSessionConsumeRecoveryStoring: Sendable {
  @discardableResult
  func save(
    _ evidence: NativeAgentSessionConsumeRecoveryEvidence,
    nowMilliseconds: Int64?
  ) throws -> NativeAgentSessionConsumeRecoveryEvidence

  /// Durably records the exact audit intent before an audit append begins.
  /// Repeating the same transition is idempotent; every substituted digest or
  /// tuple is rejected.
  @discardableResult
  func prepareForActivation(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    preparedRecord: NativeAgentSessionConsumeRecoveryPreparedRecord
  ) throws -> NativeAgentSessionConsumeRecoveryPreparedRecord

  /// Completes an exact prepared audit with the durable audit-chain digest.
  /// This is the only API that advances `audit_prepared -> audited`.
  @discardableResult
  func completeAfterAudit(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    preparedRecord: NativeAgentSessionConsumeRecoveryPreparedRecord,
    auditedRecord: NativeAgentSessionConsumeRecoveryAuditedRecord
  ) throws -> NativeAgentSessionConsumeRecoveryAuditedRecord

  func lookupExact(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    nowMilliseconds: Int64?
  ) throws -> NativeAgentSessionConsumeRecoveryLookup

  @discardableResult
  func abandon(_ expected: NativeAgentSessionConsumeRecoveryEvidence) throws -> Bool
}

/// A bounded, digest-only, crash-safe recovery evidence store.
///
/// The v3 on-disk format has three explicit states. A bootstrap tuple is
/// immutable while pending. Before an audit append, the exact session/result/
/// audit-evidence tuple is atomically published as `audit_prepared`. Once the
/// audit chain returns its durable record digest, that same tuple is atomically
/// replaced with `audited`. Every transition is exact and idempotent; a v1 or
/// v2 file is rejected rather than reinterpreted.
public final class NativeAgentSessionConsumeRecoveryStore:
  NativeAgentSessionConsumeRecoveryStoring, @unchecked Sendable
{
  private static let version = 3
  private static let maximumEntries = 128
  private static let maximumBytes = 256 * 1024
  private static let fileMode: mode_t = 0o600
  private static let directoryMode: mode_t = 0o700
  private static let temporaryPrefix = ".agentpass-session-consume-recovery.tmp-"
  private static let immutableRecordKeys: Set<String> = [
    "adapter_kind", "agent_id", "ancestry_binding_sha256", "authority_generation",
    "control_sequence", "device_id", "grant_proof_sha256", "key_generation",
    "organization_id", "process_binding_sha256", "recovery_expires_at_ms",
    "worktree_binding_sha256",
  ]
  private static let pendingRecordKeys = immutableRecordKeys.union(["state"])
  private static let preparedRecordKeys = immutableRecordKeys.union([
    "audit_evidence_sha256", "expires_at_ms", "result_sha256", "session_id",
    "session_sha256", "state",
  ])
  private static let auditedRecordKeys = preparedRecordKeys.union([
    "audit_sha256"
  ])

  private enum Record: Equatable, Sendable {
    case pending(NativeAgentSessionConsumeRecoveryEvidence)
    case auditPrepared(NativeAgentSessionConsumeRecoveryPreparedRecord)
    case audited(NativeAgentSessionConsumeRecoveryAuditedRecord)

    var evidence: NativeAgentSessionConsumeRecoveryEvidence {
      switch self {
      case .pending(let evidence): evidence
      case .auditPrepared(let prepared): prepared.evidence
      case .audited(let record): record.evidence
      }
    }

    var recoveryKey: String { evidence.recoveryKey }

    var expiresAtMilliseconds: Int64 {
      switch self {
      case .pending(let evidence): evidence.recoveryExpiresAtMilliseconds
      case .auditPrepared(let prepared): prepared.expiresAtMilliseconds
      case .audited(let record): record.expiresAtMilliseconds
      }
    }

    var state: String {
      switch self {
      case .pending: "pending"
      case .auditPrepared: "audit_prepared"
      case .audited: "audited"
      }
    }
  }

  private let path: String
  private let lock = NSLock()
  private var records: [String: Record] = [:]

  public init(path: String) throws {
    let components = path.split(separator: "/", omittingEmptySubsequences: false)
    let name = components.last.map(String.init) ?? ""
    guard path.hasPrefix("/"), !path.hasSuffix("/"), !path.contains("\0"),
      !components.dropFirst().contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }),
      !name.isEmpty, !name.contains("/")
    else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidPath }
    self.path = path

    let parent = try Self.openPrivateParent(for: path)
    defer { close(parent.fd) }
    try Self.removeCrashRemnants(parentFD: parent.fd, parentPath: parent.path)
    records = try Self.load(pathName: parent.name, parentFD: parent.fd)
  }

  /// Saves an immutable recovery tuple.  Exact replay is idempotent.
  @discardableResult
  public func save(_ evidence: NativeAgentSessionConsumeRecoveryEvidence)
    throws -> NativeAgentSessionConsumeRecoveryEvidence
  {
    try save(evidence, nowMilliseconds: nil)
  }

  /// Saves after pruning expired records. Supplying the clock explicitly keeps
  /// capacity behavior deterministic for restart recovery and tests.
  @discardableResult
  public func save(
    _ evidence: NativeAgentSessionConsumeRecoveryEvidence,
    nowMilliseconds: Int64?
  ) throws -> NativeAgentSessionConsumeRecoveryEvidence {
    lock.lock()
    defer { lock.unlock() }
    if let nowMilliseconds {
      guard nowMilliseconds >= 0 else {
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
      }
      _ = try pruneExpiredLocked(nowMilliseconds: nowMilliseconds)
      guard evidence.recoveryExpiresAtMilliseconds > nowMilliseconds else {
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
      }
    }
    if let old = records[evidence.recoveryKey] {
      switch old {
      case .pending(let pending):
        guard pending.matchesAuthority(evidence),
          nowMilliseconds.map({ pending.recoveryExpiresAtMilliseconds > $0 }) ?? true
        else {
          throw NativeAgentSessionConsumeRecoveryStoreError.conflict
        }
        return pending
      case .auditPrepared, .audited:
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
    }
    guard records.count < Self.maximumEntries else {
      throw NativeAgentSessionConsumeRecoveryStoreError.capacityExceeded
    }
    records[evidence.recoveryKey] = .pending(evidence)
    do {
      try persistLocked()
    } catch {
      records.removeValue(forKey: evidence.recoveryKey)
      throw error
    }
    return evidence
  }

  /// Removes every record at or past its bounded recovery expiry. The final
  /// record file is unlinked and its parent directory is fsync'd.
  @discardableResult
  public func pruneExpired(nowMilliseconds: Int64) throws -> Int {
    guard nowMilliseconds >= 0 else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
    }
    lock.lock()
    defer { lock.unlock() }
    return try pruneExpiredLocked(nowMilliseconds: nowMilliseconds)
  }

  /// Compatibility lookup for pending callers.  An audited terminal record is
  /// deliberately reported as a conflict instead of a cache miss so callers
  /// cannot create a second pending transaction.
  public func lookup(_ expected: NativeAgentSessionConsumeRecoveryEvidence)
    throws -> NativeAgentSessionConsumeRecoveryEvidence?
  {
    switch try lookupExact(expected) {
    case .missing:
      return nil
    case .pending(let evidence):
      return evidence
    case .auditPrepared, .audited:
      throw NativeAgentSessionConsumeRecoveryStoreError.conflict
    }
  }

  /// Returns the exact durable state for retry.  A tuple mismatch, including
  /// a mismatch against an audited record, is never treated as a cache miss.
  public func lookupExact(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    nowMilliseconds: Int64? = nil
  ) throws -> NativeAgentSessionConsumeRecoveryLookup {
    lock.lock()
    defer { lock.unlock() }
    if let nowMilliseconds {
      guard nowMilliseconds >= 0 else {
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidEvidence
      }
      _ = try pruneExpiredLocked(nowMilliseconds: nowMilliseconds)
    }
    guard let actual = records[expected.recoveryKey] else { return .missing }
    switch actual {
    case .pending(let evidence):
      guard evidence.matchesAuthority(expected) else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return .pending(evidence)
    case .auditPrepared(let preparedRecord):
      guard preparedRecord.evidence.matchesAuthority(expected) else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return .auditPrepared(preparedRecord)
    case .audited(let auditedRecord):
      guard auditedRecord.evidence.matchesAuthority(expected) else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return .audited(auditedRecord)
    }
  }

  /// Atomically advances a matching pending record to `audit_prepared`.
  /// Repeating the exact transition is idempotent. The in-memory transition is
  /// rolled back if the canonical write, file fsync, rename, or parent-directory
  /// fsync fails.
  @discardableResult
  public func prepareForActivation(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    preparedRecord: NativeAgentSessionConsumeRecoveryPreparedRecord
  ) throws -> NativeAgentSessionConsumeRecoveryPreparedRecord {
    guard preparedRecord.evidence == expected else {
      throw NativeAgentSessionConsumeRecoveryStoreError.conflict
    }
    lock.lock()
    defer { lock.unlock() }
    guard let actual = records[expected.recoveryKey] else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    switch actual {
    case .pending(let pending):
      guard pending == expected else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
    case .auditPrepared(let existing):
      guard existing == preparedRecord else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return existing
    case .audited:
      throw NativeAgentSessionConsumeRecoveryStoreError.conflict
    }
    let old = records
    records[expected.recoveryKey] = .auditPrepared(preparedRecord)
    do {
      try persistLocked()
      return preparedRecord
    } catch {
      records = old
      throw error
    }
  }

  /// Atomically advances an exact `audit_prepared` record to `audited`.
  /// Repeating the exact terminalization is idempotent. A pending record can
  /// never skip the prepared state, and an existing audited record must match
  /// the complete prepared tuple and audit-chain digest byte-for-byte.
  @discardableResult
  public func completeAfterAudit(
    _ expected: NativeAgentSessionConsumeRecoveryEvidence,
    preparedRecord: NativeAgentSessionConsumeRecoveryPreparedRecord,
    auditedRecord: NativeAgentSessionConsumeRecoveryAuditedRecord
  ) throws -> NativeAgentSessionConsumeRecoveryAuditedRecord {
    guard preparedRecord.evidence == expected,
      auditedRecord.preparedRecord == preparedRecord
    else {
      throw NativeAgentSessionConsumeRecoveryStoreError.conflict
    }
    lock.lock()
    defer { lock.unlock() }
    guard let actual = records[expected.recoveryKey] else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    switch actual {
    case .pending:
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    case .auditPrepared(let existing):
      guard existing == preparedRecord else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
    case .audited(let existing):
      guard existing == auditedRecord else {
        throw NativeAgentSessionConsumeRecoveryStoreError.conflict
      }
      return existing
    }
    let old = records
    records[expected.recoveryKey] = .audited(auditedRecord)
    do {
      try persistLocked()
      return auditedRecord
    } catch {
      records = old
      throw error
    }
  }

  /// Terminally deletes a record when activation has been explicitly
  /// abandoned.  It uses the same exact-match guard as activation completion.
  @discardableResult
  public func abandon(_ expected: NativeAgentSessionConsumeRecoveryEvidence) throws -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard let actual = records[expected.recoveryKey] else { return false }
    guard case .pending(let pending) = actual else {
      throw NativeAgentSessionConsumeRecoveryStoreError.conflict
    }
    guard pending == expected else {
      throw NativeAgentSessionConsumeRecoveryStoreError.conflict
    }
    let old = records
    records.removeValue(forKey: expected.recoveryKey)
    do {
      try persistLocked()
      return true
    } catch {
      records = old
      throw error
    }
  }

  // MARK: - Loading and canonical validation

  private static func load(pathName: String, parentFD: Int32) throws
    -> [String: Record]
  {
    var metadata = stat()
    if fstatat(parentFD, pathName, &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
      guard errno == ENOENT else {
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
      }
      return [:]
    }
    try validateRecordMetadata(metadata)
    let descriptor = openat(parentFD, pathName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    defer { close(descriptor) }
    let data = try readDescriptor(descriptor, before: metadata)
    guard data.last == 0x0a, data.count <= maximumBytes else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    let payload = Data(data.dropLast())
    do {
      let object = try NativeStrictJSON.object(
        from: payload, maxBytes: maximumBytes, maxDepth: 8)
      guard Set(object.keys) == ["records", "version"],
        integer(object["version"]) == Int64(version),
        let values = object["records"] as? [[String: Any]],
        values.count <= maximumEntries,
        try NativeStrictJSON.data(object) == payload
      else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidState }

      var decoded: [String: Record] = [:]
      for value in values {
        let record = try decode(value)
        guard decoded[record.recoveryKey] == nil,
          try NativeStrictJSON.data(encode(record)) == NativeStrictJSON.data(value)
        else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidState }
        decoded[record.recoveryKey] = record
      }
      return decoded
    } catch let error as NativeAgentSessionConsumeRecoveryStoreError {
      throw error
    } catch {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
  }

  private static func decode(_ value: [String: Any]) throws -> Record {
    guard let state = value["state"] as? String,
      let organizationID = value["organization_id"] as? String,
      let deviceID = value["device_id"] as? String,
      let agentID = value["agent_id"] as? String,
      let adapterText = value["adapter_kind"] as? String,
      let adapterKind = AgentPassAgentAdapterKind(rawValue: adapterText),
      let grantProofDigest = digest(value["grant_proof_sha256"]),
      let processDigest = digest(value["process_binding_sha256"]),
      let ancestryDigest = digest(value["ancestry_binding_sha256"]),
      let worktreeDigest = digest(value["worktree_binding_sha256"]),
      let controlSequence = integer(value["control_sequence"]),
      let authorityGeneration = integer(value["authority_generation"]),
      let keyGeneration = integer(value["key_generation"]),
      let recoveryExpiresAtMilliseconds = integer(value["recovery_expires_at_ms"])
    else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidState }
    let recordKeys: Set<String>
    switch state {
    case "pending": recordKeys = pendingRecordKeys
    case "audit_prepared": recordKeys = preparedRecordKeys
    case "audited": recordKeys = auditedRecordKeys
    default: throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    guard Set(value.keys) == recordKeys else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    do {
      let evidence = try NativeAgentSessionConsumeRecoveryEvidence(
        organizationID: organizationID, deviceID: deviceID, agentID: agentID,
        adapterKind: adapterKind, grantProofDigest: grantProofDigest,
        processBindingDigest: processDigest, ancestryBindingDigest: ancestryDigest,
        worktreeBindingDigest: worktreeDigest, controlSequence: controlSequence,
        authorityGeneration: authorityGeneration, keyGeneration: keyGeneration,
        recoveryExpiresAtMilliseconds: recoveryExpiresAtMilliseconds)
      if state == "pending" { return .pending(evidence) }
      guard let sessionDigest = digest(value["session_sha256"]),
        let resultDigest = digest(value["result_sha256"]),
        let expiresAtMilliseconds = integer(value["expires_at_ms"])
      else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidState }
      let prepared = try NativeAgentSessionConsumeRecoveryPreparedRecord(
        evidence: evidence, sessionID: try requiredUUID(value["session_id"]),
        sessionDigest: sessionDigest,
        resultDigest: resultDigest,
        auditEvidenceDigest: try requiredDigest(value["audit_evidence_sha256"]),
        expiresAtMilliseconds: expiresAtMilliseconds)
      if state == "audit_prepared" { return .auditPrepared(prepared) }
      return .audited(
        try NativeAgentSessionConsumeRecoveryAuditedRecord(
          preparedRecord: prepared,
          auditDigest: try requiredDigest(value["audit_sha256"])))
    } catch {
      if let error = error as? NativeAgentSessionConsumeRecoveryStoreError { throw error }
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
  }

  private static func encode(_ record: Record) -> [String: Any] {
    let evidence = record.evidence
    var object: [String: Any] = [
      "adapter_kind": evidence.adapterKind.rawValue,
      "agent_id": evidence.agentID,
      "ancestry_binding_sha256": hex(evidence.ancestryBindingDigest),
      "authority_generation": evidence.authorityGeneration,
      "control_sequence": evidence.controlSequence,
      "device_id": evidence.deviceID,
      "grant_proof_sha256": hex(evidence.grantProofDigest),
      "key_generation": evidence.keyGeneration,
      "organization_id": evidence.organizationID,
      "process_binding_sha256": hex(evidence.processBindingDigest),
      "recovery_expires_at_ms": evidence.recoveryExpiresAtMilliseconds,
      "state": record.state,
      "worktree_binding_sha256": hex(evidence.worktreeBindingDigest),
    ]
    switch record {
    case .pending:
      break
    case .auditPrepared(let preparedRecord):
      object["audit_evidence_sha256"] = hex(preparedRecord.auditEvidenceDigest)
      object["expires_at_ms"] = preparedRecord.expiresAtMilliseconds
      object["result_sha256"] = hex(preparedRecord.resultDigest)
      object["session_id"] = preparedRecord.sessionID
      object["session_sha256"] = hex(preparedRecord.sessionDigest)
    case .audited(let auditedRecord):
      object["audit_evidence_sha256"] = hex(auditedRecord.auditEvidenceDigest)
      object["audit_sha256"] = hex(auditedRecord.auditDigest)
      object["expires_at_ms"] = auditedRecord.expiresAtMilliseconds
      object["result_sha256"] = hex(auditedRecord.resultDigest)
      object["session_id"] = auditedRecord.sessionID
      object["session_sha256"] = hex(auditedRecord.sessionDigest)
    }
    return object
  }

  private func persistLocked() throws {
    let values = records.values.sorted { $0.recoveryKey < $1.recoveryKey }.map(Self.encode)
    let object: [String: Any] = ["records": values, "version": Self.version]
    let data: Data
    do {
      data = try NativeStrictJSON.data(object) + Data("\n".utf8)
    } catch {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    guard data.count <= Self.maximumBytes else {
      throw NativeAgentSessionConsumeRecoveryStoreError.capacityExceeded
    }
    let parent = try Self.openPrivateParent(for: path)
    defer { close(parent.fd) }
    if records.isEmpty {
      try Self.removeRecordFile(parentFD: parent.fd, parentName: parent.name)
      return
    }
    try Self.atomicWrite(
      parentFD: parent.fd, parentName: parent.name, data: data)
  }

  private func pruneExpiredLocked(nowMilliseconds: Int64) throws -> Int {
    let expired = records.values.filter {
      $0.expiresAtMilliseconds <= nowMilliseconds
    }
    guard !expired.isEmpty else { return 0 }
    let old = records
    for record in expired { records.removeValue(forKey: record.recoveryKey) }
    do {
      try persistLocked()
      return expired.count
    } catch {
      records = old
      throw error
    }
  }

  // MARK: - Secure filesystem primitives

  private static func openPrivateParent(for filePath: String)
    throws -> (fd: Int32, path: String, name: String)
  {
    let url = URL(fileURLWithPath: filePath)
    let name = url.lastPathComponent
    let parentPath = url.deletingLastPathComponent().path
    guard !name.isEmpty, name != ".", name != "..", !name.contains("/") else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidPath
    }

    var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidPath }
    let components = parentPath.split(separator: "/", omittingEmptySubsequences: true)
    do {
      for component in components {
        let next = openat(
          descriptor, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard next >= 0 else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidPath }
        close(descriptor)
        descriptor = next
      }
      try validatePrivateDirectory(descriptor)
      return (descriptor, parentPath, name)
    } catch let error as NativeAgentSessionConsumeRecoveryStoreError {
      close(descriptor)
      throw error
    } catch {
      close(descriptor)
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidPath
    }
  }

  private static func validatePrivateDirectory(_ descriptor: Int32) throws {
    var info = stat()
    guard fstat(descriptor, &info) == 0,
      (info.st_mode & S_IFMT) == S_IFDIR,
      info.st_uid == geteuid(),
      (info.st_mode & 0o777) == directoryMode
    else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidState }
  }

  private static func validateRecordMetadata(_ info: stat) throws {
    guard (info.st_mode & S_IFMT) == S_IFREG,
      info.st_uid == geteuid(),
      (info.st_mode & 0o777) == fileMode,
      info.st_nlink == 1,
      info.st_size > 0,
      info.st_size <= off_t(maximumBytes)
    else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidState }
  }

  private static func readDescriptor(_ descriptor: Int32, before: stat) throws -> Data {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
      let count = buffer.withUnsafeMutableBytes { bytes in
        Darwin.read(descriptor, bytes.baseAddress, bytes.count)
      }
      if count < 0 {
        if errno == EINTR { continue }
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
      }
      if count == 0 { break }
      guard data.count <= Self.maximumBytes - count else {
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
      }
      data.append(buffer, count: count)
    }
    var after = stat()
    guard fstat(descriptor, &after) == 0,
      before.st_dev == after.st_dev,
      before.st_ino == after.st_ino,
      before.st_mode == after.st_mode,
      before.st_uid == after.st_uid,
      before.st_gid == after.st_gid,
      before.st_nlink == after.st_nlink,
      before.st_size == after.st_size,
      data.count == Int(before.st_size)
    else { throw NativeAgentSessionConsumeRecoveryStoreError.invalidState }
    return data
  }

  private static func writeAll(_ data: Data, descriptor: Int32) throws {
    try data.withUnsafeBytes { bytes in
      guard let base = bytes.baseAddress else { return }
      var offset = 0
      while offset < bytes.count {
        let written = Darwin.write(descriptor, base.advanced(by: offset), bytes.count - offset)
        if written < 0 {
          if errno == EINTR { continue }
          throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure
        }
        guard written > 0 else {
          throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure
        }
        offset += written
      }
    }
  }

  private static func atomicWrite(parentFD: Int32, parentName: String, data: Data) throws {
    let temporaryName = "\(temporaryPrefix)\(UUID().uuidString.lowercased())"
    var descriptor = openat(
      parentFD, temporaryName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, fileMode)
    guard descriptor >= 0 else { throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure }
    var renamed = false
    defer {
      if descriptor >= 0 { close(descriptor) }
      if !renamed { unlinkat(parentFD, temporaryName, 0) }
    }
    do {
      try writeAll(data, descriptor: descriptor)
      guard fchmod(descriptor, fileMode) == 0,
        fsync(descriptor) == 0,
        close(descriptor) == 0
      else { throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure }
      descriptor = -1
      guard renameat(parentFD, temporaryName, parentFD, parentName) == 0 else {
        throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure
      }
      renamed = true
      guard fsync(parentFD) == 0 else {
        throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure
      }
    } catch let error as NativeAgentSessionConsumeRecoveryStoreError {
      throw error
    } catch {
      throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure
    }
  }

  private static func removeRecordFile(parentFD: Int32, parentName: String) throws {
    var info = stat()
    if fstatat(parentFD, parentName, &info, AT_SYMLINK_NOFOLLOW) != 0 {
      guard errno == ENOENT else {
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
      }
      return
    }
    try validateRecordMetadata(info)
    guard unlinkat(parentFD, parentName, 0) == 0 else {
      throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure
    }
    guard fsync(parentFD) == 0 else {
      throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure
    }
  }

  private static func removeCrashRemnants(parentFD: Int32, parentPath: String) throws {
    let names: [String]
    do { names = try FileManager.default.contentsOfDirectory(atPath: parentPath) } catch {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    var removed = false
    for name in names where name.hasPrefix(temporaryPrefix) {
      var info = stat()
      guard fstatat(parentFD, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
        if errno == ENOENT { continue }
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
      }
      try validateRecordMetadata(info)
      guard unlinkat(parentFD, name, 0) == 0 else {
        throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure
      }
      removed = true
    }
    if removed, fsync(parentFD) != 0 {
      throw NativeAgentSessionConsumeRecoveryStoreError.ioFailure
    }
  }

  private static func digest(_ value: Any?) -> Data? {
    guard let value = value as? String,
      value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
      let data = Data(hex: value),
      data.count == NativeAgentSessionConsumeRecoveryEvidence.digestByteCount
    else { return nil }
    return data
  }

  private static func requiredDigest(_ value: Any?) throws -> Data {
    guard let result = digest(value) else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    return result
  }

  private static func requiredUUID(_ value: Any?) throws -> String {
    guard let value = value as? String,
      value.utf8.count == 36,
      value.range(
        of: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        options: .regularExpression) != nil,
      UUID(uuidString: value) != nil
    else {
      throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
    }
    return value
  }

  private static func integer(_ value: Any?) -> Int64? {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID(),
      number.doubleValue.isFinite,
      number.doubleValue.rounded() == number.doubleValue,
      Double(number.int64Value) == number.doubleValue,
      number.int64Value >= 1
    else { return nil }
    return number.int64Value
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }
}

extension Data {
  fileprivate init?(hex: String) {
    guard hex.utf8.count % 2 == 0 else { return nil }
    var result = Data(capacity: hex.utf8.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
      result.append(byte)
      index = next
    }
    self = result
  }
}
