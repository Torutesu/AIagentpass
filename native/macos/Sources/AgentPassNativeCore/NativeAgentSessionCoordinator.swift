import CryptoKit
import Foundation

public enum NativeAgentSessionCoordinatorError: String, Error, Equatable, Sendable {
  case invalidConfiguration = "invalid_configuration"
  case invalidInput = "invalid_input"
  case connectionDenied = "connection_denied"
  case challengeDenied = "challenge_denied"
  case bindingDenied = "binding_denied"
  case grantDenied = "grant_denied"
  case leaseDenied = "lease_denied"
  case activationDenied = "activation_denied"
  case sessionDenied = "session_denied"
  case auditUnavailable = "audit_unavailable"
  case invalidated = "invalidated"
}

public struct NativeAgentSessionActivationResult: Equatable, Sendable {
  public let status: NativeAgentSessionRegistryStatus
  public let binding: NativeAgentSessionBinding
}

/// The sole transaction owner for one authenticated Agent connection.
///
/// Authority-bearing values are obtained from the connection-scoped challenge
/// and the live binding observer. Callers can provide only the opaque bootstrap
/// proof or a public session identifier.
public final class NativeAgentSessionCoordinator: @unchecked Sendable {
  private struct Attempt {
    let bootstrapID: String
    let proofDigest: Data
    let evidence: NativeAgentBootstrapEvidence
    let binding: NativeAgentSessionBinding
    var lease: NativeAgentVerifiedCloudLease?
    var localLeaseID: String?
    var recoveryEvidence: NativeAgentSessionConsumeRecoveryEvidence?
    var attempts: Int
  }

  private struct CompletedStart {
    let bootstrapID: String
    let proofDigest: Data
    let result: NativeAgentSessionActivationResult
  }

  private let connectionTokenIdentity: String
  private let connectionRevalidator: @Sendable () throws -> Void
  private let bootstrapStore: NativeAgentBootstrapChallengeStore
  private let bindingObserver: any NativeAgentSessionBindingObserving
  private let grantConsumer: any NativeAgentGrantLeaseConsuming
  private let recoveryStore: any NativeAgentSessionConsumeRecoveryStoring
  private let registry: NativeAgentSessionRegistry
  private let audit: any NativeAgentSessionAuditAppending
  private let wallClock: any NativeAgentWallClock
  private let monotonicClock: any NativeAgentMonotonicClock
  private let random: any NativeAgentRandomBytesGenerating
  private let authority: NativeAgentRuntimeAuthorityConfiguration
  private let operationLock = NSLock()
  private let stateLock = NSLock()
  private var invalidated = false
  private var pendingAttempt: Attempt?
  private var completedStart: CompletedStart?
  private var sessionBindings: [String: NativeAgentSessionBinding] = [:]
  private var auditedClosedSessions: Set<String> = []

  public init(
    connectionTokenIdentity: String,
    connectionRevalidator: @escaping @Sendable () throws -> Void,
    bootstrapStore: NativeAgentBootstrapChallengeStore,
    bindingObserver: any NativeAgentSessionBindingObserving,
    grantConsumer: any NativeAgentGrantLeaseConsuming,
    recoveryStore: any NativeAgentSessionConsumeRecoveryStoring,
    registry: NativeAgentSessionRegistry,
    audit: any NativeAgentSessionAuditAppending,
    wallClock: any NativeAgentWallClock,
    monotonicClock: any NativeAgentMonotonicClock,
    random: any NativeAgentRandomBytesGenerating = NativeAgentSystemRandomBytesGenerator(),
    authority: NativeAgentRuntimeAuthorityConfiguration
  ) throws {
    guard Self.hash(connectionTokenIdentity) else {
      throw NativeAgentSessionCoordinatorError.invalidConfiguration
    }
    self.connectionTokenIdentity = connectionTokenIdentity
    self.connectionRevalidator = connectionRevalidator
    self.bootstrapStore = bootstrapStore
    self.bindingObserver = bindingObserver
    self.grantConsumer = grantConsumer
    self.recoveryStore = recoveryStore
    self.registry = registry
    self.audit = audit
    self.wallClock = wallClock
    self.monotonicClock = monotonicClock
    self.random = random
    self.authority = authority
  }

  public func start(bootstrapID: String, proof: Data) throws
    -> NativeAgentSessionActivationResult
  {
    let proofRange = ClosedRange(
      uncheckedBounds: (
        lower: NativeAgentGrantConsumptionRequest.minimumProofBytes,
        upper: NativeAgentGrantConsumptionRequest.maximumProofBytes
      ))
    guard Self.uuid(bootstrapID),
      proofRange.contains(proof.count)
    else { throw NativeAgentSessionCoordinatorError.invalidInput }

    operationLock.lock()
    defer { operationLock.unlock() }
    try revalidateConnection()
    try ensureLive()

    let proofDigest = Data(SHA256.hash(data: proof))
    if let completed = stateLock.withLock({ completedStart }) {
      guard completed.bootstrapID == bootstrapID.lowercased(),
        completed.proofDigest == proofDigest
      else { throw NativeAgentSessionCoordinatorError.challengeDenied }
      let observed: NativeAgentSessionBinding
      do {
        observed = try bindingObserver.observeSessionBinding(
          agentID: completed.result.binding.agentID)
      } catch {
        invalidateSession(
          sessionID: completed.result.status.sessionID, binding: completed.result.binding)
        throw NativeAgentSessionCoordinatorError.bindingDenied
      }
      guard observed == completed.result.binding else {
        invalidateSession(
          sessionID: completed.result.status.sessionID, binding: completed.result.binding)
        throw NativeAgentSessionCoordinatorError.bindingDenied
      }
      let status: NativeAgentSessionRegistryStatus
      do {
        status = try registry.status(
          sessionID: completed.result.status.sessionID,
          connectionTokenIdentity: connectionTokenIdentity,
          binding: completed.result.binding,
          wallClock: sampleWall(), monotonicClock: sampleMonotonic())
      } catch {
        throw NativeAgentSessionCoordinatorError.sessionDenied
      }
      guard status.state == .active else {
        throw NativeAgentSessionCoordinatorError.sessionDenied
      }
      return NativeAgentSessionActivationResult(
        status: status, binding: completed.result.binding)
    }

    var attempt: Attempt
    if let pending = stateLock.withLock({ pendingAttempt }) {
      guard pending.bootstrapID == bootstrapID.lowercased(),
        pending.proofDigest == proofDigest,
        pending.attempts < authority.bootstrapAttemptLimit
      else { throw NativeAgentSessionCoordinatorError.challengeDenied }
      attempt = pending
      attempt.attempts += 1
    } else {
      let monotonic = try sampleMonotonic()
      let wall = try sampleWall()
      let evidence: NativeAgentBootstrapEvidence
      do {
        evidence = try bootstrapStore.consume(
          bootstrapID: bootstrapID,
          nowMilliseconds: wall.millisecondsSinceUnixEpoch,
          nowMonotonicNanoseconds: monotonic.nanoseconds)
      } catch {
        throw NativeAgentSessionCoordinatorError.challengeDenied
      }
      let binding: NativeAgentSessionBinding
      do {
        binding = try bindingObserver.observeSessionBinding(agentID: evidence.agentID)
      } catch {
        throw NativeAgentSessionCoordinatorError.bindingDenied
      }
      try validate(evidence: evidence, binding: binding, monotonic: monotonic)
      attempt = Attempt(
        bootstrapID: bootstrapID.lowercased(), proofDigest: proofDigest,
        evidence: evidence, binding: binding, lease: nil, localLeaseID: nil,
        recoveryEvidence: nil, attempts: 1)
    }
    stateLock.withLock { pendingAttempt = attempt }

    if attempt.recoveryEvidence == nil {
      do {
        let recoveryEvidence = try NativeAgentSessionConsumeRecoveryEvidence(
          organizationID: authority.organizationID,
          deviceID: attempt.binding.deviceID,
          agentID: attempt.binding.agentID,
          adapterKind: attempt.evidence.adapterKind,
          grantProofDigest: attempt.proofDigest,
          processBindingDigest: attempt.binding.processBindingDigest,
          ancestryBindingDigest: attempt.binding.ancestryBindingDigest,
          worktreeBindingDigest: attempt.binding.worktreeBindingDigest,
          controlSequence: attempt.binding.controlSequence,
          authorityGeneration: attempt.binding.authorityGeneration,
          keyGeneration: attempt.binding.keyGeneration,
          bootstrapIssuedAtMilliseconds: attempt.evidence.issuedAtMilliseconds,
          requestedTTLSeconds: attempt.evidence.requestedTTLSeconds)
        let savedEvidence = try recoveryStore.save(
          recoveryEvidence, nowMilliseconds: try sampleWall().millisecondsSinceUnixEpoch)
        attempt.recoveryEvidence = savedEvidence
      } catch {
        throw NativeAgentSessionCoordinatorError.activationDenied
      }
    }
    stateLock.withLock { pendingAttempt = attempt }

    if attempt.lease == nil {
      do {
        attempt.lease = try grantConsumer.consumeGrant(
          NativeAgentGrantConsumptionRequest(
            bootstrapID: attempt.bootstrapID, proof: proof, binding: attempt.binding))
      } catch {
        stateLock.withLock { pendingAttempt = attempt }
        throw NativeAgentSessionCoordinatorError.grantDenied
      }
      stateLock.withLock { pendingAttempt = attempt }
    }
    try ensureLive()
    guard let lease = attempt.lease else {
      throw NativeAgentSessionCoordinatorError.leaseDenied
    }

    let monotonic = try sampleMonotonic()
    let wall = try sampleWall()
    guard
      attempt.evidence.connectionBinding.bootIdentityHash
        == Self.hex(Data(SHA256.hash(data: Data(monotonic.bootIdentity.utf8))))
    else {
      throw NativeAgentSessionCoordinatorError.bindingDenied
    }
    try validate(lease: lease, evidence: attempt.evidence, activationWall: wall)
    let deadline: NativeAgentSessionDeadline
    do {
      deadline = try NativeAgentSessionDeadline(
        signedWallExpiryMilliseconds: lease.expiresAtMilliseconds,
        wallClock: wall,
        monotonicClock: monotonic)
    } catch {
      throw NativeAgentSessionCoordinatorError.leaseDenied
    }

    if attempt.localLeaseID == nil {
      attempt.localLeaseID = try localLeaseID()
      stateLock.withLock { pendingAttempt = attempt }
    }
    guard let localLeaseID = attempt.localLeaseID else {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    let status: NativeAgentSessionRegistryStatus
    do {
      status = try registry.activate(
        lease: lease,
        localLeaseID: localLeaseID,
        connectionTokenIdentity: connectionTokenIdentity,
        deadline: deadline,
        globalLimit: authority.globalSessionLimit,
        perAgentLimit: authority.perAgentSessionLimit,
        perWorktreeLimit: authority.perWorktreeSessionLimit)
    } catch {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    do {
      try ensureLive()
    } catch {
      invalidateSession(
        sessionID: status.sessionID, binding: attempt.binding,
        reasonCode: "connection_invalidated")
      stateLock.withLock { pendingAttempt = nil }
      throw error
    }
    do {
      try audit.appendAgentSessionAudit(
        NativeAgentSessionAuditEvidence(
          action: .sessionActivated, sessionID: status.sessionID, binding: attempt.binding))
    } catch {
      try? registry.invalidate(
        sessionID: status.sessionID,
        connectionTokenIdentity: connectionTokenIdentity,
        as: .revoked)
      stateLock.withLock { pendingAttempt = nil }
      throw NativeAgentSessionCoordinatorError.auditUnavailable
    }

    guard let recoveryEvidence = attempt.recoveryEvidence else {
      invalidateSession(
        sessionID: status.sessionID, binding: attempt.binding,
        reasonCode: "recovery_store_unavailable")
      stateLock.withLock { pendingAttempt = nil }
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    do {
      guard try recoveryStore.completeAfterLocalActivation(recoveryEvidence) else {
        throw NativeAgentSessionConsumeRecoveryStoreError.invalidState
      }
    } catch {
      invalidateSession(
        sessionID: status.sessionID, binding: attempt.binding,
        reasonCode: "recovery_store_unavailable")
      stateLock.withLock { pendingAttempt = nil }
      throw NativeAgentSessionCoordinatorError.activationDenied
    }

    let result = NativeAgentSessionActivationResult(status: status, binding: attempt.binding)
    let published = stateLock.withLock { () -> Bool in
      guard !invalidated else {
        pendingAttempt = nil
        return false
      }
      sessionBindings[status.sessionID] = attempt.binding
      completedStart = CompletedStart(
        bootstrapID: attempt.bootstrapID, proofDigest: proofDigest, result: result)
      pendingAttempt = nil
      return true
    }
    guard published else {
      invalidateSession(
        sessionID: status.sessionID, binding: attempt.binding,
        reasonCode: "connection_invalidated")
      throw NativeAgentSessionCoordinatorError.invalidated
    }
    return result
  }

  public func status(sessionID: String) throws -> NativeAgentSessionRegistryStatus {
    guard Self.uuid(sessionID) else { throw NativeAgentSessionCoordinatorError.invalidInput }
    operationLock.lock()
    defer { operationLock.unlock() }
    try revalidateConnection()
    try ensureLive()
    guard let expected = stateLock.withLock({ sessionBindings[sessionID.lowercased()] }) else {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
    let observed: NativeAgentSessionBinding
    do {
      observed = try bindingObserver.observeSessionBinding(agentID: expected.agentID)
    } catch {
      invalidateSession(sessionID: sessionID, binding: expected)
      throw NativeAgentSessionCoordinatorError.bindingDenied
    }
    guard observed == expected else {
      invalidateSession(sessionID: sessionID, binding: expected)
      throw NativeAgentSessionCoordinatorError.bindingDenied
    }
    do {
      return try registry.status(
        sessionID: sessionID.lowercased(),
        connectionTokenIdentity: connectionTokenIdentity,
        binding: expected,
        wallClock: sampleWall(),
        monotonicClock: sampleMonotonic())
    } catch {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
  }

  public func close(
    sessionID: String,
    reason: AgentPassAgentSessionCloseReason
  ) throws -> NativeAgentSessionRegistryStatus {
    guard Self.uuid(sessionID) else { throw NativeAgentSessionCoordinatorError.invalidInput }
    operationLock.lock()
    defer { operationLock.unlock() }
    try revalidateConnection()
    guard let binding = stateLock.withLock({ sessionBindings[sessionID.lowercased()] }) else {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
    let status: NativeAgentSessionRegistryStatus
    do {
      status = try registry.close(
        sessionID: sessionID.lowercased(),
        connectionTokenIdentity: connectionTokenIdentity)
    } catch {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
    let needsAudit = stateLock.withLock { !auditedClosedSessions.contains(status.sessionID) }
    if needsAudit {
      do {
        try audit.appendAgentSessionAudit(
          NativeAgentSessionAuditEvidence(
            action: .sessionClosed, sessionID: status.sessionID,
            binding: binding, reasonCode: reason.rawValue))
      } catch {
        throw NativeAgentSessionCoordinatorError.auditUnavailable
      }
      _ = stateLock.withLock { auditedClosedSessions.insert(status.sessionID) }
    }
    return status
  }

  /// Called by the XPC invalidation handler. It never waits for a network
  /// operation and only revokes authority owned by this connection.
  public func invalidateConnection() {
    bootstrapStore.invalidate()
    let bindings = stateLock.withLock { () -> [String: NativeAgentSessionBinding] in
      invalidated = true
      pendingAttempt = nil
      completedStart = nil
      return sessionBindings
    }
    let statuses = registry.invalidateOwned(
      by: connectionTokenIdentity, as: .revoked)
    for status in statuses {
      guard let binding = bindings[status.sessionID] else { continue }
      try? audit.appendAgentSessionAudit(
        NativeAgentSessionAuditEvidence(
          action: .sessionInvalidated, sessionID: status.sessionID,
          binding: binding, reasonCode: "connection_invalidated"))
    }
  }

  /// Compensates for a response that cannot be safely constructed or sent.
  public func abortActivation(sessionID: String) {
    let binding = stateLock.withLock { () -> NativeAgentSessionBinding? in
      if completedStart?.result.status.sessionID == sessionID.lowercased() {
        completedStart = nil
      }
      return sessionBindings.removeValue(forKey: sessionID.lowercased())
    }
    guard let binding else { return }
    invalidateSession(sessionID: sessionID, binding: binding)
  }

  private func validate(
    evidence: NativeAgentBootstrapEvidence,
    binding: NativeAgentSessionBinding,
    monotonic: NativeAgentMonotonicClockValue
  ) throws {
    guard evidence.connectionBinding.connectionTokenIdentity == connectionTokenIdentity,
      evidence.connectionBinding.processBindingHash == Self.hex(binding.processBindingDigest),
      evidence.connectionBinding.ancestryBindingHash == Self.hex(binding.ancestryBindingDigest),
      evidence.connectionBinding.bootIdentityHash
        == Self.hex(Data(SHA256.hash(data: Data(monotonic.bootIdentity.utf8)))),
      evidence.agentID == binding.agentID,
      binding.deviceID == authority.deviceID
    else { throw NativeAgentSessionCoordinatorError.bindingDenied }
  }

  private func validate(
    lease: NativeAgentVerifiedCloudLease,
    evidence: NativeAgentBootstrapEvidence,
    activationWall: NativeAgentWallClockValue
  ) throws {
    let requestedLifetime = Int64(evidence.requestedTTLSeconds) * 1_000
    let maximumExpiry = evidence.issuedAtMilliseconds.addingReportingOverflow(requestedLifetime)
    guard !maximumExpiry.overflow,
      lease.organizationID == authority.organizationID,
      lease.deviceID == authority.deviceID,
      lease.agentID == evidence.agentID,
      Self.agentKind(for: evidence.adapterKind) == lease.agentKind,
      lease.usedSignatures < lease.maxSignatures,
      lease.notBeforeMilliseconds <= activationWall.millisecondsSinceUnixEpoch,
      lease.expiresAtMilliseconds > activationWall.millisecondsSinceUnixEpoch,
      lease.expiresAtMilliseconds <= maximumExpiry.partialValue
    else { throw NativeAgentSessionCoordinatorError.leaseDenied }
  }

  private func revalidateConnection() throws {
    do { try connectionRevalidator() } catch {
      invalidateConnection()
      throw NativeAgentSessionCoordinatorError.connectionDenied
    }
  }

  private func ensureLive() throws {
    guard !stateLock.withLock({ invalidated }) else {
      throw NativeAgentSessionCoordinatorError.invalidated
    }
  }

  private func invalidateSession(
    sessionID: String,
    binding: NativeAgentSessionBinding,
    reasonCode: String = "binding_changed"
  ) {
    try? registry.invalidate(
      sessionID: sessionID.lowercased(),
      connectionTokenIdentity: connectionTokenIdentity,
      as: .revoked)
    try? audit.appendAgentSessionAudit(
      NativeAgentSessionAuditEvidence(
        action: .sessionInvalidated, sessionID: sessionID.lowercased(),
        binding: binding, reasonCode: reasonCode))
  }

  private func sampleWall() throws -> NativeAgentWallClockValue {
    do { return try wallClock.sample() } catch {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
  }

  private func sampleMonotonic() throws -> NativeAgentMonotonicClockValue {
    do { return try monotonicClock.sample() } catch {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
  }

  private func localLeaseID() throws -> String {
    let bytes: Data
    do { bytes = try random.randomBytes(count: 16) } catch {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    guard bytes.count == 16 else { throw NativeAgentSessionCoordinatorError.activationDenied }
    var value = Array(bytes)
    value[6] = (value[6] & 0x0f) | 0x40
    value[8] = (value[8] & 0x3f) | 0x80
    let hex = value.map { String(format: "%02x", $0) }
    return hex[0...3].joined() + "-" + hex[4...5].joined() + "-"
      + hex[6...7].joined() + "-" + hex[8...9].joined() + "-" + hex[10...15].joined()
  }

  private static func agentKind(for adapter: AgentPassAgentAdapterKind) -> String? {
    switch adapter {
    case .claudeCode: "claude-code"
    case .cursor: "cursor"
    case .generic: nil
    }
  }

  private static func uuid(_ value: String) -> Bool {
    value.utf8.count == 36 && UUID(uuidString: value) != nil
  }

  private static func hash(_ value: String) -> Bool {
    value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }
}
