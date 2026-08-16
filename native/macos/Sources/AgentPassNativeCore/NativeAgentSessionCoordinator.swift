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
    var preparedRecovery: NativeAgentSessionConsumeRecoveryPreparedRecord?
    var auditedRecovery: NativeAgentSessionConsumeRecoveryAuditedRecord?
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
  private let activationRecoveryStore: any NativeAgentSessionConsumeRecoveryV4Storing
  private let qualificationFaultConsumer: any NativeAgentSessionQualificationFaultConsuming
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
    activationRecoveryStore: any NativeAgentSessionConsumeRecoveryV4Storing,
    qualificationFaultConsumer: any NativeAgentSessionQualificationFaultConsuming =
      NativeAgentSessionQualificationNoopFaultConsumer(),
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
    self.activationRecoveryStore = activationRecoveryStore
    self.qualificationFaultConsumer = qualificationFaultConsumer
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
        recoveryEvidence: nil, preparedRecovery: nil, auditedRecovery: nil, attempts: 1)
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
        let now = try sampleWall().millisecondsSinceUnixEpoch
        switch try recoveryStore.lookupExact(recoveryEvidence, nowMilliseconds: now) {
        case .missing:
          attempt.recoveryEvidence = try recoveryStore.save(
            recoveryEvidence, nowMilliseconds: now)
        case .pending(let savedEvidence):
          attempt.recoveryEvidence = savedEvidence
        case .auditPrepared(let preparedRecord):
          attempt.recoveryEvidence = preparedRecord.evidence
          attempt.preparedRecovery = preparedRecord
        case .audited(let auditedRecord):
          attempt.recoveryEvidence = auditedRecord.evidence
          attempt.auditedRecovery = auditedRecord
        }
      } catch {
        throw NativeAgentSessionCoordinatorError.activationDenied
      }
    }
    stateLock.withLock { pendingAttempt = attempt }

    // `audit_prepared` is already a durable, authority-free hand-off. Reconcile
    // it before any network retry so an unavailable or expired Cloud Lease
    // cannot force a duplicate audit append. This path never activates the
    // in-memory registry and therefore cannot recreate authority after restart.
    if let preparedRecovery = attempt.preparedRecovery,
      let recoveryEvidence = attempt.recoveryEvidence
    {
      do {
        let auditEvidence = try NativeAgentSessionAuditEvidence(
          action: .sessionActivated, sessionID: preparedRecovery.sessionID,
          binding: attempt.binding)
        let auditEvidenceDigest = try auditEvidence.evidenceDigest()
        guard preparedRecovery.evidence == recoveryEvidence,
          preparedRecovery.auditEvidenceDigest == auditEvidenceDigest
        else { throw NativeAgentSessionCoordinatorError.auditUnavailable }
        let receipt = try audit.reconcileAgentSessionActivationAudit(auditEvidence)
        guard receipt.evidenceDigest == auditEvidenceDigest else {
          throw NativeAgentSessionCoordinatorError.auditUnavailable
        }
        let auditedRecord = try NativeAgentSessionConsumeRecoveryAuditedRecord(
          preparedRecord: preparedRecovery, auditDigest: receipt.recordDigest)
        _ = try recoveryStore.completeAfterAudit(
          recoveryEvidence, preparedRecord: preparedRecovery,
          auditedRecord: auditedRecord)
      } catch {
        stateLock.withLock { pendingAttempt = attempt }
        throw NativeAgentSessionCoordinatorError.auditUnavailable
      }
      stateLock.withLock { pendingAttempt = nil }
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }

    if attempt.lease == nil {
      do {
        try qualificationFaultConsumer.reach(.beforeCloudConsume)
        attempt.lease = try grantConsumer.consumeGrant(
          NativeAgentGrantConsumptionRequest(
            bootstrapID: attempt.bootstrapID, proof: proof, binding: attempt.binding))
        try qualificationFaultConsumer.reach(.afterCloudLeaseVerified)
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
    let sessionDigest: Data
    do {
      sessionDigest = Data(SHA256.hash(data: try NativeAgentLeaseCodec.canonicalJSON(lease)))
    } catch {
      throw NativeAgentSessionCoordinatorError.leaseDenied
    }
    let auditEvidence: NativeAgentSessionAuditEvidence
    let auditEvidenceDigest: Data
    do {
      auditEvidence = try NativeAgentSessionAuditEvidence(
        action: .sessionActivated, sessionID: lease.sessionID, binding: attempt.binding)
      auditEvidenceDigest = try auditEvidence.evidenceDigest()
    } catch {
      throw NativeAgentSessionCoordinatorError.auditUnavailable
    }
    guard let recoveryEvidence = attempt.recoveryEvidence else {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    if let auditedRecovery = attempt.auditedRecovery {
      guard auditedRecovery.sessionDigest == sessionDigest,
        auditedRecovery.sessionID == lease.sessionID,
        auditedRecovery.auditEvidenceDigest == auditEvidenceDigest,
        auditedRecovery.expiresAtMilliseconds
          == min(recoveryEvidence.recoveryExpiresAtMilliseconds, lease.expiresAtMilliseconds)
      else {
        throw NativeAgentSessionCoordinatorError.leaseDenied
      }
      stateLock.withLock { pendingAttempt = nil }
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
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
      attempt.localLeaseID = try Self.localLeaseID(
        sessionID: lease.sessionID, proofDigest: attempt.proofDigest)
      stateLock.withLock { pendingAttempt = attempt }
    }
    guard let localLeaseID = attempt.localLeaseID else {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    let reservation: NativeAgentSessionActivationReservation
    do {
      reservation = try registry.reserveActivation(
        lease: lease,
        localLeaseID: localLeaseID,
        connectionTokenIdentity: connectionTokenIdentity,
        deadline: deadline,
        globalLimit: authority.globalSessionLimit,
        perAgentLimit: authority.perAgentSessionLimit,
        perWorktreeLimit: authority.perWorktreeSessionLimit,
        wallClock: wall,
        monotonicClock: monotonic)
    } catch {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    do {
      try qualificationFaultConsumer.reach(.afterAdmissionReserved)
    } catch {
      _ = try? registry.abortActivation(
        reservation, connectionTokenIdentity: connectionTokenIdentity)
      stateLock.withLock { pendingAttempt = attempt }
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    let plannedResult = NativeAgentSessionActivationResult(
      status: reservation.plannedStatus, binding: attempt.binding)
    let resultDigest: Data
    let transactionDigest: Data
    let commitReceiptDigest: Data
    let v4Evidence: NativeAgentSessionConsumeRecoveryV4Evidence
    let activationAuditEvidence: NativeAgentSessionAuditEvidence
    let activationAuditEvidenceDigest: Data
    do {
      resultDigest = try Self.activationResultDigest(plannedResult)
      transactionDigest = try Self.activationTransactionDigest(
        recoveryEvidence: recoveryEvidence,
        sessionDigest: sessionDigest,
        resultDigest: resultDigest,
        expiresAtMilliseconds: min(
          recoveryEvidence.recoveryExpiresAtMilliseconds, lease.expiresAtMilliseconds))
      commitReceiptDigest = try Self.activationCommitReceiptDigest(
        transactionDigest: transactionDigest,
        sessionID: lease.sessionID,
        resultDigest: resultDigest)
      v4Evidence = try NativeAgentSessionConsumeRecoveryV4Evidence(
        evidence: recoveryEvidence, transactionDigest: transactionDigest)
      activationAuditEvidence = try NativeAgentSessionAuditEvidence(
        action: .sessionActivated,
        sessionID: lease.sessionID,
        activationTransactionDigest: transactionDigest,
        activationCommitReceiptDigest: commitReceiptDigest,
        binding: attempt.binding)
      activationAuditEvidenceDigest = try activationAuditEvidence.evidenceDigest()
    } catch {
      _ = try? registry.abortActivation(
        reservation, connectionTokenIdentity: connectionTokenIdentity)
      throw NativeAgentSessionCoordinatorError.activationDenied
    }

    let preparedRecord: NativeAgentSessionConsumeRecoveryV4PreparedRecord
    do {
      let now = try sampleWall().millisecondsSinceUnixEpoch
      let lookup = try activationRecoveryStore.lookupExact(
        v4Evidence, nowMilliseconds: now)
      switch lookup {
      case .missing:
        _ = try activationRecoveryStore.save(v4Evidence, nowMilliseconds: now)
      case .pending:
        break
      case .auditPrepared(let existing):
        _ = try? registry.abortActivation(
          reservation, connectionTokenIdentity: connectionTokenIdentity)
        try completeRecoveredV4Outcome(
          preparedRecord: existing, outcome: .outcomeUnknown,
          commitReceiptDigest: nil, binding: attempt.binding)
        stateLock.withLock { pendingAttempt = nil }
        throw NativeAgentSessionCoordinatorError.sessionDenied
      case .commitReceipt(let existing):
        _ = try? registry.abortActivation(
          reservation, connectionTokenIdentity: connectionTokenIdentity)
        try completeRecoveredV4CommitReceipt(
          existing, binding: attempt.binding)
        stateLock.withLock { pendingAttempt = nil }
        throw NativeAgentSessionCoordinatorError.sessionDenied
      case .audited:
        _ = try? registry.abortActivation(
          reservation, connectionTokenIdentity: connectionTokenIdentity)
        stateLock.withLock { pendingAttempt = nil }
        throw NativeAgentSessionCoordinatorError.sessionDenied
      }
      preparedRecord = try NativeAgentSessionConsumeRecoveryV4PreparedRecord(
        evidence: v4Evidence,
        sessionID: lease.sessionID,
        sessionDigest: sessionDigest,
        resultDigest: resultDigest,
        auditEvidenceDigest: activationAuditEvidenceDigest,
        expiresAtMilliseconds: min(
          recoveryEvidence.recoveryExpiresAtMilliseconds, lease.expiresAtMilliseconds))
      _ = try activationRecoveryStore.prepareForActivation(
        v4Evidence, preparedRecord: preparedRecord)
      try qualificationFaultConsumer.reach(.afterRecoveryPrepared)
    } catch {
      _ = try? registry.abortActivation(
        reservation, connectionTokenIdentity: connectionTokenIdentity)
      if let error = error as? NativeAgentSessionCoordinatorError,
        error == .sessionDenied
      {
        // A recovered v4 terminal is final.  Do not resurrect the consumed
        // bootstrap attempt in this process after durable reconciliation.
        stateLock.withLock { pendingAttempt = nil }
        throw error
      }
      stateLock.withLock { pendingAttempt = attempt }
      if let error = error as? NativeAgentSessionCoordinatorError { throw error }
      throw NativeAgentSessionCoordinatorError.activationDenied
    }

    do {
      try revalidateConnection()
      try revalidate(binding: attempt.binding)
      try ensureLive()
      _ = try registry.commitActivation(
        reservation,
        connectionTokenIdentity: connectionTokenIdentity,
        wallClock: sampleWall(),
        monotonicClock: sampleMonotonic())
      try qualificationFaultConsumer.reach(.afterHiddenCommit)
    } catch {
      _ = try? registry.abortActivation(
        reservation, connectionTokenIdentity: connectionTokenIdentity)
      _ = try? completeV4Outcome(
        preparedRecord: preparedRecord, outcome: .aborted,
        commitReceiptDigest: nil, binding: attempt.binding)
      stateLock.withLock { pendingAttempt = nil }
      if let error = error as? NativeAgentSessionCoordinatorError { throw error }
      throw NativeAgentSessionCoordinatorError.activationDenied
    }

    let commitReceipt: NativeAgentSessionConsumeRecoveryV4CommitReceipt
    do {
      commitReceipt = try NativeAgentSessionConsumeRecoveryV4CommitReceipt(
        preparedRecord: preparedRecord,
        commitReceiptDigest: commitReceiptDigest)
      _ = try activationRecoveryStore.recordCommitReceipt(
        v4Evidence, preparedRecord: preparedRecord,
        commitReceipt: commitReceipt)
      try qualificationFaultConsumer.reach(.afterCommitReceipt)
    } catch {
      _ = try? registry.abortActivation(
        reservation, connectionTokenIdentity: connectionTokenIdentity)
      stateLock.withLock { pendingAttempt = attempt }
      throw NativeAgentSessionCoordinatorError.activationDenied
    }

    do {
      let receipt = try audit.reconcileAgentSessionActivationOutcomeAudit(
        activationAuditEvidence)
      guard receipt.evidenceDigest == activationAuditEvidenceDigest else {
        throw NativeAgentSessionCoordinatorError.auditUnavailable
      }
      try qualificationFaultConsumer.reach(.afterAuditDurable)
      let terminal = try NativeAgentSessionConsumeRecoveryV4AuditedTerminalRecord(
        preparedRecord: preparedRecord,
        outcome: .activated,
        commitReceiptDigest: commitReceipt.commitReceiptDigest,
        auditDigest: receipt.recordDigest)
      _ = try activationRecoveryStore.completeAfterAudit(
        v4Evidence, preparedRecord: preparedRecord, auditedRecord: terminal)
      try qualificationFaultConsumer.reach(.afterRecoveryTerminal)
    } catch {
      _ = try? registry.abortActivation(
        reservation, connectionTokenIdentity: connectionTokenIdentity)
      stateLock.withLock { pendingAttempt = attempt }
      throw NativeAgentSessionCoordinatorError.auditUnavailable
    }

    let status: NativeAgentSessionRegistryStatus
    do {
      try revalidateConnection()
      try revalidate(binding: attempt.binding)
      try ensureLive()
      status = try registry.publishActivation(
        reservation,
        connectionTokenIdentity: connectionTokenIdentity,
        wallClock: sampleWall(),
        monotonicClock: sampleMonotonic())
    } catch {
      _ = try? registry.abortActivation(
        reservation, connectionTokenIdentity: connectionTokenIdentity)
      stateLock.withLock { pendingAttempt = nil }
      if let error = error as? NativeAgentSessionCoordinatorError { throw error }
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    do {
      try qualificationFaultConsumer.reach(.afterPublication)
    } catch {
      invalidateSession(
        sessionID: status.sessionID, binding: attempt.binding,
        reasonCode: "qualification_interrupted")
      stateLock.withLock { pendingAttempt = nil }
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    let result = NativeAgentSessionActivationResult(status: status, binding: attempt.binding)
    let resultPublished = stateLock.withLock { () -> Bool in
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
    guard resultPublished else {
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

  /// Reserves one fixed Git-sign request after a fresh process, worktree,
  /// control, generation, and key binding observation. The returned
  /// reservation is the only authority accepted by the signing transitions.
  public func reserveSigningRequest(
    _ request: AgentPassAgentSignRequest
  ) throws -> (NativeAgentSessionReservation, NativeAgentSessionBinding) {
    operationLock.lock()
    defer { operationLock.unlock() }
    try revalidateConnection()
    try ensureLive()
    guard let expected = stateLock.withLock({ sessionBindings[request.sessionID.lowercased()] }) else {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
    try revalidate(binding: expected)
    do {
      let reservation = try registry.reserve(
        sessionID: request.sessionID.lowercased(),
        requestID: request.requestID.lowercased(),
        capabilityID: request.capabilityID.lowercased(),
        nonce: request.requestNonce,
        payloadDigest: Data(SHA256.hash(data: request.commitPayload)),
        connectionTokenIdentity: connectionTokenIdentity,
        binding: expected,
        wallClock: sampleWall(),
        monotonicClock: sampleMonotonic())
      return (reservation, expected)
    } catch {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
  }

  /// Performs the final binding observation and crosses the registry's
  /// durable-intent boundary. No provider may be called before this returns.
  public func beginSigningIntent(
    _ reservation: NativeAgentSessionReservation
  ) throws -> NativeAgentSessionBinding {
    operationLock.lock()
    defer { operationLock.unlock() }
    try revalidateConnection()
    try ensureLive()
    guard let expected = stateLock.withLock({ sessionBindings[reservation.sessionID] }) else {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
    try revalidate(binding: expected)
    do {
      try registry.beginSigningIntent(reservation)
      return expected
    } catch {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
  }

  public func recoverSigningReservation(
    _ request: AgentPassAgentSignRequest,
    budgetSequence: Int
  ) throws -> (NativeAgentSessionReservation, NativeAgentSessionBinding) {
    operationLock.lock()
    defer { operationLock.unlock() }
    try revalidateConnection()
    try ensureLive()
    guard let expected = stateLock.withLock({ sessionBindings[request.sessionID.lowercased()] }) else {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
    try revalidate(binding: expected)
    do {
      let reservation = try registry.recoverSigningReservation(
        sessionID: request.sessionID.lowercased(),
        requestID: request.requestID.lowercased(),
        capabilityID: request.capabilityID.lowercased(),
        payloadDigest: Data(SHA256.hash(data: request.commitPayload)),
        budgetSequence: budgetSequence,
        connectionTokenIdentity: connectionTokenIdentity,
        binding: expected,
        wallClock: sampleWall(),
        monotonicClock: sampleMonotonic())
      return (reservation, expected)
    } catch {
      throw NativeAgentSessionCoordinatorError.sessionDenied
    }
  }

  public func recordSigning(_ reservation: NativeAgentSessionReservation) throws {
    operationLock.lock()
    defer { operationLock.unlock() }
    try registry.recordSigned(reservation)
  }

  public func completeSigning(_ reservation: NativeAgentSessionReservation) throws -> NativeAgentSessionRegistryStatus {
    operationLock.lock()
    defer { operationLock.unlock() }
    return try registry.complete(reservation)
  }

  public func finalizeSigning(_ reservation: NativeAgentSessionReservation) throws -> NativeAgentSessionRegistryStatus {
    operationLock.lock()
    defer { operationLock.unlock() }
    return try registry.finalizeSigning(reservation)
  }

  public func releaseSigningBeforeKey(_ reservation: NativeAgentSessionReservation) throws {
    operationLock.lock()
    defer { operationLock.unlock() }
    try registry.releaseBeforeKey(reservation)
  }

  public func markSigningOutcomeUnknown(_ reservation: NativeAgentSessionReservation) throws {
    operationLock.lock()
    defer { operationLock.unlock() }
    try registry.markOutcomeUnknown(reservation)
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
      _ = try? audit.appendAgentSessionAudit(
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

  private func revalidate(binding expected: NativeAgentSessionBinding) throws {
    let observed: NativeAgentSessionBinding
    do {
      observed = try bindingObserver.observeSessionBinding(agentID: expected.agentID)
    } catch {
      throw NativeAgentSessionCoordinatorError.bindingDenied
    }
    guard observed == expected else {
      throw NativeAgentSessionCoordinatorError.bindingDenied
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
    _ = try? audit.appendAgentSessionAudit(
      NativeAgentSessionAuditEvidence(
        action: .sessionInvalidated, sessionID: sessionID.lowercased(),
        binding: binding, reasonCode: reasonCode))
  }

  private func completeRecoveredV4Outcome(
    preparedRecord: NativeAgentSessionConsumeRecoveryV4PreparedRecord,
    outcome: NativeAgentSessionConsumeRecoveryV4Outcome,
    commitReceiptDigest: Data?,
    binding: NativeAgentSessionBinding
  ) throws {
    _ = try completeV4Outcome(
      preparedRecord: preparedRecord, outcome: outcome,
      commitReceiptDigest: commitReceiptDigest, binding: binding)
  }

  @discardableResult
  private func completeV4Outcome(
    preparedRecord: NativeAgentSessionConsumeRecoveryV4PreparedRecord,
    outcome: NativeAgentSessionConsumeRecoveryV4Outcome,
    commitReceiptDigest: Data?,
    binding: NativeAgentSessionBinding
  ) throws -> NativeAgentSessionConsumeRecoveryV4AuditedTerminalRecord {
    let action: NativeAgentSessionAuditAction
    switch outcome {
    case .activated: action = .sessionActivated
    case .aborted: action = .sessionActivationAborted
    case .outcomeUnknown: action = .sessionActivationOutcomeUnknown
    }
    let evidence = try NativeAgentSessionAuditEvidence(
      action: action,
      sessionID: preparedRecord.sessionID,
      activationTransactionDigest: preparedRecord.evidence.transactionDigest,
      activationCommitReceiptDigest: commitReceiptDigest,
      binding: binding)
    let receipt = try audit.reconcileAgentSessionActivationOutcomeAudit(evidence)
    let evidenceDigest = try evidence.evidenceDigest()
    guard receipt.evidenceDigest == evidenceDigest else {
      throw NativeAgentSessionCoordinatorError.auditUnavailable
    }
    let terminal = try NativeAgentSessionConsumeRecoveryV4AuditedTerminalRecord(
      preparedRecord: preparedRecord,
      outcome: outcome,
      commitReceiptDigest: commitReceiptDigest,
      auditDigest: receipt.recordDigest)
    return try activationRecoveryStore.completeAfterAudit(
      preparedRecord.evidence,
      preparedRecord: preparedRecord,
      auditedRecord: terminal)
  }

  private func completeRecoveredV4CommitReceipt(
    _ commitReceipt: NativeAgentSessionConsumeRecoveryV4CommitReceipt,
    binding: NativeAgentSessionBinding
  ) throws {
    let prepared = commitReceipt.preparedRecord
    let successEvidence = try NativeAgentSessionAuditEvidence(
      action: .sessionActivated,
      sessionID: prepared.sessionID,
      activationTransactionDigest: prepared.evidence.transactionDigest,
      activationCommitReceiptDigest: commitReceipt.commitReceiptDigest,
      binding: binding)
    let successDigest = try successEvidence.evidenceDigest()
    guard successDigest == prepared.auditEvidenceDigest else {
      throw NativeAgentSessionCoordinatorError.auditUnavailable
    }
    if let existing = try audit.lookupAgentSessionActivationOutcomeAudit(successEvidence) {
      guard existing.evidenceDigest == successDigest else {
        throw NativeAgentSessionCoordinatorError.auditUnavailable
      }
      let terminal = try NativeAgentSessionConsumeRecoveryV4AuditedTerminalRecord(
        preparedRecord: prepared,
        outcome: .activated,
        commitReceiptDigest: commitReceipt.commitReceiptDigest,
        auditDigest: existing.recordDigest)
      _ = try activationRecoveryStore.completeAfterAudit(
        prepared.evidence, preparedRecord: prepared, auditedRecord: terminal)
      return
    }
    _ = try completeV4Outcome(
      preparedRecord: prepared,
      outcome: .outcomeUnknown,
      commitReceiptDigest: commitReceipt.commitReceiptDigest,
      binding: binding)
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

  private static func localLeaseID(sessionID: String, proofDigest: Data) throws -> String {
    guard uuid(sessionID), proofDigest.count == 32 else {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    let statement: [String: Any] = [
      "version": 1,
      "purpose": "agentpass-local-session-correlation",
      "session_id": sessionID.lowercased(),
      "grant_proof_sha256": hex(proofDigest),
    ]
    let digest = Data(SHA256.hash(data: try NativeStrictJSON.data(statement)))
    var value = Array(digest.prefix(16))
    value[6] = (value[6] & 0x0f) | 0x40
    value[8] = (value[8] & 0x3f) | 0x80
    let hex = value.map { String(format: "%02x", $0) }
    return hex[0...3].joined() + "-" + hex[4...5].joined() + "-"
      + hex[6...7].joined() + "-" + hex[8...9].joined() + "-" + hex[10...15].joined()
  }

  private static func activationTransactionDigest(
    recoveryEvidence: NativeAgentSessionConsumeRecoveryEvidence,
    sessionDigest: Data,
    resultDigest: Data,
    expiresAtMilliseconds: Int64
  ) throws -> Data {
    let object: [String: Any] = [
      "version": 1,
      "purpose": "agentpass-session-activation",
      "grant_proof_sha256": hex(recoveryEvidence.grantProofDigest),
      "session_sha256": hex(sessionDigest),
      "result_sha256": hex(resultDigest),
      "control_sequence": recoveryEvidence.controlSequence,
      "authority_generation": recoveryEvidence.authorityGeneration,
      "key_generation": recoveryEvidence.keyGeneration,
      "expires_at_ms": expiresAtMilliseconds,
    ]
    return Data(SHA256.hash(data: try NativeStrictJSON.data(object)))
  }

  private static func activationCommitReceiptDigest(
    transactionDigest: Data,
    sessionID: String,
    resultDigest: Data
  ) throws -> Data {
    guard transactionDigest.count == 32, resultDigest.count == 32, uuid(sessionID) else {
      throw NativeAgentSessionCoordinatorError.activationDenied
    }
    let object: [String: Any] = [
      "version": 1,
      "purpose": "agentpass-session-hidden-commit",
      "transaction_sha256": hex(transactionDigest),
      "session_id": sessionID.lowercased(),
      "result_sha256": hex(resultDigest),
    ]
    return Data(SHA256.hash(data: try NativeStrictJSON.data(object)))
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

  private static func activationResultDigest(
    _ result: NativeAgentSessionActivationResult
  ) throws -> Data {
    let object: [String: Any] = [
      "version": 1,
      "session_id": result.status.sessionID,
      "lease_id": result.status.leaseID,
      "state": result.status.state.rawValue,
      "expires_at_ms": result.status.expiresAtMilliseconds,
      "max_signatures": result.status.maxSignatures,
      "used_signatures": result.status.usedSignatures,
      "agent_id": result.binding.agentID,
      "device_id": result.binding.deviceID,
      "process_binding_sha256": hex(result.binding.processBindingDigest),
      "ancestry_binding_sha256": hex(result.binding.ancestryBindingDigest),
      "worktree_binding_sha256": hex(result.binding.worktreeBindingDigest),
      "control_sequence": result.binding.controlSequence,
      "authority_generation": result.binding.authorityGeneration,
      "key_generation": result.binding.keyGeneration,
    ]
    return Data(SHA256.hash(data: try NativeStrictJSON.data(object)))
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }
}
