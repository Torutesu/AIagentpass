import Foundation

/// Closed activation boundaries observable by the qualification harness.
///
/// These values are not part of the Agent XPC protocol.  They exist only as
/// dependency-injected, process-local checkpoints so a separately authorized
/// qualification controller can terminate the daemon at an exact boundary.
public enum NativeAgentSessionQualificationBoundary: String, CaseIterable, Sendable {
  case beforeCloudConsume = "before-cloud-consume"
  case afterCloudLeaseVerified = "after-cloud-lease-verified"
  case afterAdmissionReserved = "after-admission-reserved"
  case afterRecoveryPrepared = "after-recovery-prepared"
  case afterHiddenCommit = "after-hidden-commit"
  case afterCommitReceipt = "after-commit-receipt"
  case afterAuditDurable = "after-audit-durable"
  case afterRecoveryTerminal = "after-recovery-terminal"
  case afterPublication = "after-publication"
  case afterResultEncoded = "after-result-encoded"
}

/// Process-local qualification checkpoint dependency.
///
/// Implementations must not retain authority-bearing request data.  A normal
/// production runtime uses the no-op value below.  Qualification adapters may
/// throw only after atomically consuming their one-shot external control.
public protocol NativeAgentSessionQualificationFaultConsuming: Sendable {
  func reach(_ boundary: NativeAgentSessionQualificationBoundary) throws
}

/// Zero-surface default used whenever the root-owned qualification mode is not
/// configured.  Keeping this a value type prevents a latent mutable fault slot
/// from existing in ordinary Agent connections.
public struct NativeAgentSessionQualificationNoopFaultConsumer:
  NativeAgentSessionQualificationFaultConsuming, Sendable
{
  public init() {}

  public func reach(_ boundary: NativeAgentSessionQualificationBoundary) throws {}
}

/// Separate transport disposition used only after a complete response has
/// been encoded. Returning `true` drops that one reply without revoking the
/// already audited session, allowing an exact client retry to recover it.
public protocol NativeAgentSessionTransportReplyFaultConsuming: Sendable {
  func shouldDropEncodedResult() -> Bool
}

public struct NativeAgentSessionTransportReplyNoopFaultConsumer:
  NativeAgentSessionTransportReplyFaultConsuming, Sendable
{
  public init() {}
  public func shouldDropEncodedResult() -> Bool { false }
}
