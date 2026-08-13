import Testing

@testable import AgentPassNativeCore

@Test("qualification boundaries are a closed, ordered protocol surface")
func qualificationBoundariesAreClosedAndOrdered() {
  #expect(
    NativeAgentSessionQualificationBoundary.allCases == [
      .beforeCloudConsume,
      .afterCloudLeaseVerified,
      .afterAdmissionReserved,
      .afterRecoveryPrepared,
      .afterHiddenCommit,
      .afterCommitReceipt,
      .afterAuditDurable,
      .afterRecoveryTerminal,
      .afterPublication,
      .afterResultEncoded,
    ])
  #expect(
    NativeAgentSessionQualificationBoundary(rawValue: "unknown-boundary") == nil)
}

@Test("the no-op qualification fault consumer accepts every boundary")
func qualificationNoopFaultConsumerAcceptsEveryBoundary() throws {
  let consumer: any NativeAgentSessionQualificationFaultConsuming =
    NativeAgentSessionQualificationNoopFaultConsumer()

  for boundary in NativeAgentSessionQualificationBoundary.allCases {
    try consumer.reach(boundary)
  }
}
