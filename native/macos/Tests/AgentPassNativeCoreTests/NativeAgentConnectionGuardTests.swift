import Foundation
import Testing
@testable import AgentPassNativeCore

private func connectionObservation(pid: Int32 = 42, uid: UInt32 = 501, pidVersion: UInt64 = 9, hash: String = String(repeating: "a", count: 64)) throws -> NativeProcessObservation {
    let facts = try NativeObservedProcessFacts(
        uid: uid,
        pid: pid,
        pidVersion: pidVersion,
        bootIdentity: "boot-1",
        executableFileIdentity: NativeExecutableFileIdentity(deviceID: 1, inode: 2, fileSize: 3, modificationTimeNanoseconds: 4),
        codeDirectoryHash: hash,
        bundleIdentifier: "dev.agentpass.agent-host",
        teamIdentifier: "ABCDE12345",
        signatureKind: .developerID,
        entitlements: [NativeAgentCodeRequirement.clientEntitlement: .boolean(true)]
    )
    return try NativeProcessObservation(process: facts, ancestry: [])
}

@Test func connectionGuardBindsOSPeerFieldsToTheObservedProcess() throws {
    let context = try NativeConnectionContext(osProcessID: 42, effectiveUserID: 501, auditSessionID: 7, pidVersion: 9)
    let observation = try connectionObservation()
    let guardValue = try NativeAgentConnectionGuard(context: context, observation: observation)

    #expect(guardValue.processBindingHash.count == 64)
    #expect(guardValue.ancestryBindingHash.count == 64)
    try guardValue.revalidate(observation: observation)
}

@Test func connectionGuardRejectsPIDVersionAndCodeIdentityDrift() throws {
    let context = try NativeConnectionContext(osProcessID: 42, effectiveUserID: 501, auditSessionID: 7, pidVersion: 9)
    let guardValue = try NativeAgentConnectionGuard(context: context, observation: connectionObservation())

    #expect(throws: NativeAgentConnectionGuardError.connectionObservationMismatch) {
        try guardValue.revalidate(observation: connectionObservation(pidVersion: 10))
    }
    #expect(throws: NativeAgentConnectionGuardError.processIdentityChanged) {
        try guardValue.revalidate(observation: connectionObservation(hash: String(repeating: "b", count: 64)))
    }
}

@Test func connectionGuardRejectsContextAndInitialObservationSubstitution() throws {
    let context = try NativeConnectionContext(osProcessID: 42, effectiveUserID: 501, auditSessionID: 7, pidVersion: 9)
    #expect(throws: NativeAgentConnectionGuardError.connectionObservationMismatch) {
        _ = try NativeAgentConnectionGuard(context: context, observation: connectionObservation(pid: 43))
    }
}
