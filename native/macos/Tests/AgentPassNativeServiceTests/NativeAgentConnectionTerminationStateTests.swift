import AgentPassNativeCore
@testable import AgentPassNativeService
import Foundation
import Testing

private let terminationBinding = try! NativeAgentSessionBinding(
    agentID: "11111111-1111-4111-8111-111111111111",
    deviceID: "22222222-2222-4222-8222-222222222222",
    processBindingDigest: Data(repeating: 0x11, count: 32),
    ancestryBindingDigest: Data(repeating: 0x22, count: 32),
    worktreeBindingDigest: Data(repeating: 0x33, count: 32),
    controlSequence: 1,
    authorityGeneration: 1,
    keyGeneration: 1
)

@Test("connection termination rejects late session installation and is idempotent")
func connectionTerminationStateIsOneShot() {
    let state = NativeAgentConnectionTerminationState()
    #expect(state.install(terminationBinding))

    let first = state.beginCleanup()
    #expect(first.shouldCleanup)
    #expect(first.binding == terminationBinding)
    #expect(!state.install(terminationBinding))

    let second = state.beginCleanup()
    #expect(!second.shouldCleanup)
    #expect(second.binding == nil)
    #expect(state.takeInstalledBinding() == nil)
}

@Test("activation rollback can take a binding without marking the connection terminated")
func connectionTerminationStateSupportsActivationRollback() {
    let state = NativeAgentConnectionTerminationState()
    #expect(state.install(terminationBinding))
    #expect(state.takeInstalledBinding() == terminationBinding)
    #expect(state.install(terminationBinding))
    #expect(state.beginCleanup().shouldCleanup)
}
