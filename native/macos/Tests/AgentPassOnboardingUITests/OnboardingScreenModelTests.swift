import Foundation
import Testing
@testable import AgentPassApp
@testable import AgentPassOnboardingUI

@Test @MainActor func screenModelLoadsAndPublishesValidatedStatus() async {
    let provider = AgentPassOnboardingStatusProvider { _, _, _, _ in Data(validStatus.utf8) }
    let model = OnboardingScreenModel(provider: provider)

    #expect(model.state == .idle)
    let task = model.refresh()
    #expect(model.isLoading)
    await task.value

    #expect(model.status?.state == .appVerified)
    #expect(model.error == nil)
    #expect(model.isLoading == false)
}

@Test @MainActor func screenModelMapsProviderFailureToSafeError() async {
    let provider = AgentPassOnboardingStatusProvider { _, _, _, _ in
        throw FakeProviderError.secretToken
    }
    let model = OnboardingScreenModel(provider: provider)

    await model.refresh().value

    #expect(model.state == .failed(.statusUnavailable))
    #expect(model.error?.localizedDescription.contains("secret") == false)
    #expect(model.status == nil)
}

@Test @MainActor func refreshCanRecoverFromError() async {
    let responses = ResponseSequence(responses: [
        .failure,
        .success(Data(completeStatus.utf8))
    ])
    let provider = AgentPassOnboardingStatusProvider { _, _, _, _ in
        try await responses.next()
    }
    let model = OnboardingScreenModel(provider: provider)

    await model.refresh().value
    #expect(model.error == .statusUnavailable)

    await model.refresh().value
    #expect(model.status?.isComplete == true)
    #expect(model.error == nil)
}

@Test @MainActor func supersededRefreshCannotOverwriteNewerResult() async {
    let responses = ControlledResponses()
    let provider = AgentPassOnboardingStatusProvider { _, _, _, _ in
        try await responses.next()
    }
    let model = OnboardingScreenModel(provider: provider)

    let first = model.refresh()
    await responses.waitUntilFirstStarted()
    let second = model.refresh()
    await responses.releaseSecond()
    await second.value
    await responses.releaseFirst()
    await first.value

    #expect(model.status?.isComplete == true)
    #expect(model.state != .failed(.statusUnavailable))
}

private let validStatus = #"{"version":1,"initialized":true,"journal_id":"123e4567-e89b-12d3-a456-426614174000","revision":1,"state":"app_verified","updated_at":"2030-01-01T00:00:00.000Z","setup_complete":false,"next_actions":[{"id":"initialize_local_config","target_state":"local_config_initialized","command":"agentpass setup continue"}],"history_length":2}"#
private let completeStatus = #"{"version":1,"initialized":true,"journal_id":"123e4567-e89b-12d3-a456-426614174000","revision":11,"state":"complete","updated_at":"2030-01-01T00:00:00.000Z","setup_complete":true,"next_actions":[],"history_length":12}"#

private enum FakeProviderError: Error {
    case secretToken
}

private actor ResponseSequence {
    enum Response {
        case failure
        case success(Data)
    }

    private var responses: [Response]

    init(responses: [Response]) {
        self.responses = responses
    }

    func next() throws -> Data {
        switch responses.removeFirst() {
        case .failure: throw FakeProviderError.secretToken
        case let .success(data): return data
        }
    }
}

private actor ControlledResponses {
    private var callCount = 0
    private var firstStarted = false
    private var firstRelease = false
    private var secondRelease = false

    func next() async throws -> Data {
        callCount += 1
        let call = callCount
        if call == 1 {
            firstStarted = true
            while !firstRelease { await Task.yield() }
            return Data(validStatus.utf8)
        }
        while !secondRelease { await Task.yield() }
        return Data(completeStatus.utf8)
    }

    func waitUntilFirstStarted() async {
        while !firstStarted { await Task.yield() }
    }

    func releaseFirst() {
        firstRelease = true
    }

    func releaseSecond() {
        secondRelease = true
    }
}
