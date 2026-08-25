import Foundation
import Testing
@testable import AgentPassApp

private let adapter = AgentPassOnboardingStatusAdapter()

private func status(
    initialized: Bool = true,
    state: String = "app_verified",
    revision: Int = 1,
    setupComplete: Bool = false,
    nextActions: String? = nil,
    blockedError: String? = nil,
    extra: String = ""
) -> String {
    let action = nextActions ?? #"[{"id":"initialize_local_config","target_state":"local_config_initialized","command":"agentpass setup continue","description":"Initialize user-owned local configuration"}]"#
    let blocked = blockedError.map { ",\"blocked_error\":\($0)" } ?? ""
    if !initialized {
        return "{\"version\":1,\"initialized\":false,\"state\":\"not_started\",\"setup_complete\":false,\"next_actions\":[{\"id\":\"verify_app\",\"command\":\"agentpass setup --client claude-code --project DIR --team-id TEAMID --execute\"}]\(extra)}"
    }
    return "{\"version\":1,\"initialized\":true,\"journal_id\":\"123e4567-e89b-12d3-a456-426614174000\",\"revision\":\(revision),\"state\":\"\(state)\",\"updated_at\":\"2030-01-01T00:00:00.000Z\",\"setup_complete\":\(setupComplete),\"next_actions\":\(action),\"history_length\":\(revision + 1)\(blocked)\(extra)}"
}

private func completeStatus() -> String {
    status(state: "complete", revision: 11, setupComplete: true, nextActions: "[]")
}

@Test func mapsEveryJournalStateToStableProgressAndAction() throws {
    let states = AgentPassOnboardingState.allCases
    for state in states {
        let index = states.firstIndex(of: state)!
        let expectedAction: AgentPassOnboardingActionID? = switch state {
        case .notStarted: .verifyApp
        case .appVerified: .initializeLocalConfig
        case .localConfigInitialized: .selectNativeBridge
        case .nativeBridgeSelected: .registerService
        case .serviceRegistered: .startBootstrap
        case .bootstrapStarted: .enrollApprovalKey
        case .approvalKeyEnrolled: .activateServiceKeys
        case .serviceKeysActivated: .enrollDevice
        case .deviceEnrolled: .connectEditor
        case .editorConnected: .verifyTestCommit
        case .testCommitVerified: .completeSetup
        case .complete: nil
        }
        let json: String
        if state == .notStarted {
            json = status(initialized: false)
        } else if state == .complete {
            json = completeStatus()
        } else {
            let next = actionJSON(for: expectedAction!, target: states[index + 1])
            json = status(state: state.rawValue, revision: index, nextActions: next)
        }
        let model = try adapter.viewModel(from: json)
        #expect(model.state == state)
        #expect(model.progress.completedSteps == index)
        #expect(model.progress.totalSteps == 11)
        #expect(model.nextAction?.id == expectedAction)
        #expect(model.nextAction?.targetState == (index < 11 ? states[index + 1] : nil))
    }
}

@Test func parsesUninitializedCLIStatusWithoutCreatingLocalState() throws {
    let model = try adapter.viewModel(from: status(initialized: false))
    #expect(model.initialized == false)
    #expect(model.state == .notStarted)
    #expect(model.nextAction?.id == .verifyApp)
    #expect(model.nextAction?.command.contains("TEAMID") == true)
    #expect(model.interaction == .readOnly)
}

@Test func rejectsUnknownDuplicateMissingAndMalformedFields() {
    let cases = [
        (status(extra: ",\"unexpected\":true"), AgentPassOnboardingStatusError.unknownField),
        (status(extra: ",\"blocked_error\":null,\"blocked_error\":null"), AgentPassOnboardingStatusError.duplicateField),
        (#"{"version":1,"initialized":true,"state":"app_verified","setup_complete":false,"next_actions":[]}"#, AgentPassOnboardingStatusError.missingField),
        (status() + " trailing", AgentPassOnboardingStatusError.malformedJSON),
        (status(state: "future_state"), AgentPassOnboardingStatusError.invalidField),
        (status(revision: 2), AgentPassOnboardingStatusError.invalidField),
        (status(extra: ",\"version\":1"), AgentPassOnboardingStatusError.duplicateField),
        (status().replacingOccurrences(of: "\"revision\":1", with: "\"revision\":1.0"), AgentPassOnboardingStatusError.invalidField),
        (status().replacingOccurrences(of: "\"initialized\":true", with: "\"initialized\":1"), AgentPassOnboardingStatusError.invalidField)
    ]
    for (json, expected) in cases {
        do {
            _ = try adapter.viewModel(from: json)
            Issue.record("Expected parsing to fail")
        } catch let error as AgentPassOnboardingStatusError {
            #expect(error == expected)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}

@Test func rejectsInconsistentStateProgressAndActionData() {
    let cases = [
        status(state: "complete", revision: 11, setupComplete: false, nextActions: "[]"),
        status(state: "app_verified", revision: 1, nextActions: "[]"),
        status(nextActions: #"[{"id":"unknown","target_state":"local_config_initialized","command":"agentpass setup continue"}]"#),
        status(nextActions: #"[{"id":"initialize_local_config","target_state":"complete","command":"agentpass setup continue"}]"#),
        status(nextActions: #"[{"id":"initialize_local_config","target_state":"local_config_initialized","command":42}]"#),
        status(nextActions: #"[{"id":"initialize_local_config","target_state":"local_config_initialized","command":"agentpass setup continue","unknown":true}]"#),
        status(nextActions: #"[{"id":"initialize_local_config","target_state":"local_config_initialized","command":"agentpass setup continue"},{"id":"initialize_local_config","target_state":"local_config_initialized","command":"agentpass setup continue"}]"#)
    ]
    for json in cases {
        #expect(throws: AgentPassOnboardingStatusError.self) { try adapter.viewModel(from: json) }
    }
}

@Test func blocksUnsupportedVersionsAndUnsafeBlockedErrorsWithoutLeakingSecretsOrPaths() throws {
    #expect(throws: AgentPassOnboardingStatusError.self) {
        try adapter.viewModel(from: status(extra: ",\"version\":2"))
    }

    let blocked = #"{"code":"bootstrap_blocked","message":"Cannot use token=super-secret at /Users/alice/Secrets/key.json","remediation":"Run agentpass setup --project /Users/alice/project"}"#
    let model = try adapter.viewModel(from: status(blockedError: #""# + blocked))
    #expect(model.isBlocked)
    #expect(model.blockedError?.code == "bootstrap_blocked")
    #expect(model.blockedError?.message == "Setup is blocked. Review local AgentPass diagnostics.")
    #expect(model.blockedError?.remediation?.contains("/Users/alice") == false)
}

@Test func rejectsOversizedAndDeeplyNestedStatusBeforeMaterializingIt() {
    #expect(throws: AgentPassOnboardingStatusError.self) {
        try adapter.viewModel(from: Data(repeating: 0x20, count: 256 * 1024 + 1))
    }
    let deep = String(repeating: "[", count: 34) + "0" + String(repeating: "]", count: 34)
    #expect(throws: AgentPassOnboardingStatusError.self) {
        try adapter.viewModel(from: #"{"version":1,"initialized":false,"state":"not_started","setup_complete":false,"next_actions":\#(deep)}"#)
    }
}

@Test func rejectsDuplicateFieldsAtNestedDepthAndInvalidJSON() {
    let nestedDuplicate = status(nextActions: #"[{"id":"initialize_local_config","target_state":"local_config_initialized","command":"agentpass setup continue","description":"ok","description":"again"}]"#)
    #expect(throws: AgentPassOnboardingStatusError.self) { try adapter.viewModel(from: nestedDuplicate) }

    for json in ["null", "[]", "{", "{\"version\":1,}", "{\"version\":1,\"initialized\":true,\"state\":\"app_verified\",\"setup_complete\":false,\"next_actions\":[]}"] {
        #expect(throws: AgentPassOnboardingStatusError.self) { try adapter.viewModel(from: json) }
    }
}

@Test func outputIsDefensiveAndReadOnly() throws {
    let first = try adapter.viewModel(from: status())
    let second = try adapter.viewModel(from: status())
    #expect(first == second)
    #expect(first.interaction == .readOnly)
    #expect(first.isComplete == false)
    #expect(first.nextAction?.command == "agentpass setup continue")
}

@Test func parsesProductionDiagnosticsWithoutExposingRawFields() throws {
    let distribution = try AgentPassDoctorStatusAdapter().distributionStatus(from: Data(doctorReport.utf8))
    #expect(distribution.developerID == .verified)
    #expect(distribution.notarization == .verified)
    #expect(distribution.releaseReceipt == .verified)

    let capability = try AgentPassNativeStatusAdapter().capabilityStatus(from: Data(nativeStatus.utf8))
    #expect(capability.secureEnclave == .verified)
    #expect(capability.tpm == .notApplicable)
}

@Test func recoveryActionsAreCopyOnlyAndNeverContainSecretsOrPaths() throws {
    let base = try adapter.viewModel(from: status())
    let model = base.withDiagnostics(AgentPassOnboardingDiagnostics(
        distribution: AgentPassDistributionStatus(developerID: .blocked, notarization: .actionRequired, releaseReceipt: .unavailable),
        capability: AgentPassCapabilityStatus(secureEnclave: .verified)
    ))

    let actions = model.safeRecoveryActions
    #expect(actions.map(\.id) == [.install, .check, .repair, .revoke])
    for action in actions {
        #expect(action.command.hasPrefix("agentpass "))
        #expect(action.command.contains("--execute") == false)
        #expect(action.command.localizedCaseInsensitiveContains("token") == false)
        #expect(action.command.localizedCaseInsensitiveContains("secret") == false)
        #expect(action.command.contains("/Users/") == false)
        #expect(action.explanation.localizedCaseInsensitiveContains("execute") == false || action.id == .install)
    }
}

private let doctorReport = #"{"schema_version":1,"state":"healthy","ok":true,"generated_at":"2030-01-01T00:00:00.000Z","mode":"production-native","checks":[{"id":"app.code_identity","state":"healthy","severity":"info","summary":"ok"},{"id":"release.installed_receipt","state":"healthy","severity":"info","summary":"ok"}],"summary":{"healthy":2,"action_required":0,"degraded":0,"blocked":0},"host":{"platform":"darwin","architecture":"arm64"}}"#
private let nativeStatus = #"{"health":{"ok":true,"version":13},"audit":{"configured":true}}"#

private func actionJSON(for id: AgentPassOnboardingActionID, target: AgentPassOnboardingState) -> String {
    "[{\"id\":\"\(id.rawValue)\",\"target_state\":\"\(target.rawValue)\",\"command\":\"agentpass setup continue\",\"description\":\"safe\"}]"
}
