import Foundation
import Testing
@testable import AgentPassApp

@Test func recoveryCommandsSeparateDryRunFromApprovedExecution() throws {
    let status = try AgentPassOnboardingStatusAdapter().viewModel(from: #"{"version":1,"initialized":true,"journal_id":"123e4567-e89b-12d3-a456-426614174000","revision":1,"state":"app_verified","updated_at":"2030-01-01T00:00:00.000Z","setup_complete":false,"next_actions":[{"id":"initialize_local_config","target_state":"local_config_initialized","command":"agentpass setup continue"}],"history_length":2}"#)
        .withDiagnostics(AgentPassOnboardingDiagnostics(
            distribution: AgentPassDistributionStatus(developerID: .blocked, notarization: .actionRequired, releaseReceipt: .unavailable),
            capability: AgentPassCapabilityStatus(secureEnclave: .verified)
        ))

    let actions = status.safeRecoveryActions
    #expect(actions.map(\.id) == [.install, .check, .repair, .revoke])
    for action in actions {
        #expect(action.isDryRunCommand)
        #expect(action.command.contains("--execute") == false)
        #expect(action.command.localizedCaseInsensitiveContains("token") == false)
        #expect(action.command.localizedCaseInsensitiveContains("secret") == false)
        #expect(action.command.contains("/Users/") == false)
        if let approved = action.approvedCommand {
            #expect(approved.contains("--execute") || action.id == .revoke)
            #expect(approved.localizedCaseInsensitiveContains("token") == false)
            #expect(approved.localizedCaseInsensitiveContains("secret") == false)
            #expect(approved.contains("/Users/") == false)
        }
    }
    #expect(actions.first?.inputRequirement?.displayName.contains("public") == true)
}

@Test func diagnosticsSourceDoesNotExecuteCommandsOrExposeSecretMaterial() throws {
    let source = try sourceText("Sources/AgentPassApp/OnboardingDiagnostics.swift")
    #expect(source.contains("Process(") == false)
    #expect(source.contains("NSTask") == false)
    #expect(source.contains("/Users/") == false)
    #expect(source.localizedCaseInsensitiveContains("private key") == false)
    #expect(source.localizedCaseInsensitiveContains("secret") == true)
    #expect(source.contains("approvedCommand") == true)
    #expect(source.contains("inputRequirement") == true)
}

private func sourceText(_ relativePath: String) throws -> String {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let sourceURL = testDirectory
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent(relativePath)
    return try String(contentsOf: sourceURL, encoding: .utf8)
}
