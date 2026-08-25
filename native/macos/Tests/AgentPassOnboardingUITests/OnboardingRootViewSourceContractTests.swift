import Foundation
import Testing

@Test func onboardingRootViewIsCopyOnlyAndNeverRunsACommand() throws {
    let source = try rootViewSource()
    #expect(source.contains("Process(") == false)
    #expect(source.contains("NSTask") == false)
    #expect(source.contains("launch()") == false)
    #expect(source.contains("--password") == false)
    #expect(source.localizedCaseInsensitiveContains("private key") == false)
    #expect(source.contains("This app will not execute it.") == true)
    #expect(source.contains("Input required:") == true)
    #expect(source.contains("Open Terminal and copies") == true)
}

private func rootViewSource() throws -> String {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let sourceURL = testDirectory
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentPassOnboardingUI/OnboardingRootView.swift")
    return try String(contentsOf: sourceURL, encoding: .utf8)
}
