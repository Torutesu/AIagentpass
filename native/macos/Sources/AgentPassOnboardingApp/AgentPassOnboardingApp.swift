import SwiftUI
import AgentPassOnboardingUI

/// The macOS onboarding companion. All setup mutations remain in the CLI or
/// service; this window only reads status and copies a display-only command.
@main
@MainActor
public struct AgentPassOnboardingApp: App {
    @StateObject private var model: OnboardingScreenModel

    public init() {
        _model = StateObject(wrappedValue: OnboardingScreenModel())
    }

    public var body: some Scene {
        WindowGroup("AgentPass Setup") {
            OnboardingRootView(model: model)
        }
        .defaultSize(width: 560, height: 440)
    }
}
