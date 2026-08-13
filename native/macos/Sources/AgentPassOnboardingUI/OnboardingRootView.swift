import AppKit
import SwiftUI
import AgentPassApp

/// The read-only onboarding window for AgentPass.
///
/// This view deliberately exposes only status, refresh, and copy. It never
/// invokes an onboarding action, starts a process, or displays secret material
/// or local paths.
@MainActor
public struct OnboardingRootView: View {
    @ObservedObject private var model: OnboardingScreenModel
    @State private var copyFeedback: CopyFeedback?

    public init(model: OnboardingScreenModel) {
        self.model = model
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content

            if copyFeedback == .copied {
                Text("Command copied to the clipboard")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.bottom, 12)
                    .accessibilityAddTraits(.isStaticText)
            }
        }
        .frame(minWidth: 480, idealWidth: 560, minHeight: 360, idealHeight: 440)
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            model.refresh()
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "key.horizontal")
                .font(.system(size: 25, weight: .semibold))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text("AgentPass")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(.primary)

                Text("Read-only onboarding status")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 16)

            Button("Refresh", systemImage: "arrow.clockwise") {
                model.refresh()
            }
            .buttonStyle(.bordered)
            .keyboardShortcut("r", modifiers: [.command])
            .accessibilityHint("Reloads the local onboarding status without changing setup.")
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 20)
    }

    @ViewBuilder
    private var content: some View {
        switch model.state {
        case .idle:
            LoadingStateView()
        case .loading:
            LoadingStateView()
        case .failed:
            ErrorStateView(
                refresh: { _ = model.refresh() }
            )
        case .loaded(let status):
            LoadedStateView(
                status: status,
                copyCommand: copyCommand
            )
        }
    }

    private func copyCommand(_ command: String) {
        guard !command.isEmpty else { return }

        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(command, forType: .string)
        copyFeedback = .copied

        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            if copyFeedback == .copied {
                copyFeedback = nil
            }
        }
    }
}

private struct LoadingStateView: View {
    var body: some View {
        StatusCard {
            ProgressView()
                .controlSize(.small)
                .accessibilityLabel("Loading onboarding status")

            VStack(spacing: 6) {
                Text("Checking AgentPass")
                    .font(.headline)
                Text("Reading local status…")
                    .font(.body)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Loading onboarding status")
    }
}

private struct ErrorStateView: View {
    let refresh: () -> Void

    var body: some View {
        StatusCard {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 25))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 8) {
                Text("Status unavailable")
                    .font(.headline)

                Text("The local onboarding status could not be read. Refresh to try again.")
                    .font(.body)
                    .foregroundStyle(.secondary)

                Button("Refresh", systemImage: "arrow.clockwise", action: refresh)
                    .buttonStyle(.bordered)
                    .accessibilityHint("Tries reading the local onboarding status again.")
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Onboarding status unavailable")
    }
}

private struct LoadedStateView: View {
    let status: AgentPassOnboardingViewModel
    let copyCommand: (String) -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                ProgressSection(status: status)

                if let blockedError = status.blockedError {
                    BlockedSection(error: blockedError)
                } else if status.isComplete {
                    CompleteSection()
                } else {
                    NextActionSection(
                        action: status.nextAction,
                        copyCommand: copyCommand
                    )
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Onboarding status")
    }
}

private struct ProgressSection: View {
    let status: AgentPassOnboardingViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(status.state.displayName)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.primary)

                Spacer()

                Text("\(status.progress.completedSteps) of \(status.progress.totalSteps)")
                    .font(.subheadline.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            ProgressView(value: status.progress.fraction)
                .progressViewStyle(.linear)
                .tint(.accentColor)
                .accessibilityValue(
                    "\(status.progress.completedSteps) of \(status.progress.totalSteps) steps"
                )

            Text(status.initialized ? "AgentPass is configured on this Mac." : "AgentPass setup has not started.")
                .font(.body)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Onboarding progress")
    }
}

private struct BlockedSection: View {
    let error: AgentPassOnboardingBlockedError

    var body: some View {
        StatusCard {
            Image(systemName: "hand.raised.fill")
                .font(.system(size: 23))
                .foregroundStyle(.red)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 8) {
                Text("Setup is blocked")
                    .font(.headline)

                Text(error.message)
                    .font(.body)
                    .foregroundStyle(.secondary)

                if let remediation = error.remediation {
                    Text(remediation)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Onboarding setup is blocked")
    }
}

private struct CompleteSection: View {
    var body: some View {
        StatusCard {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 25))
                .foregroundStyle(.green)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 6) {
                Text("Setup complete")
                    .font(.headline)
                Text("AgentPass is ready for your configured coding agents.")
                    .font(.body)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Onboarding setup complete")
    }
}

private struct NextActionSection: View {
    let action: AgentPassOnboardingNextAction?
    let copyCommand: (String) -> Void

    var body: some View {
        StatusCard {
            Image(systemName: "arrow.right.circle")
                .font(.system(size: 23))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 10) {
                Text("Next step")
                    .font(.headline)

                if let action {
                    Text(action.title)
                        .font(.body)
                        .foregroundStyle(.primary)

                    Button("Copy Command", systemImage: "doc.on.doc") {
                        copyCommand(action.command)
                    }
                    .buttonStyle(.bordered)
                    .accessibilityHint("Copies the display-only command. It is not executed by this app.")
                } else {
                    Text("No action is currently available. Refresh to check again.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Next onboarding step")
    }
}

private struct StatusCard<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        HStack(alignment: .top, spacing: 14, content: content)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(18)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

private enum CopyFeedback: Equatable {
    case copied
}
