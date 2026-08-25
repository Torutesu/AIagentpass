import Combine
import Foundation
import AgentPassApp

public enum AgentPassOnboardingScreenState: Equatable, Sendable {
    case idle
    case loading
    case loaded(AgentPassOnboardingViewModel)
    case failed(AgentPassOnboardingScreenError)
}

public enum AgentPassOnboardingScreenError: Error, Equatable, Sendable {
    case statusUnavailable
}

extension AgentPassOnboardingScreenError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .statusUnavailable:
            return "AgentPass setup status is unavailable. Try again."
        }
    }
}

/// Main-actor state for a read-only SwiftUI onboarding screen.
@MainActor
public final class OnboardingScreenModel: ObservableObject {
    @Published public private(set) var state: AgentPassOnboardingScreenState = .idle

    public var status: AgentPassOnboardingViewModel? {
        guard case let .loaded(status) = state else { return nil }
        return status
    }

    public var isLoading: Bool {
        if case .loading = state { return true }
        return false
    }

    public var error: AgentPassOnboardingScreenError? {
        guard case let .failed(error) = state else { return nil }
        return error
    }

    private let provider: AgentPassOnboardingStatusProvider
    private var refreshTask: Task<Void, Never>?
    private var refreshGeneration = 0

    public init(provider: AgentPassOnboardingStatusProvider = AgentPassOnboardingStatusProvider()) {
        self.provider = provider
    }

    deinit {
        refreshTask?.cancel()
    }

    /// Starts a refresh and returns the task so tests or a SwiftUI caller can await it.
    @discardableResult
    public func refresh() -> Task<Void, Never> {
        refreshTask?.cancel()
        refreshGeneration &+= 1
        let generation = refreshGeneration
        state = .loading

        let task = Task { [weak self] in
            guard let self else { return }
            do {
                let status = try await self.provider.status()
                guard !Task.isCancelled, self.refreshGeneration == generation else { return }
                self.state = .loaded(status)
            } catch is CancellationError {
                // A superseded request must never overwrite the newer request's state.
            } catch {
                guard !Task.isCancelled, self.refreshGeneration == generation else { return }
                self.state = .failed(.statusUnavailable)
            }
        }
        refreshTask = task
        return task
    }
}
