import Foundation

/// The setup journal states are deliberately kept in their CLI order. The numeric
/// position is part of the status contract and is used only to calculate progress.
public enum AgentPassOnboardingState: String, CaseIterable, Codable, Equatable, Sendable {
    case notStarted = "not_started"
    case appVerified = "app_verified"
    case localConfigInitialized = "local_config_initialized"
    case nativeBridgeSelected = "native_bridge_selected"
    case serviceRegistered = "service_registered"
    case bootstrapStarted = "bootstrap_started"
    case approvalKeyEnrolled = "approval_key_enrolled"
    case serviceKeysActivated = "service_keys_activated"
    case deviceEnrolled = "device_enrolled"
    case editorConnected = "editor_connected"
    case testCommitVerified = "test_commit_verified"
    case complete

    fileprivate var index: Int {
        switch self {
        case .notStarted: return 0
        case .appVerified: return 1
        case .localConfigInitialized: return 2
        case .nativeBridgeSelected: return 3
        case .serviceRegistered: return 4
        case .bootstrapStarted: return 5
        case .approvalKeyEnrolled: return 6
        case .serviceKeysActivated: return 7
        case .deviceEnrolled: return 8
        case .editorConnected: return 9
        case .testCommitVerified: return 10
        case .complete: return 11
        }
    }

    public var displayName: String {
        switch self {
        case .notStarted: return "Not started"
        case .appVerified: return "App verified"
        case .localConfigInitialized: return "Local configuration initialized"
        case .nativeBridgeSelected: return "Native bridge selected"
        case .serviceRegistered: return "Service registered"
        case .bootstrapStarted: return "Bootstrap started"
        case .approvalKeyEnrolled: return "Approval key enrolled"
        case .serviceKeysActivated: return "Service keys activated"
        case .deviceEnrolled: return "Device enrolled"
        case .editorConnected: return "Editor connected"
        case .testCommitVerified: return "Test commit verified"
        case .complete: return "Complete"
        }
    }
}

public enum AgentPassOnboardingActionID: String, Codable, Equatable, Sendable {
    case verifyApp = "verify_app"
    case initializeLocalConfig = "initialize_local_config"
    case selectNativeBridge = "select_native_bridge"
    case registerService = "register_service"
    case startBootstrap = "start_bootstrap"
    case enrollApprovalKey = "enroll_approval_key"
    case activateServiceKeys = "activate_service_keys"
    case enrollDevice = "enroll_device"
    case connectEditor = "connect_editor"
    case verifyTestCommit = "verify_test_commit"
    case completeSetup = "complete_setup"
}

public struct AgentPassOnboardingProgress: Equatable, Sendable {
    public let completedSteps: Int
    public let totalSteps: Int

    public var fraction: Double {
        guard totalSteps > 0 else { return 0 }
        return Double(completedSteps) / Double(totalSteps)
    }

    public var isComplete: Bool { completedSteps == totalSteps }

    fileprivate init(state: AgentPassOnboardingState) {
        completedSteps = state.index
        totalSteps = AgentPassOnboardingState.allCases.count - 1
    }
}

public struct AgentPassOnboardingNextAction: Equatable, Sendable {
    public let id: AgentPassOnboardingActionID
    public let targetState: AgentPassOnboardingState
    public let title: String
    /// A display-only, canonical command. It is never executable by this adapter.
    public let command: String
}

public struct AgentPassOnboardingBlockedError: Equatable, Sendable {
    public let code: String
    public let message: String
    public let remediation: String?
}

/// A display-only representation of CLI onboarding status.
///
/// This type intentionally contains no journal URL, journal identifier, history,
/// key material, or operation that can advance setup or mutate security state.
public struct AgentPassOnboardingViewModel: Equatable, Sendable {
    public enum Interaction: String, Codable, Equatable, Sendable {
        case readOnly = "read_only"
    }

    public let interaction: Interaction
    public let initialized: Bool
    public let state: AgentPassOnboardingState
    public let progress: AgentPassOnboardingProgress
    public let nextAction: AgentPassOnboardingNextAction?
    public let blockedError: AgentPassOnboardingBlockedError?

    public var isBlocked: Bool { blockedError != nil }
    public var isComplete: Bool { state == .complete }

    fileprivate init(
        initialized: Bool,
        state: AgentPassOnboardingState,
        nextAction: AgentPassOnboardingNextAction?,
        blockedError: AgentPassOnboardingBlockedError?
    ) {
        self.interaction = .readOnly
        self.initialized = initialized
        self.state = state
        self.progress = AgentPassOnboardingProgress(state: state)
        self.nextAction = nextAction
        self.blockedError = blockedError
    }
}

public enum AgentPassOnboardingStatusError: Error, Equatable, Sendable {
    case malformedJSON
    case duplicateField
    case unknownField
    case missingField
    case invalidField
    case unsupportedVersion
}

extension AgentPassOnboardingStatusError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformedJSON: return "The onboarding status document is not valid JSON."
        case .duplicateField: return "The onboarding status document contains a duplicate field."
        case .unknownField: return "The onboarding status document contains an unknown field."
        case .missingField: return "The onboarding status document is missing a required field."
        case .invalidField: return "The onboarding status document contains an invalid field."
        case .unsupportedVersion: return "The onboarding status document uses an unsupported version."
        }
    }
}

/// Parses the read-only JSON emitted by `agentpass setup status`.
public struct AgentPassOnboardingStatusAdapter: Sendable {
    public init() {}

    public func viewModel(from data: Data) throws -> AgentPassOnboardingViewModel {
        guard !data.isEmpty, data.count <= 256 * 1024 else { throw AgentPassOnboardingStatusError.malformedJSON }
        var scanner = JSONDuplicateScanner(data: data)
        try scanner.scanDocument()

        let object: [String: Any]
        do {
            guard let decoded = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as? [String: Any] else {
                throw AgentPassOnboardingStatusError.malformedJSON
            }
            object = decoded
        } catch let error as AgentPassOnboardingStatusError {
            throw error
        } catch {
            throw AgentPassOnboardingStatusError.malformedJSON
        }

        return try parse(object)
    }

    public func viewModel(from json: String) throws -> AgentPassOnboardingViewModel {
        try viewModel(from: Data(json.utf8))
    }

    private func parse(_ object: [String: Any]) throws -> AgentPassOnboardingViewModel {
        let common = Set(["version", "initialized", "state", "setup_complete", "next_actions", "blocked_error"])
        let requiredCommon = Set(["version", "initialized", "state", "setup_complete", "next_actions"])
        let metadata = Set(["journal_id", "revision", "updated_at", "history_length"])
        let initialized = try bool(object, key: "initialized")
        let allowed = initialized ? common.union(metadata) : common
        try exactKeys(object, allowed: allowed, required: initialized ? requiredCommon.union(metadata) : requiredCommon)
        guard try integer(object, key: "version") == 1 else { throw AgentPassOnboardingStatusError.unsupportedVersion }

        let rawState = try string(object, key: "state")
        guard let state = AgentPassOnboardingState(rawValue: rawState) else {
            throw AgentPassOnboardingStatusError.invalidField
        }
        let setupComplete = try bool(object, key: "setup_complete")
        guard setupComplete == (state == .complete) else { throw AgentPassOnboardingStatusError.invalidField }

        if initialized {
            let revision = try integer(object, key: "revision")
            guard revision == state.index else { throw AgentPassOnboardingStatusError.invalidField }
            guard (0..<AgentPassOnboardingState.allCases.count).contains(revision) else { throw AgentPassOnboardingStatusError.invalidField }
            _ = try uuid(object, key: "journal_id")
            _ = try isoTimestamp(object, key: "updated_at")
            guard try integer(object, key: "history_length") == revision + 1 else { throw AgentPassOnboardingStatusError.invalidField }
        } else {
            guard state == .notStarted else { throw AgentPassOnboardingStatusError.invalidField }
        }

        let nextAction = try parseNextAction(object["next_actions"], state: state, initialized: initialized)
        let blockedError = try parseBlockedError(object["blocked_error"])
        return AgentPassOnboardingViewModel(
            initialized: initialized,
            state: state,
            nextAction: nextAction,
            blockedError: blockedError
        )
    }

    private func parseNextAction(_ value: Any?, state: AgentPassOnboardingState, initialized: Bool) throws -> AgentPassOnboardingNextAction? {
        guard let value else { throw AgentPassOnboardingStatusError.missingField }
        guard let actions = value as? [Any], actions.count <= 1 else { throw AgentPassOnboardingStatusError.invalidField }
        let expected = actionSpec(for: state)
        guard let expected else {
            guard actions.isEmpty else { throw AgentPassOnboardingStatusError.invalidField }
            return nil
        }
        guard actions.count == 1, let action = actions[0] as? [String: Any] else {
            throw AgentPassOnboardingStatusError.invalidField
        }

        let allowed = Set(["id", "target_state", "command", "description"])
        let required = Set(["id", "command"])
        try exactKeys(action, allowed: allowed, required: required)
        guard try string(action, key: "id") == expected.id.rawValue else { throw AgentPassOnboardingStatusError.invalidField }
        if let target = action["target_state"] {
            guard let target = target as? String, target == expected.target.rawValue else { throw AgentPassOnboardingStatusError.invalidField }
        } else if initialized {
            throw AgentPassOnboardingStatusError.missingField
        }
        let command = try string(action, key: "command")
        guard !command.isEmpty, command.count <= 512 else { throw AgentPassOnboardingStatusError.invalidField }
        if let description = action["description"] {
            guard let description = description as? String, !description.isEmpty, description.count <= 512 else {
                throw AgentPassOnboardingStatusError.invalidField
            }
        }

        // Do not pass through CLI-controlled text. The UI receives only the
        // canonical action selected from the validated state machine.
        return AgentPassOnboardingNextAction(
            id: expected.id,
            targetState: expected.target,
            title: expected.title,
            command: expected.command
        )
    }

    private func parseBlockedError(_ value: Any?) throws -> AgentPassOnboardingBlockedError? {
        guard let value else { return nil }
        guard !(value is NSNull), let object = value as? [String: Any] else { throw AgentPassOnboardingStatusError.invalidField }
        try exactKeys(object, allowed: Set(["code", "message", "remediation"]), required: Set(["code", "message"]))
        let code = try string(object, key: "code")
        guard code.range(of: "^(?:[a-z][a-z0-9_.-]{0,63}|[A-Z][A-Z0-9_]{0,63})$", options: .regularExpression) != nil else {
            throw AgentPassOnboardingStatusError.invalidField
        }
        let message = try string(object, key: "message")
        guard !message.isEmpty, message.count <= 1024 else { throw AgentPassOnboardingStatusError.invalidField }
        var hasRemediation = false
        if let raw = object["remediation"] {
            guard let value = raw as? String, !value.isEmpty, value.count <= 1024 else { throw AgentPassOnboardingStatusError.invalidField }
            hasRemediation = true
        }
        return AgentPassOnboardingBlockedError(code: code, message: "Setup is blocked. Review local AgentPass diagnostics.", remediation: hasRemediation ? "Run agentpass doctor and follow the local remediation." : nil)
    }

    private func exactKeys(_ object: [String: Any], allowed: Set<String>, required: Set<String>) throws {
        guard object.keys.allSatisfy({ allowed.contains($0) }) else { throw AgentPassOnboardingStatusError.unknownField }
        guard required.allSatisfy({ object[$0] != nil }) else { throw AgentPassOnboardingStatusError.missingField }
    }

    private func string(_ object: [String: Any], key: String) throws -> String {
        guard let value = object[key] as? String else { throw AgentPassOnboardingStatusError.invalidField }
        return value
    }

    private func bool(_ object: [String: Any], key: String) throws -> Bool {
        guard let value = object[key] as? NSNumber, String(cString: value.objCType) == "c" else {
            throw AgentPassOnboardingStatusError.invalidField
        }
        return value.boolValue
    }

    private func integer(_ object: [String: Any], key: String) throws -> Int {
        guard let value = object[key], let number = value as? NSNumber,
              ["q", "i", "s", "l", "Q", "I", "S", "L"].contains(String(cString: number.objCType)),
              number.doubleValue.rounded() == number.doubleValue,
              number.doubleValue >= Double(Int.min), number.doubleValue <= Double(Int.max) else {
            throw AgentPassOnboardingStatusError.invalidField
        }
        return number.intValue
    }

    private func uuid(_ object: [String: Any], key: String) throws -> UUID {
        guard let value = object[key] as? String, let uuid = UUID(uuidString: value) else { throw AgentPassOnboardingStatusError.invalidField }
        return uuid
    }

    private func isoTimestamp(_ object: [String: Any], key: String) throws -> Date {
        guard let value = object[key] as? String,
              value.range(of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$", options: .regularExpression) != nil else {
            throw AgentPassOnboardingStatusError.invalidField
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: value) else { throw AgentPassOnboardingStatusError.invalidField }
        return date
    }
}

private struct ActionSpec {
    let id: AgentPassOnboardingActionID
    let target: AgentPassOnboardingState
    let title: String
    let command: String
}

private func actionSpec(for state: AgentPassOnboardingState) -> ActionSpec? {
    switch state {
    case .notStarted: return ActionSpec(id: .verifyApp, target: .appVerified, title: "Verify the AgentPass app", command: "agentpass setup --client claude-code --project DIR --team-id TEAMID --execute")
    case .appVerified: return ActionSpec(id: .initializeLocalConfig, target: .localConfigInitialized, title: "Initialize local configuration", command: "agentpass setup continue")
    case .localConfigInitialized: return ActionSpec(id: .selectNativeBridge, target: .nativeBridgeSelected, title: "Select the native bridge", command: "agentpass setup continue")
    case .nativeBridgeSelected: return ActionSpec(id: .registerService, target: .serviceRegistered, title: "Register the native service", command: "agentpass setup continue")
    case .serviceRegistered: return ActionSpec(id: .startBootstrap, target: .bootstrapStarted, title: "Start the native bootstrap", command: "agentpass setup continue")
    case .bootstrapStarted: return ActionSpec(id: .enrollApprovalKey, target: .approvalKeyEnrolled, title: "Enroll the approval key", command: "agentpass setup continue")
    case .approvalKeyEnrolled: return ActionSpec(id: .activateServiceKeys, target: .serviceKeysActivated, title: "Activate service keys", command: "agentpass setup continue")
    case .serviceKeysActivated: return ActionSpec(id: .enrollDevice, target: .deviceEnrolled, title: "Enroll this device", command: "agentpass setup continue")
    case .deviceEnrolled: return ActionSpec(id: .connectEditor, target: .editorConnected, title: "Connect the editor", command: "agentpass setup continue")
    case .editorConnected: return ActionSpec(id: .verifyTestCommit, target: .testCommitVerified, title: "Verify a test commit", command: "agentpass setup continue")
    case .testCommitVerified: return ActionSpec(id: .completeSetup, target: .complete, title: "Complete setup", command: "agentpass setup continue")
    case .complete: return nil
    }
}

private struct JSONDuplicateScanner {
    private let bytes: [UInt8]
    private var index: Int = 0

    init(data: Data) { bytes = Array(data) }

    mutating func scanDocument() throws {
        skipWhitespace()
        guard peek() == 123 else { throw AgentPassOnboardingStatusError.malformedJSON }
        try scanValue(depth: 0)
        skipWhitespace()
        guard index == bytes.count else { throw AgentPassOnboardingStatusError.malformedJSON }
    }

    private mutating func scanValue(depth: Int) throws {
        guard depth <= 32 else { throw AgentPassOnboardingStatusError.malformedJSON }
        skipWhitespace()
        guard let byte = peek() else { throw AgentPassOnboardingStatusError.malformedJSON }
        switch byte {
        case 34: _ = try scanString()
        case 91: try scanArray(depth: depth)
        case 123: try scanObject(depth: depth)
        case 116: try scanLiteral(Array("true".utf8))
        case 102: try scanLiteral(Array("false".utf8))
        case 110: try scanLiteral(Array("null".utf8))
        case 45, 48...57: try scanNumber()
        default: throw AgentPassOnboardingStatusError.malformedJSON
        }
    }

    private mutating func scanObject(depth: Int) throws {
        try consume(123)
        skipWhitespace()
        var keys = Set<String>()
        if consumeIf(125) { return }
        while true {
            skipWhitespace()
            guard peek() == 34 else { throw AgentPassOnboardingStatusError.malformedJSON }
            let key = try scanString()
            guard keys.insert(key).inserted else { throw AgentPassOnboardingStatusError.duplicateField }
            skipWhitespace()
            try consume(58)
            try scanValue(depth: depth + 1)
            skipWhitespace()
            if consumeIf(125) { return }
            try consume(44)
        }
    }

    private mutating func scanArray(depth: Int) throws {
        try consume(91)
        skipWhitespace()
        if consumeIf(93) { return }
        while true {
            try scanValue(depth: depth + 1)
            skipWhitespace()
            if consumeIf(93) { return }
            try consume(44)
        }
    }

    private mutating func scanString() throws -> String {
        let start = index
        try consume(34)
        while let byte = peek() {
            index += 1
            if byte == 34 {
                let data = Data(bytes[start..<index])
                guard let value = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as? String else {
                    throw AgentPassOnboardingStatusError.malformedJSON
                }
                return value
            }
            if byte == 92 {
                guard let escaped = peek() else { throw AgentPassOnboardingStatusError.malformedJSON }
                index += 1
                if escaped == 117 {
                    for _ in 0..<4 {
                        guard let hex = peek(), (48...57).contains(hex) || (65...70).contains(hex) || (97...102).contains(hex) else {
                            throw AgentPassOnboardingStatusError.malformedJSON
                        }
                        index += 1
                    }
                } else if ![34, 92, 47, 98, 102, 110, 114, 116].contains(escaped) {
                    throw AgentPassOnboardingStatusError.malformedJSON
                }
            } else if byte < 0x20 {
                throw AgentPassOnboardingStatusError.malformedJSON
            }
        }
        throw AgentPassOnboardingStatusError.malformedJSON
    }

    private mutating func scanLiteral(_ literal: [UInt8]) throws {
        guard index + literal.count <= bytes.count, Array(bytes[index..<(index + literal.count)]) == literal else {
            throw AgentPassOnboardingStatusError.malformedJSON
        }
        index += literal.count
    }

    private mutating func scanNumber() throws {
        let start = index
        while let byte = peek(), ![9, 10, 13, 32, 44, 93, 125].contains(byte) { index += 1 }
        guard start < index else { throw AgentPassOnboardingStatusError.malformedJSON }
        let data = Data(bytes[start..<index])
        guard (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) != nil else {
            throw AgentPassOnboardingStatusError.malformedJSON
        }
    }

    private func peek() -> UInt8? { index < bytes.count ? bytes[index] : nil }

    private mutating func skipWhitespace() {
        while let byte = peek(), [9, 10, 13, 32].contains(byte) { index += 1 }
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard consumeIf(expected) else { throw AgentPassOnboardingStatusError.malformedJSON }
    }

    private mutating func consumeIf(_ expected: UInt8) -> Bool {
        guard peek() == expected else { return false }
        index += 1
        return true
    }
}
