import Foundation

/// A public, display-only status. Raw CLI summaries, paths, keys, and error
/// messages never cross the onboarding view-model boundary.
public enum AgentPassVerificationState: String, Equatable, Sendable {
    case verified
    case actionRequired = "action_required"
    case blocked
    case unavailable
    case notApplicable = "not_applicable"

    public var displayName: String {
        switch self {
        case .verified: return "Verified"
        case .actionRequired: return "Action required"
        case .blocked: return "Blocked"
        case .unavailable: return "Not verified"
        case .notApplicable: return "Not applicable"
        }
    }
}

public struct AgentPassDistributionStatus: Equatable, Sendable {
    public let developerID: AgentPassVerificationState
    public let notarization: AgentPassVerificationState
    public let releaseReceipt: AgentPassVerificationState

    public static let unavailable = AgentPassDistributionStatus(
        developerID: .unavailable,
        notarization: .unavailable,
        releaseReceipt: .unavailable
    )

    public init(
        developerID: AgentPassVerificationState,
        notarization: AgentPassVerificationState,
        releaseReceipt: AgentPassVerificationState
    ) {
        self.developerID = developerID
        self.notarization = notarization
        self.releaseReceipt = releaseReceipt
    }
}

public struct AgentPassCapabilityStatus: Equatable, Sendable {
    public let secureEnclave: AgentPassVerificationState
    public let tpm: AgentPassVerificationState

    public static let unavailable = AgentPassCapabilityStatus(
        secureEnclave: .unavailable,
        tpm: .notApplicable
    )

    public init(
        secureEnclave: AgentPassVerificationState,
        tpm: AgentPassVerificationState = .notApplicable
    ) {
        self.secureEnclave = secureEnclave
        self.tpm = tpm
    }
}

public struct AgentPassOnboardingDiagnostics: Equatable, Sendable {
    public let distribution: AgentPassDistributionStatus
    public let capability: AgentPassCapabilityStatus

    public static let unavailable = AgentPassOnboardingDiagnostics(
        distribution: .unavailable,
        capability: .unavailable
    )

    public init(
        distribution: AgentPassDistributionStatus,
        capability: AgentPassCapabilityStatus
    ) {
        self.distribution = distribution
        self.capability = capability
    }
}

public enum AgentPassRecoveryActionID: String, Hashable, Sendable {
    case install
    case check
    case setup
    case repair
    case revoke
}

public enum AgentPassRecoveryInputRequirement: String, Sendable {
    case verifiedReleaseFiles

    public var displayName: String {
        switch self {
        case .verifiedReleaseFiles:
            return "Verified release files and public release identifiers"
        }
    }
}

public struct AgentPassRecoveryAction: Equatable, Identifiable, Sendable {
    public let id: AgentPassRecoveryActionID
    public let title: String
    public let explanation: String
    /// A canonical dry-run command. It is copied for the user and never run by
    /// the app. It intentionally contains no invitation, token, key, credential,
    /// placeholder, or local path.
    public let command: String
    /// The command that may be copied only after an explicit user confirmation.
    /// The app still never executes it.
    public let approvedCommand: String?
    public let inputRequirement: AgentPassRecoveryInputRequirement?

    public var requiresUserApproval: Bool { approvedCommand != nil }

    /// The command shown by the onboarding UI is always the non-mutating
    /// preview. An approved command is a separate, explicit copy operation.
    public var isDryRunCommand: Bool {
        !command.contains("--execute")
    }

    public init(
        id: AgentPassRecoveryActionID,
        title: String,
        explanation: String,
        command: String,
        approvedCommand: String? = nil,
        inputRequirement: AgentPassRecoveryInputRequirement? = nil
    ) {
        self.id = id
        self.title = title
        self.explanation = explanation
        self.command = command
        self.approvedCommand = approvedCommand
        self.inputRequirement = inputRequirement
    }
}

public extension AgentPassOnboardingViewModel {
    var safeRecoveryActions: [AgentPassRecoveryAction] {
        var actions: [AgentPassRecoveryAction] = []
        if distribution.developerID != .verified || distribution.notarization != .verified {
            actions.append(AgentPassRecoveryAction(
                id: .install,
                title: "Install the verified production package",
                explanation: "Choose the three verified release files and enter the public release identifiers. The first command only verifies; installation requires explicit approval.",
                command: "agentpass install",
                approvedCommand: "agentpass install --execute",
                inputRequirement: .verifiedReleaseFiles
            ))
        }
        actions.append(AgentPassRecoveryAction(
            id: .check,
            title: "Check this Mac",
            explanation: "Read-only diagnosis of the app, service, release receipt, and native integration.",
            command: "agentpass doctor"
        ))
        if isBlocked || !isComplete {
            actions.append(AgentPassRecoveryAction(
                id: .repair,
                title: "Repair or resume safely",
                explanation: "Preview the next bounded setup step first. Applying it requires explicit approval and advances only one durable state at a time.",
                command: "agentpass setup continue",
                approvedCommand: "agentpass setup continue --execute"
            ))
        }
        if capability.secureEnclave == .verified {
            actions.append(AgentPassRecoveryAction(
                id: .revoke,
                title: "Revoke active native sessions",
                explanation: "Inspect native health first. Revocation immediately invalidates active native sessions and requires explicit approval.",
                command: "agentpass native status",
                approvedCommand: "agentpass native revoke-sessions"
            ))
        }
        return actions
    }
}

/// Parses only the stable, non-secret portion of `agentpass doctor`.
public struct AgentPassDoctorStatusAdapter: Sendable {
    public init() {}

    public func distributionStatus(from data: Data) throws -> AgentPassDistributionStatus {
        let root = try boundedObject(data, maximumBytes: 256 * 1024)
        try exactKeys(root, allowed: ["schema_version", "state", "ok", "generated_at", "mode", "checks", "summary", "host"], required: ["schema_version", "state", "ok", "generated_at", "mode", "checks", "summary", "host"])
        guard integer(root, "schema_version") == 1,
              let checks = root["checks"] as? [Any], !checks.isEmpty else {
            throw AgentPassOnboardingStatusError.invalidField
        }

        var states: [String: AgentPassVerificationState] = [:]
        for raw in checks {
            guard let check = raw as? [String: Any],
                  check.keys.allSatisfy({ ["id", "state", "severity", "summary", "remediation", "detail"].contains($0) }),
                  let id = check["id"] as? String,
                  let state = check["state"] as? String,
                  let normalized = AgentPassVerificationState(doctorState: state) else {
                throw AgentPassOnboardingStatusError.invalidField
            }
            guard id.range(of: "^[a-z][a-z0-9_.-]{0,63}$", options: .regularExpression) != nil else {
                throw AgentPassOnboardingStatusError.invalidField
            }
            guard states[id] == nil else { throw AgentPassOnboardingStatusError.duplicateField }
            states[id] = normalized
        }

        let app = distributionState(states, ids: ["app.code_identity", "app.code_signature", "app.gatekeeper", "app.layout"])
        let receipt = distributionState(states, ids: ["release.installed_receipt", "release.receipt_team_id", "package.receipt"])
        return AgentPassDistributionStatus(
            developerID: app,
            // `doctor` performs a Gatekeeper assessment of the signed app. It
            // is the runtime verification surface; release notarization proof
            // remains the stapled, manifest-bound release evidence.
            notarization: app,
            releaseReceipt: receipt
        )
    }

    private func exactKeys(_ object: [String: Any], allowed: Set<String>, required: Set<String>) throws {
        guard object.keys.allSatisfy({ allowed.contains($0) }) else { throw AgentPassOnboardingStatusError.unknownField }
        guard required.allSatisfy({ object[$0] != nil }) else { throw AgentPassOnboardingStatusError.missingField }
    }

    private func distributionState(_ states: [String: AgentPassVerificationState], ids: [String]) -> AgentPassVerificationState {
        let values = ids.compactMap { states[$0] }
        if values.contains(.blocked) { return .blocked }
        if values.contains(.actionRequired) { return .actionRequired }
        if values.contains(.unavailable) || values.isEmpty { return .unavailable }
        return values.allSatisfy { $0 == .verified } ? .verified : .unavailable
    }

    private func boundedObject(_ data: Data, maximumBytes: Int) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= maximumBytes else { throw AgentPassOnboardingStatusError.malformedJSON }
        var scanner = JSONDuplicateScanner(data: data)
        try scanner.scanDocument()
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AgentPassOnboardingStatusError.malformedJSON
        }
        return value
    }

    private func integer(_ object: [String: Any], _ key: String) -> Int? {
        guard let number = object[key] as? NSNumber,
              ["q", "i", "s", "l", "Q", "I", "S", "L"].contains(String(cString: number.objCType)),
              number.doubleValue.rounded() == number.doubleValue else { return nil }
        return number.intValue
    }
}

private extension AgentPassVerificationState {
    init?(doctorState: String) {
        switch doctorState {
        case "healthy": self = .verified
        case "action_required", "degraded": self = .actionRequired
        case "blocked": self = .blocked
        default: return nil
        }
    }
}

/// Parses the public health envelope from `agentpass native status` without
/// displaying public keys, hashes, control state, or error text.
public struct AgentPassNativeStatusAdapter: Sendable {
    public init() {}

    public func capabilityStatus(from data: Data) throws -> AgentPassCapabilityStatus {
        guard !data.isEmpty, data.count <= 256 * 1024 else { throw AgentPassOnboardingStatusError.malformedJSON }
        var scanner = JSONDuplicateScanner(data: data)
        try scanner.scanDocument()
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let health = root["health"] as? [String: Any],
              health["ok"] as? Bool == true,
              integer(health, "version") == 13,
              root["audit"] is [String: Any] else {
            throw AgentPassOnboardingStatusError.invalidField
        }
        return AgentPassCapabilityStatus(secureEnclave: .verified, tpm: .notApplicable)
    }

    private func integer(_ object: [String: Any], _ key: String) -> Int? {
        guard let number = object[key] as? NSNumber,
              ["q", "i", "s", "l", "Q", "I", "S", "L"].contains(String(cString: number.objCType)),
              number.doubleValue.rounded() == number.doubleValue else { return nil }
        return number.intValue
    }
}
