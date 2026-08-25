import CryptoKit
import Foundation

/// Stable, machine-readable denial reasons for process identity policy and
/// revalidation failures. These values are part of the audit contract.
public enum NativeProcessIdentityReasonCode: String, CaseIterable, Codable, Sendable {
    case uidMismatch = "uid_mismatch"
    case pidMismatch = "pid_mismatch"
    case pidReused = "pid_reused"
    case bootIdentityChanged = "boot_identity_changed"
    case executableFileIdentityChanged = "executable_file_identity_changed"
    case codeDirectoryHashChanged = "code_directory_hash_changed"
    case bundleIdentifierMismatch = "bundle_id_mismatch"
    case teamIdentifierMismatch = "team_id_mismatch"
    case signatureKindMismatch = "signature_kind_mismatch"
    case adHocSignature = "ad_hoc_signature"
    case entitlementMismatch = "entitlement_mismatch"
    case parentDied = "parent_died"
    case ancestorChainSubstitution = "ancestor_chain_substitution"
    case ancestorPIDReused = "ancestor_pid_reused"
    case unknownAncestor = "unknown_ancestor"
}

public typealias NativeProcessIdentityDenialReason = NativeProcessIdentityReasonCode

public enum NativeProcessIdentityError: Error, Equatable, Sendable {
    case invalidObservation(String)
}

private let nativeProcessMaximumAncestors = 16
private let nativeProcessMaximumEntitlements = 32
private let nativeProcessMaximumEntitlementDepth = 8
private let nativeProcessMaximumCollectionValues = 64
private let nativeProcessMaximumStringBytes = 4096

public enum NativeCodeSignatureKind: String, Codable, CaseIterable, Hashable, Sendable {
    case developerID = "developer_id"
    case apple = "apple"
    case adhoc = "ad_hoc"
    case unsigned = "unsigned"
    case other = "other"
}

/// A recursively typed entitlement value. It deliberately excludes arbitrary
/// objects so canonicalization cannot depend on Foundation's dictionary order.
public indirect enum NativeEntitlementValue: Sendable {
    case string(String)
    case boolean(Bool)
    case integer(Int64)
    case unsignedInteger(UInt64)
    case array([NativeEntitlementValue])
    case object([String: NativeEntitlementValue])
}

public struct NativeExecutableFileIdentity: Equatable, Hashable, Sendable {
    public let deviceID: UInt64
    public let inode: UInt64
    public let fileSize: UInt64
    public let modificationTimeNanoseconds: Int64

    public init(
        deviceID: UInt64,
        inode: UInt64,
        fileSize: UInt64,
        modificationTimeNanoseconds: Int64
    ) throws {
        guard deviceID > 0 else {
            throw NativeProcessIdentityError.invalidObservation("executable device ID must be positive")
        }
        guard inode > 0 else {
            throw NativeProcessIdentityError.invalidObservation("executable inode must be positive")
        }
        guard fileSize > 0 else {
            throw NativeProcessIdentityError.invalidObservation("executable size must be positive")
        }
        guard modificationTimeNanoseconds >= 0 else {
            throw NativeProcessIdentityError.invalidObservation("executable modification time must not be negative")
        }
        self.deviceID = deviceID
        self.inode = inode
        self.fileSize = fileSize
        self.modificationTimeNanoseconds = modificationTimeNanoseconds
    }
}

/// The immutable facts an OS-backed observation adapter must provide.
///
/// This type has no public initializer on purpose. A production adapter in
/// AgentPassNativeCore must create it from OS observations, while tests can
/// inject a fixture through `@testable` access. Request fields, process IDs
/// supplied by an XPC caller, argv, environment, and raw audit tokens are not
/// accepted by this model as observations.
public struct NativeObservedProcessFacts: Sendable {
    public let uid: UInt32
    public let pid: Int32
    public let pidVersion: UInt64
    public let bootIdentity: String
    public let executableFileIdentity: NativeExecutableFileIdentity
    public let codeDirectoryHash: String
    public let bundleIdentifier: String?
    public let teamIdentifier: String?
    public let signatureKind: NativeCodeSignatureKind
    public let entitlements: [String: NativeEntitlementValue]

    internal init(
        uid: UInt32,
        pid: Int32,
        pidVersion: UInt64,
        bootIdentity: String,
        executableFileIdentity: NativeExecutableFileIdentity,
        codeDirectoryHash: String,
        bundleIdentifier: String?,
        teamIdentifier: String?,
        signatureKind: NativeCodeSignatureKind,
        entitlements: [String: NativeEntitlementValue]
    ) throws {
        guard pid > 0, pidVersion > 0 else {
            throw NativeProcessIdentityError.invalidObservation("process PID must be positive")
        }
        guard !bootIdentity.isEmpty, bootIdentity.utf8.count <= 128 else {
            throw NativeProcessIdentityError.invalidObservation("boot identity must not be empty")
        }
        try NativeProcessIdentityValidation.validateSHA256(codeDirectoryHash, field: "code directory hash")
        try NativeProcessIdentityValidation.validateOptionalIdentifier(bundleIdentifier, field: "bundle identifier")
        try NativeProcessIdentityValidation.validateOptionalIdentifier(teamIdentifier, field: "team identifier")
        try NativeProcessIdentityValidation.validateEntitlements(entitlements)

        self.uid = uid
        self.pid = pid
        self.pidVersion = pidVersion
        self.bootIdentity = bootIdentity
        self.executableFileIdentity = executableFileIdentity
        self.codeDirectoryHash = codeDirectoryHash.lowercased()
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.signatureKind = signatureKind
        self.entitlements = entitlements
    }
}

public enum NativeProcessAncestryEntry: Sendable {
    /// The array is ordered from the immediate parent outwards.
    case observed(NativeObservedProcessFacts)
    /// The OS adapter could not safely observe this ancestor. Unknown is never
    /// treated as a wildcard by policy matching or revalidation.
    case unknown(pid: Int32?, pidVersion: UInt64?)
}

/// The injectable boundary for a future native OS observer.
///
/// Implementations must obtain the returned facts from the OS and must not
/// translate caller-supplied claims into observations. This slice intentionally
/// does not claim to extract or validate a live XPC audit token.
public protocol NativeProcessObservationSource: Sendable {
    func observe() throws -> NativeProcessObservation
}

public struct NativeProcessObservation: Sendable {
    public let process: NativeObservedProcessFacts
    public let ancestry: [NativeProcessAncestryEntry]

    internal init(
        process: NativeObservedProcessFacts,
        ancestry: [NativeProcessAncestryEntry]
    ) throws {
        guard ancestry.count <= nativeProcessMaximumAncestors else {
            throw NativeProcessIdentityError.invalidObservation("process ancestry exceeds its fixed bound")
        }
        for ancestor in ancestry {
            switch ancestor {
            case let .observed(facts):
                guard facts.bootIdentity == process.bootIdentity, facts.uid == process.uid else {
                    throw NativeProcessIdentityError.invalidObservation("process ancestry crosses boot or user identity")
                }
            case let .unknown(pid, pidVersion):
                guard (pid == nil || pid! > 0), (pidVersion == nil || pidVersion! > 0) else {
                    throw NativeProcessIdentityError.invalidObservation("unknown ancestor hint is invalid")
                }
            }
        }
        self.process = process
        self.ancestry = ancestry
    }
}

public struct NativeProcessIdentity: Sendable {
    public let process: NativeObservedProcessFacts
    public let ancestry: [NativeProcessAncestryEntry]

    internal init(observation: NativeProcessObservation) {
        self.process = observation.process
        self.ancestry = observation.ancestry
    }

    public static func capture(from source: any NativeProcessObservationSource) throws -> Self {
        Self(observation: try source.observe())
    }

    public var uid: UInt32 { process.uid }
    public var pid: Int32 { process.pid }
    public var pidVersion: UInt64 { process.pidVersion }
    public var bootIdentity: String { process.bootIdentity }
    public var executableFileIdentity: NativeExecutableFileIdentity { process.executableFileIdentity }
    public var codeDirectoryHash: String { process.codeDirectoryHash }
    public var bundleIdentifier: String? { process.bundleIdentifier }
    public var teamIdentifier: String? { process.teamIdentifier }
    public var signatureKind: NativeCodeSignatureKind { process.signatureKind }
    public var entitlements: [String: NativeEntitlementValue] { process.entitlements }

    public var canonicalRepresentation: String {
        NativeProcessIdentityCanonical.object([
            ("version", NativeProcessIdentityCanonical.string("native_process_identity/v1")),
            ("process", process.canonicalRepresentation),
            ("ancestry", NativeProcessIdentityCanonical.array(ancestry.map(\.canonicalRepresentation)))
        ])
    }

    public var canonicalBindingData: Data {
        Data(canonicalRepresentation.utf8)
    }

    public var canonicalBindingHash: String {
        NativeProcessIdentityCanonical.hex(SHA256.hash(data: canonicalBindingData))
    }

    public var canonicalAncestryBindingHash: String {
        let representation = NativeProcessIdentityCanonical.array(ancestry.map(\.canonicalRepresentation))
        return NativeProcessIdentityCanonical.hex(SHA256.hash(data: Data(representation.utf8)))
    }

    /// Stable principal identity used for an explicitly authorized control
    /// operation. Unlike `canonicalBindingHash`, this intentionally excludes
    /// PID, PID generation, executable inode/mtime, and ancestry: a separate
    /// process of the same signed product may perform a control close, while
    /// an executable substitution may not. This is an identity label, never
    /// a bearer credential and never serialized into an XPC request.
    public var canonicalControlPrincipalHash: String {
        let representation = NativeProcessIdentityCanonical.object([
            ("version", NativeProcessIdentityCanonical.string("native_control_principal/v1")),
            ("uid", String(process.uid)),
            ("boot_identity", NativeProcessIdentityCanonical.string(process.bootIdentity)),
            ("code_directory_hash", NativeProcessIdentityCanonical.string(process.codeDirectoryHash)),
            ("bundle_identifier", NativeProcessIdentityCanonical.optionalString(process.bundleIdentifier)),
            ("team_identifier", NativeProcessIdentityCanonical.optionalString(process.teamIdentifier)),
            ("signature_kind", NativeProcessIdentityCanonical.string(process.signatureKind.rawValue)),
            ("entitlements", NativeProcessIdentityCanonical.entitlements(process.entitlements))
        ])
        return NativeProcessIdentityCanonical.hex(SHA256.hash(data: Data(representation.utf8)))
    }

    public func matches(policy: NativeProcessIdentityPolicy) -> Bool {
        evaluate(policy: policy).isAllowed
    }

    public func evaluate(policy: NativeProcessIdentityPolicy) -> NativeProcessIdentityPolicyEvaluation {
        var reasons: [NativeProcessIdentityReasonCode] = []
        func append(_ reason: NativeProcessIdentityReasonCode) {
            if !reasons.contains(reason) { reasons.append(reason) }
        }

        if let expectedUID = policy.expectedUID, uid != expectedUID { append(.uidMismatch) }
        if let expectedPID = policy.expectedPID, pid != expectedPID { append(.pidMismatch) }
        if let expectedPIDVersion = policy.expectedPIDVersion,
           pidVersion != expectedPIDVersion,
           policy.expectedPID == nil || pid == policy.expectedPID {
            append(.pidReused)
        }
        if let expectedBootIdentity = policy.expectedBootIdentity, bootIdentity != expectedBootIdentity {
            append(.bootIdentityChanged)
        }
        if let expectedExecutable = policy.expectedExecutableFileIdentity,
           executableFileIdentity != expectedExecutable {
            append(.executableFileIdentityChanged)
        }
        if let expectedCodeDirectoryHash = policy.expectedCodeDirectoryHash,
           codeDirectoryHash != expectedCodeDirectoryHash.lowercased() {
            append(.codeDirectoryHashChanged)
        }
        if let expectedBundleIdentifier = policy.expectedBundleIdentifier,
           bundleIdentifier != expectedBundleIdentifier {
            append(.bundleIdentifierMismatch)
        }
        if let expectedTeamIdentifier = policy.expectedTeamIdentifier,
           teamIdentifier != expectedTeamIdentifier {
            append(.teamIdentifierMismatch)
        }
        if let expectedSignatureKind = policy.expectedSignatureKind,
           signatureKind != expectedSignatureKind {
            append(.signatureKindMismatch)
        }
        if policy.rejectAdHocSignature && signatureKind == .adhoc {
            append(.adHocSignature)
        }
        if let allowedSignatureKinds = policy.allowedSignatureKinds,
           !allowedSignatureKinds.contains(signatureKind) {
            append(.signatureKindMismatch)
        }
        for (key, expectedValue) in policy.requiredEntitlements {
            guard let actualValue = entitlements[key],
                  NativeProcessIdentityCanonical.value(actualValue) == NativeProcessIdentityCanonical.value(expectedValue) else {
                append(.entitlementMismatch)
                break
            }
        }
        if policy.rejectUnknownAncestors && ancestry.contains(where: \.isUnknown) {
            append(.unknownAncestor)
        }
        if let expectedAncestry = policy.expectedAncestry {
            for reason in Self.compareAncestry(expectedAncestry, ancestry) { append(reason) }
        }

        return NativeProcessIdentityPolicyEvaluation(denialReasons: reasons)
    }

    /// Revalidates a previously captured identity against a fresh OS snapshot.
    /// The result is deny-by-default if any immutable fact or ordered ancestor
    /// differs. It is intentionally independent of caller-supplied PID claims.
    public func revalidate(against current: NativeProcessIdentity) -> NativeProcessIdentityRevalidationResult {
        var reasons: [NativeProcessIdentityReasonCode] = []
        func append(_ reason: NativeProcessIdentityReasonCode) {
            if !reasons.contains(reason) { reasons.append(reason) }
        }

        if uid != current.uid { append(.uidMismatch) }
        if pid != current.pid { append(.pidMismatch) }
        if pid == current.pid, pidVersion != current.pidVersion { append(.pidReused) }
        if bootIdentity != current.bootIdentity { append(.bootIdentityChanged) }
        if executableFileIdentity != current.executableFileIdentity { append(.executableFileIdentityChanged) }
        if codeDirectoryHash != current.codeDirectoryHash { append(.codeDirectoryHashChanged) }
        if bundleIdentifier != current.bundleIdentifier { append(.bundleIdentifierMismatch) }
        if teamIdentifier != current.teamIdentifier { append(.teamIdentifierMismatch) }
        if signatureKind != current.signatureKind { append(.signatureKindMismatch) }
        if NativeProcessIdentityCanonical.entitlements(entitlements) != NativeProcessIdentityCanonical.entitlements(current.entitlements) {
            append(.entitlementMismatch)
        }
        for reason in Self.compareAncestry(ancestry, current.ancestry) { append(reason) }

        return NativeProcessIdentityRevalidationResult(denialReasons: reasons)
    }

    public func revalidationDenialReasons(against current: NativeProcessIdentity) -> [NativeProcessIdentityReasonCode] {
        revalidate(against: current).denialReasons
    }

    private static func compareAncestry(
        _ expected: [NativeProcessAncestryEntry],
        _ current: [NativeProcessAncestryEntry]
    ) -> [NativeProcessIdentityReasonCode] {
        var reasons: [NativeProcessIdentityReasonCode] = []
        func append(_ reason: NativeProcessIdentityReasonCode) {
            if !reasons.contains(reason) { reasons.append(reason) }
        }

        if current.count < expected.count { append(.parentDied) }
        if current.count > expected.count { append(.ancestorChainSubstitution) }
        if expected.isEmpty && !current.isEmpty { append(.ancestorChainSubstitution) }

        for index in 0..<min(expected.count, current.count) {
            switch (expected[index], current[index]) {
            case (.unknown, _), (_, .unknown):
                append(.unknownAncestor)
            case let (.observed(expectedFacts), .observed(currentFacts)):
                if expectedFacts.pid == currentFacts.pid && expectedFacts.pidVersion != currentFacts.pidVersion {
                    append(.ancestorPIDReused)
                } else if !Self.sameFacts(expectedFacts, currentFacts) {
                    append(.ancestorChainSubstitution)
                }
            }
        }
        return reasons
    }

    private static func sameFacts(_ lhs: NativeObservedProcessFacts, _ rhs: NativeObservedProcessFacts) -> Bool {
        NativeProcessIdentityCanonical.facts(lhs) == NativeProcessIdentityCanonical.facts(rhs)
    }
}

public struct NativeProcessIdentityPolicy: Sendable {
    public let expectedUID: UInt32?
    public let expectedPID: Int32?
    public let expectedPIDVersion: UInt64?
    public let expectedBootIdentity: String?
    public let expectedExecutableFileIdentity: NativeExecutableFileIdentity?
    public let expectedCodeDirectoryHash: String?
    public let expectedBundleIdentifier: String?
    public let expectedTeamIdentifier: String?
    public let expectedSignatureKind: NativeCodeSignatureKind?
    public let allowedSignatureKinds: Set<NativeCodeSignatureKind>?
    public let requiredEntitlements: [String: NativeEntitlementValue]
    public let expectedAncestry: [NativeProcessAncestryEntry]?
    public let rejectAdHocSignature: Bool
    public let rejectUnknownAncestors: Bool

    public init(
        expectedUID: UInt32? = nil,
        expectedPID: Int32? = nil,
        expectedPIDVersion: UInt64? = nil,
        expectedBootIdentity: String? = nil,
        expectedExecutableFileIdentity: NativeExecutableFileIdentity? = nil,
        expectedCodeDirectoryHash: String? = nil,
        expectedBundleIdentifier: String? = nil,
        expectedTeamIdentifier: String? = nil,
        expectedSignatureKind: NativeCodeSignatureKind? = nil,
        allowedSignatureKinds: Set<NativeCodeSignatureKind>? = nil,
        requiredEntitlements: [String: NativeEntitlementValue] = [:],
        expectedAncestry: [NativeProcessAncestryEntry]? = nil,
        rejectAdHocSignature: Bool = false,
        rejectUnknownAncestors: Bool = true
    ) throws {
        if let expectedCodeDirectoryHash {
            try NativeProcessIdentityValidation.validateSHA256(expectedCodeDirectoryHash, field: "expected code directory hash")
        }
        try NativeProcessIdentityValidation.validateEntitlements(requiredEntitlements)
        self.expectedUID = expectedUID
        self.expectedPID = expectedPID
        self.expectedPIDVersion = expectedPIDVersion
        self.expectedBootIdentity = expectedBootIdentity
        self.expectedExecutableFileIdentity = expectedExecutableFileIdentity
        self.expectedCodeDirectoryHash = expectedCodeDirectoryHash?.lowercased()
        self.expectedBundleIdentifier = expectedBundleIdentifier
        self.expectedTeamIdentifier = expectedTeamIdentifier
        self.expectedSignatureKind = expectedSignatureKind
        self.allowedSignatureKinds = allowedSignatureKinds
        self.requiredEntitlements = requiredEntitlements
        self.expectedAncestry = expectedAncestry
        self.rejectAdHocSignature = rejectAdHocSignature
        self.rejectUnknownAncestors = rejectUnknownAncestors
    }

    public static func exact(_ identity: NativeProcessIdentity, includePID: Bool = false) throws -> Self {
        try Self(
            expectedUID: identity.uid,
            expectedPID: includePID ? identity.pid : nil,
            expectedPIDVersion: includePID ? identity.pidVersion : nil,
            expectedBootIdentity: identity.bootIdentity,
            expectedExecutableFileIdentity: identity.executableFileIdentity,
            expectedCodeDirectoryHash: identity.codeDirectoryHash,
            expectedBundleIdentifier: identity.bundleIdentifier,
            expectedTeamIdentifier: identity.teamIdentifier,
            expectedSignatureKind: identity.signatureKind,
            requiredEntitlements: identity.entitlements,
            expectedAncestry: identity.ancestry,
            rejectAdHocSignature: false,
            rejectUnknownAncestors: true
        )
    }
}

public struct NativeProcessIdentityPolicyEvaluation: Sendable {
    public let denialReasons: [NativeProcessIdentityReasonCode]
    public var isAllowed: Bool { denialReasons.isEmpty }
}

public struct NativeProcessIdentityRevalidationResult: Sendable {
    public let denialReasons: [NativeProcessIdentityReasonCode]
    public var isValid: Bool { denialReasons.isEmpty }
}

private enum NativeProcessIdentityValidation {
    static func validateSHA256(_ value: String, field: String) throws {
        guard value.count == 64,
              value.unicodeScalars.allSatisfy({ scalar in
                  (scalar.value >= 48 && scalar.value <= 57) ||
                  (scalar.value >= 65 && scalar.value <= 70) ||
                  (scalar.value >= 97 && scalar.value <= 102)
              }) else {
            throw NativeProcessIdentityError.invalidObservation("\(field) must be a 64-character hexadecimal SHA-256 value")
        }
    }

    static func validateOptionalIdentifier(_ value: String?, field: String) throws {
        if let value, value.isEmpty || value.utf8.count > 256 || value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }) {
            throw NativeProcessIdentityError.invalidObservation("\(field) is invalid")
        }
    }

    static func validateEntitlements(_ values: [String: NativeEntitlementValue]) throws {
        guard values.count <= nativeProcessMaximumEntitlements else {
            throw NativeProcessIdentityError.invalidObservation("entitlement count exceeds its fixed bound")
        }
        for (key, value) in values {
            guard !key.isEmpty, key.utf8.count <= 256, !key.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }) else {
                throw NativeProcessIdentityError.invalidObservation("entitlement key is invalid")
            }
            try validateEntitlementValue(value, depth: 0)
        }
    }

    private static func validateEntitlementValue(_ value: NativeEntitlementValue, depth: Int) throws {
        guard depth <= nativeProcessMaximumEntitlementDepth else {
            throw NativeProcessIdentityError.invalidObservation("entitlement nesting exceeds its fixed bound")
        }
        switch value {
        case let .string(value):
            guard value.utf8.count <= nativeProcessMaximumStringBytes else {
                throw NativeProcessIdentityError.invalidObservation("entitlement string exceeds its fixed bound")
            }
        case .boolean, .integer, .unsignedInteger:
            break
        case let .array(values):
            guard values.count <= nativeProcessMaximumCollectionValues else {
                throw NativeProcessIdentityError.invalidObservation("entitlement array exceeds its fixed bound")
            }
            for value in values { try validateEntitlementValue(value, depth: depth + 1) }
        case let .object(values):
            guard values.count <= nativeProcessMaximumCollectionValues else {
                throw NativeProcessIdentityError.invalidObservation("entitlement object exceeds its fixed bound")
            }
            for (key, value) in values {
                guard !key.isEmpty, key.utf8.count <= 256 else {
                    throw NativeProcessIdentityError.invalidObservation("nested entitlement key is invalid")
                }
                try validateEntitlementValue(value, depth: depth + 1)
            }
        }
    }
}

private enum NativeProcessIdentityCanonical {
    static func string(_ value: String) -> String {
        let data = try! JSONSerialization.data(withJSONObject: [value], options: [.withoutEscapingSlashes])
        let encoded = String(decoding: data, as: UTF8.self)
        return String(encoded.dropFirst().dropLast())
    }

    static func object(_ values: [(String, String)]) -> String {
        let members = values
            .sorted { $0.0.utf8.lexicographicallyPrecedes($1.0.utf8) }
            .map { "\(string($0.0)):\($0.1)" }
            .joined(separator: ",")
        return "{\(members)}"
    }

    static func array(_ values: [String]) -> String {
        "[\(values.joined(separator: ","))]"
    }

    static func optionalString(_ value: String?) -> String {
        value.map(string) ?? "null"
    }

    static func boolean(_ value: Bool) -> String { value ? "true" : "false" }

    static func value(_ value: NativeEntitlementValue) -> String {
        switch value {
        case let .string(value): return string(value)
        case let .boolean(value): return boolean(value)
        case let .integer(value): return String(value)
        case let .unsignedInteger(value): return String(value)
        case let .array(values): return array(values.map { item in self.value(item) })
        case let .object(values): return object(values.map { ($0.key, self.value($0.value)) })
        }
    }

    static func entitlements(_ values: [String: NativeEntitlementValue]) -> String {
        object(values.map { ($0.key, value($0.value)) })
    }

    static func executable(_ value: NativeExecutableFileIdentity) -> String {
        object([
            ("device_id", String(value.deviceID)),
            ("file_size", String(value.fileSize)),
            ("inode", String(value.inode)),
            ("modification_time_ns", String(value.modificationTimeNanoseconds))
        ])
    }

    static func facts(_ value: NativeObservedProcessFacts) -> String {
        object([
            ("bundle_identifier", optionalString(value.bundleIdentifier)),
            ("code_directory_hash", string(value.codeDirectoryHash)),
            ("entitlements", entitlements(value.entitlements)),
            ("executable_file_identity", executable(value.executableFileIdentity)),
            ("pid", String(value.pid)),
            ("pid_version", String(value.pidVersion)),
            ("signature_kind", string(value.signatureKind.rawValue)),
            ("team_identifier", optionalString(value.teamIdentifier)),
            ("uid", String(value.uid)),
            ("boot_identity", string(value.bootIdentity))
        ])
    }

    static func process(_ value: NativeObservedProcessFacts) -> String { facts(value) }

    static func ancestor(_ value: NativeProcessAncestryEntry) -> String {
        switch value {
        case let .observed(facts):
            return object([("kind", string("observed")), ("facts", self.facts(facts))])
        case let .unknown(pid, pidVersion):
            return object([
                ("kind", string("unknown")),
                ("pid", pid.map(String.init) ?? "null"),
                ("pid_version", pidVersion.map(String.init) ?? "null")
            ])
        }
    }

    static func hex<H: Sequence>(_ digest: H) -> String where H.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}

private extension NativeProcessAncestryEntry {
    var isUnknown: Bool {
        if case .unknown = self { return true }
        return false
    }

    var canonicalRepresentation: String {
        NativeProcessIdentityCanonical.ancestor(self)
    }
}

private extension NativeObservedProcessFacts {
    var canonicalRepresentation: String {
        NativeProcessIdentityCanonical.facts(self)
    }
}
