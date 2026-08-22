import CryptoKit
import Foundation
import ObjectiveC.runtime

/// The frozen, machine-readable contract shared by the native management,
/// Agent, and supervised Host XPC surfaces.
///
/// The protocol declarations remain the source of ObjC interoperability. This
/// inventory is intentionally separate from those declarations so a protocol
/// change cannot silently become a compatible-looking wire change: callers
/// can compare `fingerprint`, and the native process can call
/// `verifyRuntimeSurface()` before accepting connections.
public enum AgentPassNativeXPCContract {
    public static let contractIdentifier = "dev.agentpass.native-xpc"
    public static let contractVersion = 3
    public static let fingerprintAlgorithm = "SHA-256"

    public enum Purpose: String, Codable, Equatable, Hashable, Sendable {
        case management
        case agent
        case host
        case hostControl = "host_control"
        case childGit
    }

    public enum DTORole: String, Codable, Equatable, Hashable, Sendable {
        case request
        case response
    }

    public struct MethodInventory: Codable, Equatable, Sendable {
        public let selector: String
        public let purpose: Purpose
        public let requestTypes: [String]
        public let replyTypes: [String]
        public let objcTypeEncoding: String

        public init(
            selector: String,
            purpose: Purpose,
            requestTypes: [String],
            replyTypes: [String],
            objcTypeEncoding: String
        ) {
            self.selector = selector
            self.purpose = purpose
            self.requestTypes = requestTypes
            self.replyTypes = replyTypes
            self.objcTypeEncoding = objcTypeEncoding
        }
    }

    public struct ProtocolInventory: Codable, Equatable, Sendable {
        public let name: String
        public let version: Int
        public let purpose: Purpose
        public let methods: [MethodInventory]

        public init(name: String, version: Int, purpose: Purpose, methods: [MethodInventory]) {
            self.name = name
            self.version = version
            self.purpose = purpose
            self.methods = methods
        }
    }

    public struct DTOInventory: Codable, Equatable, Sendable {
        public let name: String
        public let objcName: String
        public let purpose: Purpose
        public let role: DTORole
        public let selector: String
        public let secureCoding: Bool

        public init(
            name: String,
            objcName: String,
            purpose: Purpose,
            role: DTORole,
            selector: String,
            secureCoding: Bool
        ) {
            self.name = name
            self.objcName = objcName
            self.purpose = purpose
            self.role = role
            self.selector = selector
            self.secureCoding = secureCoding
        }
    }

    public enum ValidationError: Error, Equatable, Sendable {
        case fingerprintMismatch(expected: String, actual: String)
        case duplicateProtocol(name: String)
        case duplicateSelector(protocolName: String, selector: String)
        case selectorDrift(protocolName: String, expected: [String], actual: [String])
        case methodSignatureDrift(selector: String, expected: String, actual: String)
        case selectorPurposeMixing(selector: String, purposes: [Purpose])
        case methodPurposeMixing(selector: String, expected: Purpose, actual: Purpose)
        case duplicateDTO(name: String)
        case dtoPurposeMixing(name: String, purposes: [Purpose])
        case dtoDrift(name: String, expected: String, actual: String)
        case dtoPurposeMismatch(name: String, selector: String, expected: Purpose, actual: Purpose)
        case dtoRoleMismatch(name: String, selector: String, expected: DTORole, actual: DTORole)
        case unreferencedDTO(name: String)
        case missingDTO(name: String, selector: String)
        case missingRuntimeDTO(name: String)
        case interfaceDTORegistrationDrift(selector: String, expected: [String], actual: [String])
    }

    // This is deliberately a literal. Any intentional contract change must
    // update the version and this value together, making the change visible to
    // binaries and CI rather than deriving a new identity silently.
    public static let frozenFingerprint = "SHA256:f74fea0f9d0a4c2394a7e5c248353f80613f39b289de400eb007369e8a6224ae"

    public static let managementProtocol = ProtocolInventory(
        name: "AgentPassNativeServiceProtocol",
        version: 1,
        purpose: .management,
        methods: [
            method("healthWithReply:", .management, [], ["NSDictionary"], "v24@0:8@?16"),
            method("publicKeyWithReply:", .management, [], ["NSString", "NSError"], "v24@0:8@?16"),
            method("signWithRequest:withReply:", .management, ["NSData"], ["NSString", "NSError"], "v32@0:8@16@?24"),
            method("auditStatusWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("auditPublicKeyWithReply:", .management, [], ["NSString", "NSError"], "v24@0:8@?16"),
            method("createAuditCheckpointWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("rotateAuditWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("rotateAuditEvidenceWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("keyLifecycleStatusWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("stageKeyWithRole:withReply:", .management, ["NSString"], ["NSData", "NSError"], "v32@0:8@16@?24"),
            method("approvalKeyStagePlanWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("stageApprovalKeyWithGeneration:applicationTag:publicKey:withReply:", .management, ["Int", "NSString", "NSData"], ["NSData", "NSError"], "v48@0:8q16@24@32@?40"),
            method("beginKeyActivationWithRole:generation:reason:withReply:", .management, ["NSString", "Int", "NSString"], ["NSData", "NSError"], "v48@0:8@16q24@32@?40"),
            method("completeKeyActivationWithChallengeID:approvalSignature:withReply:", .management, ["NSString", "NSData"], ["NSData", "NSError"], "v40@0:8@16@24@?32"),
            method("completeApprovalKeyActivationWithChallengeID:oldSignature:newSignature:withReply:", .management, ["NSString", "NSData", "NSData"], ["NSData", "NSError"], "v48@0:8@16@24@32@?40"),
            method("beginKeyAbortWithRole:generation:reason:withReply:", .management, ["NSString", "Int", "NSString"], ["NSData", "NSError"], "v48@0:8@16q24@32@?40"),
            method("completeKeyAbortWithChallengeID:approvalSignature:withReply:", .management, ["NSString", "NSData"], ["NSData", "NSError"], "v40@0:8@16@24@?32"),
            method("beginKeyDeletionWithRole:generation:reason:minimumRetentionSeconds:proof:withReply:", .management, ["NSString", "Int", "NSString", "Int", "NSData"], ["NSData", "NSError"], "v64@0:8@16q24@32q40@48@?56"),
            method("completeKeyDeletionWithChallengeID:approvalSignature:withReply:", .management, ["NSString", "NSData"], ["NSData", "NSError"], "v40@0:8@16@24@?32"),
            method("beginRecoveryWithRole:withReply:", .management, ["NSString"], ["NSData", "NSError"], "v32@0:8@16@?24"),
            method("prepareRecoveryInstallationWithEvidence:withReply:", .management, ["NSData"], ["NSData", "NSError"], "v32@0:8@16@?24"),
            method("completeRecoveryWithChallengeID:localSignature:withReply:", .management, ["NSString", "NSData"], ["NSData", "NSError"], "v40@0:8@16@24@?32"),
            method("prepareAuditRecoveryInstallationWithEvidence:withReply:", .management, ["NSData"], ["NSData", "NSError"], "v32@0:8@16@?24"),
            method("completeAuditRecoveryWithChallengeID:localSignature:withReply:", .management, ["NSString", "NSData"], ["NSData", "NSError"], "v40@0:8@16@24@?32"),
            method("abortExpiredAuditRecoveryWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("auditRecoveryStatusWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("auditAnchorStatusWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("pushAuditAnchorWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("prepareAuditPruneWithRequest:withReply:", .management, ["NSData"], ["NSData", "NSError"], "v32@0:8@16@?24"),
            method("submitAuditPruneWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("executeAuditPruneWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("auditPruneStatusWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("beginSessionWithAgentID:ttlSeconds:withReply:", .management, ["NSString", "Int"], ["NSData", "NSError"], "v40@0:8@16q24@?32"),
            method("completeSessionWithChallenge:signature:withReply:", .management, ["NSData", "NSData"], ["NSData", "NSError"], "v40@0:8@16@24@?32"),
            method("revokeSessionsWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("revokeSessionsWithAgentID:withReply:", .management, ["NSString"], ["NSData", "NSError"], "v32@0:8@16@?24"),
            method("validateSessionWithToken:agentID:withReply:", .management, ["NSString", "NSString"], ["Bool", "NSError"], "v40@0:8@16@24@?32"),
            method("applyControlBundleWithBundle:withReply:", .management, ["NSData"], ["NSData", "NSError"], "v32@0:8@16@?24"),
            method("controlStatusWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("refreshControlWithReply:", .management, [], ["NSData", "NSError"], "v24@0:8@?16"),
            method("validateControlWithAgentID:withReply:", .management, ["NSString"], ["Bool", "NSError"], "v32@0:8@16@?24"),
        ])

    public static let agentProtocol = ProtocolInventory(
        name: "AgentPassAgentXPCProtocol",
        version: 1,
        purpose: .agent,
        methods: [
            method("bootstrapAgent:withReply:", .agent, ["AgentPassAgentBootstrapRequest"], ["AgentPassAgentBootstrapResponse", "NSError"], "v32@0:8@16@?24"),
            method("startAgentSession:withReply:", .agent, ["AgentPassAgentSessionRequest"], ["AgentPassAgentSessionResponse", "NSError"], "v32@0:8@16@?24"),
            method("agentSessionStatus:withReply:", .agent, ["AgentPassAgentSessionStatusRequest"], ["AgentPassAgentSessionStatusResponse", "NSError"], "v32@0:8@16@?24"),
            method("signGitCommit:withReply:", .agent, ["AgentPassAgentSignRequest"], ["AgentPassAgentSignResponse", "NSError"], "v32@0:8@16@?24"),
            method("closeAgentSession:withReply:", .agent, ["AgentPassAgentCloseSessionRequest"], ["AgentPassAgentCloseSessionResponse", "NSError"], "v32@0:8@16@?24"),
        ])

    public static let hostProtocol = ProtocolInventory(
        name: "AgentPassHostXPCProtocol",
        version: 1,
        purpose: .host,
        methods: [
            method("prepareHostSession:withReply:", .host, ["AgentPassHostPrepareRequest"], ["AgentPassHostPrepareResponse", "NSError"], "v32@0:8@16@?24"),
            method("attachHostChild:withReply:", .host, ["AgentPassHostAttachChildRequest"], ["AgentPassHostAttachChildResponse", "NSError"], "v32@0:8@16@?24"),
            method("signHostPayload:withReply:", .host, ["AgentPassHostSignRequest"], ["AgentPassHostSignResponse", "NSError"], "v32@0:8@16@?24"),
            method("hostSessionStatus:withReply:", .host, ["AgentPassHostStatusRequest"], ["AgentPassHostStatusResponse", "NSError"], "v32@0:8@16@?24"),
            method("closeHostSession:withReply:", .host, ["AgentPassHostCloseRequest"], ["AgentPassHostCloseResponse", "NSError"], "v32@0:8@16@?24"),
        ])

    public static let hostControlProtocol = ProtocolInventory(
        name: "AgentPassHostControlXPCProtocol",
        version: AgentPassHostControlXPCContract.protocolVersion,
        purpose: .hostControl,
        methods: [
            method("closeHostSessionFromControl:withReply:", .hostControl, ["AgentPassHostControlCloseRequest"], ["AgentPassHostControlCloseResponse", "NSError"], "v32@0:8@16@?24"),
        ])

    public static let childGitProtocol = ProtocolInventory(
        name: "AgentPassChildGitXPCProtocol",
        version: AgentPassChildGitXPCContract.protocolVersion,
        purpose: .childGit,
        methods: [
            method(
                "attachChildGit:withReply:",
                .childGit,
                ["AgentPassChildGitAttachRequest"],
                ["AgentPassChildGitAttachResponse", "NSError"],
                "v32@0:8@16@?24"
            ),
            method(
                "signChildGitCommit:withReply:",
                .childGit,
                ["AgentPassChildGitSignRequest"],
                ["AgentPassChildGitSignResponse", "NSError"],
                "v32@0:8@16@?24"
            ),
        ])

    public static let protocolInventories = [managementProtocol, agentProtocol, hostProtocol, hostControlProtocol, childGitProtocol]

    public static let dtoInventories: [DTOInventory] = [
        dto("AgentPassAgentBootstrapRequest", .request, "bootstrapAgent:withReply:"),
        dto("AgentPassAgentBootstrapResponse", .response, "bootstrapAgent:withReply:"),
        dto("AgentPassAgentSessionRequest", .request, "startAgentSession:withReply:"),
        dto("AgentPassAgentSessionResponse", .response, "startAgentSession:withReply:"),
        dto("AgentPassAgentSessionStatusRequest", .request, "agentSessionStatus:withReply:"),
        dto("AgentPassAgentSessionStatusResponse", .response, "agentSessionStatus:withReply:"),
        dto("AgentPassAgentSignRequest", .request, "signGitCommit:withReply:"),
        dto("AgentPassAgentSignResponse", .response, "signGitCommit:withReply:"),
        dto("AgentPassAgentCloseSessionRequest", .request, "closeAgentSession:withReply:"),
        dto("AgentPassAgentCloseSessionResponse", .response, "closeAgentSession:withReply:"),
        hostDTO("AgentPassHostPrepareRequest", .request, "prepareHostSession:withReply:"),
        hostDTO("AgentPassHostPrepareResponse", .response, "prepareHostSession:withReply:"),
        hostDTO("AgentPassHostAttachChildRequest", .request, "attachHostChild:withReply:"),
        hostDTO("AgentPassHostAttachChildResponse", .response, "attachHostChild:withReply:"),
        hostDTO("AgentPassHostSignRequest", .request, "signHostPayload:withReply:"),
        hostDTO("AgentPassHostSignResponse", .response, "signHostPayload:withReply:"),
        hostDTO("AgentPassHostStatusRequest", .request, "hostSessionStatus:withReply:"),
        hostDTO("AgentPassHostStatusResponse", .response, "hostSessionStatus:withReply:"),
        hostDTO("AgentPassHostCloseRequest", .request, "closeHostSession:withReply:"),
        hostDTO("AgentPassHostCloseResponse", .response, "closeHostSession:withReply:"),
        hostControlDTO("AgentPassHostControlCloseRequest", .request, "closeHostSessionFromControl:withReply:"),
        hostControlDTO("AgentPassHostControlCloseResponse", .response, "closeHostSessionFromControl:withReply:"),
        childGitDTO("AgentPassChildGitAttachRequest", .request, "attachChildGit:withReply:"),
        childGitDTO("AgentPassChildGitAttachResponse", .response, "attachChildGit:withReply:"),
        childGitDTO("AgentPassChildGitSignRequest", .request, "signChildGitCommit:withReply:"),
        childGitDTO("AgentPassChildGitSignResponse", .response, "signChildGitCommit:withReply:"),
    ]

    /// The canonical, line-oriented representation used as the fingerprint
    /// input. It is public so release tooling can print and archive it.
    public static let canonicalInventory: String = {
        var lines = [
            "contract=\(contractIdentifier)",
            "version=\(contractVersion)",
        ]
        for protocolInventory in protocolInventories {
            lines.append("protocol=\(protocolInventory.name)|version=\(protocolInventory.version)|purpose=\(protocolInventory.purpose.rawValue)")
            for method in protocolInventory.methods {
                lines.append(
                    "method=\(method.selector)|purpose=\(method.purpose.rawValue)|request=\(method.requestTypes.joined(separator: ","))|reply=\(method.replyTypes.joined(separator: ","))|objc=\(method.objcTypeEncoding)"
                )
            }
        }
        for dto in dtoInventories {
            lines.append(
                "dto=\(dto.name)|objc=\(dto.objcName)|purpose=\(dto.purpose.rawValue)|role=\(dto.role.rawValue)|selector=\(dto.selector)|secure_coding=\(dto.secureCoding ? "yes" : "no")"
            )
        }
        return lines.joined(separator: "\n") + "\n"
    }()

    /// Stable identity of the frozen wire contract.
    public static var fingerprint: String { frozenFingerprint }

    /// The digest calculated from the checked-in inventory. Keeping this
    /// separate from `fingerprint` lets production startup detect a stale or
    /// hand-edited frozen constant.
    public static var derivedFingerprint: String {
        "SHA256:" + Data(SHA256.hash(data: Data(canonicalInventory.utf8))).map { String(format: "%02x", $0) }.joined()
    }

    /// Validates the inventory itself without touching ObjC runtime state.
    /// This is useful to release tooling and makes purpose mixing testable with
    /// synthetic inventories.
    public static func validateClosedInventory() throws {
        try validateClosedInventory(protocols: protocolInventories, dtos: dtoInventories)
    }

    public static func validateClosedInventory(
        protocols: [ProtocolInventory],
        dtos: [DTOInventory]
    ) throws {
        var protocolNames = Set<String>()
        var selectorPurposes = [String: Set<Purpose>]()
        var allMethods = [MethodInventory]()

        for protocolInventory in protocols {
            guard protocolNames.insert(protocolInventory.name).inserted else {
                throw ValidationError.duplicateProtocol(name: protocolInventory.name)
            }
            var selectors = Set<String>()
            for method in protocolInventory.methods {
                guard selectors.insert(method.selector).inserted else {
                    throw ValidationError.duplicateSelector(protocolName: protocolInventory.name, selector: method.selector)
                }
                guard method.purpose == protocolInventory.purpose else {
                    throw ValidationError.methodPurposeMixing(
                        selector: method.selector,
                        expected: protocolInventory.purpose,
                        actual: method.purpose
                    )
                }
                selectorPurposes[method.selector, default: []].insert(method.purpose)
                allMethods.append(method)
            }
        }

        for (selector, purposes) in selectorPurposes where purposes.count > 1 {
            throw ValidationError.selectorPurposeMixing(selector: selector, purposes: purposes.sorted { $0.rawValue < $1.rawValue })
        }

        var dtoNames = Set<String>()
        var dtoPurposes = [String: Set<Purpose>]()
        for dto in dtos {
            if dtoNames.contains(dto.name) {
                dtoPurposes[dto.name, default: []].insert(dto.purpose)
                let purposes = dtoPurposes[dto.name, default: []]
                if purposes.count > 1 {
                    throw ValidationError.dtoPurposeMixing(name: dto.name, purposes: purposes.sorted { $0.rawValue < $1.rawValue })
                }
                throw ValidationError.duplicateDTO(name: dto.name)
            }
            dtoNames.insert(dto.name)
            dtoPurposes[dto.name] = [dto.purpose]
            guard dto.name == dto.objcName else {
                throw ValidationError.dtoDrift(name: dto.name, expected: dto.name, actual: dto.objcName)
            }
        }

        var referencedDTOs = Set<String>()
        for method in allMethods {
            for type in method.requestTypes {
                try validateDTOReference(
                    type: type,
                    selector: method.selector,
                    purpose: method.purpose,
                    role: .request,
                    dtos: dtos,
                    referencedDTOs: &referencedDTOs
                )
            }
            for type in method.replyTypes {
                try validateDTOReference(
                    type: type,
                    selector: method.selector,
                    purpose: method.purpose,
                    role: .response,
                    dtos: dtos,
                    referencedDTOs: &referencedDTOs
                )
            }
        }

        for dto in dtos where !referencedDTOs.contains(dto.name) {
            throw ValidationError.unreferencedDTO(name: dto.name)
        }
    }

    /// Verifies the compiled ObjC selectors, type encodings, DTO class names,
    /// and Agent NSXPCInterface allowlists against the frozen inventory.
    public static func verifyRuntimeSurface() throws {
        guard derivedFingerprint == frozenFingerprint else {
            throw ValidationError.fingerprintMismatch(expected: frozenFingerprint, actual: derivedFingerprint)
        }
        try validateClosedInventory()
        try verifyProtocolRuntime(AgentPassNativeServiceProtocol.self, inventory: managementProtocol)
        try verifyProtocolRuntime(AgentPassAgentXPCProtocol.self, inventory: agentProtocol)
        try verifyProtocolRuntime(AgentPassHostXPCProtocol.self, inventory: hostProtocol)
        try verifyProtocolRuntime(AgentPassHostControlXPCProtocol.self, inventory: hostControlProtocol)
        try verifyProtocolRuntime(AgentPassChildGitXPCProtocol.self, inventory: childGitProtocol)
        try verifyRuntimeDTOs()
        try verifyAgentInterface()
        try verifyHostInterface()
        try verifyHostControlInterface()
        try verifyChildGitInterface()
    }

    private static func verifyProtocolRuntime(_ runtimeProtocol: Protocol, inventory: ProtocolInventory) throws {
        var count: UInt32 = 0
        guard let descriptions = protocol_copyMethodDescriptionList(runtimeProtocol, true, true, &count) else {
            throw ValidationError.selectorDrift(protocolName: inventory.name, expected: inventory.methods.map(\.selector).sorted(), actual: [])
        }
        defer { free(descriptions) }

        var runtimeTypes = [String: String]()
        for index in 0..<Int(count) {
            let description = descriptions[index]
            guard let selector = description.name.map(NSStringFromSelector),
                  let typesPointer = description.types else {
                continue
            }
            let types = String(cString: typesPointer)
            runtimeTypes[selector] = types
        }

        let expectedSelectors = inventory.methods.map(\.selector).sorted()
        let actualSelectors = runtimeTypes.keys.sorted()
        guard expectedSelectors == actualSelectors else {
            throw ValidationError.selectorDrift(protocolName: inventory.name, expected: expectedSelectors, actual: actualSelectors)
        }
        for method in inventory.methods {
            guard runtimeTypes[method.selector] == method.objcTypeEncoding else {
                throw ValidationError.methodSignatureDrift(
                    selector: method.selector,
                    expected: method.objcTypeEncoding,
                    actual: runtimeTypes[method.selector] ?? "<missing>"
                )
            }
        }
    }

    private static func verifyRuntimeDTOs() throws {
        for dto in dtoInventories {
            guard let actual = runtimeDTOClassName(dto.name) else {
                throw ValidationError.missingRuntimeDTO(name: dto.name)
            }
            guard actual == dto.objcName else {
                throw ValidationError.dtoDrift(name: dto.name, expected: dto.objcName, actual: actual)
            }
        }
    }

    private static func verifyAgentInterface() throws {
        let interface = AgentPassAgentXPCInterface.make()
        for method in agentProtocol.methods {
            let requestDTOs = dtoInventories.filter { $0.selector == method.selector && $0.role == .request }
            let responseDTOs = dtoInventories.filter { $0.selector == method.selector && $0.role == .response }
            let selector = NSSelectorFromString(method.selector)
            let actualRequests = classNames(interface.classes(for: selector, argumentIndex: 0, ofReply: false))
            let actualResponses = classNames(interface.classes(for: selector, argumentIndex: 0, ofReply: true))
            let expectedRequests = requestDTOs.map(\.objcName).sorted()
            let expectedResponses = responseDTOs.map(\.objcName).sorted()
            guard expectedRequests.allSatisfy({ actualRequests.contains($0) }), actualRequests.count == expectedRequests.count else {
                throw ValidationError.interfaceDTORegistrationDrift(selector: method.selector, expected: expectedRequests, actual: actualRequests.sorted())
            }
            guard expectedResponses.allSatisfy({ actualResponses.contains($0) }), actualResponses.count == expectedResponses.count else {
                throw ValidationError.interfaceDTORegistrationDrift(selector: method.selector, expected: expectedResponses, actual: actualResponses.sorted())
            }
        }
    }

    private static func verifyHostInterface() throws {
        let interface = AgentPassHostXPCInterface.make()
        for method in hostProtocol.methods {
            let requestDTOs = dtoInventories.filter { $0.selector == method.selector && $0.role == .request }
            let responseDTOs = dtoInventories.filter { $0.selector == method.selector && $0.role == .response }
            let selector = NSSelectorFromString(method.selector)
            let actualRequests = classNames(interface.classes(for: selector, argumentIndex: 0, ofReply: false))
            let actualResponses = classNames(interface.classes(for: selector, argumentIndex: 0, ofReply: true))
            let expectedRequests = requestDTOs.map(\.objcName).sorted()
            let expectedResponses = responseDTOs.map(\.objcName).sorted()
            guard expectedRequests.allSatisfy({ actualRequests.contains($0) }), actualRequests.count == expectedRequests.count else {
                throw ValidationError.interfaceDTORegistrationDrift(selector: method.selector, expected: expectedRequests, actual: actualRequests.sorted())
            }
            guard expectedResponses.allSatisfy({ actualResponses.contains($0) }), actualResponses.count == expectedResponses.count else {
                throw ValidationError.interfaceDTORegistrationDrift(selector: method.selector, expected: expectedResponses, actual: actualResponses.sorted())
            }
        }
    }

    private static func verifyHostControlInterface() throws {
        let interface = AgentPassHostControlXPCInterface.make()
        for method in hostControlProtocol.methods {
            let requestDTOs = dtoInventories.filter { $0.selector == method.selector && $0.role == .request }
            let responseDTOs = dtoInventories.filter { $0.selector == method.selector && $0.role == .response }
            let selector = NSSelectorFromString(method.selector)
            let actualRequests = classNames(interface.classes(for: selector, argumentIndex: 0, ofReply: false))
            let actualResponses = classNames(interface.classes(for: selector, argumentIndex: 0, ofReply: true))
            let expectedRequests = Set(requestDTOs.map(\.objcName))
            let expectedResponses = Set(responseDTOs.map(\.objcName))
            guard actualRequests == expectedRequests, actualResponses == expectedResponses else {
                throw ValidationError.interfaceDTORegistrationDrift(
                    selector: method.selector,
                    expected: (expectedRequests.union(expectedResponses)).sorted(),
                    actual: (actualRequests.union(actualResponses)).sorted()
                )
            }
        }
    }

    private static func verifyChildGitInterface() throws {
        for method in childGitProtocol.methods {
            let requestDTOs = dtoInventories.filter { $0.selector == method.selector && $0.role == .request }
            let responseDTOs = dtoInventories.filter { $0.selector == method.selector && $0.role == .response }
            let selector = NSSelectorFromString(method.selector)
            let actualRequests = classNames(AgentPassChildGitXPCInterface.make().classes(for: selector, argumentIndex: 0, ofReply: false))
            let actualResponses = classNames(AgentPassChildGitXPCInterface.make().classes(for: selector, argumentIndex: 0, ofReply: true))
            let expectedRequests = requestDTOs.map(\.objcName).sorted()
            let expectedResponses = responseDTOs.map(\.objcName).sorted()
            guard expectedRequests.allSatisfy({ actualRequests.contains($0) }), actualRequests.count == expectedRequests.count else {
                throw ValidationError.interfaceDTORegistrationDrift(selector: method.selector, expected: expectedRequests, actual: actualRequests.sorted())
            }
            guard expectedResponses.allSatisfy({ actualResponses.contains($0) }), actualResponses.count == expectedResponses.count else {
                throw ValidationError.interfaceDTORegistrationDrift(selector: method.selector, expected: expectedResponses, actual: actualResponses.sorted())
            }
        }
    }

    private static func validateDTOReference(
        type: String,
        selector: String,
        purpose: Purpose,
        role: DTORole,
        dtos: [DTOInventory],
        referencedDTOs: inout Set<String>
    ) throws {
        guard let dto = dtos.first(where: { $0.name == type }) else {
            if type.hasPrefix("AgentPassAgent") || type.hasPrefix("AgentPassHost") || type.hasPrefix("AgentPassChildGit") {
                throw ValidationError.missingDTO(name: type, selector: selector)
            }
            return
        }
        guard dto.purpose == purpose else {
            throw ValidationError.dtoPurposeMismatch(name: dto.name, selector: selector, expected: purpose, actual: dto.purpose)
        }
        guard dto.role == role else {
            throw ValidationError.dtoRoleMismatch(name: dto.name, selector: selector, expected: role, actual: dto.role)
        }
        referencedDTOs.insert(dto.name)
    }

    private static func runtimeDTOClassName(_ name: String) -> String? {
        switch name {
        case "AgentPassAgentBootstrapRequest": return NSStringFromClass(AgentPassAgentBootstrapRequest.self)
        case "AgentPassAgentBootstrapResponse": return NSStringFromClass(AgentPassAgentBootstrapResponse.self)
        case "AgentPassAgentSessionRequest": return NSStringFromClass(AgentPassAgentSessionRequest.self)
        case "AgentPassAgentSessionResponse": return NSStringFromClass(AgentPassAgentSessionResponse.self)
        case "AgentPassAgentSessionStatusRequest": return NSStringFromClass(AgentPassAgentSessionStatusRequest.self)
        case "AgentPassAgentSessionStatusResponse": return NSStringFromClass(AgentPassAgentSessionStatusResponse.self)
        case "AgentPassAgentSignRequest": return NSStringFromClass(AgentPassAgentSignRequest.self)
        case "AgentPassAgentSignResponse": return NSStringFromClass(AgentPassAgentSignResponse.self)
        case "AgentPassAgentCloseSessionRequest": return NSStringFromClass(AgentPassAgentCloseSessionRequest.self)
        case "AgentPassAgentCloseSessionResponse": return NSStringFromClass(AgentPassAgentCloseSessionResponse.self)
        case "AgentPassHostPrepareRequest": return NSStringFromClass(AgentPassHostPrepareRequest.self)
        case "AgentPassHostPrepareResponse": return NSStringFromClass(AgentPassHostPrepareResponse.self)
        case "AgentPassHostAttachChildRequest": return NSStringFromClass(AgentPassHostAttachChildRequest.self)
        case "AgentPassHostAttachChildResponse": return NSStringFromClass(AgentPassHostAttachChildResponse.self)
        case "AgentPassHostSignRequest": return NSStringFromClass(AgentPassHostSignRequest.self)
        case "AgentPassHostSignResponse": return NSStringFromClass(AgentPassHostSignResponse.self)
        case "AgentPassHostStatusRequest": return NSStringFromClass(AgentPassHostStatusRequest.self)
        case "AgentPassHostStatusResponse": return NSStringFromClass(AgentPassHostStatusResponse.self)
        case "AgentPassHostCloseRequest": return NSStringFromClass(AgentPassHostCloseRequest.self)
        case "AgentPassHostCloseResponse": return NSStringFromClass(AgentPassHostCloseResponse.self)
        case "AgentPassHostControlCloseRequest": return NSStringFromClass(AgentPassHostControlCloseRequest.self)
        case "AgentPassHostControlCloseResponse": return NSStringFromClass(AgentPassHostControlCloseResponse.self)
        case "AgentPassChildGitAttachRequest": return NSStringFromClass(AgentPassChildGitAttachRequest.self)
        case "AgentPassChildGitAttachResponse": return NSStringFromClass(AgentPassChildGitAttachResponse.self)
        case "AgentPassChildGitSignRequest": return NSStringFromClass(AgentPassChildGitSignRequest.self)
        case "AgentPassChildGitSignResponse": return NSStringFromClass(AgentPassChildGitSignResponse.self)
        default: return nil
        }
    }

    private static func classNames(_ classes: Set<AnyHashable>) -> Set<String> {
        Set(classes.map { value in
            let description = String(describing: value.base)
            return description.split(separator: ".").last.map(String.init) ?? description
        })
    }

    private static func method(
        _ selector: String,
        _ purpose: Purpose,
        _ requestTypes: [String],
        _ replyTypes: [String],
        _ objcTypeEncoding: String
    ) -> MethodInventory {
        MethodInventory(
            selector: selector,
            purpose: purpose,
            requestTypes: requestTypes,
            replyTypes: replyTypes,
            objcTypeEncoding: objcTypeEncoding
        )
    }

    private static func dto(_ name: String, _ role: DTORole, _ selector: String) -> DTOInventory {
        DTOInventory(
            name: name,
            objcName: name,
            purpose: .agent,
            role: role,
            selector: selector,
            secureCoding: true
        )
    }

    private static func hostDTO(_ name: String, _ role: DTORole, _ selector: String) -> DTOInventory {
        DTOInventory(
            name: name,
            objcName: name,
            purpose: .host,
            role: role,
            selector: selector,
            secureCoding: true
        )
    }

    private static func hostControlDTO(_ name: String, _ role: DTORole, _ selector: String) -> DTOInventory {
        DTOInventory(
            name: name,
            objcName: name,
            purpose: .hostControl,
            role: role,
            selector: selector,
            secureCoding: true
        )
    }

    private static func childGitDTO(_ name: String, _ role: DTORole, _ selector: String) -> DTOInventory {
        DTOInventory(
            name: name,
            objcName: name,
            purpose: .childGit,
            role: role,
            selector: selector,
            secureCoding: true
        )
    }
}
