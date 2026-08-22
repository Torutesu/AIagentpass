import AgentPassNativeCore
import Foundation
import Testing

@Test func nativeXPCContractHasFrozenFingerprintAndClosedInventory() {
    #expect(AgentPassNativeXPCContract.contractVersion == 3)
    #expect(AgentPassNativeXPCContract.fingerprint == "SHA256:f74fea0f9d0a4c2394a7e5c248353f80613f39b289de400eb007369e8a6224ae")
    #expect(AgentPassNativeXPCContract.fingerprint == AgentPassNativeXPCContract.derivedFingerprint)
    #expect(AgentPassNativeXPCContract.managementProtocol.methods.count == 41)
    #expect(AgentPassNativeXPCContract.agentProtocol.methods.count == 5)
    #expect(AgentPassNativeXPCContract.hostProtocol.methods.count == 5)
    #expect(AgentPassNativeXPCContract.protocolInventories.count == 5)
    #expect(AgentPassNativeXPCContract.childGitProtocol.methods.count == 2)
    #expect(AgentPassNativeXPCContract.dtoInventories.count == 26)
}

@Test func nativeXPCContractRejectsAnUninventoriedChildGitDTO() {
    let incompleteDTOs = AgentPassNativeXPCContract.dtoInventories.filter {
        $0.name != "AgentPassChildGitAttachRequest"
    }

    do {
        try AgentPassNativeXPCContract.validateClosedInventory(
            protocols: AgentPassNativeXPCContract.protocolInventories,
            dtos: incompleteDTOs
        )
        Issue.record("missing Child Git DTO was accepted")
    } catch let error as AgentPassNativeXPCContract.ValidationError {
        guard case .missingDTO(let name, let selector) = error else {
            Issue.record("unexpected validation error: \(error)")
            return
        }
        #expect(name == "AgentPassChildGitAttachRequest")
        #expect(selector == "attachChildGit:withReply:")
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}

@Test func nativeXPCContractRuntimeSurfaceMatchesInventory() throws {
    try AgentPassNativeXPCContract.verifyRuntimeSurface()
}

@Test func nativeXPCContractRejectsSelectorPurposeMixing() {
    let managementMethod = AgentPassNativeXPCContract.MethodInventory(
        selector: "bootstrapAgent:withReply:",
        purpose: .management,
        requestTypes: ["NSData"],
        replyTypes: ["NSData", "NSError"],
        objcTypeEncoding: "v32@0:8@16@?24"
    )
    let management = AgentPassNativeXPCContract.ProtocolInventory(
        name: "SyntheticManagementProtocol",
        version: 1,
        purpose: .management,
        methods: [managementMethod]
    )

    do {
        try AgentPassNativeXPCContract.validateClosedInventory(
            protocols: [management, AgentPassNativeXPCContract.agentProtocol],
            dtos: AgentPassNativeXPCContract.dtoInventories
        )
        Issue.record("selector purpose mixing was accepted")
    } catch let error as AgentPassNativeXPCContract.ValidationError {
        guard case .selectorPurposeMixing(let selector, let purposes) = error else {
            Issue.record("unexpected validation error: \(error)")
            return
        }
        #expect(selector == "bootstrapAgent:withReply:")
        #expect(Set(purposes) == [.management, .agent])
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}

@Test func nativeXPCContractRejectsDTOPurposeMixing() {
    let managementDTO = AgentPassNativeXPCContract.DTOInventory(
        name: "AgentPassAgentBootstrapRequest",
        objcName: "AgentPassAgentBootstrapRequest",
        purpose: .management,
        role: .request,
        selector: "bootstrapAgent:withReply:",
        secureCoding: true
    )

    do {
        try AgentPassNativeXPCContract.validateClosedInventory(
            protocols: AgentPassNativeXPCContract.protocolInventories,
            dtos: AgentPassNativeXPCContract.dtoInventories + [managementDTO]
        )
        Issue.record("DTO purpose mixing was accepted")
    } catch let error as AgentPassNativeXPCContract.ValidationError {
        guard case .dtoPurposeMixing(let name, let purposes) = error else {
            Issue.record("unexpected validation error: \(error)")
            return
        }
        #expect(name == "AgentPassAgentBootstrapRequest")
        #expect(Set(purposes) == [.management, .agent])
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}

@Test func nativeXPCContractRejectsAnUninventoriedAgentDTO() {
    let incompleteDTOs = AgentPassNativeXPCContract.dtoInventories.filter {
        $0.name != "AgentPassAgentSignRequest"
    }

    do {
        try AgentPassNativeXPCContract.validateClosedInventory(
            protocols: AgentPassNativeXPCContract.protocolInventories,
            dtos: incompleteDTOs
        )
        Issue.record("missing Agent DTO was accepted")
    } catch let error as AgentPassNativeXPCContract.ValidationError {
        guard case .missingDTO(let name, let selector) = error else {
            Issue.record("unexpected validation error: \(error)")
            return
        }
        #expect(name == "AgentPassAgentSignRequest")
        #expect(selector == "signGitCommit:withReply:")
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}
