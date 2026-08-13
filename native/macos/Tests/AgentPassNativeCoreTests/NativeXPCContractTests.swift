import AgentPassNativeCore
import Foundation
import Testing

@Test func nativeXPCContractHasFrozenFingerprintAndClosedInventory() {
    #expect(AgentPassNativeXPCContract.fingerprint == "SHA256:e674b7eb5fa9b80313a57571f9a14ab28e2295c356bbb57592c8f61b3bb6165e")
    #expect(AgentPassNativeXPCContract.fingerprint == AgentPassNativeXPCContract.derivedFingerprint)
    #expect(AgentPassNativeXPCContract.managementProtocol.methods.count == 41)
    #expect(AgentPassNativeXPCContract.agentProtocol.methods.count == 5)
    #expect(AgentPassNativeXPCContract.dtoInventories.count == 10)
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
