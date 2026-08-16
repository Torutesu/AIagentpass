import AgentPassNativeCore
import Foundation
import ObjectiveC.runtime
import Testing

private let hostSessionID = "22222222-2222-4222-8222-222222222222"
private let hostDigest = Data(repeating: 0x11, count: AgentPassHostXPCContract.digestBytes)
private let hostDigest2 = Data(repeating: 0x22, count: AgentPassHostXPCContract.digestBytes)
private let hostDigest3 = Data(repeating: 0x33, count: AgentPassHostXPCContract.digestBytes)
private let hostNonce = Data(repeating: 0x44, count: AgentPassHostXPCContract.minimumNonceBytes)

private func archive(_ object: NSSecureCoding) throws -> Data {
    try NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: true)
}

private func unarchive<T: NSObject & NSSecureCoding>(_ type: T.Type, from data: Data) throws -> T {
    let object = try NSKeyedUnarchiver.unarchivedObject(ofClass: type, from: data)
    return try #require(object)
}

private func protocolSelectors(_ proto: Protocol) -> Set<String> {
    var count: UInt32 = 0
    guard let descriptions = protocol_copyMethodDescriptionList(proto, true, true, &count) else { return [] }
    defer { free(descriptions) }
    return Set((0..<Int(count)).compactMap { index in
        descriptions[index].name.map(NSStringFromSelector)
    })
}

private func classNames(_ classes: Set<AnyHashable>) -> Set<String> {
    Set(classes.map { value in
        let description = String(describing: value.base)
        return description.split(separator: ".").last.map(String.init) ?? description
    })
}

/// A same-shaped but authority-bearing object must not cross the Host
/// interface as a substitute for a closed Host DTO.
@objc(AgentPassHostAuthorityBearingObject)
private final class HostAuthorityBearingObject: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let capability: Data
    let algorithm: String

    override init() {
        capability = Data(repeating: 0xAA, count: 32)
        algorithm = "ed25519"
        super.init()
    }

    required init?(coder: NSCoder) {
        capability = coder.decodeObject(of: NSData.self, forKey: "capability") as Data? ?? Data()
        algorithm = coder.decodeObject(of: NSString.self, forKey: "algorithm") as String? ?? ""
        super.init()
    }

    func encode(with coder: NSCoder) {
        coder.encode(capability as NSData, forKey: "capability")
        coder.encode(algorithm as NSString, forKey: "algorithm")
    }
}

private final class HostForbiddenKeyCoder: NSCoder {
    private let forbiddenKey: String

    init(forbiddenKey: String) {
        self.forbiddenKey = forbiddenKey
        super.init()
    }

    override var allowsKeyedCoding: Bool { true }

    override func containsValue(forKey key: String) -> Bool {
        key == forbiddenKey || key == "commit_payload"
    }

}

@Test func hostProtocolHasExactlyFiveFrozenSelectorsAndIsDisjoint() {
    #expect(protocolSelectors(AgentPassHostXPCProtocol.self) == [
        "prepareHostSession:withReply:",
        "attachHostChild:withReply:",
        "signHostPayload:withReply:",
        "hostSessionStatus:withReply:",
        "closeHostSession:withReply:",
    ])
    #expect(protocolSelectors(AgentPassHostXPCProtocol.self).intersection(protocolSelectors(AgentPassAgentXPCProtocol.self)).isEmpty)
    #expect(protocolSelectors(AgentPassHostXPCProtocol.self).intersection(protocolSelectors(AgentPassNativeServiceProtocol.self)).isEmpty)
}

@Test func hostInterfaceRegistersOnlyFrozenRequestAndReplyClasses() {
    let interface = AgentPassHostXPCInterface.make()
    let expected: [(Selector, Set<String>, Set<String>)] = [
        (
            #selector(AgentPassHostXPCProtocol.prepareHostSession(_:withReply:)),
            ["AgentPassHostPrepareRequest"],
            ["AgentPassHostPrepareResponse"]
        ),
        (
            #selector(AgentPassHostXPCProtocol.attachHostChild(_:withReply:)),
            ["AgentPassHostAttachChildRequest"],
            ["AgentPassHostAttachChildResponse"]
        ),
        (
            #selector(AgentPassHostXPCProtocol.signHostPayload(_:withReply:)),
            ["AgentPassHostSignRequest"],
            ["AgentPassHostSignResponse"]
        ),
        (
            #selector(AgentPassHostXPCProtocol.hostSessionStatus(_:withReply:)),
            ["AgentPassHostStatusRequest"],
            ["AgentPassHostStatusResponse"]
        ),
        (
            #selector(AgentPassHostXPCProtocol.closeHostSession(_:withReply:)),
            ["AgentPassHostCloseRequest"],
            ["AgentPassHostCloseResponse"]
        ),
    ]

    for (selector, requests, responses) in expected {
        #expect(classNames(interface.classes(for: selector, argumentIndex: 0, ofReply: false)) == requests)
        #expect(classNames(interface.classes(for: selector, argumentIndex: 0, ofReply: true)) == responses)
    }
}

@Test func hostDTOsRoundTripWithSecureCodingAndServiceAssignedSessionOnly() throws {
    let prepare = try #require(AgentPassHostPrepareRequest(launchNonce: hostNonce))
    let prepareResponse = try #require(AgentPassHostPrepareResponse(
        sessionID: hostSessionID,
        status: .prepared,
        expiresAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 2
    ))
    let attach = try #require(AgentPassHostAttachChildRequest(
        childPID: 42,
        childPIDVersion: 1_735_000_000_000_000,
        executableIdentityDigest: hostDigest,
        ancestryBindingDigest: hostDigest2,
        worktreeBindingDigest: hostDigest3
    ))
    let attachResponse = try #require(AgentPassHostAttachChildResponse(
        sessionID: hostSessionID,
        attachedAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 2
    ))
    let sign = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data("tree deadbeef\n".utf8)))
    let signResponse = try #require(AgentPassHostSignResponse(responseSequence: 1, signature: Data(repeating: 0x55, count: 64), remainingSignatures: 1))
    let statusRequest = try #require(AgentPassHostStatusRequest())
    let statusResponse = try #require(AgentPassHostStatusResponse(
        sessionID: hostSessionID,
        status: .active,
        expiresAtMilliseconds: 4_000_000_000_000,
        maxSignatures: 2,
        usedSignatures: 1,
        childAttached: true
    ))
    let closeRequest = try #require(AgentPassHostCloseRequest(reason: .completed))
    let closeResponse = try #require(AgentPassHostCloseResponse(sessionID: hostSessionID, closedAtMilliseconds: 4_000_000_000_000))

    #expect((try unarchive(AgentPassHostPrepareRequest.self, from: archive(prepare))).launchNonce == hostNonce)
    #expect((try unarchive(AgentPassHostPrepareResponse.self, from: archive(prepareResponse))).sessionID == hostSessionID)
    #expect((try unarchive(AgentPassHostAttachChildRequest.self, from: archive(attach))).childPIDVersion == 1_735_000_000_000_000)
    #expect((try unarchive(AgentPassHostAttachChildResponse.self, from: archive(attachResponse))).status == "attached")
    #expect((try unarchive(AgentPassHostSignRequest.self, from: archive(sign))).requestSequence == 1)
    #expect((try unarchive(AgentPassHostSignResponse.self, from: archive(signResponse))).responseSequence == 1)
    #expect((try unarchive(AgentPassHostStatusRequest.self, from: archive(statusRequest))).protocolVersion == 1)
    #expect((try unarchive(AgentPassHostStatusResponse.self, from: archive(statusResponse))).childAttached)
    #expect((try unarchive(AgentPassHostCloseRequest.self, from: archive(closeRequest))).reason == "completed")
    #expect((try unarchive(AgentPassHostCloseResponse.self, from: archive(closeResponse))).status == "closed")

    let signLabels = Set(Mirror(reflecting: sign).children.compactMap(\.label))
    #expect(signLabels == ["requestSequence", "commitPayload"])
    for forbidden in ["capability", "privateKey", "algorithm", "operation", "repositoryPath", "sessionID", "token"] {
        #expect(signLabels.contains(forbidden) == false)
    }
}

@Test func attachRejectsMalformedPIDVersionProtocolAndDigests() {
    func attach(
        protocolVersion: Int = AgentPassHostXPCContract.protocolVersion,
        pid: Int = 42,
        pidVersion: Int64 = 1_735_000_000_000_000,
        executable: Data = hostDigest,
        ancestry: Data = hostDigest2,
        worktree: Data = hostDigest3
    ) -> AgentPassHostAttachChildRequest? {
        AgentPassHostAttachChildRequest(
            protocolVersion: protocolVersion,
            childPID: pid,
            childPIDVersion: pidVersion,
            executableIdentityDigest: executable,
            ancestryBindingDigest: ancestry,
            worktreeBindingDigest: worktree
        )
    }

    #expect(attach(pid: 0) == nil)
    #expect(attach(pid: -1) == nil)
    #expect(attach(pid: Int(Int32.max) + 1) == nil)
    #expect(attach(pidVersion: 0) == nil)
    #expect(attach(pidVersion: -1) == nil)
    #expect(attach(pidVersion: AgentPassHostXPCContract.maximumChildPIDVersion + 1) == nil)
    #expect(attach(protocolVersion: 0) == nil)
    #expect(attach(protocolVersion: 2) == nil)
    #expect(attach(executable: Data(repeating: 0, count: 32)) == nil)
    #expect(attach(ancestry: Data(repeating: 0xAA, count: 31)) == nil)
    #expect(attach(worktree: Data(repeating: 0xAA, count: 33)) == nil)
}

@Test func hostPrepareAndResponsesRejectMalformedVersionAndBounds() {
    #expect(AgentPassHostPrepareRequest(protocolVersion: 0, launchNonce: hostNonce) == nil)
    #expect(AgentPassHostPrepareRequest(launchNonce: Data(repeating: 0, count: 15)) == nil)
    #expect(AgentPassHostPrepareRequest(launchNonce: Data(repeating: 0, count: 65)) == nil)
    #expect(AgentPassHostPrepareResponse(protocolVersion: 2, sessionID: hostSessionID, status: .prepared, expiresAtMilliseconds: 1, maxSignatures: 1) == nil)
    #expect(AgentPassHostPrepareResponse(sessionID: hostSessionID, status: .active, expiresAtMilliseconds: 1, maxSignatures: 1) == nil)
    #expect(AgentPassHostPrepareResponse(sessionID: hostSessionID, status: .prepared, expiresAtMilliseconds: 0, maxSignatures: 2) == nil)
    #expect(AgentPassHostPrepareResponse(sessionID: hostSessionID, status: .prepared, expiresAtMilliseconds: -1, maxSignatures: 1) == nil)
    #expect(AgentPassHostPrepareResponse(sessionID: hostSessionID, status: .prepared, expiresAtMilliseconds: 1, maxSignatures: 0) == nil)
    #expect(AgentPassHostStatusRequest(protocolVersion: 2) == nil)
}

@Test func hostAttachAcceptsMicrosecondPIDVersionAndRejectsMillisecondRangeOverflow() throws {
    #expect(AgentPassHostAttachChildRequest(
        childPID: 42,
        childPIDVersion: 1_735_000_000_000_000,
        executableIdentityDigest: hostDigest,
        ancestryBindingDigest: hostDigest2,
        worktreeBindingDigest: hostDigest3
    ) != nil)
    #expect(AgentPassHostAttachChildRequest(
        childPID: 42,
        childPIDVersion: AgentPassHostXPCContract.maximumChildPIDVersion + 1,
        executableIdentityDigest: hostDigest,
        ancestryBindingDigest: hostDigest2,
        worktreeBindingDigest: hostDigest3
    ) == nil)
}

@Test func signCarriesOnlySequenceAndPayloadAndOrderingRejectsSignBeforeAttach() throws {
    let request = try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data(repeating: 0x01, count: 1)))
    #expect(request.requestSequence == 1)
    #expect(request.commitPayload.count == 1)
    #expect(AgentPassHostXPCContract.isAllowed(.signPayload, in: .prepared) == false)
    #expect(AgentPassHostXPCContract.isAllowed(.status, in: .prepared) == false)
    #expect(throws: AgentPassHostXPCContract.ValidationError.invalidOrdering) {
        try AgentPassHostXPCContract.requireAllowed(.signPayload, in: .prepared)
    }
    try AgentPassHostXPCContract.requireAllowed(.signPayload, in: .attached)
    #expect(AgentPassHostSignRequest(requestSequence: 0, commitPayload: Data([1])) == nil)
    #expect(AgentPassHostSignRequest(requestSequence: 3, commitPayload: Data([1])) == nil)
    #expect(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data()) == nil)
    #expect(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data(repeating: 0x01, count: AgentPassHostXPCContract.maximumCommitPayloadBytes + 1)) == nil)
    #expect(AgentPassHostSignResponse(responseSequence: 1, signature: Data([1]), remainingSignatures: 0) == nil)
    #expect(AgentPassHostSignResponse(responseSequence: 2, signature: Data([1]), remainingSignatures: 0) != nil)
}

@Test func everyHostRequestShapeExcludesAuthorityKeyMaterialAndPaths() throws {
    let requests: [NSObject] = [
        try #require(AgentPassHostPrepareRequest(launchNonce: hostNonce)),
        try #require(AgentPassHostAttachChildRequest(
            childPID: 42,
            childPIDVersion: 1_735_000_000_000_000,
            executableIdentityDigest: hostDigest,
            ancestryBindingDigest: hostDigest2,
            worktreeBindingDigest: hostDigest3
        )),
        try #require(AgentPassHostSignRequest(requestSequence: 1, commitPayload: Data([0x01]))),
        try #require(AgentPassHostStatusRequest()),
        try #require(AgentPassHostCloseRequest(reason: .completed)),
    ]
    let forbiddenFragments = [
        "capability", "privateKey", "key", "algorithm", "repository", "worktreePath",
        "operation", "sessionID", "sessionToken", "token", "ttl", "scope", "authority",
    ]

    for request in requests {
        let labels = Set(Mirror(reflecting: request).children.compactMap(\.label))
        for fragment in forbiddenFragments {
            #expect(labels.allSatisfy { $0.localizedCaseInsensitiveContains(fragment) == false })
        }
    }
}

@Test func authorityBearingArchiveCannotDecodeAsHostSignDTO() throws {
    let authorityObject = HostAuthorityBearingObject()
    let bytes = try archive(authorityObject)
    #expect(throws: Error.self) {
        _ = try unarchive(AgentPassHostSignRequest.self, from: bytes)
    }
}

@Test func hostRequestsRejectUnexpectedAuthorityKeysIncludingCallerSessionID() {
    for key in ["capability", "private_key", "algorithm", "operation", "repository_path", "session_id", "agent_id", "adapter_kind"] {
        #expect(AgentPassHostSignRequest(coder: HostForbiddenKeyCoder(forbiddenKey: key)) == nil)
    }
}

@Test func hostContractInventoryAndRuntimeSurfaceIncludeExactHostClasses() throws {
    #expect(AgentPassNativeXPCContract.hostProtocol.methods.count == 5)
    #expect(AgentPassNativeXPCContract.dtoInventories.filter { $0.purpose == .host }.count == 10)
    #expect(AgentPassNativeXPCContract.dtoInventories.filter { $0.purpose == .host }.allSatisfy { $0.secureCoding })
    try AgentPassNativeXPCContract.verifyRuntimeSurface()
}
