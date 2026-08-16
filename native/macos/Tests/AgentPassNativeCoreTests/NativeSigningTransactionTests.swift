import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private let transactionSession = "11111111-1111-4111-8111-111111111111"
private let transactionRequestID = "22222222-2222-4222-8222-222222222222"
private let transactionCapability = "33333333-3333-4333-8333-333333333333"
private let transactionAgent = "44444444-4444-4444-8444-444444444444"

private func transactionCapabilityData(_ capabilityID: String) throws -> Data {
    try NativeStrictJSON.data([
        "version": 1,
        "capability_id": capabilityID,
        "nonce": String(repeating: "N", count: 32),
        "issuer": "agentpass-cloud",
        "key_id": "capability-v1",
        "audience": [
            "agent_id": transactionAgent,
            "device_id": "55555555-5555-4555-8555-555555555555",
        ],
        "scope": [
            "operations": ["git.commit.sign"],
            "repositories": ["/work/repo"],
            "branches": ["allow": ["feature/*"], "deny": []],
            "remotes": ["allow": ["git@example.test:repo.git"], "deny": []],
        ],
        "not_before": "2027-01-15T07:59:59.000Z",
        "expires_at": "2027-01-15T08:00:30.000Z",
        "sequence": 1,
        "signature": String(repeating: "A", count: 86) + "==",
    ])
}

private func transactionRequest(
    requestID: String = transactionRequestID,
    payload: Data = Data("commit payload".utf8),
    capabilityID: String = transactionCapability,
    capabilityData: Data? = nil,
    nonce: Data = Data(repeating: 0x2a, count: 16)
) throws -> AgentPassAgentSignRequest {
    try #require(AgentPassAgentSignRequest(
        sessionID: transactionSession,
        requestID: requestID,
        capabilityID: capabilityID,
        capability: try capabilityData ?? transactionCapabilityData(capabilityID),
        commitPayload: payload,
        requestNonce: nonce,
        createdAtMilliseconds: 1_800_000_000_000))
}

private func transactionBinding(
    processByte: UInt8 = 0x11,
    worktreeByte: UInt8 = 0x33,
    controlSequence: Int64 = 12,
    authorityGeneration: Int64 = 7,
    keyGeneration: Int64 = 9
) throws -> NativeAgentSessionBinding {
    try NativeAgentSessionBinding(
        agentID: transactionAgent,
        deviceID: "55555555-5555-4555-8555-555555555555",
        processBindingDigest: Data(repeating: processByte, count: 32),
        ancestryBindingDigest: Data(repeating: 0x22, count: 32),
        worktreeBindingDigest: Data(repeating: worktreeByte, count: 32),
        controlSequence: controlSequence,
        authorityGeneration: authorityGeneration,
        keyGeneration: keyGeneration)
}

private func transactionWorktree(
    branch: String = "feature/native",
    remoteURL: String = "git@example.test:repo.git",
    repositoryInode: UInt64 = 20
) throws -> NativeAgentWorktreeBinding {
    let repository = try NativeAgentWorktreeDirectoryIdentity(device: 1, inode: repositoryInode, generation: 1, ownerUserID: 501, permissions: 0o755)
    let git = try NativeAgentWorktreeDirectoryIdentity(device: 1, inode: 21, generation: 1, ownerUserID: 501, permissions: 0o755)
    let remote = try NativeAgentGitRemote(name: "origin", url: remoteURL)
    return try NativeAgentWorktreeBinding(
        layout: .embedded,
        repositoryPath: "/work/repo",
        gitDirectoryPath: "/work/repo/.git",
        commonDirectoryPath: "/work/repo/.git",
        repositoryIdentity: repository,
        gitDirectoryIdentity: git,
        commonDirectoryIdentity: git,
        objectFormat: .sha1,
        head: .branch(branch),
        headObjectID: String(repeating: "a", count: 40),
        headTreeID: String(repeating: "b", count: 40),
        remotes: [remote])
}

private func transactionAuthority(
    request: AgentPassAgentSignRequest,
    binding: NativeAgentSessionBinding = try! transactionBinding(),
    worktree: NativeAgentWorktreeBinding = try! transactionWorktree(),
    keyIdentity: String = String(repeating: "f", count: 64)
) throws -> NativeSigningTransactionAuthority {
    try NativeSigningTransactionAuthority(
        request: try NativeSigningTransactionRequest(request),
        binding: binding,
        worktree: worktree,
        keyLifecycleIdentity: keyIdentity)
}

private func transactionPath() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return root
}

private func legacyRequestData(id: String, nonce: String = "nonce-abcdefghijklmnopqrstuvwxyz-123456") throws -> Data {
    try JSONSerialization.data(withJSONObject: ["request_id": id, "nonce": nonce], options: [.sortedKeys, .withoutEscapingSlashes])
}

private func advanceToCompleted(
    _ store: NativeSigningTransactionStore,
    request: AgentPassAgentSignRequest,
    authority: NativeSigningTransactionAuthority,
    signature: String = "verified-signature"
) throws {
    let identity = try NativeSigningTransactionRequest(request)
    _ = try store.admit(request: identity, authority: authority)
    _ = try store.markIntent(requestID: identity.requestID, authority: authority)
    _ = try store.markProviderStarted(requestID: identity.requestID)
    _ = try store.recordVerified(requestID: identity.requestID, signature: signature)
    _ = try store.complete(requestID: identity.requestID, remainingSignatures: 1)
}

@Test func nativeSigningTransactionReturnsExactCompletedReplayWithoutResigningAcrossRestart() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let request = try transactionRequest()
    let identity = try NativeSigningTransactionRequest(request)
    let authority = try transactionAuthority(request: request)
    let store = try NativeSigningTransactionStore(path: root.appendingPathComponent("transactions.json").path)
    try advanceToCompleted(store, request: request, authority: authority)

    let restarted = try NativeSigningTransactionStore(path: root.appendingPathComponent("transactions.json").path)
    let replay = try #require(try restarted.lookup(request: identity))
    #expect(replay.phase == .completed)
    #expect(replay.signature == "verified-signature")
    #expect(replay.remainingSignatures == 1)
}

@Test func completedReplayKeepsOriginalRemainingAfterLaterSigningTransaction() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let first = try transactionRequest()
    let firstIdentity = try NativeSigningTransactionRequest(first)
    let store = try NativeSigningTransactionStore(path: path)
    try advanceToCompleted(store, request: first, authority: try transactionAuthority(request: first), signature: "first-signature")

    let later = try transactionRequest(requestID: "66666666-6666-4666-8666-666666666666", capabilityID: "77777777-7777-4777-8777-777777777777")
    try advanceToCompleted(store, request: later, authority: try transactionAuthority(request: later), signature: "later-signature")
    let replay = try #require(try store.lookup(request: firstIdentity))
    #expect(replay.phase == .completed)
    #expect(replay.signature == "first-signature")
    #expect(replay.remainingSignatures == 1)
}

@Test func providerStartedBecomesDurableUncertainOnRestartAndCannotBeSignedAgain() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let request = try transactionRequest()
    let identity = try NativeSigningTransactionRequest(request)
    let authority = try transactionAuthority(request: request)
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.admit(request: identity, authority: authority)
    _ = try store.markIntent(requestID: identity.requestID, authority: authority)
    _ = try store.markProviderStarted(requestID: identity.requestID)

    let restarted = try NativeSigningTransactionStore(path: path)
    #expect(try restarted.lookup(request: identity)?.phase == .uncertain)
    #expect(throws: NativeSigningTransactionError.phaseConflict) {
        _ = try restarted.recordVerified(requestID: identity.requestID, signature: "second-attempt")
    }
}

@Test func providerStartedIsPersistedBeforeTheProviderBoundary() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let request = try transactionRequest()
    let identity = try NativeSigningTransactionRequest(request)
    let authority = try transactionAuthority(request: request)
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.admit(request: identity, authority: authority)
    _ = try store.markIntent(requestID: identity.requestID, authority: authority)
    _ = try store.markProviderStarted(requestID: identity.requestID)
    let persisted = String(decoding: try Data(contentsOf: URL(fileURLWithPath: path)), as: UTF8.self)
    #expect(persisted.contains("provider_started"))
    #expect(try store.lookup(request: identity)?.phase == .providerStarted)
}

@Test func transactionRejectsRequestPayloadCapabilityAndAuthoritySubstitution() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let original = try transactionRequest()
    let identity = try NativeSigningTransactionRequest(original)
    let authority = try transactionAuthority(request: original)
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.admit(request: identity, authority: authority)

    let changedPayload = try NativeSigningTransactionRequest(transactionRequest(payload: Data("substituted payload".utf8)))
    #expect(throws: NativeSigningTransactionError.requestConflict) { _ = try store.lookup(request: changedPayload) }
    let changedCapability = try NativeSigningTransactionRequest(transactionRequest(capabilityID: "66666666-6666-4666-8666-666666666666"))
    #expect(throws: NativeSigningTransactionError.requestConflict) { _ = try store.lookup(request: changedCapability) }
    var substitutedCapability = try #require(
        JSONSerialization.jsonObject(with: transactionCapabilityData(transactionCapability)) as? [String: Any])
    substitutedCapability["signature"] = String(repeating: "B", count: 86) + "=="
    let changedCapabilityStatement = try NativeSigningTransactionRequest(transactionRequest(
        capabilityData: try NativeStrictJSON.data(substitutedCapability)))
    #expect(throws: NativeSigningTransactionError.requestConflict) {
        _ = try store.lookup(request: changedCapabilityStatement)
    }

    let substitutions: [NativeSigningTransactionAuthority] = [
        try transactionAuthority(request: original, binding: try transactionBinding(processByte: 0x44)),
        try transactionAuthority(request: original, binding: try transactionBinding(keyGeneration: 10)),
        try transactionAuthority(request: original, binding: try transactionBinding(controlSequence: 13)),
        try transactionAuthority(request: original, worktree: try transactionWorktree(branch: "substituted-branch")),
        try transactionAuthority(request: original, worktree: try transactionWorktree(repositoryInode: 99)),
        try transactionAuthority(request: original, worktree: try transactionWorktree(remoteURL: "git@example.test:substituted.git")),
        try transactionAuthority(request: original, keyIdentity: String(repeating: "e", count: 64)),
    ]
    for substitution in substitutions {
        #expect(throws: NativeSigningTransactionError.authorityConflict) {
            _ = try store.markIntent(requestID: identity.requestID, authority: substitution)
        }
    }
}

@Test func preProviderAuthorityDriftLeavesNoProviderStartedState() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let request = try transactionRequest()
    let identity = try NativeSigningTransactionRequest(request)
    let authority = try transactionAuthority(request: request)
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.admit(request: identity, authority: authority)
    #expect(throws: NativeSigningTransactionError.authorityConflict) {
        _ = try store.markIntent(requestID: identity.requestID, authority: try transactionAuthority(request: request, binding: try transactionBinding(controlSequence: 13)))
    }
    #expect(try store.lookup(request: identity)?.phase == .admitted)
    #expect(throws: NativeSigningTransactionError.phaseConflict) {
        _ = try store.markProviderStarted(requestID: identity.requestID)
    }
}

@Test func transactionRejectsUnknownFieldsRollbackAndSymlinkedState() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let request = try transactionRequest()
    let identity = try NativeSigningTransactionRequest(request)
    let authority = try transactionAuthority(request: request)
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.admit(request: identity, authority: authority)
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    let persisted = String(decoding: data, as: UTF8.self)
    let text = persisted.replacingOccurrences(
        of: "\"records\"",
        with: "\"unknown\":true,\"records\"",
        options: [],
        range: persisted.range(of: "\"records\""))
    try Data(text.utf8).write(to: URL(fileURLWithPath: path), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    #expect(throws: NativeSigningTransactionError.invalidState) { _ = try NativeSigningTransactionStore(path: path) }

    let link = root.appendingPathComponent("linked.json").path
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: path)
    #expect(throws: Error.self) { _ = try NativeSigningTransactionStore(path: link) }
}

@Test func tamperedPersistedSignatureFailsClosedBeforeReplay() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let request = try transactionRequest()
    let identity = try NativeSigningTransactionRequest(request)
    let authority = try transactionAuthority(request: request)
    let signer = try NativeAgentGitCommitSigner(signer: AgentCountingP256Signer())
    let valid = try signer.signGitCommitPayload(request.commitPayload)
    let signatureForAnotherPayload = try signer.signGitCommitPayload(Data("another payload".utf8))
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.admit(request: identity, authority: authority)
    _ = try store.markIntent(requestID: identity.requestID, authority: authority)
    _ = try store.markProviderStarted(requestID: identity.requestID)
    _ = try store.recordVerified(requestID: identity.requestID, signature: String(decoding: valid, as: UTF8.self))
    _ = try store.complete(requestID: identity.requestID, remainingSignatures: 1)

    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    var object = try #require(JSONSerialization.jsonObject(with: Data(data.dropLast())) as? [String: Any])
    var records = try #require(object["records"] as? [[String: Any]])
    records[0]["signature"] = String(decoding: signatureForAnotherPayload, as: UTF8.self)
    object["records"] = records
    try (NativeStrictJSON.data(object) + Data("\n".utf8)).write(to: URL(fileURLWithPath: path), options: .atomic)

    let restarted = try NativeSigningTransactionStore(path: path)
    let persisted = try #require(try restarted.lookup(request: identity))
    let persistedSignature = try #require(persisted.signature)
    #expect(persisted.phase == .completed)
    #expect(try signer.verifyGitCommitSignature(
        payload: request.commitPayload,
        signature: Data(persistedSignature.utf8)) == false)
}

// These two compatibility tests are intentionally retained from the original
// transaction suite while the new Agent contract is tested above.
@Test func nativeSigningTransactionReturnsCompletedEvidenceWithoutResigningAcrossRestart() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let request = try legacyRequestData(id: id)
    let authorized = AuthorizedSignRequest(requestID: id, payload: Data("commit".utf8), agentID: transactionAgent, repository: "/work/repo", branch: "feature/native", remote: "git@example.test:repo.git")
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.begin(requestData: request, authorized: authorized, payloadHash: String(repeating: "a", count: 64))
    _ = try store.recordSigned(requestID: id, signature: "SSHSIG")
    _ = try store.complete(requestID: id)
    let restarted = try NativeSigningTransactionStore(path: path)
    let record = try #require(try restarted.lookup(requestData: request))
    #expect(record.phase == .complete)
    #expect(record.signature == "SSHSIG")
    #expect(throws: AgentPassNativeError.self) { _ = try restarted.lookup(requestData: try legacyRequestData(id: id, nonce: "different-abcdefghijklmnopqrstuvwxyz-123")) }
}

@Test func nativeSigningTransactionMarksAmbiguousIntentAndRejectsUnsafeState() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let request = try legacyRequestData(id: id)
    let authorized = AuthorizedSignRequest(requestID: id, payload: Data(), agentID: transactionAgent, repository: "/work/repo", branch: "feature/native", remote: "git@example.test:repo.git")
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.begin(requestData: request, authorized: authorized, payloadHash: String(repeating: "b", count: 64))
    #expect(try store.markOutcomeUnknown(requestID: id).phase == .outcomeUnknown)
    let link = root.appendingPathComponent("linked.json").path
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: path)
    #expect(throws: NativeControlBundleV2Error.self) { _ = try NativeSigningTransactionStore(path: link) }
}

@Test func legacyTransactionSurfaceStillReplaysAndMarksAmbiguity() throws {
    let root = try transactionPath(); defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("legacy.json").path
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let request = try JSONSerialization.data(withJSONObject: ["request_id": id, "nonce": "nonce-abcdefghijklmnopqrstuvwxyz-123456"], options: [.sortedKeys, .withoutEscapingSlashes])
    let authorized = AuthorizedSignRequest(requestID: id, payload: Data("commit".utf8), agentID: transactionAgent, repository: "/work/repo", branch: "feature/native", remote: "git@example.test:repo.git")
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.begin(requestData: request, authorized: authorized, payloadHash: String(repeating: "a", count: 64))
    #expect(try store.markOutcomeUnknown(requestID: id).phase == .uncertain)
    let link = root.appendingPathComponent("linked.json").path
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: path)
    #expect(throws: Error.self) { _ = try NativeSigningTransactionStore(path: link) }
}
