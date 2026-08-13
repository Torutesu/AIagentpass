import Foundation
import Testing
@testable import AgentPassNativeCore

private func intentEvidence(request: String = "11111111-1111-4111-8111-111111111111") throws -> NativeAgentSigningIntentEvidence {
    try NativeAgentSigningIntentEvidence(requestID: request, sessionID: "22222222-2222-4222-8222-222222222222", capabilityID: "33333333-3333-4333-8333-333333333333", payloadHash: String(repeating:"a",count:64), processBindingHash: String(repeating:"b",count:64), ancestryBindingHash: String(repeating:"c",count:64), worktreeBindingHash: String(repeating:"d",count:64), keyGeneration: 2, controlSequence: 3, budgetSequence: 1)
}

private func intentPath() throws -> (URL, String) {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return (root, root.appendingPathComponent("agent-intents.json").path)
}

@Test func intentStorePersistsOnlyHashesAndCompletesExactPhases() throws {
    let (root,path) = try intentPath(); defer { try? FileManager.default.removeItem(at: root) }
    let store = try NativeAgentSigningIntentStore(path: path); let evidence = try intentEvidence()
    #expect(try store.begin(evidence).phase == .intent)
    #expect(try store.recordSigned(requestID: evidence.requestID, signatureHash: String(repeating:"e",count:64)).phase == .signed)
    #expect(try store.complete(requestID: evidence.requestID).phase == .complete)
    let data = try Data(contentsOf: URL(fileURLWithPath: path)); let text = String(decoding:data,as:UTF8.self)
    #expect(!text.contains("BEGIN SSH SIGNATURE")); #expect(text.contains(String(repeating:"e",count:64)))
    #expect(try NativeAgentSigningIntentStore(path: path).lookup(requestID: evidence.requestID)?.phase == .complete)
}

@Test func restartMakesUnresolvedIntentTerminalBeforeLookup() throws {
    let (root,path) = try intentPath(); defer { try? FileManager.default.removeItem(at: root) }
    let evidence = try intentEvidence(); _ = try NativeAgentSigningIntentStore(path: path).begin(evidence)
    let restarted = try NativeAgentSigningIntentStore(path: path)
    #expect(try restarted.lookup(requestID: evidence.requestID)?.phase == .outcomeUnknown)
    #expect(throws: NativeAgentSigningIntentStoreError.phaseConflict) { _ = try restarted.recordSigned(requestID: evidence.requestID, signatureHash: String(repeating:"e",count:64)) }
}

@Test func intentStoreRejectsReplayEquivocationAndUnsafeFiles() throws {
    let (root,path) = try intentPath(); defer { try? FileManager.default.removeItem(at: root) }
    let store = try NativeAgentSigningIntentStore(path: path); let evidence = try intentEvidence(); _ = try store.begin(evidence)
    #expect(throws: NativeAgentSigningIntentStoreError.phaseConflict) { _ = try store.begin(evidence) }
    let changed = try NativeAgentSigningIntentEvidence(requestID: evidence.requestID, sessionID: evidence.sessionID, capabilityID: evidence.capabilityID, payloadHash: String(repeating:"f",count:64), processBindingHash: evidence.processBindingHash, ancestryBindingHash: evidence.ancestryBindingHash, worktreeBindingHash: evidence.worktreeBindingHash, keyGeneration: 2, controlSequence: 3, budgetSequence: 1)
    #expect(throws: NativeAgentSigningIntentStoreError.requestConflict) { _ = try store.begin(changed) }
    let link = root.appendingPathComponent("linked.json").path; try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: path)
    #expect(throws: NativeAgentSigningIntentStoreError.invalidState) { _ = try NativeAgentSigningIntentStore(path: link) }
}

@Test func intentStoreRejectsTruncationUnknownFieldsAndSignatureHashSubstitution() throws {
    let (root,path) = try intentPath(); defer { try? FileManager.default.removeItem(at: root) }
    let store = try NativeAgentSigningIntentStore(path: path); let evidence = try intentEvidence(); _ = try store.begin(evidence)
    #expect(throws: NativeAgentSigningIntentStoreError.invalidEvidence) { _ = try store.recordSigned(requestID: evidence.requestID, signatureHash: "secret") }
    var data = try Data(contentsOf: URL(fileURLWithPath:path)); data.removeLast(); try data.write(to: URL(fileURLWithPath:path), options:.atomic); try FileManager.default.setAttributes([.posixPermissions:0o600], ofItemAtPath:path)
    #expect(throws: NativeAgentSigningIntentStoreError.invalidState) { _ = try NativeAgentSigningIntentStore(path:path) }
}
