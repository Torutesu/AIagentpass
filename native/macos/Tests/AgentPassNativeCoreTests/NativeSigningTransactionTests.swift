import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private func transactionRequest(id: String, nonce: String = "nonce-abcdefghijklmnopqrstuvwxyz-123456") throws -> Data {
    try JSONSerialization.data(withJSONObject: ["request_id": id, "nonce": nonce], options: [.sortedKeys, .withoutEscapingSlashes])
}

@Test func nativeSigningTransactionReturnsCompletedEvidenceWithoutResigningAcrossRestart() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let request = try transactionRequest(id: id)
    let authorized = AuthorizedSignRequest(requestID: id, payload: Data("commit".utf8), agentID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", repository: "/work/repo", branch: "feature/native", remote: "git@example.test:repo.git")
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.begin(requestData: request, authorized: authorized, payloadHash: String(repeating: "a", count: 64))
    _ = try store.recordSigned(requestID: id, signature: "SSHSIG")
    _ = try store.complete(requestID: id)
    let restarted = try NativeSigningTransactionStore(path: path)
    let lookedUp = try restarted.lookup(requestData: request)
    let record = try #require(lookedUp)
    #expect(record.phase == .complete)
    #expect(record.signature == "SSHSIG")
    #expect(throws: AgentPassNativeError.self) { _ = try restarted.lookup(requestData: try transactionRequest(id: id, nonce: "different-abcdefghijklmnopqrstuvwxyz-123")) }
}

@Test func nativeSigningTransactionMarksAmbiguousIntentAndRejectsUnsafeState() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("transactions.json").path
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let request = try transactionRequest(id: id)
    let authorized = AuthorizedSignRequest(requestID: id, payload: Data(), agentID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", repository: "/work/repo", branch: "feature/native", remote: "git@example.test:repo.git")
    let store = try NativeSigningTransactionStore(path: path)
    _ = try store.begin(requestData: request, authorized: authorized, payloadHash: String(repeating: "b", count: 64))
    #expect(try store.markOutcomeUnknown(requestID: id).phase == .outcomeUnknown)
    let link = root.appendingPathComponent("linked.json").path
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: path)
    #expect(throws: NativeControlBundleV2Error.self) { _ = try NativeSigningTransactionStore(path: link) }
}
