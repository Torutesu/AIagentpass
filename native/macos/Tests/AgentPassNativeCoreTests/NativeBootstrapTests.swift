import CryptoKit
import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private final class BootstrapKey: NativeLifecycleKeyHandle, @unchecked Sendable {
    private let key = P256.Signing.PrivateKey()
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

private final class BootstrapProvider: NativeLifecycleKeyProvider, @unchecked Sendable {
    private var keys: [String: BootstrapKey] = [:]
    func create(applicationTag: String, requiresUserPresence: Bool) throws -> any NativeLifecycleKeyHandle {
        guard keys[applicationTag] == nil else { throw AgentPassNativeError.invalidKey("duplicate") }
        let key = BootstrapKey(); keys[applicationTag] = key; return key
    }
    func load(applicationTag: String) throws -> any NativeLifecycleKeyHandle {
        guard let key = keys[applicationTag] else { throw AgentPassNativeError.invalidKey("missing") }
        return key
    }
    func exists(applicationTag: String) throws -> Bool { keys[applicationTag] != nil }
    func delete(applicationTag: String) throws { guard keys.removeValue(forKey: applicationTag) != nil else { throw AgentPassNativeError.invalidKey("missing") } }
}

private func bootstrapDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return url
}

@Test func bootstrapTransportJSONIsCanonicalAndDuplicateSafe() throws {
    let canonical = Data(#"{"public_key_base64":"QUJD","version":1}"#.utf8)
    let object = try NativeStrictJSON.object(from: canonical, maxBytes: 64 * 1024, maxDepth: 8)
    #expect(try NativeStrictJSON.data(object) == canonical)
    #expect(throws: NativeControlBundleV2Error.self) {
        try NativeStrictJSON.object(from: Data(#"{"version":1,"version":1}"#.utf8), maxBytes: 64 * 1024, maxDepth: 8)
    }
}

@Test func bootstrapCeremonyIsOrderedResumableAndComplete() throws {
    let root = try bootstrapDirectory(); defer { try? FileManager.default.removeItem(at: root) }
    let store = try NativeKeyLifecycleStore(directory: root.path)
    let provider = BootstrapProvider()
    let approval = BootstrapKey()
    let date = Date(timeIntervalSince1970: 1_810_000_000)
    let coordinator = try NativeBootstrapCoordinator(store: store, serviceKeys: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], now: { date })

    #expect(try coordinator.bootstrapSnapshot().sequence == 0)
    #expect(throws: AgentPassNativeError.self) { try coordinator.completedSnapshot() }
    #expect(throws: AgentPassNativeError.self) { try coordinator.prepareServiceRole(.gitSigning) }
    let approvalPlan = try coordinator.prepareApproval(publicKeyX963: approval.publicKeyX963)
    #expect(approvalPlan.fingerprint.range(of: "^SHA256:[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil)
    #expect(try coordinator.bootstrapSnapshot().sequence == 1)
    let resumedApproval = try coordinator.prepareApproval(publicKeyX963: approval.publicKeyX963)
    #expect(resumedApproval.fingerprint == approvalPlan.fingerprint)
    let approvalSignature = try approval.sign(message: resumedApproval.statement.canonicalData())
    _ = try coordinator.commitApproval(plan: resumedApproval, signature: approvalSignature)
    _ = try coordinator.commitApproval(plan: resumedApproval, signature: approvalSignature)
    #expect(try coordinator.bootstrapSnapshot().sequence == 2)

    let signingPlan = try coordinator.prepareServiceRole(.gitSigning)
    #expect(try coordinator.bootstrapSnapshot().sequence == 3)
    let resumedSigning = try coordinator.prepareServiceRole(.gitSigning)
    #expect(resumedSigning.fingerprint == signingPlan.fingerprint)
    _ = try coordinator.commitServiceRole(plan: resumedSigning, approvalSignature: approval.sign(message: resumedSigning.statement.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)
    #expect(try coordinator.bootstrapSnapshot().sequence == 4)

    let auditPlan = try coordinator.prepareServiceRole(.auditCheckpoint)
    #expect(try coordinator.bootstrapSnapshot().sequence == 5)
    _ = try coordinator.commitServiceRole(plan: auditPlan, approvalSignature: approval.sign(message: auditPlan.statement.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)
    let final = try coordinator.completedSnapshot()
    #expect(final.sequence == 6)
    #expect(final.active(for: .sessionApproval)?.applicationTag == "approval.g1")
    #expect(final.active(for: .gitSigning)?.applicationTag == "git.g1")
    #expect(final.active(for: .auditCheckpoint)?.applicationTag == "audit.g1")
}

@Test func bootstrapRejectsSubstitutionAndUnexpectedOrphans() throws {
    let root = try bootstrapDirectory(); defer { try? FileManager.default.removeItem(at: root) }
    let store = try NativeKeyLifecycleStore(directory: root.path)
    let provider = BootstrapProvider()
    let approval = BootstrapKey()
    let attacker = BootstrapKey()
    let date = Date(timeIntervalSince1970: 1_810_000_000)
    let coordinator = try NativeBootstrapCoordinator(store: store, serviceKeys: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], now: { date })

    let plan = try coordinator.prepareApproval(publicKeyX963: approval.publicKeyX963)
    #expect(throws: AgentPassNativeError.self) { try coordinator.prepareApproval(publicKeyX963: attacker.publicKeyX963) }
    #expect(throws: AgentPassNativeError.self) {
        try coordinator.commitApproval(plan: plan, signature: attacker.sign(message: plan.statement.canonicalData()))
    }
    _ = try coordinator.commitApproval(plan: plan, signature: approval.sign(message: plan.statement.canonicalData()))
    _ = try provider.create(applicationTag: "git.g1", requiresUserPresence: false)
    #expect(throws: AgentPassNativeError.self) { try coordinator.prepareServiceRole(.gitSigning) }
}

@Test func bootstrapCeremonyAdvancesDurablePinForEveryLedgerRecord() throws {
    let parent = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    guard let resolved = Darwin.realpath(parent.path, nil) else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { free(resolved) }
    let root = URL(fileURLWithPath: String(cString: resolved)).appendingPathComponent("bootstrap-pin-\(UUID().uuidString)")
    let ledger = root.appendingPathComponent("ledger"), pins = root.appendingPathComponent("pins")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    try FileManager.default.createDirectory(at: ledger, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    try FileManager.default.createDirectory(at: pins, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }

    let store = try NativeKeyLifecycleStore(directory: ledger.path)
    let pin = try NativeLifecyclePinTransaction(rootPath: pins.path)
    let provider = BootstrapProvider(), approval = BootstrapKey()
    let date = Date(timeIntervalSince1970: 1_810_000_000)
    let coordinator = try NativeBootstrapCoordinator(store: store, serviceKeys: provider, baseTags: [.gitSigning: "git", .auditCheckpoint: "audit", .sessionApproval: "approval"], pinTransaction: pin, now: { date })
    let approvalPlan = try coordinator.prepareApproval(publicKeyX963: approval.publicKeyX963)
    _ = try coordinator.commitApproval(plan: approvalPlan, signature: approval.sign(message: approvalPlan.statement.canonicalData()))
    for role in [NativeKeyRole.gitSigning, .auditCheckpoint] {
        let plan = try coordinator.prepareServiceRole(role)
        _ = try coordinator.commitServiceRole(plan: plan, approvalSignature: approval.sign(message: plan.statement.canonicalData()), approvalPublicKeyX963: approval.publicKeyX963)
    }
    let final = try coordinator.completedSnapshot()
    #expect(try pin.current()?.sequence == 6)
    #expect(try pin.current()?.newLifecycleHead == final.headHash)
    #expect(try pin.pending() == nil)
}
