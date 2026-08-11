import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct ControlFixture {
    let key = Curve25519.Signing.PrivateKey()
    let agentID = "11111111-1111-4111-8111-111111111111"
    let now: Int64 = 1_800_000_000_000
    var publicKeyDER: Data { Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + key.publicKey.rawRepresentation }
    var publicKeyPEM: String { "-----BEGIN PUBLIC KEY-----\n\(publicKeyDER.base64EncodedString())\n-----END PUBLIC KEY-----\n" }
    var fingerprint: String {
        "SHA256:" + Data(SHA256.hash(data: publicKeyDER)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    func policy() throws -> Data {
        try JSONSerialization.data(withJSONObject: ["control": ["required": true, "public_key": publicKeyPEM]], options: [.sortedKeys])
    }

    func bundle(sequence: Int64, globalRevoked: Bool = false, revokedAgents: [String] = [], issuedOffset: Int64 = -1_000, expiresOffset: Int64 = 300_000, signingKey: Curve25519.Signing.PrivateKey? = nil) throws -> Data {
        let statement: [String: Any] = [
            "version": 1,
            "sequence": sequence,
            "issued_at": timestamp(now + issuedOffset),
            "expires_at": timestamp(now + expiresOffset),
            "global_revoked": globalRevoked,
            "revoked_agents": Array(Set(revokedAgents)).sorted()
        ]
        let signer = signingKey ?? key
        var record = statement
        record["key_fingerprint"] = fingerprint
        record["signature"] = try signer.signature(for: NativeAuditLog.canonical(statement)).base64EncodedString()
        return try NativeAuditLog.canonical(record)
    }

    private func timestamp(_ milliseconds: Int64) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        return formatter.string(from: Date(timeIntervalSince1970: Double(milliseconds) / 1000))
    }
}

@Test func nativeControlPersistsSequenceAndEnforcesRevocation() throws {
    let fixture = ControlFixture()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let state = root.appendingPathComponent("control.json")
    try fixture.bundle(sequence: 1).write(to: state)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: state.path)
    let manager = try NativeControlManager(policyData: fixture.policy(), statePath: state.path, nowMilliseconds: fixture.now)
    try manager.validateControl(agentID: fixture.agentID, nowMilliseconds: fixture.now)
    #expect(manager.status().sequence == 1)

    let revokedBundle = try fixture.bundle(sequence: 2, revokedAgents: [fixture.agentID])
    #expect(try manager.validateBundle(bundleData: revokedBundle, nowMilliseconds: fixture.now))
    try manager.beginAuditedUpdate()
    let revoked = try manager.apply(bundleData: revokedBundle, nowMilliseconds: fixture.now)
    try manager.completeAuditedUpdate()
    #expect(revoked.sequence == 2)
    #expect(throws: AgentPassNativeError.self) { try manager.validateControl(agentID: fixture.agentID, nowMilliseconds: fixture.now) }
    #expect(throws: AgentPassNativeError.self) { try manager.apply(bundleData: fixture.bundle(sequence: 1), nowMilliseconds: fixture.now) }
    #expect(throws: AgentPassNativeError.self) { try manager.apply(bundleData: fixture.bundle(sequence: 2, globalRevoked: true), nowMilliseconds: fixture.now) }
    #expect(try manager.validateBundle(bundleData: revokedBundle, nowMilliseconds: fixture.now) == false)

    let restarted = try NativeControlManager(policyData: fixture.policy(), statePath: state.path, nowMilliseconds: fixture.now)
    #expect(restarted.status().sequence == 2)
    #expect(restarted.status().operational)
    #expect(throws: AgentPassNativeError.self) { try restarted.validateControl(agentID: fixture.agentID, nowMilliseconds: fixture.now) }
}

@Test func nativeControlRefreshConfigurationRejectsUnsafeSources() throws {
    let valid = try NativeControlRefreshConfiguration(urlString: "https://control.example.com/agentpass/bundle.json", refreshSeconds: 60)
    #expect(valid.url.host == "control.example.com")
    #expect(throws: AgentPassNativeError.self) { try NativeControlRefreshConfiguration(urlString: "http://control.example.com/bundle.json", refreshSeconds: 60) }
    #expect(throws: AgentPassNativeError.self) { try NativeControlRefreshConfiguration(urlString: "https://user:secret@control.example.com/bundle.json", refreshSeconds: 60) }
    #expect(throws: AgentPassNativeError.self) { try NativeControlRefreshConfiguration(urlString: "https://control.example.com/bundle.json?token=secret", refreshSeconds: 60) }
    #expect(throws: AgentPassNativeError.self) { try NativeControlRefreshConfiguration(urlString: "https://control.example.com/bundle.json#fragment", refreshSeconds: 60) }
    #expect(throws: AgentPassNativeError.self) { try NativeControlRefreshConfiguration(urlString: "https://control.example.com/bundle.json", refreshSeconds: 14) }
}

@Test func nativeControlRetryScheduleUsesBoundedOneSidedJitterAndBackoff() throws {
    var schedule = try NativeControlRetrySchedule(refreshSeconds: 60)
    #expect(schedule.successDelay(randomUnit: 0) == 54)
    #expect(schedule.successDelay(randomUnit: 1) == 60)
    #expect(schedule.failureDelay(randomUnit: 1) == 5)
    #expect(schedule.failureDelay(randomUnit: 1) == 10)
    #expect(schedule.failureDelay(randomUnit: 1) == 20)
    #expect(schedule.failureDelay(randomUnit: 1) == 40)
    #expect(schedule.failureDelay(randomUnit: 1) == 60)
    #expect(schedule.failureDelay(randomUnit: 0) == 45)
    #expect(schedule.consecutiveFailures == 6)
    #expect(schedule.successDelay(randomUnit: .nan) == 54)
    #expect(schedule.consecutiveFailures == 0)
    #expect(throws: AgentPassNativeError.self) { try NativeControlRetrySchedule(refreshSeconds: 14) }
}

@Test func nativeControlRejectsExpiredForgedAndUnsafeState() throws {
    let fixture = ControlFixture()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let state = root.appendingPathComponent("control.json")
    try fixture.bundle(sequence: 1, issuedOffset: -301_000, expiresOffset: -1).write(to: state)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: state.path)
    let manager = try NativeControlManager(policyData: fixture.policy(), statePath: state.path, nowMilliseconds: fixture.now)
    #expect(throws: AgentPassNativeError.self) { try manager.validateControl(agentID: fixture.agentID, nowMilliseconds: fixture.now) }
    #expect(throws: AgentPassNativeError.self) { try manager.apply(bundleData: fixture.bundle(sequence: 2, signingKey: Curve25519.Signing.PrivateKey()), nowMilliseconds: fixture.now) }
    try manager.apply(bundleData: fixture.bundle(sequence: 2, globalRevoked: true), nowMilliseconds: fixture.now)
    #expect(throws: AgentPassNativeError.self) { try manager.validateControl(agentID: "another", nowMilliseconds: fixture.now) }

    manager.invalidate()
    #expect(manager.status().operational == false)
    #expect(throws: AgentPassNativeError.self) { try manager.apply(bundleData: fixture.bundle(sequence: 3), nowMilliseconds: fixture.now) }
    let poisonedRestart = try NativeControlManager(policyData: fixture.policy(), statePath: state.path, nowMilliseconds: fixture.now)
    #expect(poisonedRestart.status().operational == false)
    #expect(throws: AgentPassNativeError.self) { try poisonedRestart.validateControl(agentID: fixture.agentID, nowMilliseconds: fixture.now) }

    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: state.path)
    #expect(throws: (any Error).self) { try NativeControlManager(policyData: fixture.policy(), statePath: state.path, nowMilliseconds: fixture.now) }
}
