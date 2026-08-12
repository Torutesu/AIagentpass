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

@Test func nativeControlV2VerifiesNodeIssuedBundleAndCapabilityVector() throws {
    let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeKxHAljpDZC+IgnnVZlnDl+YYgZRWY9JjUMuWDCBrJE=\n-----END PUBLIC KEY-----\n"
    let audience = NativeControlBundleV2Audience(organizationID: "11111111-1111-4111-8111-111111111111", deviceID: "22222222-2222-4222-8222-222222222222")
    let trust = try NativeControlBundleV2Trust(publicKeyPEM: pem, issuer: "agentpass-cloud", keyID: "control-v2", audience: audience)
    let bundle = Data(#"{"format_epoch":2,"issuer":"agentpass-cloud","organization_id":"11111111-1111-4111-8111-111111111111","device_id":"22222222-2222-4222-8222-222222222222","audience":{"organization_id":"11111111-1111-4111-8111-111111111111","device_id":"22222222-2222-4222-8222-222222222222"},"issued_at":"2026-08-12T00:00:00.000Z","expires_at":"2026-08-12T00:01:00.000Z","sequence":7,"policy_scope":{"operations":["git.commit.sign"],"repositories":["/work/project"],"branches":{"allow":["feature/*"],"deny":["main"]},"remotes":{"allow":["git@github.com:org/repo.git"]}},"global_revoked":false,"revoked_devices":[],"revoked_agents":[],"revoked_capabilities":[],"offline_ttl_ms":120000,"key_id":"control-v2","signature":"NCLDRc0wp4gCKnQeTZdf2dSlyMKoR8VeN7fTc5yJfhCke64orZuw/4NGCiKc92EP3nlJE0KmiaAzX7TktVV7Bg=="}"#.utf8)
    let verified = try verifyControlBundleV2(bundle, trust: trust, options: .init(nowMilliseconds: 1_786_492_801_000))
    #expect(verified.sequence == 7)
    #expect(String(data: try NativeControlBundleV2Codec.canonicalJSON(bundle), encoding: .utf8)?.contains(#""deny":["main"]"#) == true)

    let capability = Data(#"{"version":1,"capability_id":"44444444-4444-4444-8444-444444444444","nonce":"Naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issuer":"agentpass-cloud","key_id":"control-v2","audience":{"agent_id":"33333333-3333-4333-8333-333333333333","device_id":"22222222-2222-4222-8222-222222222222"},"scope":{"operations":["git.commit.sign"],"repositories":["/work/project"],"branches":{"allow":["feature/*"],"deny":["main"]},"remotes":{"allow":["git@github.com:org/repo.git"]}},"not_before":"2026-08-12T00:00:00.000Z","expires_at":"2026-08-12T00:00:30.000Z","sequence":9,"signature":"q+v8SCoR0W/t3zSBy88adYEh6Kf2DbXHgA2iF43xG8JashVFeSbMm7hy8GsF9EJaMk/LNNzmkZQ0M3dWS/L+BQ=="}"#.utf8)
    let capabilityVerifier = try NativeCapabilityVerifier(trust: NativeCapabilityTrust(publicKey: trust.publicKey, issuer: "agentpass-cloud", keyID: "control-v2"))
    let verifiedCapability = try capabilityVerifier.verify(capability, options: .init(nowMilliseconds: 1_786_492_801_000))
    #expect(verifiedCapability.sequence == 9)
}

@Test func nativeControlV2RejectsDuplicateFieldsAndPersistsCapabilityReplayAcrossRestart() throws {
    let duplicate = Data(#"{"format_epoch":2,"format_epoch":2}"#.utf8)
    #expect(throws: NativeControlBundleV2Error.self) { try NativeControlBundleV2Codec.parse(duplicate, nowMilliseconds: 1_786_492_800_000) }

    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let storePath = root.appendingPathComponent("capability-state.json").path
    let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeKxHAljpDZC+IgnnVZlnDl+YYgZRWY9JjUMuWDCBrJE=\n-----END PUBLIC KEY-----\n"
    let publicKey = try NativeControlBundleV2Trust(publicKeyPEM: pem).publicKey
    let capability = Data(#"{"version":1,"capability_id":"44444444-4444-4444-8444-444444444444","nonce":"Naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issuer":"agentpass-cloud","key_id":"control-v2","audience":{"agent_id":"33333333-3333-4333-8333-333333333333","device_id":"22222222-2222-4222-8222-222222222222"},"scope":{"operations":["git.commit.sign"],"repositories":["/work/project"],"branches":{"allow":["feature/*"],"deny":["main"]},"remotes":{"allow":["git@github.com:org/repo.git"]}},"not_before":"2026-08-12T00:00:00.000Z","expires_at":"2026-08-12T00:00:30.000Z","sequence":9,"signature":"q+v8SCoR0W/t3zSBy88adYEh6Kf2DbXHgA2iF43xG8JashVFeSbMm7hy8GsF9EJaMk/LNNzmkZQ0M3dWS/L+BQ=="}"#.utf8)
    let verifier = try NativeCapabilityVerifier(trust: NativeCapabilityTrust(publicKey: publicKey, issuer: "agentpass-cloud", keyID: "control-v2"), statePath: storePath)
    _ = try verifier.verifyAndConsume(capability, options: .init(nowMilliseconds: 1_786_492_801_000))
    let restarted = try NativeCapabilityVerifier(trust: NativeCapabilityTrust(publicKey: publicKey, issuer: "agentpass-cloud", keyID: "control-v2"), statePath: storePath)
    #expect(throws: NativeControlBundleV2Error.self) { _ = try restarted.verifyAndConsume(capability, options: .init(nowMilliseconds: 1_786_492_801_000)) }
    let snapshot = try NativeCapabilityStateStore(path: storePath)
    #expect(try snapshot.load().highestSequence == 9)
    #expect(try snapshot.load().consumedCapabilityIDs == ["44444444-4444-4444-8444-444444444444"])
}

@Test func nativeControlV2AuditTransactionFailsClosedAcrossRestart() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeKxHAljpDZC+IgnnVZlnDl+YYgZRWY9JjUMuWDCBrJE=\n-----END PUBLIC KEY-----\n"
    let audience = NativeControlBundleV2Audience(organizationID: "11111111-1111-4111-8111-111111111111", deviceID: "22222222-2222-4222-8222-222222222222")
    let trust = try NativeControlBundleV2Trust(publicKeyPEM: pem, issuer: "agentpass-cloud", keyID: "control-v2", audience: audience)
    let bundle = Data(#"{"format_epoch":2,"issuer":"agentpass-cloud","organization_id":"11111111-1111-4111-8111-111111111111","device_id":"22222222-2222-4222-8222-222222222222","audience":{"organization_id":"11111111-1111-4111-8111-111111111111","device_id":"22222222-2222-4222-8222-222222222222"},"issued_at":"2026-08-12T00:00:00.000Z","expires_at":"2026-08-12T00:01:00.000Z","sequence":7,"policy_scope":{"operations":["git.commit.sign"],"repositories":["/work/project"],"branches":{"allow":["feature/*"],"deny":["main"]},"remotes":{"allow":["git@github.com:org/repo.git"]}},"global_revoked":false,"revoked_devices":[],"revoked_agents":[],"revoked_capabilities":[],"offline_ttl_ms":120000,"key_id":"control-v2","signature":"NCLDRc0wp4gCKnQeTZdf2dSlyMKoR8VeN7fTc5yJfhCke64orZuw/4NGCiKc92EP3nlJE0KmiaAzX7TktVV7Bg=="}"#.utf8)
    let state = root.appendingPathComponent("control-v2.json").path
    let manager = try NativeControlBundleV2Manager(trust: trust, statePath: state, nowMilliseconds: 1_786_492_801_000)
    try manager.beginAuditedUpdate()
    _ = try manager.apply(bundleData: bundle, nowMilliseconds: 1_786_492_801_000)
    let interrupted = try NativeControlBundleV2Manager(trust: trust, statePath: state, nowMilliseconds: 1_786_492_801_000)
    #expect(interrupted.status(nowMilliseconds: 1_786_492_801_000).operational == false)
    #expect(throws: AgentPassNativeError.self) { try interrupted.validateControl(agentID: "33333333-3333-4333-8333-333333333333", nowMilliseconds: 1_786_492_801_000) }

    try manager.completeAuditedUpdate()
    let completed = try NativeControlBundleV2Manager(trust: trust, statePath: state, nowMilliseconds: 1_786_492_801_000)
    #expect(completed.status(nowMilliseconds: 1_786_492_801_000).operational)
    #expect(completed.status(nowMilliseconds: 1_786_492_801_000).sequence == 7)
}
