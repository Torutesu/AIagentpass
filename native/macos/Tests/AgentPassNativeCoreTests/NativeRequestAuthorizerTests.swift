import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private final class TestControlValidator: NativeControlValidating, @unchecked Sendable {
    var blocked = false
    func validateControl(agentID: String, nowMilliseconds: Int64) throws {
        if blocked { throw AgentPassNativeError.unauthorizedClient("remote_agent_revoked") }
    }
}

private struct AuthorizerFixture {
    let root: URL
    let repository: URL
    let privateKey: Curve25519.Signing.PrivateKey
    let policy: Data
    let payload: Data

    init(branchPattern: String = "feature/*") throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        repository = root.appendingPathComponent("repo")
        try FileManager.default.createDirectory(at: repository, withIntermediateDirectories: true)
        try Self.git(repository, ["init", "-b", "main"])
        try Self.git(repository, ["switch", "-c", "feature/native"])
        try Self.git(repository, ["remote", "add", "origin", "git@github.com:example/native.git"])
        try Data("native\n".utf8).write(to: repository.appendingPathComponent("file.txt"))
        try Self.git(repository, ["add", "file.txt"])
        let tree = try Self.gitOutput(repository, ["write-tree"])
        payload = Data("tree \(tree)\nauthor Native <native@example.com> 0 +0000\ncommitter Native <native@example.com> 0 +0000\n\nNative commit\n".utf8)
        privateKey = Curve25519.Signing.PrivateKey()
        let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
        let pem = "-----BEGIN PUBLIC KEY-----\n\((prefix + privateKey.publicKey.rawRepresentation).base64EncodedString())\n-----END PUBLIC KEY-----\n"
        let scope: [String: Any] = [
            "operations": ["git.commit.sign"],
            "repositories": [repository.path],
            "branches": ["allow": [branchPattern], "deny": ["main"]],
            "remotes": ["allow": ["git@github.com:example/native.git"]]
        ]
        policy = try JSONSerialization.data(withJSONObject: [
            "version": 4,
            "agents": [["id": "11111111-1111-4111-8111-111111111111", "name": "native-test", "public_key": pem, "scope": scope]],
            "operations": ["git.commit.sign"],
            "repositories": [repository.path],
            "branches": ["allow": [branchPattern], "deny": ["main"]],
            "remotes": ["allow": ["git@github.com:example/native.git"]],
            "session": ["required": false, "ttl_seconds": 300]
        ], options: [.sortedKeys, .withoutEscapingSlashes])
    }

    func signedRequest(nonce: String = String(repeating: "n", count: 32), payloadOverride: Data? = nil, timestamp: Int64 = 1_800_000_000_000, session: String? = nil, capability: [String: Any]? = nil) throws -> Data {
        var request: [String: Any] = [
            "request_id": UUID().uuidString.lowercased(),
            "operation": "git.commit.sign",
            "cwd": repository.path,
            "sign_args": ["-Y", "sign", "-n", "git", "-f", "/tmp/untrusted"],
            "payload_base64": (payloadOverride ?? payload).base64EncodedString(),
            "session": session ?? NSNull(),
            "agent_id": "11111111-1111-4111-8111-111111111111",
            "timestamp_ms": timestamp,
            "nonce": nonce
        ]
        if let capability { request["capability"] = capability }
        let canonical = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys, .withoutEscapingSlashes])
        request["signature"] = try privateKey.signature(for: canonical).base64EncodedString()
        return try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    static func git(_ repository: URL, _ arguments: [String]) throws { _ = try gitOutput(repository, arguments) }
    static func gitOutput(_ repository: URL, _ arguments: [String]) throws -> String {
        let process = Process(), output = Pipe(), errors = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", repository.path] + arguments
        process.standardOutput = output
        process.standardError = errors
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw AgentPassNativeError.invalidConfiguration(String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "git failed")
        }
        return (String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

@Test func nativeAuthorizerEnforcesV2BundleAndCapabilityOnTheActualRequestPath() throws {
    let fixture = try AuthorizerFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let now: Int64 = 1_800_000_000_000
    let organizationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let deviceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    let cloudKey = Curve25519.Signing.PrivateKey()
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    let pem = "-----BEGIN PUBLIC KEY-----\n\((prefix + cloudKey.publicKey.rawRepresentation).base64EncodedString())\n-----END PUBLIC KEY-----\n"
    let scope: [String: Any] = ["operations": ["git.commit.sign"], "repositories": [fixture.repository.path], "branches": ["allow": ["feature/*"], "deny": ["main"]], "remotes": ["allow": ["git@github.com:example/native.git"], "deny": []]]
    let unsignedBundle: [String: Any] = ["format_epoch": 2, "issuer": "agentpass-cloud", "organization_id": organizationID, "device_id": deviceID, "audience": ["organization_id": organizationID, "device_id": deviceID], "issued_at": "2027-01-15T07:59:59.000Z", "expires_at": "2027-01-15T08:01:00.000Z", "sequence": 1, "policy_scope": scope, "global_revoked": false, "revoked_devices": [], "revoked_agents": [], "revoked_capabilities": [], "offline_ttl_ms": 60_000, "key_id": "control-v2"]
    let bundle = try NativeControlBundleV2Codec.issue(unsignedJSON: JSONSerialization.data(withJSONObject: unsignedBundle, options: [.sortedKeys, .withoutEscapingSlashes]), signingKey: cloudKey, nowMilliseconds: now)
    let trust = try NativeControlBundleV2Trust(publicKeyPEM: pem, issuer: "agentpass-cloud", keyID: "control-v2", audience: .init(organizationID: organizationID, deviceID: deviceID))
    let manager = try NativeControlBundleV2Manager(trust: trust, statePath: fixture.root.appendingPathComponent("control-v2.json").path, nowMilliseconds: now)
    _ = try manager.apply(bundleData: bundle, nowMilliseconds: now)
    var capability: [String: Any] = ["version": 1, "capability_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "nonce": String(repeating: "C", count: 32), "issuer": "agentpass-cloud", "key_id": "control-v2", "audience": ["agent_id": "11111111-1111-4111-8111-111111111111", "device_id": deviceID], "scope": scope, "not_before": "2027-01-15T07:59:59.000Z", "expires_at": "2027-01-15T08:00:30.000Z", "sequence": 1]
    let capabilityStatement = try JSONSerialization.data(withJSONObject: capability, options: [.sortedKeys, .withoutEscapingSlashes])
    capability["signature"] = try cloudKey.signature(for: capabilityStatement).base64EncodedString()
    let verifier = try NativeCapabilityVerifier(trust: NativeCapabilityTrust(publicKey: cloudKey.publicKey, issuer: "agentpass-cloud", keyID: "control-v2"), statePath: fixture.root.appendingPathComponent("capabilities.json").path)
    let evidence = try NativeRequestEvidenceStore(path: fixture.root.appendingPathComponent("requests.json").path)
    let authorizer = try NativeRequestAuthorizer(policyData: fixture.policy, capabilityValidator: verifier, v2ControlManager: manager, requestEvidenceStore: evidence, controlV2Configured: true, v2DeviceID: deviceID)
    let request = try fixture.signedRequest(capability: capability)
    let authorized = try authorizer.authorize(requestData: request, nowMilliseconds: now)
    #expect(authorized.agentID == "11111111-1111-4111-8111-111111111111")
    #expect(throws: AgentPassNativeError.self) { _ = try authorizer.authorize(requestData: request, nowMilliseconds: now + 1) }

    let revokedCapabilityID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    var revokedBundleStatement = unsignedBundle
    revokedBundleStatement["sequence"] = 2
    revokedBundleStatement["revoked_capabilities"] = [revokedCapabilityID]
    let revokedBundle = try NativeControlBundleV2Codec.issue(unsignedJSON: JSONSerialization.data(withJSONObject: revokedBundleStatement, options: [.sortedKeys, .withoutEscapingSlashes]), signingKey: cloudKey, nowMilliseconds: now)
    _ = try manager.apply(bundleData: revokedBundle, nowMilliseconds: now)
    #expect(throws: AgentPassNativeError.self) { try manager.validateCapability(capabilityID: revokedCapabilityID) }
    var revokedCapability: [String: Any] = ["version": 1, "capability_id": revokedCapabilityID, "nonce": String(repeating: "D", count: 32), "issuer": "agentpass-cloud", "key_id": "control-v2", "audience": ["agent_id": "11111111-1111-4111-8111-111111111111", "device_id": deviceID], "scope": scope, "not_before": "2027-01-15T07:59:59.000Z", "expires_at": "2027-01-15T08:00:30.000Z", "sequence": 2]
    revokedCapability["signature"] = try cloudKey.signature(for: JSONSerialization.data(withJSONObject: revokedCapability, options: [.sortedKeys, .withoutEscapingSlashes])).base64EncodedString()
    let revokedRequest = try fixture.signedRequest(nonce: String(repeating: "d", count: 32), capability: revokedCapability)
    #expect(throws: AgentPassNativeError.self) { _ = try authorizer.authorize(requestData: revokedRequest, nowMilliseconds: now) }
}

@Test func nativeAuthorizerAcceptsAnExactSignedGitRequestAndRejectsReplay() throws {
    let fixture = try AuthorizerFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let authorizer = try NativeRequestAuthorizer(policyData: fixture.policy)
    let request = try fixture.signedRequest()
    let authorized = try authorizer.authorize(requestData: request, nowMilliseconds: 1_800_000_000_000)
    #expect(authorized.payload == fixture.payload)
    #expect(authorized.branch == "feature/native")
    #expect(throws: AgentPassNativeError.self) {
        try authorizer.authorize(requestData: request, nowMilliseconds: 1_800_000_000_001)
    }
}

@Test func nativeAuthorizerRejectsTamperingAndScopeBypass() throws {
    let fixture = try AuthorizerFixture(branchPattern: "fix/*")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let authorizer = try NativeRequestAuthorizer(policyData: fixture.policy)
    #expect(throws: AgentPassNativeError.self) {
        try authorizer.authorize(requestData: fixture.signedRequest(), nowMilliseconds: 1_800_000_000_000)
    }

    let allowedFixture = try AuthorizerFixture()
    defer { try? FileManager.default.removeItem(at: allowedFixture.root) }
    let allowed = try NativeRequestAuthorizer(policyData: allowedFixture.policy)
    var object = try #require(JSONSerialization.jsonObject(with: allowedFixture.signedRequest()) as? [String: Any])
    object["payload_base64"] = Data("forged".utf8).base64EncodedString()
    let tampered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    #expect(throws: AgentPassNativeError.self) {
        try allowed.authorize(requestData: tampered, nowMilliseconds: 1_800_000_000_000)
    }
}

@Test func nativeAuthorizerRejectsUnknownFieldsAndAmbiguousCommitHeaders() throws {
    let fixture = try AuthorizerFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let authorizer = try NativeRequestAuthorizer(policyData: fixture.policy)

    var unknown = try #require(JSONSerialization.jsonObject(with: fixture.signedRequest()) as? [String: Any])
    unknown["unexpected"] = true
    let unknownData = try JSONSerialization.data(withJSONObject: unknown, options: [.sortedKeys, .withoutEscapingSlashes])
    #expect(throws: AgentPassNativeError.self) {
        try authorizer.authorize(requestData: unknownData, nowMilliseconds: 1_800_000_000_000)
    }

    let tree = try AuthorizerFixture.gitOutput(fixture.repository, ["write-tree"])
    let malformedPayloads = [
        "tree \(tree)\ntree \(tree)\nauthor Native <native@example.com> 0 +0000\ncommitter Native <native@example.com> 0 +0000\n\nDuplicate\n",
        "tree \(tree)\nauthor Native <native@example.com> 0 +0000\ncommitter Native <native@example.com> 0 +0000\ngpgsig forged\n\nSigned\n",
        "tree \(tree)\nauthor Native <native@example.com> 0 +0000\ncommitter Native <native@example.com> 0 +0000\n continued\n\nContinued\n"
    ]
    for (index, payload) in malformedPayloads.enumerated() {
        #expect(throws: AgentPassNativeError.self) {
            try authorizer.authorize(
                requestData: fixture.signedRequest(nonce: String(repeating: String(index), count: 32), payloadOverride: Data(payload.utf8)),
                nowMilliseconds: 1_800_000_000_000
            )
        }
    }
}

@Test func nativeAuthorizerRejectsSessionAndRemoteControlBypass() throws {
    let fixture = try AuthorizerFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    var object = try #require(JSONSerialization.jsonObject(with: fixture.policy) as? [String: Any])
    object["session"] = ["required": true, "ttl_seconds": 300]
    #expect(throws: AgentPassNativeError.self) {
        try NativeRequestAuthorizer(policyData: JSONSerialization.data(withJSONObject: object))
    }
    object["session"] = ["required": false, "ttl_seconds": 300]
    object["control"] = ["required": true]
    #expect(throws: AgentPassNativeError.self) {
        try NativeRequestAuthorizer(policyData: JSONSerialization.data(withJSONObject: object))
    }
    #expect(throws: AgentPassNativeError.self) {
        try NativeRequestAuthorizer(policyData: fixture.policy, controlV2Configured: true)
    }
}

@Test func nativeAuthorizerEnforcesProtectedAgentBoundSession() throws {
    let fixture = try AuthorizerFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    var object = try #require(JSONSerialization.jsonObject(with: fixture.policy) as? [String: Any])
    object["session"] = ["required": true, "ttl_seconds": 300]
    let policy = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    let approvalKey = P256.Signing.PrivateKey()
    let approvalPublicKey = try SSHSIG.authorizedKey(publicKeyX963: approvalKey.publicKey.x963Representation)
    let sessions = try NativeSessionManager(policyData: policy, approvalPublicKey: approvalPublicKey)
    let now: Int64 = 1_800_000_000_000
    let challenge = try sessions.beginSession(agentID: "11111111-1111-4111-8111-111111111111", requestedTTLSeconds: 300, nowMilliseconds: now)
    let approval = try approvalKey.signature(for: challenge).rawRepresentation
    let issued = try sessions.completeSession(challengeData: challenge, signature: approval, nowMilliseconds: now)
    let authorizer = try NativeRequestAuthorizer(policyData: policy, sessionValidator: sessions)
    _ = try authorizer.authorize(requestData: fixture.signedRequest(session: issued.token), nowMilliseconds: now)
    #expect(throws: AgentPassNativeError.self) {
        try authorizer.authorize(requestData: fixture.signedRequest(nonce: String(repeating: "x", count: 32), session: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), nowMilliseconds: now)
    }
}

@Test func nativeAuthorizerEnforcesInjectedRemoteControl() throws {
    let fixture = try AuthorizerFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    var object = try #require(JSONSerialization.jsonObject(with: fixture.policy) as? [String: Any])
    object["control"] = ["required": true]
    let policy = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    let control = TestControlValidator()
    let authorizer = try NativeRequestAuthorizer(policyData: policy, controlValidator: control)
    _ = try authorizer.authorize(requestData: fixture.signedRequest(), nowMilliseconds: 1_800_000_000_000)
    control.blocked = true
    #expect(throws: AgentPassNativeError.self) {
        try authorizer.authorize(requestData: fixture.signedRequest(nonce: String(repeating: "c", count: 32)), nowMilliseconds: 1_800_000_000_000)
    }
}

@Test func nativeAuthorizerFailsClosedWhenControlBundleV2IsConfiguredWithoutV2Wiring() throws {
    let fixture = try AuthorizerFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    var object = try #require(JSONSerialization.jsonObject(with: fixture.policy) as? [String: Any])
    object["control_v2"] = ["required": true, "capability_required": true, "public_key": "pinned", "issuer": "agentpass-cloud", "key_id": "control-v2", "organization_id": "11111111-1111-4111-8111-111111111111", "device_id": "22222222-2222-4222-8222-222222222222"]
    #expect(throws: AgentPassNativeError.self) {
        try NativeRequestAuthorizer(policyData: JSONSerialization.data(withJSONObject: object))
    }
}

@Test func nativeRequestEvidencePersistsRequestCapabilityBindingAcrossRestart() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("request-evidence.json").path
    let requestID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let capabilityID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    let store = try NativeRequestEvidenceStore(path: path)
    try store.record(requestID: requestID, capabilityID: capabilityID, capabilitySequence: 9)
    let restarted = try NativeRequestEvidenceStore(path: path)
    #expect(restarted.evidence(for: requestID)?.capabilityID == capabilityID)
    #expect(throws: AgentPassNativeError.self) { try restarted.record(requestID: requestID, capabilityID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", capabilitySequence: 10) }
}
