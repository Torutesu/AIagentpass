import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

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

    func signedRequest(nonce: String = String(repeating: "n", count: 32), payloadOverride: Data? = nil, timestamp: Int64 = 1_800_000_000_000, session: String? = nil) throws -> Data {
        var request: [String: Any] = [
            "operation": "git.commit.sign",
            "cwd": repository.path,
            "sign_args": ["-Y", "sign", "-n", "git", "-f", "/tmp/untrusted"],
            "payload_base64": (payloadOverride ?? payload).base64EncodedString(),
            "session": session ?? NSNull(),
            "agent_id": "11111111-1111-4111-8111-111111111111",
            "timestamp_ms": timestamp,
            "nonce": nonce
        ]
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
