import CryptoKit
import Foundation

public struct AuthorizedSignRequest: Sendable {
    public let payload: Data
    public let agentID: String
    public let repository: String
    public let branch: String
    public let remote: String
}

public final class NativeRequestAuthorizer: @unchecked Sendable {
    private let policy: Policy
    private let sessionValidator: (any NativeSessionValidating)?
    private let controlValidator: (any NativeControlValidating)?
    private var replayCache: [String: Int64] = [:]
    private let lock = NSLock()

    public init(policyData: Data, sessionValidator: (any NativeSessionValidating)? = nil, controlValidator: (any NativeControlValidating)? = nil) throws {
        policy = try JSONDecoder().decode(Policy.self, from: policyData)
        self.sessionValidator = sessionValidator
        self.controlValidator = controlValidator
        guard policy.version == 4, !policy.agents.isEmpty else {
            throw AgentPassNativeError.invalidConfiguration("Native broker requires a version 4 policy with enrolled agents")
        }
        guard !policy.session.required || sessionValidator != nil else {
            throw AgentPassNativeError.invalidConfiguration("Native broker requires a protected session validator when session.required=true")
        }
        guard policy.control == nil || controlValidator != nil else {
            throw AgentPassNativeError.invalidConfiguration("Native broker requires protected remote-control state when control is configured")
        }
        for agent in policy.agents {
            _ = try Self.ed25519Key(fromPEM: agent.publicKey)
            try Self.validate(scope: agent.scope)
        }
        try Self.validate(scope: policy.globalScope)
    }

    public func authorize(requestData: Data, nowMilliseconds: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws -> AuthorizedSignRequest {
        guard requestData.count > 0, requestData.count <= 12 * 1024 * 1024 else {
            throw AgentPassNativeError.unauthorizedClient("Native broker request size is invalid")
        }
        let request = try JSONDecoder().decode(SignRequest.self, from: requestData)
        guard request.operation == "git.commit.sign" else {
            throw AgentPassNativeError.unauthorizedClient("Unsupported native broker operation")
        }
        guard request.timestampMilliseconds >= nowMilliseconds - 60_000,
              request.timestampMilliseconds <= nowMilliseconds + 60_000 else {
            throw AgentPassNativeError.unauthorizedClient("Agent request timestamp is outside the allowed window")
        }
        guard request.nonce.count >= 32, request.nonce.count <= 256 else {
            throw AgentPassNativeError.unauthorizedClient("Agent request nonce is invalid")
        }
        guard let agent = policy.agents.first(where: { $0.id == request.agentID }) else {
            throw AgentPassNativeError.unauthorizedClient("Unknown agent identity")
        }
        let signature = try strictBase64(request.signature, label: "Agent request signature")
        guard signature.count == 64 else { throw AgentPassNativeError.unauthorizedClient("Agent request signature is invalid") }
        let canonical = try Self.canonicalUnsignedRequest(requestData)
        let key = try Self.ed25519Key(fromPEM: agent.publicKey)
        guard key.isValidSignature(signature, for: canonical) else {
            throw AgentPassNativeError.unauthorizedClient("Agent request signature is invalid")
        }
        try consumeNonce(request.nonce, nowMilliseconds: nowMilliseconds)
        try controlValidator?.validateControl(agentID: agent.id, nowMilliseconds: nowMilliseconds)
        try sessionValidator?.validateSession(token: request.session, agentID: agent.id, nowMilliseconds: nowMilliseconds)

        let payload = try strictBase64(request.payloadBase64, label: "Signing payload")
        guard !payload.isEmpty, payload.count <= 8 * 1024 * 1024 else {
            throw AgentPassNativeError.unauthorizedClient("Signing payload size is invalid")
        }
        let context = try trustedGitContext(request.cwd)
        try validate(scope: policy.globalScope, context: context)
        do { try validate(scope: agent.scope, context: context) }
        catch { throw AgentPassNativeError.unauthorizedClient("Agent scope denied the request: \(error.localizedDescription)") }
        try validateCommit(payload: payload, repository: context.repository)
        return AuthorizedSignRequest(payload: payload, agentID: agent.id, repository: context.repository, branch: context.branch, remote: context.remote)
    }

    private func consumeNonce(_ nonce: String, nowMilliseconds: Int64) throws {
        lock.lock()
        defer { lock.unlock() }
        replayCache = replayCache.filter { $0.value > nowMilliseconds }
        guard replayCache[nonce] == nil else { throw AgentPassNativeError.unauthorizedClient("Agent request replay detected") }
        guard replayCache.count < 10_000 else { throw AgentPassNativeError.unauthorizedClient("Agent replay cache capacity exceeded") }
        replayCache[nonce] = nowMilliseconds + 120_000
    }

    private func trustedGitContext(_ requestedPath: String) throws -> Context {
        guard requestedPath.hasPrefix("/") else { throw AgentPassNativeError.unauthorizedClient("Repository path must be absolute") }
        let root = try git(directory: requestedPath, arguments: ["rev-parse", "--show-toplevel"])
        let resolved = URL(fileURLWithPath: root).resolvingSymlinksInPath().standardizedFileURL.path
        let branch = try git(directory: resolved, arguments: ["branch", "--show-current"], optional: true)
        let remote = try git(directory: resolved, arguments: ["remote", "get-url", "origin"], optional: true)
        return Context(repository: resolved, branch: branch.isEmpty ? "HEAD" : branch, remote: remote)
    }

    private func validate(scope: Scope, context: Context) throws {
        guard scope.operations.contains(where: { Self.glob("git.commit.sign", matches: $0) }) else { throw AgentPassNativeError.unauthorizedClient("operation_not_allowed") }
        let allowedRepository = scope.repositories.contains { configured in
            URL(fileURLWithPath: configured).resolvingSymlinksInPath().standardizedFileURL.path == context.repository
        }
        guard allowedRepository else { throw AgentPassNativeError.unauthorizedClient("repository_not_allowed") }
        if scope.branches.deny?.contains(where: { Self.glob(context.branch, matches: $0) }) == true { throw AgentPassNativeError.unauthorizedClient("branch_denied") }
        guard scope.branches.allow.contains(where: { Self.glob(context.branch, matches: $0) }) else { throw AgentPassNativeError.unauthorizedClient("branch_not_allowed") }
        if scope.remotes.deny?.contains(where: { Self.glob(context.remote, matches: $0) }) == true { throw AgentPassNativeError.unauthorizedClient("remote_denied") }
        guard scope.remotes.allow.contains(where: { Self.glob(context.remote, matches: $0) }) else { throw AgentPassNativeError.unauthorizedClient("remote_not_allowed") }
    }

    private func validateCommit(payload: Data, repository: String) throws {
        guard let text = String(data: payload, encoding: .utf8), let separator = text.range(of: "\n\n") else {
            throw AgentPassNativeError.unauthorizedClient("Signing payload is not a Git commit object")
        }
        let headers = text[..<separator.lowerBound].split(separator: "\n").map(String.init)
        guard let tree = headers.first(where: { $0.hasPrefix("tree ") })?.dropFirst(5),
              headers.contains(where: { $0.hasPrefix("author ") }),
              headers.contains(where: { $0.hasPrefix("committer ") }),
              Self.isObjectID(String(tree)) else {
            throw AgentPassNativeError.unauthorizedClient("Signing payload contains invalid commit headers")
        }
        let parents = headers.filter { $0.hasPrefix("parent ") }.map { String($0.dropFirst(7)) }
        guard parents.allSatisfy(Self.isObjectID) else { throw AgentPassNativeError.unauthorizedClient("Signing payload contains an invalid parent") }
        guard String(tree) == (try git(directory: repository, arguments: ["write-tree"])) else {
            throw AgentPassNativeError.unauthorizedClient("Signing payload tree does not match the repository index")
        }
        let head = try git(directory: repository, arguments: ["rev-parse", "--verify", "HEAD"], optional: true)
        if head.isEmpty {
            guard parents.isEmpty else { throw AgentPassNativeError.unauthorizedClient("Initial commit payload must not contain a parent") }
            return
        }
        var expected = [head]
        let mergePath = try git(directory: repository, arguments: ["rev-parse", "--git-path", "MERGE_HEAD"], optional: true)
        if !mergePath.isEmpty {
            let absolute = mergePath.hasPrefix("/") ? mergePath : URL(fileURLWithPath: repository).appendingPathComponent(mergePath).path
            if FileManager.default.fileExists(atPath: absolute) {
                let attributes = try FileManager.default.attributesOfItem(atPath: absolute)
                guard (attributes[.type] as? FileAttributeType) == .typeRegular else { throw AgentPassNativeError.unauthorizedClient("MERGE_HEAD is not a regular file") }
                let mergeHeads = try String(contentsOfFile: absolute, encoding: .utf8).split(whereSeparator: \.isNewline).map(String.init)
                guard !mergeHeads.isEmpty, mergeHeads.allSatisfy(Self.isObjectID) else { throw AgentPassNativeError.unauthorizedClient("MERGE_HEAD is invalid") }
                expected.append(contentsOf: mergeHeads)
            }
        }
        guard parents == expected else { throw AgentPassNativeError.unauthorizedClient("Signing payload parents do not match HEAD and MERGE_HEAD") }
    }

    private func git(directory: String, arguments: [String], optional: Bool = false) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-c", "safe.directory=*", "-C", directory] + arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty"]
        let output = Pipe(), errors = Pipe()
        process.standardOutput = output
        process.standardError = errors
        do { try process.run() }
        catch { if optional { return "" }; throw error }
        process.waitUntilExit()
        if process.terminationStatus != 0 {
            if optional { return "" }
            let detail = String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            throw AgentPassNativeError.unauthorizedClient(detail?.isEmpty == false ? detail! : "Git context verification failed")
        }
        return (String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func canonicalUnsignedRequest(_ data: Data) throws -> Data {
        guard var object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AgentPassNativeError.unauthorizedClient("Agent request JSON must be an object")
        }
        object.removeValue(forKey: "signature")
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func ed25519Key(fromPEM pem: String) throws -> Curve25519.Signing.PublicKey {
        let body = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
        guard let der = Data(base64Encoded: body), der.count == 44,
              der.prefix(12) == Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) else {
            throw AgentPassNativeError.invalidConfiguration("Agent public key must be Ed25519 SPKI PEM")
        }
        return try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32))
    }

    private static func validate(scope: Scope) throws {
        guard !scope.operations.isEmpty, !scope.repositories.isEmpty, !scope.branches.allow.isEmpty,
              scope.repositories.allSatisfy({ $0.hasPrefix("/") }) else {
            throw AgentPassNativeError.invalidConfiguration("Native policy scopes must explicitly allow operations, absolute repositories, and branches")
        }
    }

    private static func glob(_ value: String, matches pattern: String) -> Bool {
        let escaped = NSRegularExpression.escapedPattern(for: pattern).replacingOccurrences(of: "\\*", with: ".*")
        return value.range(of: "^\(escaped)$", options: .regularExpression) != nil
    }

    private static func isObjectID(_ value: String) -> Bool {
        (40...64).contains(value.count) && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }
}

private func strictBase64(_ value: String, label: String) throws -> Data {
    guard value.count % 4 == 0, value.range(of: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", options: .regularExpression) != nil,
          let decoded = Data(base64Encoded: value) else {
        throw AgentPassNativeError.unauthorizedClient("\(label) is not valid Base64")
    }
    return decoded
}

private struct Context { let repository: String; let branch: String; let remote: String }
private struct Rules: Decodable { let allow: [String]; let deny: [String]? }
private struct Scope: Decodable { let operations: [String]; let repositories: [String]; let branches: Rules; let remotes: Rules }
private struct SessionPolicy: Decodable { let required: Bool }
private struct Agent: Decodable {
    let id: String
    let publicKey: String
    let scope: Scope
    enum CodingKeys: String, CodingKey { case id, scope; case publicKey = "public_key" }
}
private struct Policy: Decodable {
    let version: Int
    let agents: [Agent]
    let operations: [String]
    let repositories: [String]
    let branches: Rules
    let remotes: Rules
    let session: SessionPolicy
    let control: JSONValue?
    var globalScope: Scope { Scope(operations: operations, repositories: repositories, branches: branches, remotes: remotes) }
}
private enum JSONValue: Decodable { case value
    init(from decoder: Decoder) throws { self = .value }
}
private struct SignRequest: Decodable {
    let operation: String
    let cwd: String
    let payloadBase64: String
    let agentID: String
    let timestampMilliseconds: Int64
    let nonce: String
    let session: String?
    let signature: String
    enum CodingKeys: String, CodingKey {
        case operation, cwd, nonce, session, signature
        case payloadBase64 = "payload_base64"
        case agentID = "agent_id"
        case timestampMilliseconds = "timestamp_ms"
    }
}
