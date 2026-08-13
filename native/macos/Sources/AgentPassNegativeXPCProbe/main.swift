import AgentPassNativeCore
import Foundation
import Security

private let protocolVersion = 1

private struct IdentityObservation: Encodable {
    let schema_version: Int
    let bundle_id: String
    let team_id: String?
    let designated_requirement: String
    let entitlements: [String: [String]]
    let signature_kind: String
}

private struct QualificationObservation: Encodable {
    let schema_version: Int
    let operation: String
    let outcome: String
    let service_protocol_version: Int?
}

private func emit<T: Encodable>(_ value: T, status: Int32 = 0) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    guard let data = try? encoder.encode(value) else { exit(2) }
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(status)
}

private func fail(_ message: String, status: Int32 = 1) -> Never {
    // The qualification lane must never expose Security.framework descriptions,
    // certificate data, or XPC errors as evidence. Keep local failures generic.
    _ = message
    emit(QualificationObservation(schema_version: protocolVersion, operation: "local", outcome: "probe-failed", service_protocol_version: nil), status: status)
}

private func signingInformation() throws -> [String: Any] {
    let path = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(path as CFURL, [], &code) == errSecSuccess, let code else {
        throw AgentPassNativeError.invalidSignature("Self code identity unavailable")
    }
    var raw: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
          let dictionary = raw as? [String: Any] else {
        throw AgentPassNativeError.invalidSignature("Self code identity unavailable")
    }
    return dictionary
}

private func stringValue(_ information: [String: Any], _ key: CFString) -> String? {
    information[key as String] as? String
}

private func requirementString(_ information: [String: Any]) -> String {
    guard let requirement = information[kSecCodeInfoDesignatedRequirement as String] else { return "(adhoc)" }
    var output: CFString?
    guard SecRequirementCopyString(requirement as! SecRequirement, SecCSFlags(), &output) == errSecSuccess,
          let output else { return "(unavailable)" }
    return output as String
}

private func entitlements() -> [String: [String]] {
    guard let task = SecTaskCreateFromSelf(nil),
          let raw = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil),
          let values = raw as? [String] else { return [:] }
    return ["keychain-access-groups": values]
}

private func observeIdentity() throws -> IdentityObservation {
    let information = try signingInformation()
    guard let bundleID = stringValue(information, kSecCodeInfoIdentifier), !bundleID.isEmpty else {
        throw AgentPassNativeError.invalidSignature("Self bundle identity unavailable")
    }
    let teamID = stringValue(information, kSecCodeInfoTeamIdentifier)
    let certificateCount: Int
    if let certificates = information[kSecCodeInfoCertificates as String] as? [Any] {
        certificateCount = certificates.count
    } else if let certificates = information[kSecCodeInfoCertificates as String] as? NSArray {
        certificateCount = certificates.count
    } else {
        certificateCount = 0
    }
    return IdentityObservation(
        schema_version: protocolVersion,
        bundle_id: bundleID,
        team_id: teamID,
        designated_requirement: requirementString(information),
        entitlements: entitlements(),
        signature_kind: certificateCount > 0 ? "developer-id" : "ad-hoc"
    )
}

private func qualify(serviceName: String) -> Never {
    guard !serviceName.isEmpty, serviceName.utf8.count <= 256 else { fail("invalid service") }
    let connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
    connection.remoteObjectInterface = NSXPCInterface(with: AgentPassNativeServiceProtocol.self)
    connection.invalidationHandler = { }
    connection.interruptionHandler = { }
    connection.resume()
    defer { connection.invalidate() }

    let semaphore = DispatchSemaphore(value: 0)
    var observation: QualificationObservation?
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
        // A code-signing requirement failure is surfaced through this path and
        // occurs before the exported health method (and therefore before sign).
        observation = QualificationObservation(schema_version: protocolVersion, operation: "qualification-health", outcome: "denied-before-signing", service_protocol_version: nil)
        semaphore.signal()
    } as! AgentPassNativeServiceProtocol
    proxy.health { health in
        let healthy = health["ok"] as? Bool == true
        let version = health["protocol_version"] as? Int
        observation = QualificationObservation(schema_version: protocolVersion, operation: "qualification-health", outcome: healthy ? "allowlisted-method-reached" : "method-reached-but-unhealthy", service_protocol_version: version)
        semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + 20) == .timedOut { fail("qualification timed out") }
    guard let observation else { fail("qualification did not produce a result") }
    emit(observation, status: observation.outcome == "method-reached-but-unhealthy" ? 1 : 0)
}

/// Probe only the qualification listener's caller boundary. The request uses
/// fixed, non-secret, deliberately non-matching digests: an authorized caller
/// must reach `readStatus` and receive the endpoint's stable binding error,
/// while every unauthorized identity must fail in the proxy error handler
/// before the selector is dispatched.
private func qualifyController() -> Never {
    let candidateDigest = Data(repeating: 0xa5, count: AgentPassQualificationXPCContract.digestBytes)
    let runIDDigest = Data(repeating: 0x5a, count: AgentPassQualificationXPCContract.digestBytes)
    guard let request = AgentPassQualificationStatusRequest(
        candidateDigest: candidateDigest,
        runIDDigest: runIDDigest
    ) else { fail("qualification-controller request creation failed") }

    let connection = NSXPCConnection(
        machServiceName: AgentPassQualificationXPCContract.machServiceName,
        options: .privileged
    )
    connection.remoteObjectInterface = AgentPassQualificationXPCContract.makeInterface()
    connection.invalidationHandler = { }
    connection.interruptionHandler = { }
    connection.resume()
    defer { connection.invalidate() }

    let semaphore = DispatchSemaphore(value: 0)
    var observation: QualificationObservation?
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
        observation = QualificationObservation(
            schema_version: protocolVersion,
            operation: "qualification-controller-status",
            outcome: "denied-before-selector",
            service_protocol_version: nil
        )
        semaphore.signal()
    } as! AgentPassQualificationXPCProtocol
    proxy.readStatus(request) { response, error in
        let outcome: String
        let version: Int?
        if error != nil {
            outcome = "selector-reached-binding-rejected"
            version = nil
        } else if let response {
            outcome = "selector-reached-unexpected-response"
            version = response.protocolVersion
        } else {
            outcome = "selector-reached-invalid-reply"
            version = nil
        }
        observation = QualificationObservation(
            schema_version: protocolVersion,
            operation: "qualification-controller-status",
            outcome: outcome,
            service_protocol_version: version
        )
        semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + 20) == .timedOut {
        fail("qualification-controller timed out")
    }
    guard let observation else { fail("qualification-controller produced no result") }
    emit(observation, status: observation.outcome == "selector-reached-unexpected-response" || observation.outcome == "selector-reached-invalid-reply" ? 1 : 0)
}

guard CommandLine.arguments.count >= 2 else { fail("missing command", status: 2) }
switch CommandLine.arguments[1] {
case "identity":
    do { emit(try observeIdentity()) } catch { fail("identity observation failed") }
case "--service":
    guard CommandLine.arguments.count == 4, CommandLine.arguments[3] == "qualification" else { fail("invalid qualification command", status: 2) }
    qualify(serviceName: CommandLine.arguments[2])
case "qualification-controller":
    guard CommandLine.arguments.count == 2 else { fail("invalid qualification-controller command", status: 2) }
    qualifyController()
default:
    fail("unknown command", status: 2)
}
