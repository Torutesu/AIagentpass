import AgentPassNativeCore
import Darwin
import Foundation
import Security

private let bundleID = "dev.agentpass.legacy-service-migration"
private let maximumInput = 64 * 1024

private struct Configuration {
    let teamID: String
    let appVersion: String
    let initialHead: String
    let expectedCDHash: String
}

private struct Operation {
    let id: UUID
    let nonce: String
    let role: NativeKeyRole
    let order: Int
    let initialHead: String
    let previousHead: String
    let issuedAt: String
    let expiresAt: String
}

private struct SigningIdentity {
    let identifier: String
    let teamID: String
    let cdHash: String
    let appVersion: String
}

private enum MigrationCLIError: Error, CustomStringConvertible {
    case message(String)
    var description: String { if case let .message(value) = self { return value }; return "migration error" }
}

@main
private enum ServiceMigrationMain {
    static func main() {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            if arguments == ["--help"] || arguments == ["help"] { printUsage(); return }
            guard geteuid() == 0, getuid() == 0 else { throw failure("service migration helper must run with real and effective uid 0") }
            guard arguments.count == 3, ["prepare", "prove"].contains(arguments[0]), arguments[1] == "--config" else {
                throw failure("unknown or incomplete command")
            }
            let config = try loadConfiguration(path: arguments[2], expectedOwner: 0)
            let identity = try currentIdentity()
            try validate(identity: identity, config: config)
            let input = try readStandardInput()
            let output: Data
            switch arguments[0] {
            case "prepare": output = try prepare(operationData: input, config: config, identity: identity)
            case "prove": output = try prove(planData: input, config: config, identity: identity)
            default: throw failure("unknown command")
            }
            FileHandle.standardOutput.write(output)
        } catch {
            FileHandle.standardError.write(Data("agentpass-legacy-service-migration: \(error)\n".utf8))
            exit(1)
        }
    }

    private static func printUsage() {
        print("Usage: agentpass-legacy-service-migration {prepare|prove} --config CONFIG\nCanonical operation/plan is read from stdin; canonical artifact is written to stdout.")
    }
}

private func prepare(operationData: Data, config: Configuration, identity: SigningIdentity) throws -> Data {
    let operation = try decodeOperation(operationData)
    guard operation.role == .gitSigning || operation.role == .auditCheckpoint,
          operation.order == (operation.role == .gitSigning ? 2 : 3),
          operation.initialHead == config.initialHead else {
        throw failure("operation is not an exact service-role migration")
    }
    try validateWindow(issuedAt: operation.issuedAt, expiresAt: operation.expiresAt)
    let sourceGroup = "\(config.teamID).\(NativeLegacyMigrationV017.sourceAccessGroupSuffix)"
    let targetGroup = "\(config.teamID).\(NativeLegacyMigrationV017.serviceAccessGroupSuffix)"
    guard let oldTag = NativeLegacyMigrationV017.oldApplicationTags[operation.role],
          let newTag = NativeLegacyMigrationV017.newApplicationTags[operation.role] else { throw failure("role tag is unavailable") }
    let oldKey = try SecureEnclaveKeyStore.loadExisting(applicationTag: oldTag, accessGroup: sourceGroup)
    let replacement = try loadOrCreate(tag: newTag, group: targetGroup, requiresUserPresence: false)
    let plan = NativeLegacyMigrationPlan(
        operationID: operation.id, nonce: operation.nonce, role: operation.role, roleOrder: operation.order,
        sourceAccessGroup: sourceGroup, targetAccessGroup: targetGroup,
        helperIdentity: .init(bundleID: identity.identifier, teamID: identity.teamID, codeDirectoryHash: identity.cdHash),
        appVersion: config.appVersion, initialLifecycleHead: operation.initialHead,
        previousLifecycleHead: operation.previousHead, issuedAt: operation.issuedAt, expiresAt: operation.expiresAt,
        binding: .init(role: operation.role, oldApplicationTag: oldTag, newApplicationTag: newTag,
                       oldPublicKeyX963: oldKey.publicKeyX963, newPublicKeyX963: replacement.publicKeyX963)
    )
    return try plan.canonicalData()
}

private func prove(planData: Data, config: Configuration, identity: SigningIdentity) throws -> Data {
    let plan = try NativeLegacyMigrationPlan.decodeCanonical(planData)
    try validate(plan: plan, config: config, identity: identity)
    guard plan.role == .gitSigning || plan.role == .auditCheckpoint,
          plan.roleOrder == (plan.role == .gitSigning ? 2 : 3) else { throw failure("service helper refuses this role") }
    let oldKey = try SecureEnclaveKeyStore.loadExisting(applicationTag: plan.binding.oldApplicationTag, accessGroup: plan.sourceAccessGroup)
    let replacement = try SecureEnclaveKeyStore.loadExisting(applicationTag: plan.binding.newApplicationTag, accessGroup: plan.targetAccessGroup)
    guard oldKey.publicKeyX963 == plan.binding.oldPublicKeyX963, replacement.publicKeyX963 == plan.binding.newPublicKeyX963 else {
        throw failure("plan public keys do not match exact Keychain bindings")
    }
    return try canonical([
        "version": 1,
        "plan": planData.base64EncodedString(),
        "old_role_signature": try oldKey.sign(message: plan.oldRoleSigningData()).base64EncodedString(),
        "replacement_key_signature": try replacement.sign(message: plan.replacementProofData()).base64EncodedString()
    ])
}

private func validate(plan: NativeLegacyMigrationPlan, config: Configuration, identity: SigningIdentity) throws {
    let expectedSource = "\(config.teamID).\(NativeLegacyMigrationV017.sourceAccessGroupSuffix)"
    let expectedTarget = "\(config.teamID).\(NativeLegacyMigrationV017.serviceAccessGroupSuffix)"
    guard plan.helperIdentity == .init(bundleID: identity.identifier, teamID: identity.teamID, codeDirectoryHash: identity.cdHash),
          plan.appVersion == config.appVersion, plan.initialLifecycleHead == config.initialHead,
          plan.sourceAccessGroup == expectedSource, plan.targetAccessGroup == expectedTarget,
          plan.binding.role == plan.role,
          plan.binding.oldApplicationTag == NativeLegacyMigrationV017.oldApplicationTags[plan.role],
          plan.binding.newApplicationTag == NativeLegacyMigrationV017.newApplicationTags[plan.role] else {
        throw failure("plan does not match this signed helper and exact migration configuration")
    }
    try validateWindow(issuedAt: plan.issuedAt, expiresAt: plan.expiresAt)
}

private func loadOrCreate(tag: String, group: String, requiresUserPresence: Bool) throws -> SecureEnclaveKeyStore {
    if try SecureEnclaveKeyStore.exists(applicationTag: tag, accessGroup: group) {
        return try SecureEnclaveKeyStore.loadExisting(applicationTag: tag, accessGroup: group)
    }
    return try SecureEnclaveKeyStore.create(applicationTag: tag, accessGroup: group, requiresUserPresence: requiresUserPresence)
}

private func decodeOperation(_ data: Data) throws -> Operation {
    let keys: Set<String> = ["version", "operation_id", "nonce", "role", "role_order", "initial_lifecycle_head", "previous_lifecycle_head", "issued_at", "expires_at"]
    guard data.count <= 16 * 1024,
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
          try canonical(object) == data, strictInteger(object["version"]) == 1,
          let idText = object["operation_id"] as? String, let id = UUID(uuidString: idText), id.uuidString.lowercased() == idText,
          let nonce = object["nonce"] as? String, nonce.range(of: "^[0-9a-f]{32,128}$", options: .regularExpression) != nil,
          let roleText = object["role"] as? String, let role = NativeKeyRole(rawValue: roleText),
          let order = strictInteger(object["role_order"]),
          let initial = object["initial_lifecycle_head"] as? String, isHash(initial),
          let previous = object["previous_lifecycle_head"] as? String, isHash(previous),
          let issued = object["issued_at"] as? String, let expires = object["expires_at"] as? String else {
        throw failure("stdin is not the exact canonical operation schema")
    }
    return Operation(id: id, nonce: nonce, role: role, order: order, initialHead: initial, previousHead: previous, issuedAt: issued, expiresAt: expires)
}

private func loadConfiguration(path: String, expectedOwner: uid_t) throws -> Configuration {
    let data = try readSecureFile(path: path, maximum: 16 * 1024, expectedOwner: expectedOwner)
    let keys: Set<String> = ["version", "team_id", "app_version", "initial_lifecycle_head", "expected_cdhash"]
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
          try canonical(object) == data, strictInteger(object["version"]) == 1,
          let team = object["team_id"] as? String, team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
          let version = object["app_version"] as? String, version.range(of: "^[0-9]+\\.[0-9]+\\.[0-9]+$", options: .regularExpression) != nil,
          let head = object["initial_lifecycle_head"] as? String, isHash(head),
          let cdHash = object["expected_cdhash"] as? String, cdHash.range(of: "^[0-9a-f]{40,128}$", options: .regularExpression) != nil else {
        throw failure("configuration is not exact canonical schema")
    }
    return Configuration(teamID: team, appVersion: version, initialHead: head, expectedCDHash: cdHash)
}

private func currentIdentity() throws -> SigningIdentity {
    guard let executableURL = Bundle.main.executableURL else { throw failure("cannot resolve the running executable") }
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(executableURL as CFURL, [], &code) == errSecSuccess, let code,
          SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess else {
        throw failure("cannot validate the running executable code signature")
    }
    var raw: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
          let info = raw as? [String: Any],
          let identifier = info[kSecCodeInfoIdentifier as String] as? String,
          let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
          let unique = info[kSecCodeInfoUnique as String] as? Data,
          let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String else {
        throw failure("production Team ID/CDHash/bundle version is unavailable; ad-hoc artifacts cannot migrate keys")
    }
    return SigningIdentity(identifier: identifier, teamID: team, cdHash: unique.map { String(format: "%02x", $0) }.joined(), appVersion: appVersion)
}

private func validate(identity: SigningIdentity, config: Configuration) throws {
    guard identity.identifier == bundleID, identity.teamID == config.teamID, identity.cdHash == config.expectedCDHash,
          identity.appVersion == config.appVersion else {
        throw failure("actual signed identity does not match the pinned migration configuration")
    }
}

private func validateWindow(issuedAt: String, expiresAt: String) throws {
    let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard let issued = formatter.date(from: issuedAt), let expires = formatter.date(from: expiresAt), issued < expires,
          expires.timeIntervalSince(issued) <= 3600, Date() >= issued, Date() < expires else { throw failure("operation is premature, expired, or exceeds one hour") }
}

private func readStandardInput() throws -> Data {
    var result = Data(); var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let capacity = min(buffer.count, maximumInput + 1 - result.count)
        let count = buffer.withUnsafeMutableBytes { Darwin.read(STDIN_FILENO, $0.baseAddress, capacity) }
        guard count >= 0 else { if errno == EINTR { continue }; throw failure("stdin read failed") }
        if count == 0 { break }
        result.append(buffer, count: count)
        guard result.count <= maximumInput else { throw failure("stdin exceeds \(maximumInput) bytes") }
    }
    guard !result.isEmpty else { throw failure("stdin is empty") }
    return result
}

private func readSecureFile(path: String, maximum: Int, expectedOwner: uid_t) throws -> Data {
    guard !path.isEmpty, path.utf8.count <= 4096 else { throw failure("configuration path is invalid") }
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw failure("configuration must be an existing non-symlink file") }
    defer { close(descriptor) }
    var before = stat(); guard fstat(descriptor, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG,
          before.st_uid == expectedOwner, before.st_mode & 0o077 == 0, before.st_nlink == 1,
          before.st_size > 0, before.st_size <= maximum else { throw failure("configuration ownership, mode, links, or size is unsafe") }
    let data = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false).readDataToEndOfFile()
    var after = stat(), named = stat()
    guard fstat(descriptor, &after) == 0, lstat(path, &named) == 0,
          before.st_dev == after.st_dev, before.st_ino == after.st_ino, before.st_size == after.st_size,
          after.st_dev == named.st_dev, after.st_ino == named.st_ino, data.count == Int(after.st_size) else { throw failure("configuration changed while being read") }
    return data
}

private func isHash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
private func strictInteger(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
    guard Set(["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"]).contains(String(cString: number.objCType)) else { return nil }
    return number.intValue
}
private func canonical(_ object: [String: Any]) throws -> Data {
    guard JSONSerialization.isValidJSONObject(object) else { throw failure("artifact contains a non-JSON value") }
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    guard data.count <= maximumInput else { throw failure("canonical artifact exceeds the size limit") }
    return data
}
private func failure(_ value: String) -> MigrationCLIError { .message(value) }
