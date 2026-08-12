import AgentPassNativeCore
import Darwin
import Foundation
import LocalAuthentication
import Security

private let bundleID = "dev.agentpass.legacy-approval-migration"
private let serviceBundleID = "dev.agentpass.legacy-service-migration"
private let maximumInput = 64 * 1024

private struct Configuration {
    let teamID: String
    let appVersion: String
    let initialHead: String
    let expectedCDHash: String
    let allowedServiceCDHash: String
}

private struct Operation {
    let id: UUID; let nonce: String; let role: NativeKeyRole; let order: Int
    let initialHead: String; let previousHead: String; let issuedAt: String; let expiresAt: String
}

private struct SigningIdentity { let identifier: String; let teamID: String; let cdHash: String; let appVersion: String }
private struct RoleProof { let planData: Data; let oldSignature: Data; let replacementSignature: Data }

private enum MigrationCLIError: Error, CustomStringConvertible {
    case message(String)
    var description: String { if case let .message(value) = self { return value }; return "migration error" }
}

@main
private enum ApprovalMigrationMain {
    static func main() async {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            if arguments == ["--help"] || arguments == ["help"] { printUsage(); return }
            guard geteuid() != 0, getuid() == geteuid() else { throw failure("approval migration helper requires a non-root interactive user without uid switching") }
            guard arguments.count == 3, ["prepare", "prove", "approve", "sign-completion"].contains(arguments[0]), arguments[1] == "--config" else {
                throw failure("unknown or incomplete command")
            }
            let config = try loadConfiguration(path: arguments[2], expectedOwner: geteuid())
            let identity = try currentIdentity(); try validate(identity: identity, config: config)
            try await requireHumanPresence(reason: "Approve the one-time AgentPass v0.17 key migration")
            let input = try readStandardInput()
            let output: Data
            switch arguments[0] {
            case "prepare": output = try prepare(operationData: input, config: config, identity: identity)
            case "prove": output = try prove(planData: input, config: config, identity: identity)
            case "approve": output = try approve(roleProofData: input, config: config)
            case "sign-completion": output = try signCompletion(unsignedData: input, config: config)
            default: throw failure("unknown command")
            }
            FileHandle.standardOutput.write(output)
        } catch {
            FileHandle.standardError.write(Data("agentpass-legacy-approval-migration: \(error)\n".utf8)); exit(1)
        }
    }

    private static func printUsage() {
        print("Usage: agentpass-legacy-approval-migration {prepare|prove|approve|sign-completion} --config CONFIG\nCanonical input is read from stdin; canonical artifact is written to stdout. Every command requires local user authentication.")
    }
}

private func prepare(operationData: Data, config: Configuration, identity: SigningIdentity) throws -> Data {
    let operation = try decodeOperation(operationData)
    guard operation.role == .sessionApproval, operation.order == 1, operation.initialHead == config.initialHead,
          operation.previousHead == operation.initialHead else {
        throw failure("approval helper only prepares role 1 session_approval")
    }
    try validateWindow(issuedAt: operation.issuedAt, expiresAt: operation.expiresAt)
    let source = "\(config.teamID).\(NativeLegacyMigrationV017.sourceAccessGroupSuffix)"
    let target = "\(config.teamID).\(NativeLegacyMigrationV017.approvalAccessGroupSuffix)"
    guard let oldTag = NativeLegacyMigrationV017.oldApplicationTags[.sessionApproval],
          let newTag = NativeLegacyMigrationV017.newApplicationTags[.sessionApproval] else { throw failure("approval tags are unavailable") }
    let oldKey = try SecureEnclaveKeyStore.loadExisting(applicationTag: oldTag, accessGroup: source, operationPrompt: "Read the legacy AgentPass approval key")
    let replacement = try loadOrCreateApproval(tag: newTag, group: target)
    return try NativeLegacyMigrationPlan(
        operationID: operation.id, nonce: operation.nonce, role: .sessionApproval, roleOrder: 1,
        sourceAccessGroup: source, targetAccessGroup: target,
        helperIdentity: .init(bundleID: identity.identifier, teamID: identity.teamID, codeDirectoryHash: identity.cdHash),
        appVersion: config.appVersion, initialLifecycleHead: operation.initialHead, previousLifecycleHead: operation.previousHead,
        issuedAt: operation.issuedAt, expiresAt: operation.expiresAt,
        binding: .init(role: .sessionApproval, oldApplicationTag: oldTag, newApplicationTag: newTag,
                       oldPublicKeyX963: oldKey.publicKeyX963, newPublicKeyX963: replacement.publicKeyX963)
    ).canonicalData()
}

private func prove(planData: Data, config: Configuration, identity: SigningIdentity) throws -> Data {
    let plan = try NativeLegacyMigrationPlan.decodeCanonical(planData)
    try validateApprovalPlan(plan, config: config, identity: identity)
    let oldKey = try SecureEnclaveKeyStore.loadExisting(applicationTag: plan.binding.oldApplicationTag, accessGroup: plan.sourceAccessGroup, operationPrompt: "Authorize legacy approval-key continuity")
    let replacement = try SecureEnclaveKeyStore.loadExisting(applicationTag: plan.binding.newApplicationTag, accessGroup: plan.targetAccessGroup, operationPrompt: "Authorize replacement approval-key proof")
    guard oldKey.publicKeyX963 == plan.binding.oldPublicKeyX963, replacement.publicKeyX963 == plan.binding.newPublicKeyX963 else {
        throw failure("plan public keys do not match exact approval Keychain bindings")
    }
    return try fullProof(planData: planData,
                         old: oldKey.sign(message: plan.oldRoleSigningData()),
                         replacement: replacement.sign(message: plan.replacementProofData()),
                         approval: oldKey.sign(message: plan.humanPresenceApprovalData()))
}

private func approve(roleProofData: Data, config: Configuration) throws -> Data {
    let proof = try decodeRoleProof(roleProofData)
    let plan = try NativeLegacyMigrationPlan.decodeCanonical(proof.planData)
    let source = "\(config.teamID).\(NativeLegacyMigrationV017.sourceAccessGroupSuffix)"
    let target = "\(config.teamID).\(NativeLegacyMigrationV017.serviceAccessGroupSuffix)"
    guard plan.role == .gitSigning || plan.role == .auditCheckpoint,
          plan.roleOrder == (plan.role == .gitSigning ? 2 : 3),
          plan.helperIdentity.bundleID == serviceBundleID, plan.helperIdentity.teamID == config.teamID,
          plan.helperIdentity.codeDirectoryHash == config.allowedServiceCDHash,
          plan.appVersion == config.appVersion, plan.initialLifecycleHead == config.initialHead,
          plan.sourceAccessGroup == source, plan.targetAccessGroup == target,
          plan.binding.role == plan.role,
          plan.binding.oldApplicationTag == NativeLegacyMigrationV017.oldApplicationTags[plan.role],
          plan.binding.newApplicationTag == NativeLegacyMigrationV017.newApplicationTags[plan.role] else {
        throw failure("service proof is not bound to the pinned service helper or exact role")
    }
    try validateWindow(issuedAt: plan.issuedAt, expiresAt: plan.expiresAt)
    let verifier = NativeP256LifecycleVerifier()
    guard verifier.isValid(signature: proof.oldSignature, message: try plan.oldRoleSigningData(), publicKeyX963: plan.binding.oldPublicKeyX963),
          verifier.isValid(signature: proof.replacementSignature, message: try plan.replacementProofData(), publicKeyX963: plan.binding.newPublicKeyX963) else {
        throw failure("service role proof signatures are invalid")
    }
    let approvalGroup = "\(config.teamID).\(NativeLegacyMigrationV017.approvalAccessGroupSuffix)"
    guard let tag = NativeLegacyMigrationV017.newApplicationTags[.sessionApproval] else { throw failure("approval tag is unavailable") }
    let approvalKey = try SecureEnclaveKeyStore.loadExisting(applicationTag: tag, accessGroup: approvalGroup, operationPrompt: "Approve \(plan.role.rawValue) migration")
    return try fullProof(planData: proof.planData, old: proof.oldSignature, replacement: proof.replacementSignature,
                         approval: approvalKey.sign(message: plan.humanPresenceApprovalData()))
}

private func signCompletion(unsignedData: Data, config: Configuration) throws -> Data {
    let keys: Set<String> = ["version", "initial_lifecycle_head", "new_lifecycle_head", "roles", "operation_ids", "role_receipt_hashes", "completed_at", "approval_public_key"]
    guard unsignedData.count <= 32 * 1024,
          let object = try JSONSerialization.jsonObject(with: unsignedData) as? [String: Any], Set(object.keys) == keys,
          try canonical(object) == unsignedData, strictInteger(object["version"]) == 1,
          object["initial_lifecycle_head"] as? String == config.initialHead,
          let newHead = object["new_lifecycle_head"] as? String, isHash(newHead), newHead != config.initialHead,
          let roles = object["roles"] as? [String], roles == NativeLegacyMigrationCoordinator.requiredOrder.map(\.rawValue),
          let idTexts = object["operation_ids"] as? [String], idTexts.count == 3, Set(idTexts).count == 3,
          case let ids = idTexts.compactMap(UUID.init(uuidString:)), ids.count == 3,
          zip(idTexts, ids).allSatisfy({ $0.1.uuidString.lowercased() == $0.0 }),
          let hashes = object["role_receipt_hashes"] as? [String], hashes.count == 3, Set(hashes).count == 3, hashes.allSatisfy(isHash),
          let completedAt = object["completed_at"] as? String, let completedDate = parseDate(completedAt),
          completedDate <= Date().addingTimeInterval(60), completedDate >= Date().addingTimeInterval(-3600),
          let keyText = object["approval_public_key"] as? String, let publicKey = Data(base64Encoded: keyText),
          publicKey.base64EncodedString() == keyText, publicKey.count == 65, publicKey.first == 0x04 else {
        throw failure("completion input is not the exact canonical unsigned manifest")
    }
    let group = "\(config.teamID).\(NativeLegacyMigrationV017.approvalAccessGroupSuffix)"
    guard let tag = NativeLegacyMigrationV017.newApplicationTags[.sessionApproval] else { throw failure("approval tag is unavailable") }
    let key = try SecureEnclaveKeyStore.loadExisting(applicationTag: tag, accessGroup: group, operationPrompt: "Finalize the AgentPass migration")
    guard key.publicKeyX963 == publicKey else { throw failure("completion approval key does not match exact migrated key") }
    let unsigned = NativeLegacyMigrationCompletionManifest(initialLifecycleHead: config.initialHead, newLifecycleHead: newHead,
        operationIDs: ids, roleReceiptHashes: hashes, completedAt: completedAt, approvalPublicKeyX963: publicKey, approvalSignature: Data())
    guard try unsigned.unsignedCanonicalData() == unsignedData else { throw failure("completion manifest failed canonical reconstruction") }
    let signature = try key.sign(message: unsignedData)
    return try NativeLegacyMigrationCompletionManifest(initialLifecycleHead: config.initialHead, newLifecycleHead: newHead,
        operationIDs: ids, roleReceiptHashes: hashes, completedAt: completedAt, approvalPublicKeyX963: publicKey, approvalSignature: signature).canonicalData()
}

private func validateApprovalPlan(_ plan: NativeLegacyMigrationPlan, config: Configuration, identity: SigningIdentity) throws {
    guard plan.role == .sessionApproval, plan.roleOrder == 1,
          plan.helperIdentity == .init(bundleID: identity.identifier, teamID: identity.teamID, codeDirectoryHash: identity.cdHash),
          plan.appVersion == config.appVersion, plan.initialLifecycleHead == config.initialHead,
          plan.sourceAccessGroup == "\(config.teamID).\(NativeLegacyMigrationV017.sourceAccessGroupSuffix)",
          plan.targetAccessGroup == "\(config.teamID).\(NativeLegacyMigrationV017.approvalAccessGroupSuffix)",
          plan.binding.role == .sessionApproval,
          plan.binding.oldApplicationTag == NativeLegacyMigrationV017.oldApplicationTags[.sessionApproval],
          plan.binding.newApplicationTag == NativeLegacyMigrationV017.newApplicationTags[.sessionApproval] else {
        throw failure("plan does not match this signed approval helper and exact migration configuration")
    }
    try validateWindow(issuedAt: plan.issuedAt, expiresAt: plan.expiresAt)
}

private func fullProof(planData: Data, old: Data, replacement: Data, approval: Data) throws -> Data {
    try canonical(["version": 1, "plan": planData.base64EncodedString(),
                                  "old_role_signature": old.base64EncodedString(),
                                  "replacement_key_signature": replacement.base64EncodedString(),
                                  "human_presence_approval_signature": approval.base64EncodedString()])
}

private func decodeRoleProof(_ data: Data) throws -> RoleProof {
    let keys: Set<String> = ["version", "plan", "old_role_signature", "replacement_key_signature"]
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
          try canonical(object) == data, strictInteger(object["version"]) == 1,
          let planText = object["plan"] as? String, let plan = Data(base64Encoded: planText), plan.base64EncodedString() == planText,
          let oldText = object["old_role_signature"] as? String, let old = Data(base64Encoded: oldText), old.base64EncodedString() == oldText, old.count == 64,
          let replacementText = object["replacement_key_signature"] as? String, let replacement = Data(base64Encoded: replacementText), replacement.base64EncodedString() == replacementText, replacement.count == 64 else {
        throw failure("stdin is not the exact canonical service role-proof schema")
    }
    return RoleProof(planData: plan, oldSignature: old, replacementSignature: replacement)
}

private func decodeOperation(_ data: Data) throws -> Operation {
    let keys: Set<String> = ["version", "operation_id", "nonce", "role", "role_order", "initial_lifecycle_head", "previous_lifecycle_head", "issued_at", "expires_at"]
    guard data.count <= 16 * 1024,
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
          try canonical(object) == data, strictInteger(object["version"]) == 1,
          let idText = object["operation_id"] as? String, let id = UUID(uuidString: idText), id.uuidString.lowercased() == idText,
          let nonce = object["nonce"] as? String, nonce.range(of: "^[0-9a-f]{32,128}$", options: .regularExpression) != nil,
          let roleText = object["role"] as? String, let role = NativeKeyRole(rawValue: roleText), let order = strictInteger(object["role_order"]),
          let initial = object["initial_lifecycle_head"] as? String, isHash(initial),
          let previous = object["previous_lifecycle_head"] as? String, isHash(previous),
          let issued = object["issued_at"] as? String, let expires = object["expires_at"] as? String else { throw failure("stdin is not the exact canonical operation schema") }
    return Operation(id: id, nonce: nonce, role: role, order: order, initialHead: initial, previousHead: previous, issuedAt: issued, expiresAt: expires)
}

private func loadConfiguration(path: String, expectedOwner: uid_t) throws -> Configuration {
    let data = try readSecureFile(path: path, maximum: 16 * 1024, expectedOwner: expectedOwner)
    let keys: Set<String> = ["version", "team_id", "app_version", "initial_lifecycle_head", "expected_cdhash", "allowed_service_cdhash"]
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == keys,
          try canonical(object) == data, strictInteger(object["version"]) == 1,
          let team = object["team_id"] as? String, team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
          let version = object["app_version"] as? String, version.range(of: "^[0-9]+\\.[0-9]+\\.[0-9]+$", options: .regularExpression) != nil,
          let head = object["initial_lifecycle_head"] as? String, isHash(head),
          let cdHash = object["expected_cdhash"] as? String, isCDHash(cdHash),
          let serviceHash = object["allowed_service_cdhash"] as? String, isCDHash(serviceHash) else { throw failure("configuration is not exact canonical schema") }
    return Configuration(teamID: team, appVersion: version, initialHead: head, expectedCDHash: cdHash, allowedServiceCDHash: serviceHash)
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
          let info = raw as? [String: Any], let identifier = info[kSecCodeInfoIdentifier as String] as? String,
          let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
          let unique = info[kSecCodeInfoUnique as String] as? Data,
          let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String else {
        throw failure("production Team ID/CDHash/bundle version is unavailable; ad-hoc artifacts cannot migrate keys")
    }
    return SigningIdentity(identifier: identifier, teamID: team, cdHash: unique.map { String(format: "%02x", $0) }.joined(), appVersion: appVersion)
}

private func validate(identity: SigningIdentity, config: Configuration) throws {
    guard identity.identifier == bundleID, identity.teamID == config.teamID, identity.cdHash == config.expectedCDHash,
          identity.appVersion == config.appVersion else { throw failure("actual signed identity or bundle version does not match the pinned migration configuration") }
}

private func loadOrCreateApproval(tag: String, group: String) throws -> SecureEnclaveKeyStore {
    if try SecureEnclaveKeyStore.exists(applicationTag: tag, accessGroup: group) {
        return try SecureEnclaveKeyStore.loadExisting(applicationTag: tag, accessGroup: group, operationPrompt: "Use the existing staged approval key")
    }
    return try SecureEnclaveKeyStore.create(applicationTag: tag, accessGroup: group, requiresUserPresence: true)
}

private func requireHumanPresence(reason: String) async throws {
    let context = LAContext(); context.localizedReason = reason
    var evaluationError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else { throw evaluationError ?? failure("local authentication is unavailable") }
    guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else { throw failure("local authentication was denied") }
}

private func validateWindow(issuedAt: String, expiresAt: String) throws {
    guard let issued = parseDate(issuedAt), let expires = parseDate(expiresAt), issued < expires,
          expires.timeIntervalSince(issued) <= 3600, Date() >= issued, Date() < expires else { throw failure("operation is premature, expired, or exceeds one hour") }
}
private func parseDate(_ value: String) -> Date? { let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return formatter.date(from: value) }
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
    guard !result.isEmpty else { throw failure("stdin is empty") }; return result
}

private func readSecureFile(path: String, maximum: Int, expectedOwner: uid_t) throws -> Data {
    guard !path.isEmpty, path.utf8.count <= 4096 else { throw failure("configuration path is invalid") }
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); guard descriptor >= 0 else { throw failure("configuration must be an existing non-symlink file") }; defer { close(descriptor) }
    var before = stat(); guard fstat(descriptor, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG, before.st_uid == expectedOwner,
          before.st_mode & 0o077 == 0, before.st_nlink == 1, before.st_size > 0, before.st_size <= maximum else { throw failure("configuration ownership, mode, links, or size is unsafe") }
    let data = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false).readDataToEndOfFile(); var after = stat(), named = stat()
    guard fstat(descriptor, &after) == 0, lstat(path, &named) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino,
          before.st_size == after.st_size, after.st_dev == named.st_dev, after.st_ino == named.st_ino, data.count == Int(after.st_size) else { throw failure("configuration changed while being read") }
    return data
}

private func isHash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
private func isCDHash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{40,128}$", options: .regularExpression) != nil }
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
