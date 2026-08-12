import CryptoKit
import Darwin
import Foundation

public enum NativeControlProvisioningError: Error, LocalizedError, Equatable, Sendable {
    case invalidInput(String)
    case unsafeConfigPath(String)
    case invalidExistingConfiguration(String)
    case trustReplacementRequiresExpectedFingerprint
    case trustFingerprintMismatch
    case filesystem(String)

    public var errorDescription: String? {
        switch self {
        case .invalidInput(let message), .unsafeConfigPath(let message), .invalidExistingConfiguration(let message), .filesystem(let message):
            return message
        case .trustReplacementRequiresExpectedFingerprint:
            return "Replacing an existing Control v2 trust requires expected_old_fingerprint"
        case .trustFingerprintMismatch:
            return "expected_old_fingerprint does not match the currently pinned Control v2 key"
        }
    }
}

public struct NativeControlProvisioningMetadata: Sendable, Equatable {
    public enum Kind: String, Sendable {
        case regular
        case directory
        case symlink
        case other
    }

    public let kind: Kind
    public let ownerUID: UInt32
    public let mode: UInt16

    public init(kind: Kind, ownerUID: UInt32, mode: UInt16) {
        self.kind = kind
        self.ownerUID = ownerUID
        self.mode = mode
    }
}

/// The small filesystem surface makes the trust-boundary transaction testable without
/// weakening the production checks for root ownership, no-follow opens, or durable writes.
public protocol NativeControlProvisioningFileSystem: Sendable {
    func metadata(at path: String) throws -> NativeControlProvisioningMetadata
    func read(at path: String) throws -> Data
    func createDirectory(at path: String, mode: UInt16) throws
    func setMode(_ mode: UInt16, forPath path: String) throws
    func createExclusive(at path: String, mode: UInt16) throws -> Int32
    func write(_ data: Data, to descriptor: Int32) throws
    func setMode(_ mode: UInt16, for descriptor: Int32) throws
    func synchronize(_ descriptor: Int32) throws
    func close(_ descriptor: Int32) throws
    func rename(from: String, to: String) throws
    func synchronizeDirectory(at path: String) throws
    func remove(at path: String) throws
}

public struct NativeControlProvisioningInput: Equatable, Sendable {
    public static let version = 1

    public let issuer: String
    public let keyID: String
    public let organizationID: String
    public let deviceID: String
    public let deviceKeyEpoch: Int64
    public let controlURL: String
    public let controlV2APIBaseURL: String
    public let publicKeyPEM: String
    public let refreshHintKeyID: String
    public let refreshHintAlgorithm: String
    public let refreshHintPublicKeyPEM: String
    public let expectedOldFingerprint: String?

    public init(canonicalJSON data: Data) throws {
        guard data.count > 0, data.count <= 16 * 1024 else {
            throw NativeControlProvisioningError.invalidInput("Control provisioning input is empty or too large")
        }
        let object: [String: Any]
        do {
            object = try NativeStrictJSON.object(from: data, maxBytes: 16 * 1024, maxDepth: 8)
        } catch {
            throw NativeControlProvisioningError.invalidInput("Control provisioning input is not valid strict JSON")
        }
        let canonical: Data
        do { canonical = try NativeStrictJSON.data(object) }
        catch { throw NativeControlProvisioningError.invalidInput("Control provisioning input is not canonical JSON") }
        guard canonical == data else {
            throw NativeControlProvisioningError.invalidInput("Control provisioning input must be canonical JSON")
        }
        let allowed = Set(["version", "issuer", "key_id", "organization_id", "device_id", "device_key_epoch", "control_url", "control_v2_api_base_url", "public_key_pem", "refresh_hint", "expected_old_fingerprint"])
        guard object.keys.allSatisfy({ allowed.contains($0) }), (object.count == 10 || object.count == 11) else {
            throw NativeControlProvisioningError.invalidInput("Control provisioning input contains an unknown or missing field")
        }
        guard nativeProvisioningInt(object["version"]) == Self.version else {
            throw NativeControlProvisioningError.invalidInput("Unsupported control provisioning input version")
        }
        guard let issuer = object["issuer"] as? String, Self.validIdentifier(issuer) else {
            throw NativeControlProvisioningError.invalidInput("issuer is invalid")
        }
        guard let keyID = object["key_id"] as? String, Self.validIdentifier(keyID) else {
            throw NativeControlProvisioningError.invalidInput("key_id is invalid")
        }
        guard let organizationID = object["organization_id"] as? String, Self.validUUIDv4(organizationID),
              let deviceID = object["device_id"] as? String, Self.validUUIDv4(deviceID) else {
            throw NativeControlProvisioningError.invalidInput("organization_id and device_id must be canonical UUIDv4 values")
        }
        guard let controlURL = object["control_url"] as? String, Self.validControlURL(controlURL, organizationID: organizationID, deviceID: deviceID) else {
            throw NativeControlProvisioningError.invalidInput("control_url must be a credential-free HTTPS URL without query or fragment")
        }
        guard let controlV2APIBaseURL = object["control_v2_api_base_url"] as? String,
              Self.validAPIBaseURL(controlV2APIBaseURL),
              Self.sameOriginAndAPIPath(controlURL: controlURL, apiBaseURL: controlV2APIBaseURL) else {
            throw NativeControlProvisioningError.invalidInput("control_v2_api_base_url must be the credential-free HTTPS /v1 API base for control_url")
        }
        guard let publicKeyPEM = object["public_key_pem"] as? String else {
            throw NativeControlProvisioningError.invalidInput("public_key_pem is required")
        }
        let (_, controlDER) = try Self.ed25519KeyAndDER(from: publicKeyPEM)
        guard let rawEpoch = nativeProvisioningInt(object["device_key_epoch"]),
              rawEpoch > 0, Int64(rawEpoch) <= Self.maximumSafeInteger else {
            throw NativeControlProvisioningError.invalidInput("device_key_epoch must be a positive safe integer")
        }
        guard let refreshHint = object["refresh_hint"] as? [String: Any],
              Set(refreshHint.keys) == Set(["key_id", "algorithm", "public_key"]),
              let refreshHintKeyID = refreshHint["key_id"] as? String,
              Self.validIdentifier(refreshHintKeyID),
              let refreshHintAlgorithm = refreshHint["algorithm"] as? String,
              refreshHintAlgorithm == "ed25519",
              let refreshHintPublicKeyPEM = refreshHint["public_key"] as? String else {
            throw NativeControlProvisioningError.invalidInput("refresh_hint trust metadata is invalid")
        }
        let (_, refreshDER) = try Self.ed25519KeyAndDER(from: refreshHintPublicKeyPEM)
        guard controlDER != refreshDER else {
            throw NativeControlProvisioningError.invalidInput("refresh_hint trust key must be purpose-separated from the control key")
        }
        let expected = object["expected_old_fingerprint"] as? String
        guard object["expected_old_fingerprint"] == nil || (expected != nil && Self.validFingerprint(expected!)) else {
            throw NativeControlProvisioningError.invalidInput("expected_old_fingerprint is invalid")
        }
        self.issuer = issuer
        self.keyID = keyID
        self.organizationID = organizationID
        self.deviceID = deviceID
        self.deviceKeyEpoch = Int64(rawEpoch)
        self.controlURL = controlURL
        self.controlV2APIBaseURL = controlV2APIBaseURL
        self.publicKeyPEM = publicKeyPEM
        self.refreshHintKeyID = refreshHintKeyID
        self.refreshHintAlgorithm = refreshHintAlgorithm
        self.refreshHintPublicKeyPEM = refreshHintPublicKeyPEM
        self.expectedOldFingerprint = expected
    }

    public func canonicalJSON() throws -> Data {
        var object: [String: Any] = [
            "version": Self.version,
            "issuer": issuer,
            "key_id": keyID,
            "organization_id": organizationID,
            "device_id": deviceID,
            "device_key_epoch": deviceKeyEpoch,
            "control_url": controlURL,
            "control_v2_api_base_url": controlV2APIBaseURL,
            "public_key_pem": publicKeyPEM,
            "refresh_hint": [
                "key_id": refreshHintKeyID,
                "algorithm": refreshHintAlgorithm,
                "public_key": refreshHintPublicKeyPEM
            ]
        ]
        if let expectedOldFingerprint { object["expected_old_fingerprint"] = expectedOldFingerprint }
        return try NativeStrictJSON.data(object)
    }

    public var publicKeyFingerprint: String {
        Self.fingerprint(forDER: (try? Self.ed25519KeyAndDER(from: publicKeyPEM).der) ?? Data())
    }

    fileprivate static func validIdentifier(_ value: String) -> Bool {
        value.utf8.count <= 128 && value.range(of: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", options: .regularExpression) != nil
    }

    fileprivate static let maximumSafeInteger: Int64 = 9_007_199_254_740_991

    fileprivate static func validUUIDv4(_ value: String) -> Bool {
        value == value.lowercased() && value.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", options: .regularExpression) != nil
    }

    fileprivate static func validFingerprint(_ value: String) -> Bool {
        value.range(of: "^SHA256:[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil
    }

    fileprivate static func validControlURL(_ value: String) -> Bool {
        guard let components = URLComponents(string: value), components.scheme == "https", components.host != nil,
              components.user == nil, components.password == nil, components.query == nil, components.fragment == nil,
              components.url?.absoluteString == value else { return false }
        return true
    }

    fileprivate static func validControlURL(_ value: String, organizationID: String, deviceID: String) -> Bool {
        guard let components = URLComponents(string: value),
              components.scheme == "https",
              let host = components.host, !host.isEmpty,
              host == host.lowercased(),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              let url = components.url,
              url.absoluteString == value,
              components.path == "/v1/organizations/\(organizationID)/bundles/\(deviceID)" else { return false }
        return true
    }

    fileprivate static func validAPIBaseURL(_ value: String) -> Bool {
        guard let components = URLComponents(string: value),
              components.scheme == "https",
              let host = components.host, !host.isEmpty,
              host == host.lowercased(),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.path == "/v1",
              components.url?.absoluteString == value else { return false }
        return true
    }

    fileprivate static func sameOriginAndAPIPath(controlURL: String, apiBaseURL: String) -> Bool {
        guard let control = URLComponents(string: controlURL), let api = URLComponents(string: apiBaseURL) else { return false }
        return control.scheme == api.scheme && control.host == api.host && control.port == api.port &&
            control.path.hasPrefix(api.path + "/")
    }

    fileprivate static func ed25519KeyAndDER(from pem: String) throws -> (key: Curve25519.Signing.PublicKey, der: Data) {
        let prefix = "-----BEGIN PUBLIC KEY-----\n"
        let suffix = "\n-----END PUBLIC KEY-----\n"
        guard pem.hasPrefix(prefix), pem.hasSuffix(suffix) else {
            throw NativeControlProvisioningError.invalidInput("public_key_pem must be canonical Ed25519 SPKI PEM")
        }
        let body = String(pem.dropFirst(prefix.count).dropLast(suffix.count))
        guard !body.isEmpty, !body.contains("\n"), let der = Data(base64Encoded: body), der.count == 44,
              der.prefix(12) == Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
              body == der.base64EncodedString() else {
            throw NativeControlProvisioningError.invalidInput("public_key_pem must be canonical Ed25519 SPKI PEM")
        }
        do { return (try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)), der) }
        catch { throw NativeControlProvisioningError.invalidInput("public_key_pem is not a valid Ed25519 public key") }
    }

    fileprivate static func fingerprint(forDER der: Data) -> String {
        "SHA256:" + Data(SHA256.hash(data: der)).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

public struct NativeControlProvisioningResult: Equatable, Sendable {
    public let changed: Bool
    public let configPath: String
    public let oldFingerprint: String?
    public let newFingerprint: String

    public init(changed: Bool, configPath: String, oldFingerprint: String?, newFingerprint: String) {
        self.changed = changed
        self.configPath = configPath
        self.oldFingerprint = oldFingerprint
        self.newFingerprint = newFingerprint
    }
}

public final class NativeControlProvisioning: @unchecked Sendable {
    private let fileSystem: any NativeControlProvisioningFileSystem

    public init(fileSystem: any NativeControlProvisioningFileSystem = NativeControlProvisioningPOSIXFileSystem()) {
        self.fileSystem = fileSystem
    }

    @discardableResult
    public func provision(canonicalInput: Data, at configPath: String) throws -> NativeControlProvisioningResult {
        let path = try Self.validateConfigPath(configPath, fileSystem: fileSystem)
        let input = try NativeControlProvisioningInput(canonicalJSON: canonicalInput)
        let original = try fileSystem.read(at: path)
        let existing: [String: Any]
        do { existing = try NativeStrictJSON.object(from: original, maxBytes: 512 * 1024, maxDepth: 32) }
        catch { throw NativeControlProvisioningError.invalidExistingConfiguration("Root service configuration is not strict JSON") }
        var updated = existing
        let oldTrust = try Self.existingTrust(from: existing)
        if let rawEpoch = existing["control_v2_device_key_epoch"] {
            guard let existingEpoch = nativeProvisioningInt(rawEpoch),
                  existingEpoch > 0, Int64(existingEpoch) <= NativeControlProvisioningInput.maximumSafeInteger,
                  Int64(existingEpoch) == input.deviceKeyEpoch else {
                throw NativeControlProvisioningError.invalidExistingConfiguration("Existing device_key_epoch does not match authoritative enrollment; reprovisioning is required")
            }
        }
        let refreshHintKeyring = try Self.refreshHintKeyring(existing: existing, input: input, controlPublicKeyPEM: input.publicKeyPEM)
        if let expected = input.expectedOldFingerprint {
            guard let oldTrust, expected == oldTrust.fingerprint else { throw NativeControlProvisioningError.trustFingerprintMismatch }
        }
        let newFingerprint = input.publicKeyFingerprint
        let sameTrust = oldTrust.map {
            $0.issuer == input.issuer && $0.keyID == input.keyID && $0.organizationID == input.organizationID &&
            $0.deviceID == input.deviceID && $0.url == input.controlURL && $0.fingerprint == newFingerprint
        } ?? false
        if oldTrust != nil && !sameTrust && input.expectedOldFingerprint == nil {
            throw NativeControlProvisioningError.trustReplacementRequiresExpectedFingerprint
        }
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        updated["control_url"] = input.controlURL
        updated["control_refresh_seconds"] = existing["control_refresh_seconds"] ?? 60
        updated["control_v2_state_path"] = existing["control_v2_state_path"] ?? "\(parent)/control-v2.state.json"
        updated["control_v2_capability_state_path"] = existing["control_v2_capability_state_path"] ?? "\(parent)/control-v2-capabilities.state.json"
        updated["control_v2_request_evidence_path"] = existing["control_v2_request_evidence_path"] ?? "\(parent)/control-v2-request-evidence.state.json"
        updated["control_v2_public_key"] = input.publicKeyPEM
        updated["control_v2_issuer"] = input.issuer
        updated["control_v2_key_id"] = input.keyID
        updated["control_v2_organization_id"] = input.organizationID
        updated["control_v2_device_id"] = input.deviceID
        updated["control_v2_device_key_epoch"] = input.deviceKeyEpoch
        updated["control_v2_api_base_url"] = input.controlV2APIBaseURL
        let refreshStatePath = "\(parent)/control-v2-refresh.state.json"
        let bundleStorePath = "\(parent)/control-v2-bundles"
        if let existingRefreshStatePath = existing["control_v2_refresh_state_path"] as? String,
           existingRefreshStatePath != refreshStatePath {
            throw NativeControlProvisioningError.invalidExistingConfiguration("Existing control_v2_refresh_state_path is not the service-owned default")
        }
        if let existingBundleStorePath = existing["control_v2_bundle_store_path"] as? String,
           existingBundleStorePath != bundleStorePath {
            throw NativeControlProvisioningError.invalidExistingConfiguration("Existing control_v2_bundle_store_path is not the service-owned default")
        }
        try Self.ensureBundleStoreDirectory(at: bundleStorePath, parent: parent, fileSystem: fileSystem)
        updated["control_v2_refresh_state_path"] = refreshStatePath
        updated["control_v2_bundle_store_path"] = bundleStorePath
        updated["control_v2_refresh_hint_keyring"] = refreshHintKeyring
        updated["control_v2_device_key_tag"] = NativeEnrollmentKeyMaterial.fixedApplicationTag
        let encoded: Data
        do { encoded = try NativeStrictJSON.data(updated) }
        catch { throw NativeControlProvisioningError.invalidExistingConfiguration("Updated root service configuration is not canonical JSON") }
        let changed = encoded != original
        if changed { try Self.atomicReplace(encoded, at: path, fileSystem: fileSystem) }
        return NativeControlProvisioningResult(changed: changed, configPath: path, oldFingerprint: oldTrust?.fingerprint, newFingerprint: newFingerprint)
    }

    private struct ExistingTrust {
        let issuer: String
        let keyID: String
        let organizationID: String
        let deviceID: String
        let url: String
        let fingerprint: String
    }

    private static func existingTrust(from object: [String: Any]) throws -> ExistingTrust? {
        let keys = ["control_url", "control_v2_public_key", "control_v2_issuer", "control_v2_key_id", "control_v2_organization_id", "control_v2_device_id"]
        let present = keys.filter { object[$0] != nil }.count
        if present == 0 { return nil }
        guard present == keys.count,
              let issuer = object["control_v2_issuer"] as? String, NativeControlProvisioningInput.validIdentifier(issuer),
              let keyID = object["control_v2_key_id"] as? String, NativeControlProvisioningInput.validIdentifier(keyID),
              let organizationID = object["control_v2_organization_id"] as? String, NativeControlProvisioningInput.validUUIDv4(organizationID),
              let deviceID = object["control_v2_device_id"] as? String, NativeControlProvisioningInput.validUUIDv4(deviceID),
              let url = object["control_url"] as? String, NativeControlProvisioningInput.validControlURL(url),
              let publicKey = object["control_v2_public_key"] as? String else {
            throw NativeControlProvisioningError.invalidExistingConfiguration("Existing ControlBundle v2 trust is incomplete or invalid")
        }
        let (_, der) = try NativeControlProvisioningInput.ed25519KeyAndDER(from: publicKey)
        return ExistingTrust(issuer: issuer, keyID: keyID, organizationID: organizationID, deviceID: deviceID, url: url, fingerprint: NativeControlProvisioningInput.fingerprint(forDER: der))
    }

    private static func refreshHintKeyring(existing: [String: Any], input: NativeControlProvisioningInput, controlPublicKeyPEM: String) throws -> [[String: Any]] {
        let (_, controlDER) = try NativeControlProvisioningInput.ed25519KeyAndDER(from: controlPublicKeyPEM)
        var entries: [[String: Any]] = []
        if let raw = existing["control_v2_refresh_hint_keyring"] {
            guard let array = raw as? [[String: Any]], !array.isEmpty, array.count <= NativeRefreshHintTrust.maximumKeys else {
                throw NativeControlProvisioningError.invalidExistingConfiguration("Existing refresh hint keyring is invalid; reprovisioning is required")
            }
            for item in array {
                guard Set(item.keys) == Set(["key_id", "algorithm", "public_key"]),
                      let keyID = item["key_id"] as? String, NativeControlProvisioningInput.validIdentifier(keyID),
                      let algorithm = item["algorithm"] as? String, algorithm == "ed25519",
                      let publicKey = item["public_key"] as? String else {
                    throw NativeControlProvisioningError.invalidExistingConfiguration("Existing refresh hint keyring is invalid; reprovisioning is required")
                }
                let (_, der) = try NativeControlProvisioningInput.ed25519KeyAndDER(from: publicKey)
                guard der != controlDER else {
                    throw NativeControlProvisioningError.invalidExistingConfiguration("Existing refresh hint keyring reuses the ControlBundle key")
                }
                entries.append(["key_id": keyID, "algorithm": algorithm, "public_key": publicKey])
            }
        }
        if let index = entries.firstIndex(where: { ($0["key_id"] as? String) == input.refreshHintKeyID }) {
            guard entries[index]["algorithm"] as? String == input.refreshHintAlgorithm,
                  entries[index]["public_key"] as? String == input.refreshHintPublicKeyPEM else {
                throw NativeControlProvisioningError.invalidExistingConfiguration("Refresh hint key id is already pinned to a different key")
            }
        } else {
            guard entries.count < NativeRefreshHintTrust.maximumKeys else {
                throw NativeControlProvisioningError.invalidInput("refresh_hint trust keyring exceeds the bounded key limit")
            }
            entries.append(["key_id": input.refreshHintKeyID, "algorithm": input.refreshHintAlgorithm, "public_key": input.refreshHintPublicKeyPEM])
        }
        let ids = entries.compactMap { $0["key_id"] as? String }
        guard Set(ids).count == entries.count else {
            throw NativeControlProvisioningError.invalidExistingConfiguration("Refresh hint keyring contains duplicate key ids")
        }
        return entries
    }

    private static func validateConfigPath(_ rawPath: String, fileSystem: any NativeControlProvisioningFileSystem) throws -> String {
        let path = URL(fileURLWithPath: rawPath).standardizedFileURL.path
        guard rawPath == path, path.hasPrefix("/"), path != "/", URL(fileURLWithPath: path).lastPathComponent != "." else {
            throw NativeControlProvisioningError.unsafeConfigPath("Root service configuration path must be an absolute canonical file path")
        }
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        let parentMetadata = try fileSystem.metadata(at: parent)
        let fileMetadata = try fileSystem.metadata(at: path)
        guard parentMetadata.kind == .directory, parentMetadata.ownerUID == 0, parentMetadata.mode & 0o077 == 0 else {
            throw NativeControlProvisioningError.unsafeConfigPath("Root service configuration directory must be root-owned and private")
        }
        guard fileMetadata.kind == .regular, fileMetadata.ownerUID == 0, fileMetadata.mode & 0o077 == 0 else {
            throw NativeControlProvisioningError.unsafeConfigPath("Root service configuration must be a root-owned private regular file")
        }
        return path
    }

    private static func ensureBundleStoreDirectory(at path: String, parent: String, fileSystem: any NativeControlProvisioningFileSystem) throws {
        let canonical = URL(fileURLWithPath: path).standardizedFileURL.path
        guard canonical == path, URL(fileURLWithPath: path).deletingLastPathComponent().path == parent else {
            throw NativeControlProvisioningError.unsafeConfigPath("ControlBundle store path must be the service-owned child directory")
        }
        do {
            let metadata = try fileSystem.metadata(at: path)
            guard metadata.kind == .directory, metadata.ownerUID == 0, metadata.mode == 0o700 else {
                throw NativeControlProvisioningError.unsafeConfigPath("ControlBundle store must be a root-owned 0700 directory")
            }
            return
        } catch let error as POSIXError where error.code == .ENOENT {
            // The installer normally creates this directory. A first enrollment
            // may create it here as the root-owned setup boundary.
        } catch let error as NativeControlProvisioningError {
            throw error
        } catch {
            throw NativeControlProvisioningError.filesystem("Unable to inspect protected ControlBundle store")
        }
        do {
            try fileSystem.createDirectory(at: path, mode: 0o700)
            try fileSystem.setMode(0o700, forPath: path)
            try fileSystem.synchronizeDirectory(at: parent)
        } catch {
            throw NativeControlProvisioningError.filesystem("Unable to create protected ControlBundle store")
        }
        guard let metadata = try? fileSystem.metadata(at: path), metadata.kind == .directory, metadata.ownerUID == 0, metadata.mode == 0o700 else {
            throw NativeControlProvisioningError.unsafeConfigPath("ControlBundle store could not be verified as a root-owned 0700 directory")
        }
    }

    private static func atomicReplace(_ data: Data, at path: String, fileSystem: any NativeControlProvisioningFileSystem) throws {
        let temporary = "\(path).agentpass-control-v2.\(UUID().uuidString).tmp"
        var descriptor: Int32?
        do {
            let fd = try fileSystem.createExclusive(at: temporary, mode: 0o600)
            descriptor = fd
            try fileSystem.write(data, to: fd)
            try fileSystem.setMode(0o600, for: fd)
            try fileSystem.synchronize(fd)
            try fileSystem.close(fd)
            descriptor = nil
            try fileSystem.rename(from: temporary, to: path)
            try fileSystem.synchronizeDirectory(at: URL(fileURLWithPath: path).deletingLastPathComponent().path)
        } catch {
            if let descriptor { try? fileSystem.close(descriptor) }
            try? fileSystem.remove(at: temporary)
            throw NativeControlProvisioningError.filesystem(error.localizedDescription)
        }
    }
}

public struct NativeControlProvisioningPOSIXFileSystem: NativeControlProvisioningFileSystem, Sendable {
    public init() {}

    public func metadata(at path: String) throws -> NativeControlProvisioningMetadata {
        var info = stat()
        guard lstat(path, &info) == 0 else { throw posixError() }
        let type = info.st_mode & S_IFMT
        let kind: NativeControlProvisioningMetadata.Kind = type == S_IFREG ? .regular : type == S_IFDIR ? .directory : type == S_IFLNK ? .symlink : .other
        return NativeControlProvisioningMetadata(kind: kind, ownerUID: UInt32(info.st_uid), mode: UInt16(info.st_mode & 0o7777))
    }

    public func read(at path: String) throws -> Data {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posixError() }
        defer { Darwin.close(fd) }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count == 0 { return data }
            guard count > 0, data.count + count <= 512 * 1024 else { throw NativeControlProvisioningError.filesystem("Configuration file is too large") }
            data.append(contentsOf: buffer[0..<count])
        }
    }

    public func createDirectory(at path: String, mode: UInt16) throws {
        guard mkdir(path, mode_t(mode)) == 0 else { throw posixError() }
    }

    public func setMode(_ mode: UInt16, forPath path: String) throws {
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posixError() }
        defer { Darwin.close(fd) }
        guard fchmod(fd, mode_t(mode)) == 0 else { throw posixError() }
    }

    public func createExclusive(at path: String, mode: UInt16) throws -> Int32 {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(mode))
        guard fd >= 0 else { throw posixError() }
        return fd
    }

    public func write(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard count > 0 else { throw posixError() }
                offset += count
            }
        }
    }

    public func setMode(_ mode: UInt16, for descriptor: Int32) throws { guard fchmod(descriptor, mode_t(mode)) == 0 else { throw posixError() } }
    public func synchronize(_ descriptor: Int32) throws { guard fsync(descriptor) == 0 else { throw posixError() } }
    public func close(_ descriptor: Int32) throws { guard Darwin.close(descriptor) == 0 else { throw posixError() } }
    public func rename(from: String, to: String) throws { guard Darwin.rename(from, to) == 0 else { throw posixError() } }
    public func synchronizeDirectory(at path: String) throws {
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw posixError() }
        defer { Darwin.close(fd) }
        guard fsync(fd) == 0 else { throw posixError() }
    }
    public func remove(at path: String) throws { guard unlink(path) == 0 || errno == ENOENT else { throw posixError() } }
}

private func nativeProvisioningInt(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.rounded() == number.doubleValue else { return nil }
    return number.intValue
}

private func posixError() -> Error { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
