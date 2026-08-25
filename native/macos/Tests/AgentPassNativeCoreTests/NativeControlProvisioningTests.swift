import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private final class ProvisioningMemoryFileSystem: NativeControlProvisioningFileSystem, @unchecked Sendable {
    private struct OpenFile { var data: Data }
    private let lock = NSLock()
    var files: [String: Data] = [:]
    var entries: [String: NativeControlProvisioningMetadata] = [:]
    var events: [String] = []
    var failOn: String?
    private var nextDescriptor: Int32 = 10
    private var openFiles: [Int32: OpenFile] = [:]

    func metadata(at path: String) throws -> NativeControlProvisioningMetadata {
        try maybeFail("metadata")
        guard let entry = entries[path] else { throw POSIXError(.ENOENT) }
        return entry
    }

    func read(at path: String) throws -> Data {
        try maybeFail("read")
        guard let data = files[path] else { throw POSIXError(.ENOENT) }
        events.append("read")
        return data
    }

    func createDirectory(at path: String, mode: UInt16) throws {
        try maybeFail("mkdir")
        guard entries[path] == nil else { throw POSIXError(.EEXIST) }
        entries[path] = NativeControlProvisioningMetadata(kind: .directory, ownerUID: 0, mode: mode)
        events.append("mkdir")
    }

    func setMode(_ mode: UInt16, forPath path: String) throws {
        try maybeFail("chmod-directory")
        guard let entry = entries[path] else { throw POSIXError(.ENOENT) }
        entries[path] = NativeControlProvisioningMetadata(kind: entry.kind, ownerUID: entry.ownerUID, mode: mode)
        events.append("chmod-directory")
    }

    func createExclusive(at path: String, mode: UInt16) throws -> Int32 {
        try maybeFail("create")
        guard files[path] == nil else { throw POSIXError(.EEXIST) }
        let descriptor = nextDescriptor; nextDescriptor += 1
        openFiles[descriptor] = OpenFile(data: Data())
        entries[path] = NativeControlProvisioningMetadata(kind: .regular, ownerUID: 0, mode: mode)
        events.append("create")
        return descriptor
    }

    func write(_ data: Data, to descriptor: Int32) throws {
        try maybeFail("write")
        guard var open = openFiles[descriptor] else { throw POSIXError(.EBADF) }
        open.data.append(data); openFiles[descriptor] = open
        events.append("write")
    }

    func setMode(_ mode: UInt16, for descriptor: Int32) throws {
        try maybeFail("chmod")
        events.append("chmod")
    }

    func synchronize(_ descriptor: Int32) throws {
        try maybeFail("fsync-file")
        events.append("fsync-file")
    }

    func close(_ descriptor: Int32) throws {
        try maybeFail("close")
        guard let open = openFiles.removeValue(forKey: descriptor) else { throw POSIXError(.EBADF) }
        let temp = entries.first(where: { $0.value.kind == .regular && files[$0.key] == nil })?.key
        if let temp { files[temp] = open.data }
        events.append("close")
    }

    func rename(from: String, to: String) throws {
        try maybeFail("rename")
        guard let data = files.removeValue(forKey: from) else { throw POSIXError(.ENOENT) }
        files[to] = data
        entries[to] = entries.removeValue(forKey: from)
        events.append("rename")
    }

    func synchronizeDirectory(at path: String) throws {
        try maybeFail("fsync-directory")
        events.append("fsync-directory")
    }

    func remove(at path: String) throws {
        files.removeValue(forKey: path)
        entries.removeValue(forKey: path)
        events.append("remove")
    }

    private func maybeFail(_ operation: String) throws {
        if failOn == operation {
            failOn = nil
            throw POSIXError(.EIO)
        }
    }
}

private struct ProvisioningFixture {
    let root = "/private/var/agentpass-test-root"
    let config = "/private/var/agentpass-test-root/service.json"
    let signer = Curve25519.Signing.PrivateKey()
    let refreshSigner = Curve25519.Signing.PrivateKey()

    var pem: String {
        let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + signer.publicKey.rawRepresentation
        return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
    }

    var refreshPEM: String {
        let der = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + refreshSigner.publicKey.rawRepresentation
        return "-----BEGIN PUBLIC KEY-----\n\(der.base64EncodedString())\n-----END PUBLIC KEY-----\n"
    }

    func input(expectedOldFingerprint: String? = nil) throws -> Data {
        var object: [String: Any] = [
            "version": 1,
            "issuer": "agentpass-cloud",
            "key_id": "control-v2",
            "organization_id": "11111111-1111-4111-8111-111111111111",
            "device_id": "22222222-2222-4222-8222-222222222222",
            "device_key_epoch": 4,
            "control_url": "https://api.example.test/v1/organizations/11111111-1111-4111-8111-111111111111/bundles/22222222-2222-4222-8222-222222222222",
            "control_v2_api_base_url": "https://api.example.test/v1",
            "public_key_pem": pem,
            "refresh_hint": ["key_id": "refresh-hint-v1", "algorithm": "ed25519", "public_key": refreshPEM]
        ]
        if let expectedOldFingerprint { object["expected_old_fingerprint"] = expectedOldFingerprint }
        return try NativeStrictJSON.data(object)
    }

    func fileSystem(configData: Data? = nil) -> ProvisioningMemoryFileSystem {
        let fs = ProvisioningMemoryFileSystem()
        fs.entries[root] = .init(kind: .directory, ownerUID: 0, mode: 0o700)
        fs.entries[config] = .init(kind: .regular, ownerUID: 0, mode: 0o600)
        fs.files[config] = configData ?? Data(#"{"version":4,"repositories":["/work/project"],"unrelated":{"keep":true}}"#.utf8)
        return fs
    }
}

private func jsonObject(_ data: Data) throws -> [String: Any] {
    try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
}

@Test func nativeControlProvisioningPinsTrustAndPreservesUnrelatedConfig() throws {
    let fixture = ProvisioningFixture()
    let fs = fixture.fileSystem()
    let result = try NativeControlProvisioning(fileSystem: fs).provision(canonicalInput: try fixture.input(), at: fixture.config)
    #expect(result.changed)
    #expect(result.oldFingerprint == nil)
    #expect(result.newFingerprint.hasPrefix("SHA256:"))
    let object = try jsonObject(#require(fs.files[fixture.config]))
    #expect(object["version"] as? Int == 4)
    #expect(object["repositories"] as? [String] == ["/work/project"])
    #expect((object["unrelated"] as? [String: Any])?["keep"] as? Bool == true)
    #expect(object["control_url"] as? String == "https://api.example.test/v1/organizations/11111111-1111-4111-8111-111111111111/bundles/22222222-2222-4222-8222-222222222222")
    #expect(object["control_v2_public_key"] as? String == fixture.pem)
    #expect(object["control_v2_issuer"] as? String == "agentpass-cloud")
    #expect(object["control_v2_device_key_epoch"] as? Int == 4)
    #expect(object["control_v2_api_base_url"] as? String == "https://api.example.test/v1")
    #expect(object["control_v2_refresh_state_path"] as? String == "\(fixture.root)/control-v2-refresh.state.json")
    #expect(object["control_v2_bundle_store_path"] as? String == "\(fixture.root)/control-v2-bundles")
    #expect((object["control_v2_refresh_hint_keyring"] as? [[String: Any]])?.first?["key_id"] as? String == "refresh-hint-v1")
    #expect((object["control_v2_refresh_hint_keyring"] as? [[String: Any]])?.first?["algorithm"] as? String == "ed25519")
    #expect(object["control_v2_device_key_tag"] as? String == NativeEnrollmentKeyMaterial.fixedApplicationTag)
    #expect(object["control_v2_state_path"] as? String == "\(fixture.root)/control-v2.state.json")
    #expect(fs.events.suffix(7).elementsEqual(["create", "write", "chmod", "fsync-file", "close", "rename", "fsync-directory"]))
    #expect(fs.entries["\(fixture.root)/control-v2-bundles"]?.kind == .directory)
    #expect(fs.entries["\(fixture.root)/control-v2-bundles"]?.ownerUID == 0)
    #expect(fs.entries["\(fixture.root)/control-v2-bundles"]?.mode == 0o700)
    #expect(fs.files.keys.allSatisfy { !$0.hasSuffix(".tmp") })
}

@Test func nativeControlProvisioningRejectsMissingOrSubstitutedEpochAndRefreshTrust() throws {
    let fixture = ProvisioningFixture()
    let provisioning = NativeControlProvisioning(fileSystem: fixture.fileSystem())
    var missingEpoch = try jsonObject(try fixture.input())
    missingEpoch.removeValue(forKey: "device_key_epoch")
    #expect(throws: NativeControlProvisioningError.self) {
        try provisioning.provision(canonicalInput: try NativeStrictJSON.data(missingEpoch), at: fixture.config)
    }
    var substitutedEpoch = try jsonObject(try fixture.input())
    substitutedEpoch["device_key_epoch"] = 0
    #expect(throws: NativeControlProvisioningError.self) {
        try provisioning.provision(canonicalInput: try NativeStrictJSON.data(substitutedEpoch), at: fixture.config)
    }
    var missingAPIBase = try jsonObject(try fixture.input())
    missingAPIBase.removeValue(forKey: "control_v2_api_base_url")
    #expect(throws: NativeControlProvisioningError.self) {
        try provisioning.provision(canonicalInput: try NativeStrictJSON.data(missingAPIBase), at: fixture.config)
    }
    var credentialedAPIBase = try jsonObject(try fixture.input())
    credentialedAPIBase["control_v2_api_base_url"] = "https://user:pass@api.example.test/v1"
    #expect(throws: NativeControlProvisioningError.self) {
        try provisioning.provision(canonicalInput: try NativeStrictJSON.data(credentialedAPIBase), at: fixture.config)
    }
    var sameKey = try jsonObject(try fixture.input())
    sameKey["refresh_hint"] = ["key_id": "refresh-hint-v1", "algorithm": "ed25519", "public_key": fixture.pem]
    #expect(throws: NativeControlProvisioningError.self) {
        try provisioning.provision(canonicalInput: try NativeStrictJSON.data(sameKey), at: fixture.config)
    }
}

@Test func nativeControlProvisioningRejectsNonCanonicalUnknownDuplicateAndSecretInput() throws {
    let fixture = ProvisioningFixture()
    let fs = fixture.fileSystem()
    let provisioning = NativeControlProvisioning(fileSystem: fs)
    #expect(throws: NativeControlProvisioningError.self) {
        try provisioning.provision(canonicalInput: Data(" {\"version\":1} ".utf8), at: fixture.config)
    }
    #expect(throws: NativeControlProvisioningError.self) {
        try provisioning.provision(canonicalInput: Data(#"{"version":1,"version":1,"issuer":"agentpass-cloud","key_id":"control-v2","organization_id":"11111111-1111-4111-8111-111111111111","device_id":"22222222-2222-4222-8222-222222222222","control_url":"https://api.example.test","public_key_pem":"x"}"#.utf8), at: fixture.config)
    }
    var object = try jsonObject(try fixture.input())
    object["private_key"] = "must-never-be-accepted"
    let unknown = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    #expect(throws: NativeControlProvisioningError.self) { try provisioning.provision(canonicalInput: unknown, at: fixture.config) }
}

@Test func nativeControlProvisioningRequiresMatchingOldFingerprintForTrustReplacement() throws {
    let fixture = ProvisioningFixture()
    let old = Curve25519.Signing.PrivateKey()
    let oldDER = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) + old.publicKey.rawRepresentation
    let oldPEM = "-----BEGIN PUBLIC KEY-----\n\(oldDER.base64EncodedString())\n-----END PUBLIC KEY-----\n"
    let oldConfig = try NativeStrictJSON.data(["version": 4, "repositories": ["/work/project"], "control_url": "https://api.example.test/old", "control_refresh_seconds": 30, "control_v2_public_key": oldPEM, "control_v2_issuer": "agentpass-cloud", "control_v2_key_id": "control-v1", "control_v2_organization_id": "11111111-1111-4111-8111-111111111111", "control_v2_device_id": "22222222-2222-4222-8222-222222222222", "unrelated": "preserve"])
    let fs = fixture.fileSystem(configData: oldConfig)
    let provisioning = NativeControlProvisioning(fileSystem: fs)
    #expect(throws: NativeControlProvisioningError.self) { try provisioning.provision(canonicalInput: try fixture.input(), at: fixture.config) }
    let oldFingerprint = "SHA256:" + Data(SHA256.hash(data: oldDER)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    #expect(throws: NativeControlProvisioningError.self) { try provisioning.provision(canonicalInput: try fixture.input(expectedOldFingerprint: "SHA256:\(String(repeating: "A", count: 43))"), at: fixture.config) }
    let result = try provisioning.provision(canonicalInput: try fixture.input(expectedOldFingerprint: oldFingerprint), at: fixture.config)
    #expect(result.oldFingerprint == oldFingerprint)
    let object = try jsonObject(#require(fs.files[fixture.config]))
    #expect(object["unrelated"] as? String == "preserve")
    #expect(object["control_refresh_seconds"] as? Int == 30)
}

@Test func nativeControlProvisioningFailsClosedAndCleansTemporaryFileOnDurabilityFailure() throws {
    let fixture = ProvisioningFixture()
    let fs = fixture.fileSystem()
    let original = try #require(fs.files[fixture.config])
    fs.failOn = "fsync-file"
    #expect(throws: NativeControlProvisioningError.self) { try NativeControlProvisioning(fileSystem: fs).provision(canonicalInput: try fixture.input(), at: fixture.config) }
    #expect(fs.files[fixture.config] == original)
    #expect(fs.files.keys.allSatisfy { $0 == fixture.config })
}

@Test func nativeControlProvisioningRejectsNonRootOrSymlinkedTargets() throws {
    let fixture = ProvisioningFixture()
    let fs = fixture.fileSystem()
    fs.entries[fixture.config] = .init(kind: .regular, ownerUID: 501, mode: 0o600)
    #expect(throws: NativeControlProvisioningError.self) { try NativeControlProvisioning(fileSystem: fs).provision(canonicalInput: try fixture.input(), at: fixture.config) }
    fs.entries[fixture.config] = .init(kind: .symlink, ownerUID: 0, mode: 0o777)
    #expect(throws: NativeControlProvisioningError.self) { try NativeControlProvisioning(fileSystem: fs).provision(canonicalInput: try fixture.input(), at: fixture.config) }
}

@Test func nativeControlProvisioningRejectsSubstitutedServiceOwnedStorePath() throws {
    let fixture = ProvisioningFixture()
    let existing = try NativeStrictJSON.data([
        "version": 4,
        "control_v2_refresh_state_path": "/tmp/agentpass-refresh.state.json",
        "control_v2_bundle_store_path": "\(fixture.root)/control-v2-bundles"
    ])
    let fs = fixture.fileSystem(configData: existing)
    #expect(throws: NativeControlProvisioningError.self) {
        try NativeControlProvisioning(fileSystem: fs).provision(canonicalInput: try fixture.input(), at: fixture.config)
    }
}
