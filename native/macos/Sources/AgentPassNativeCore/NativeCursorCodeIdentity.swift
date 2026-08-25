import CryptoKit
import Darwin
import Foundation
import Security

/// Fixed AgentPass-managed Cursor Agent materialization layout.
///
/// The official Cursor shell launcher is intentionally not part of this
/// layout. It can install or execute a user-home `cursor-agent`, so the Host
/// launches the sibling Node runtime directly with the sibling index file.
internal enum NativeCursorAgentRuntimeSpec {
    static let runtimeRoot = "/Library/Application Support/AgentPass/CursorAgent/runtime"
    static let runtimeManifestPath = "/Library/Application Support/AgentPass/CursorAgent/runtime-manifest.json"
    static let runtimeTrustConfigPath = "/Library/Application Support/AgentPass/Trust/cursor-agent-runtime-key-v1.json"
    static let nodePath = runtimeRoot + "/node"
    static let indexPath = runtimeRoot + "/index.js"
    static let nodeRelativePath = "node"
    static let indexRelativePath = "index.js"
    static let requiredRelativePaths = [nodeRelativePath, indexRelativePath]
    static let requiredPaths = [nodePath, indexPath]
    static let fixedArguments = ["--use-system-ca", indexPath]
    static let invokedAsEnvironmentKey = "CURSOR_INVOKED_AS"
    static let invokedAsEnvironmentValue = "cursor-agent"
    static let fixedEnvironment = [
        invokedAsEnvironmentKey: invokedAsEnvironmentValue
    ]
}

/// Bounds are policy limits, not release metadata. They leave room for the
/// current multi-file runtime while preventing an unbounded traversal or
/// digest workload.
internal enum NativeCursorAgentRuntimePolicy {
    static let maximumSafeInteger: UInt64 = 9_007_199_254_740_991
    static let maximumFileCount = 4_096
    static let maximumDirectoryCount = 4_096
    static let maximumInventoryEntryCount = maximumFileCount + maximumDirectoryCount
    static let maximumFileSize: UInt64 = 256 * 1024 * 1024
    static let maximumTotalSize: UInt64 = 512 * 1024 * 1024
}

internal struct NativeCursorAgentRuntimeCodeIdentityClaim: Equatable, Sendable {
    let identifier: String
    let teamIdentifier: String
    let designatedRequirement: String
}

/// One closed-inventory file entry supplied by the trusted materializer.
/// `isRegularFile` is retained in the wire contract so a malformed manifest
/// cannot silently turn a directory or special file into a runtime member.
internal struct NativeCursorAgentRuntimeManifestEntry: Equatable, Sendable {
    let relativePath: String
    let sha256: String
    let size: UInt64
    let isExecutable: Bool
    let isRegularFile: Bool

    init(
        relativePath: String,
        sha256: String,
        size: UInt64,
        isExecutable: Bool,
        isRegularFile: Bool = true
    ) throws {
        guard Self.isCanonicalRelativePath(relativePath),
              Self.isSHA256(sha256),
              isRegularFile,
              size <= NativeCursorAgentRuntimePolicy.maximumFileSize else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }
        self.relativePath = relativePath
        self.sha256 = sha256.lowercased()
        self.size = size
        self.isExecutable = isExecutable
        self.isRegularFile = isRegularFile
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.utf8.count == 64
            && value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    static func isCanonicalRelativePath(_ path: String) -> Bool {
        guard path.utf8.count >= 1,
              path.utf8.count <= 1024,
              !path.contains("\0"),
              !path.contains("\\"),
              !path.hasPrefix("/"),
              !path.hasSuffix("/"),
              !path.contains("//") else {
            return false
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard components.allSatisfy({
            !$0.isEmpty && $0 != "." && $0 != ".."
                && $0.range(of: "^[A-Za-z0-9._@+-]+$", options: .regularExpression) != nil
        }) else {
            return false
        }
        return !components.contains {
            let component = String($0)
            return component.range(
                of: "^(credential|credentials|secret|secrets|token|tokens|log|logs)$",
                options: [.regularExpression, .caseInsensitive]
            ) != nil
                || component.range(
                    of: "^(credential|credentials|secret|secrets|token|tokens)([._-].*)?$",
                    options: [.regularExpression, .caseInsensitive]
                ) != nil
                || component.range(
                    of: "(^|\\.)log(\\.[0-9]+)?$",
                    options: [.regularExpression, .caseInsensitive]
                ) != nil
        }
    }
}

/// A filesystem item returned by the injected recursive runtime enumerator.
/// The production enumerator uses lstat and never follows a symlink.
internal struct NativeCursorAgentRuntimeObservedFile: Equatable, Sendable {
    let relativePath: String
    let metadata: NativeAgentHostExecutableMetadata
}

/// Release materialization contract for the complete fixed runtime.
///
/// The trusted provisioner must enumerate every runtime file. A missing,
/// extra, duplicate, malformed, or non-regular item is a denial. No release
/// digest is embedded in this source tree; a missing manifest is a production
/// denial. The optional identity claim applies only to the Node entrypoint;
/// tree closure and per-file digests remain mandatory for every entry.
internal struct NativeCursorAgentRuntimeManifest: Equatable, Sendable {
    let entries: [NativeCursorAgentRuntimeManifestEntry]
    let runtimeVersion: String
    let releaseDigest: String
    let materializationEpoch: UInt64
    let nodeCodeIdentity: NativeCursorAgentRuntimeCodeIdentityClaim?

    init(
        entries: [NativeCursorAgentRuntimeManifestEntry],
        runtimeVersion: String,
        releaseDigest: String,
        materializationEpoch: UInt64,
        nodeCodeIdentity: NativeCursorAgentRuntimeCodeIdentityClaim? = nil
    ) throws {
        guard !entries.isEmpty,
              entries.count <= NativeCursorAgentRuntimePolicy.maximumFileCount,
              runtimeVersion.utf8.count >= 1,
              runtimeVersion.utf8.count <= 128,
              runtimeVersion.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]*$", options: .regularExpression) != nil,
              releaseDigest.range(of: "^sha256:[0-9a-f]{64}$", options: .regularExpression) != nil,
              materializationEpoch > 0,
              materializationEpoch <= NativeCursorAgentRuntimePolicy.maximumSafeInteger else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }

        var paths = Set<String>()
        var totalSize: UInt64 = 0
        for entry in entries {
            guard paths.insert(entry.relativePath).inserted,
                  entry.isRegularFile,
                  entry.size <= NativeCursorAgentRuntimePolicy.maximumFileSize,
                  totalSize <= NativeCursorAgentRuntimePolicy.maximumTotalSize - entry.size else {
                throw NativeCursorAgentRuntimeTrustError.invalidManifest
            }
            totalSize += entry.size
        }

        guard NativeCursorAgentRuntimeSpec.requiredRelativePaths.allSatisfy(paths.contains),
              entries.first(where: { $0.relativePath == NativeCursorAgentRuntimeSpec.nodeRelativePath })?.isExecutable == true,
              entries.first(where: { $0.relativePath == NativeCursorAgentRuntimeSpec.indexRelativePath })?.isExecutable == false else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }

        self.entries = entries.sorted { $0.relativePath < $1.relativePath }
        self.runtimeVersion = runtimeVersion
        self.releaseDigest = releaseDigest
        self.materializationEpoch = materializationEpoch
        self.nodeCodeIdentity = nodeCodeIdentity
    }

    /// Compatibility initializer for the supervisor's test-only synthetic
    /// selection. Production-loaded manifests always use the metadata-bearing
    /// initializer above; these values are intentionally explicit and safe.
    init(
        entries: [NativeCursorAgentRuntimeManifestEntry],
        nodeCodeIdentity: NativeCursorAgentRuntimeCodeIdentityClaim? = nil
    ) throws {
        try self.init(
            entries: entries,
            runtimeVersion: "test-1",
            releaseDigest: "sha256:" + String(repeating: "a", count: 64),
            materializationEpoch: 1,
            nodeCodeIdentity: nodeCodeIdentity
        )
    }

    func entry(for relativePath: String) -> NativeCursorAgentRuntimeManifestEntry? {
        entries.first { $0.relativePath == relativePath }
    }
}

internal enum NativeCursorAgentRuntimeTrustError: Error, Equatable, Sendable {
    case manifestUnavailable
    case invalidManifest
    case artifactUnavailable
    case artifactInvalid
    case inventoryUnavailable
    case inventoryMismatch
    case digestUnavailable
    case digestMismatch
    case codeIdentityMismatch
}

/// Loads the signed, closed inventory produced by the AgentPass runtime
/// materializer. The signing key is deliberately not present in the
/// manifest: it is read from a separate, independently protected trust
/// configuration file.
internal enum NativeCursorAgentRuntimeManifestLoader {
    static let signatureDomain = "AgentPass-Cursor-Agent-Runtime-Manifest-v1\0"
    static let maximumManifestBytes = 2 * 1024 * 1024
    static let maximumTrustConfigBytes = 16 * 1024
    private static let maximumJSONDepth = 8
    private static let ed25519SPKIPrefix = Data([
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    ])

    static func load() throws -> NativeCursorAgentRuntimeManifest {
        try load(
            manifestPath: NativeCursorAgentRuntimeSpec.runtimeManifestPath,
            trustConfigPath: NativeCursorAgentRuntimeSpec.runtimeTrustConfigPath
        )
    }

    /// The path-taking overload is internal so focused tests can exercise the
    /// descriptor reader without ever modifying the fixed production paths.
    static func load(
        manifestPath: String,
        trustConfigPath: String
    ) throws -> NativeCursorAgentRuntimeManifest {
        let trustData = try NativeCursorAgentRuntimeSecureFile.read(
            path: trustConfigPath,
            maximumBytes: maximumTrustConfigBytes
        )
        let manifestData = try NativeCursorAgentRuntimeSecureFile.read(
            path: manifestPath,
            maximumBytes: maximumManifestBytes
        )
        return try verify(manifestData: manifestData, trustConfigData: trustData)
    }

    static func verify(
        manifestData: Data,
        trustConfigData: Data
    ) throws -> NativeCursorAgentRuntimeManifest {
        let trust = try parseTrustConfig(trustConfigData)
        let manifestObject = try strictManifestEnvelope(
            manifestData,
            maximumBytes: maximumManifestBytes
        )
        try requireExactKeys(manifestObject, ["core", "signature"])
        guard let rawCore = manifestObject["core"] as? [String: Any],
              let rawSignature = manifestObject["signature"] as? [String: Any] else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }
        try requireExactKeys(
            rawCore,
            ["schema_version", "runtime_id", "runtime_version", "release_digest", "materialization_epoch", "files"]
        )

        guard let schemaVersion = positiveSafeInteger(rawCore["schema_version"]),
              schemaVersion == 1,
              rawCore["runtime_id"] as? String == "cursor-agent",
              let runtimeVersion = rawCore["runtime_version"] as? String,
              isSafeIdentifier(runtimeVersion, maximumBytes: 128),
              let releaseDigest = rawCore["release_digest"] as? String,
              releaseDigest.range(of: "^sha256:[0-9a-f]{64}$", options: .regularExpression) != nil,
              let materializationEpoch = positiveUInt64(rawCore["materialization_epoch"]),
              let rawFiles = rawCore["files"] as? [[String: Any]],
              !rawFiles.isEmpty,
              rawFiles.count <= NativeCursorAgentRuntimePolicy.maximumFileCount else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }

        var entries: [NativeCursorAgentRuntimeManifestEntry] = []
        entries.reserveCapacity(rawFiles.count)
        var previousPath: String?
        for rawFile in rawFiles {
            try requireExactKeys(rawFile, ["relative_path", "sha256", "size", "executable"])
            guard let relativePath = rawFile["relative_path"] as? String,
                  NativeCursorAgentRuntimeManifestEntry.isCanonicalRelativePath(relativePath),
                  previousPath.map({ $0 < relativePath }) ?? true,
                  let sha256 = rawFile["sha256"] as? String,
                  sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  let size = positiveOrZeroUInt64(rawFile["size"]),
                  let executable = rawFile["executable"] as? Bool else {
                throw NativeCursorAgentRuntimeTrustError.invalidManifest
            }
            previousPath = relativePath
            entries.append(
                try NativeCursorAgentRuntimeManifestEntry(
                    relativePath: relativePath,
                    sha256: sha256,
                    size: size,
                    isExecutable: executable
                )
            )
        }

        try requireExactKeys(rawSignature, ["algorithm", "domain", "key_id", "signature_base64url"])
        guard rawSignature["algorithm"] as? String == "ed25519",
              rawSignature["domain"] as? String == signatureDomain,
              let keyID = rawSignature["key_id"] as? String,
              isSafeIdentifier(keyID, maximumBytes: 128),
              keyID == trust.keyID,
              let signatureText = rawSignature["signature_base64url"] as? String,
              let signature = decodeCanonicalBase64URL(signatureText, byteCount: 64) else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }

        // strictManifestEnvelope already rejected duplicate fields,
        // whitespace, alternate escaping, and non-canonical ordering.
        let signedBytes = Data(signatureDomain.utf8) + (try NativeStrictJSON.data(rawCore))
        guard trust.publicKey.isValidSignature(signature, for: signedBytes) else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }

        // The initializer enforces the required node/index entries and the
        // total-size policy. Release metadata is retained in the selection so
        // equality/revalidation cannot silently cross materialization epochs.
        return try NativeCursorAgentRuntimeManifest(
            entries: entries,
            runtimeVersion: runtimeVersion,
            releaseDigest: releaseDigest,
            materializationEpoch: materializationEpoch
        )
    }

    private struct TrustConfig {
        let keyID: String
        let publicKey: Curve25519.Signing.PublicKey
    }

    private static func parseTrustConfig(_ data: Data) throws -> TrustConfig {
        let object = try strictObject(data, maximumBytes: maximumTrustConfigBytes)
        try requireExactKeys(object, ["schema_version", "key_id", "public_key_der_base64url"])
        guard let version = positiveSafeInteger(object["schema_version"]),
              version == 1,
              let keyID = object["key_id"] as? String,
              isSafeIdentifier(keyID, maximumBytes: 128),
              let encodedDER = object["public_key_der_base64url"] as? String,
              let der = decodeCanonicalBase64URL(encodedDER, byteCount: 44),
              der.prefix(ed25519SPKIPrefix.count) == ed25519SPKIPrefix,
              der == ed25519SPKIPrefix + der.suffix(32),
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32)) else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }
        guard try NativeStrictJSON.data(object) == data else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }
        return TrustConfig(keyID: keyID, publicKey: publicKey)
    }

    private static func strictObject(_ data: Data, maximumBytes: Int) throws -> [String: Any] {
        do {
            return try NativeStrictJSON.object(
                from: data,
                maxBytes: maximumBytes,
                maxDepth: maximumJSONDepth
            )
        } catch {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }
    }

    private static func strictManifestEnvelope(
        _ data: Data,
        maximumBytes: Int
    ) throws -> [String: Any] {
        guard data.last == 0x0a,
              !data.dropLast().contains(0x0a) else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }
        let jsonData = Data(data.dropLast())
        let object = try strictObject(jsonData, maximumBytes: maximumBytes)
        guard try NativeStrictJSON.data(object) == jsonData else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }
        return object
    }

    private static func requireExactKeys(
        _ object: [String: Any],
        _ expected: Set<String>
    ) throws {
        guard Set(object.keys) == expected else {
            throw NativeCursorAgentRuntimeTrustError.invalidManifest
        }
    }

    private static func isSafeIdentifier(_ value: String, maximumBytes: Int) -> Bool {
        value.utf8.count >= 1 && value.utf8.count <= maximumBytes
            && value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]*$", options: .regularExpression) != nil
    }

    private static func positiveSafeInteger(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              String(cString: number.objCType) == "q",
              number.int64Value > 0,
              number.int64Value <= 9_007_199_254_740_991 else {
            return nil
        }
        return number.int64Value
    }

    private static func positiveUInt64(_ value: Any?) -> UInt64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              ["q", "Q"].contains(String(cString: number.objCType)),
              number.uint64Value > 0,
              number.uint64Value <= NativeCursorAgentRuntimePolicy.maximumSafeInteger else {
            return nil
        }
        return number.uint64Value
    }

    private static func positiveOrZeroUInt64(_ value: Any?) -> UInt64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              ["q", "Q"].contains(String(cString: number.objCType)),
              number.int64Value >= 0 else {
            return nil
        }
        return number.uint64Value
    }

    private static func decodeCanonicalBase64URL(
        _ value: String,
        byteCount: Int
    ) -> Data? {
        guard !value.isEmpty,
              value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else {
            return nil
        }
        var standard = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
        guard let decoded = Data(base64Encoded: standard),
              decoded.count == byteCount else {
            return nil
        }
        let canonical = decoded.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return canonical == value ? decoded : nil
    }
}

/// Descriptor-only reader for the two trust inputs. Intermediate directories
/// are also opened with O_NOFOLLOW so a path component cannot redirect the
/// trust root between validation and the final file open.
private enum NativeCursorAgentRuntimeSecureFile {
    static func read(path: String, maximumBytes: Int) throws -> Data {
        let components = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard path.hasPrefix("/"), !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("\0") }) else {
            throw NativeCursorAgentRuntimeTrustError.manifestUnavailable
        }

        var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw NativeCursorAgentRuntimeTrustError.manifestUnavailable }
        defer { Darwin.close(descriptor) }

        for component in components.dropLast() {
            let next = openat(descriptor, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw NativeCursorAgentRuntimeTrustError.manifestUnavailable }
            Darwin.close(descriptor)
            descriptor = next
            try validateDirectory(descriptor)
        }

        let fileDescriptor = openat(descriptor, components.last!, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fileDescriptor >= 0 else { throw NativeCursorAgentRuntimeTrustError.manifestUnavailable }
        defer { Darwin.close(fileDescriptor) }
        try validateFile(fileDescriptor, maximumBytes: maximumBytes)

        var before = stat()
        guard fstat(fileDescriptor, &before) == 0 else {
            throw NativeCursorAgentRuntimeTrustError.manifestUnavailable
        }
        var data = Data()
        data.reserveCapacity(Int(min(UInt64(maximumBytes), UInt64(max(0, before.st_size)))))
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(fileDescriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            guard count > 0 else {
                if errno == EINTR { continue }
                throw NativeCursorAgentRuntimeTrustError.manifestUnavailable
            }
            guard data.count <= maximumBytes - count else {
                throw NativeCursorAgentRuntimeTrustError.manifestUnavailable
            }
            data.append(contentsOf: buffer.prefix(Int(count)))
        }
        var after = stat()
        guard fstat(fileDescriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              UInt64(data.count) == UInt64(max(0, before.st_size)) else {
            throw NativeCursorAgentRuntimeTrustError.manifestUnavailable
        }
        return data
    }

    private static func validateDirectory(_ descriptor: Int32) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              UInt32(info.st_mode) & UInt32(S_IFMT) == UInt32(S_IFDIR),
              info.st_uid == 0,
              UInt32(info.st_mode) & 0o022 == 0,
              !hasExtendedACL(descriptor) else {
            throw NativeCursorAgentRuntimeTrustError.manifestUnavailable
        }
    }

    private static func validateFile(_ descriptor: Int32, maximumBytes: Int) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              UInt32(info.st_mode) & UInt32(S_IFMT) == UInt32(S_IFREG),
              info.st_uid == 0,
              UInt32(info.st_mode) & 0o022 == 0,
              info.st_nlink == 1,
              info.st_size >= 0,
              UInt64(info.st_size) <= UInt64(maximumBytes),
              !hasExtendedACL(descriptor) else {
            throw NativeCursorAgentRuntimeTrustError.manifestUnavailable
        }
    }

    private static func hasExtendedACL(_ descriptor: Int32) -> Bool {
        guard let acl = acl_get_fd(descriptor) else {
            // macOS reports ENOENT/ENOATTR when ACL_TYPE_EXTENDED is not
            // attached. That is the safe, expected "no extended ACL" case;
            // every other inspection failure remains fail-closed.
            return errno != ENOENT && errno != ENOATTR
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        return acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == 0
    }
}

/// Security.framework verifier for an identity claim provisioned with the
/// runtime manifest. This is never called with caller-provided identity data.
internal enum NativeCursorSystemCodeIdentityVerifier {
    private static let strictValidationFlags = SecCSFlags(
        rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode
    )

    static func verify(
        path: String,
        claim: NativeCursorAgentRuntimeCodeIdentityClaim
    ) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            URL(fileURLWithPath: path).standardizedFileURL as CFURL,
            [],
            &code
        ) == errSecSuccess,
        let code else {
            throw NativeCursorAgentRuntimeTrustError.artifactUnavailable
        }

        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            claim.designatedRequirement as CFString,
            [],
            &requirement
        ) == errSecSuccess,
        let requirement,
        SecStaticCodeCheckValidity(code, strictValidationFlags, requirement) == errSecSuccess else {
            throw NativeCursorAgentRuntimeTrustError.codeIdentityMismatch
        }

        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
        let rawInformation,
        let information = rawInformation as? [String: Any],
        information[kSecCodeInfoIdentifier as String] as? String == claim.identifier,
        information[kSecCodeInfoTeamIdentifier as String] as? String == claim.teamIdentifier else {
            throw NativeCursorAgentRuntimeTrustError.codeIdentityMismatch
        }

        guard let rawDesignatedRequirement = information[
            kSecCodeInfoDesignatedRequirement as String
        ],
        CFGetTypeID(rawDesignatedRequirement as CFTypeRef) == SecRequirementGetTypeID() else {
            throw NativeCursorAgentRuntimeTrustError.codeIdentityMismatch
        }
        let designatedRequirement = unsafeBitCast(
            rawDesignatedRequirement as CFTypeRef,
            to: SecRequirement.self
        )
        guard let actual = requirementString(designatedRequirement),
              let expected = requirementString(requirement),
              actual == expected else {
            throw NativeCursorAgentRuntimeTrustError.codeIdentityMismatch
        }
    }

    private static func requirementString(_ requirement: SecRequirement) -> String? {
        var output: CFString?
        guard SecRequirementCopyString(requirement, SecCSFlags(), &output) == errSecSuccess,
              let output else {
            return nil
        }
        return output as String
    }
}

internal enum NativeCursorAgentRuntimeDigest {
    static func sha256(path: String) throws -> String {
        let descriptor = path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw NativeCursorAgentRuntimeTrustError.digestUnavailable
        }
        defer { Darwin.close(descriptor) }

        var before = stat()
        guard fstat(descriptor, &before) == 0,
              UInt32(before.st_mode) & UInt32(S_IFMT) == UInt32(S_IFREG),
              before.st_size >= 0,
              UInt64(before.st_size) <= NativeCursorAgentRuntimePolicy.maximumFileSize else {
            throw NativeCursorAgentRuntimeTrustError.digestUnavailable
        }

        var hasher = SHA256()
        var total: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            guard count > 0 else {
                if errno == EINTR { continue }
                throw NativeCursorAgentRuntimeTrustError.digestUnavailable
            }
            guard total <= NativeCursorAgentRuntimePolicy.maximumFileSize - UInt64(count) else {
                throw NativeCursorAgentRuntimeTrustError.digestUnavailable
            }
            total += UInt64(count)
            hasher.update(data: Data(buffer[0..<Int(count)]))
        }

        var after = stat()
        guard fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              total == UInt64(before.st_size) else {
            throw NativeCursorAgentRuntimeTrustError.digestUnavailable
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
