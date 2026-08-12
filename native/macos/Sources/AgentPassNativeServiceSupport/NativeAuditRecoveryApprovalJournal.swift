import AgentPassNativeCore
import CryptoKit
import Darwin
import Foundation

/// Immutable, root-private evidence that user presence approved the exact
/// lifecycle statement and anchor authorization before any network submission.
public final class NativeAuditRecoveryApprovalJournal: @unchecked Sendable {
    public struct Proof: Equatable {
        let operationID: String
        let signerFingerprint: String
        let signerPublicKeyX963: Data
        let statementHash: String
        let authorizationHash: String
        let signature: Data
        let createdAt: String
    }

    private let descriptor: Int32
    private let rootPath: String
    private let lock = NSLock()

    public init(rootPath: String) throws {
        guard rootPath.hasPrefix("/"),
              URL(fileURLWithPath: rootPath).standardizedFileURL.resolvingSymlinksInPath().path == rootPath else {
            throw AgentPassNativeError.invalidConfiguration("Audit recovery approval journal path must be absolute and canonical")
        }
        let fd = open(rootPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Self.posixError() }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
            close(fd)
            throw AgentPassNativeError.invalidConfiguration("Audit recovery approval journal must be a service-owned 0700 directory")
        }
        descriptor = fd
        self.rootPath = rootPath
        do { try validateEntries() } catch { close(fd); throw error }
    }

    deinit { close(descriptor) }

    public func append(
        operationID: String,
        signerFingerprint: String,
        signerPublicKeyX963: Data,
        statementData: Data,
        authorizationData: Data,
        signature: Data,
        createdAt: String
    ) throws -> Proof {
        let proof = Proof(
            operationID: operationID,
            signerFingerprint: signerFingerprint,
            signerPublicKeyX963: signerPublicKeyX963,
            statementHash: Self.hash(statementData),
            authorizationHash: Self.hash(authorizationData),
            signature: signature,
            createdAt: createdAt
        )
        try verify(proof, statementData: statementData, authorizationData: authorizationData)
        return try withLock {
            let name = Self.name(operationID)
            if let existing = try read(name) {
                guard existing.operationID == proof.operationID,
                      existing.signerFingerprint == proof.signerFingerprint,
                      existing.signerPublicKeyX963 == proof.signerPublicKeyX963,
                      existing.statementHash == proof.statementHash,
                      existing.authorizationHash == proof.authorizationHash else {
                    throw AgentPassNativeError.invalidSignature("Audit recovery local approval proof equivocates")
                }
                try verify(existing, statementData: statementData, authorizationData: authorizationData)
                return existing
            }
            let data = try Self.encode(proof)
            let fd = openat(descriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400)
            guard fd >= 0 else { throw Self.posixError() }
            do {
                try data.withUnsafeBytes { bytes in
                    var offset = 0
                    while offset < bytes.count {
                        let written = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                        guard written > 0 else { throw Self.posixError() }
                        offset += written
                    }
                }
                guard fsync(fd) == 0, close(fd) == 0, fsync(descriptor) == 0 else { throw Self.posixError() }
            } catch {
                close(fd)
                unlinkat(descriptor, name, 0)
                throw error
            }
            return proof
        }
    }

    public func require(
        operationID: String,
        statementData: Data,
        authorizationData: Data,
        expectedSignerFingerprint: String? = nil
    ) throws -> Proof {
        try withLock {
            guard let proof = try read(Self.name(operationID)) else {
                throw AgentPassNativeError.invalidSignature("Durable audit recovery local-presence proof is missing")
            }
            if let expectedSignerFingerprint, proof.signerFingerprint != expectedSignerFingerprint {
                throw AgentPassNativeError.invalidSignature("Audit recovery local signer fingerprint was substituted")
            }
            try verify(proof, statementData: statementData, authorizationData: authorizationData)
            return proof
        }
    }

    private func verify(_ proof: Proof, statementData: Data, authorizationData: Data) throws {
        guard proof.signature.count == 64,
              proof.signerFingerprint == NativeKeyLifecycleStore.fingerprint(proof.signerPublicKeyX963),
              proof.statementHash == Self.hash(statementData),
              proof.authorizationHash == Self.hash(authorizationData),
              NativeP256LifecycleVerifier().isValid(
                signature: proof.signature, message: statementData, publicKeyX963: proof.signerPublicKeyX963
              ) else {
            throw AgentPassNativeError.invalidSignature("Audit recovery local-presence proof is invalid")
        }
    }

    private func validateEntries() throws {
        let names = try FileManager.default.contentsOfDirectory(atPath: rootPath)
        for name in names {
            guard name.wholeMatch(of: /^approval-[0-9a-f]{64}\.json$/) != nil,
                  try read(name) != nil else {
                throw AgentPassNativeError.invalidSignature("Audit recovery approval journal contains an invalid entry")
            }
        }
    }

    private func read(_ name: String) throws -> Proof? {
        let fd = openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw Self.posixError()
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o400,
              info.st_size > 0, info.st_size <= 16 * 1024 else {
            throw AgentPassNativeError.invalidSignature("Audit recovery approval proof file is not private and bounded")
        }
        var data = Data(count: Int(info.st_size))
        let count = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
        guard count == data.count else { throw Self.posixError() }
        return try Self.decode(data)
    }

    private static func encode(_ proof: Proof) throws -> Data {
        var object: [String: Any] = [
            "version": 1,
            "operation_id": proof.operationID,
            "signer_fingerprint": proof.signerFingerprint,
            "signer_public_key_x963": proof.signerPublicKeyX963.base64EncodedString(),
            "statement_hash": proof.statementHash,
            "authorization_hash": proof.authorizationHash,
            "signature": proof.signature.base64EncodedString(),
            "created_at": proof.createdAt
        ]
        object["record_hash"] = hash(try canonical(object))
        return try canonical(object)
    }

    private static func decode(_ data: Data) throws -> Proof {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              try canonical(object) == data,
              Set(object.keys) == ["version", "operation_id", "signer_fingerprint", "signer_public_key_x963", "statement_hash", "authorization_hash", "signature", "created_at", "record_hash"],
              (object["version"] as? NSNumber)?.intValue == 1,
              let operationID = object["operation_id"] as? String,
              let fingerprint = object["signer_fingerprint"] as? String,
              let publicText = object["signer_public_key_x963"] as? String,
              let publicKey = Data(base64Encoded: publicText), publicKey.base64EncodedString() == publicText,
              let statementHash = object["statement_hash"] as? String,
              let authorizationHash = object["authorization_hash"] as? String,
              let signatureText = object["signature"] as? String,
              let signature = Data(base64Encoded: signatureText), signature.base64EncodedString() == signatureText,
              let createdAt = object["created_at"] as? String,
              let recordHash = object["record_hash"] as? String else {
            throw AgentPassNativeError.invalidSignature("Audit recovery approval proof encoding is invalid")
        }
        var unsigned = object
        unsigned.removeValue(forKey: "record_hash")
        guard recordHash == hash(try canonical(unsigned)) else {
            throw AgentPassNativeError.invalidSignature("Audit recovery approval proof hash is invalid")
        }
        return Proof(operationID: operationID, signerFingerprint: fingerprint, signerPublicKeyX963: publicKey, statementHash: statementHash, authorizationHash: authorizationHash, signature: signature, createdAt: createdAt)
    }

    private static func canonical(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func name(_ operationID: String) -> String {
        "approval-\(hash(Data(operationID.utf8))).json"
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }

    private static func posixError() -> Error {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
