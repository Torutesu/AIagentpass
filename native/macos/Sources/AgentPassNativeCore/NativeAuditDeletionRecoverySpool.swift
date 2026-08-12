import CryptoKit
import Darwin
import Foundation

public struct NativeAuditDeletionPreparedEvidence: @unchecked Sendable {
    public let binding: NativeAuditDeletionIntentBinding
    public let spoolLease: NativeAuditDeletionRecoverySpoolLease
}

/// Durable, content-addressed recovery evidence created before an audit key deletion intent.
public final class NativeAuditDeletionRecoverySpoolLease: @unchecked Sendable {
    public let bundleData: Data
    public let binding: NativeAuditDeletionIntentBinding
    private let rootFD: Int32
    fileprivate let rootPath: String
    private let directoryFD: Int32
    private let fileFDs: [Int32]
    private let lock = NSLock()

    fileprivate init(rootPath: String, rootFD: Int32, directoryFD: Int32, fileFDs: [Int32], bundleData: Data, binding: NativeAuditDeletionIntentBinding) {
        self.rootPath = rootPath
        self.rootFD = rootFD; self.directoryFD = directoryFD; self.fileFDs = fileFDs
        self.bundleData = bundleData; self.binding = binding
    }

    deinit { fileFDs.forEach { close($0) }; close(directoryFD); close(rootFD) }

    public func revalidate() throws {
        lock.lock(); defer { lock.unlock() }
        try NativeAuditDeletionRecoverySpool.revalidate(self)
    }
}

public enum NativeAuditDeletionRecoverySpool {
    private static let bundleName = "bundle-v4.json"
    private static let manifestName = "manifest.json"
    private static let archiveNames = ["00-audit.archive", "01-checkpoints.archive", "02-receipts.archive"]
    private static let maximumBundleBytes = NativeAuditRetentionVerifier.maximumDocumentBytes * 7

    public static func ensureRoot(_ path: String) throws {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        let parent = url.deletingLastPathComponent().path, name = url.lastPathComponent
        guard path == url.path, !name.isEmpty, name != ".", name != ".." else { throw AgentPassNativeError.invalidConfiguration("Audit deletion spool path is invalid") }
        let parentFD = Darwin.open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentFD >= 0 else { throw posixError() }
        defer { close(parentFD) }
        if mkdirat(parentFD, name, 0o700) != 0, errno != EEXIST { throw posixError() }
        let root = openat(parentFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw posixError() }
        defer { close(root) }
        try validatePrivateDirectory(root, label: "Audit deletion spool root")
        guard fsync(root) == 0, fsync(parentFD) == 0 else { throw posixError() }
    }

    public static func prepare(
        rootPath: String,
        bundleData: Data,
        segment: NativeAuditRetentionSegment,
        identities: [NativeAuditRetentionFileIdentity],
        sourceLease: NativeAuditRetainedArchiveLease
    ) throws -> NativeAuditDeletionPreparedEvidence {
        guard !bundleData.isEmpty, bundleData.count <= maximumBundleBytes else { throw AgentPassNativeError.invalidSignature("Audit deletion bundle exceeds spool limit") }
        let canonicalObject = try JSONSerialization.jsonObject(with: bundleData)
        guard JSONSerialization.isValidJSONObject(canonicalObject),
              try JSONSerialization.data(withJSONObject: canonicalObject, options: [.sortedKeys, .withoutEscapingSlashes]) == bundleData else {
            throw AgentPassNativeError.invalidSignature("Audit deletion spool requires an exact canonical bundle")
        }
        let authorization = try NativeAuditPruneAuthorization.decodeCanonical(
            try bundleDocument(bundleData, key: "authorization_base64")
        )
        let bundleHash = hash(bundleData)
        let segmentHash = try NativeAuditDeletionEvidenceHash.retainedSegment(segment)
        let identityHash = try NativeAuditDeletionEvidenceHash.retainedIdentities(identities)
        let pathChainHash = sourceLease.pathChainHash
        let snapshot = try sourceLease.recoverySnapshot()
        guard snapshot.map(\.identity) == identities else { throw AgentPassNativeError.invalidSignature("Retained archive snapshot changed before spooling") }
        let unsigned: [String: Any] = [
            "version": 1, "bundle_sha256": bundleHash, "operation_id": authorization.operationID,
            "retained_segment_hash": segmentHash, "retained_identity_hash": identityHash,
            "archive_path_chain_hash": pathChainHash,
            "files": zip(archiveNames, snapshot).map { ["name": $0.0, "sha256": $0.1.identity.sha256, "size": $0.1.identity.size] }
        ]
        let unsignedData = try canonical(unsigned)
        let manifestHash = hash(unsignedData)
        var manifest = unsigned; manifest["manifest_hash"] = manifestHash
        let manifestData = try canonical(manifest)
        let directoryName = "spool-\(manifestHash)"
        let rootFD = try openRoot(rootPath)
        var keepRoot = false
        defer { if !keepRoot { close(rootFD) } }
        let temporary = ".tmp-\(UUID().uuidString.lowercased())"
        guard mkdirat(rootFD, temporary, 0o700) == 0 else { throw posixError() }
        let temporaryFD = openat(rootFD, temporary, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard temporaryFD >= 0 else { throw posixError() }
        var renamed = false
        defer {
            close(temporaryFD)
            if !renamed {
                for name in archiveNames + [bundleName, manifestName] { _ = unlinkat(rootFD, temporary + "/" + name, 0) }
                _ = unlinkat(rootFD, temporary, AT_REMOVEDIR)
            }
        }
        for (name, value) in zip(archiveNames, snapshot) { try writeImmutable(temporaryFD, name, value.data) }
        try writeImmutable(temporaryFD, bundleName, bundleData)
        try writeImmutable(temporaryFD, manifestName, manifestData)
        guard fsync(temporaryFD) == 0 else { throw posixError() }
        if renameatx_np(rootFD, temporary, rootFD, directoryName, UInt32(RENAME_EXCL)) != 0 {
            guard errno == EEXIST else { throw posixError() }
        } else { renamed = true; guard fsync(rootFD) == 0 else { throw posixError() } }
        if !renamed { _ = unlinkat(rootFD, temporary, AT_REMOVEDIR) }
        let directoryFD = openat(rootFD, directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directoryFD >= 0 else { throw posixError() }
        var info = stat()
        guard fstat(directoryFD, &info) == 0 else { close(directoryFD); throw posixError() }
        let binding = NativeAuditDeletionIntentBinding(bundleSHA256: bundleHash, retainedSegmentHash: segmentHash, retainedIdentityHash: identityHash, archivePathChainHash: pathChainHash, operationID: authorization.operationID, spoolManifestHash: manifestHash, spoolDirectoryName: directoryName, spoolDevice: UInt64(info.st_dev), spoolInode: UInt64(info.st_ino))
        close(directoryFD)
        close(rootFD); keepRoot = true
        let lease = try open(rootPath: rootPath, binding: binding)
        return NativeAuditDeletionPreparedEvidence(binding: binding, spoolLease: lease)
    }

    public static func open(rootPath: String, binding: NativeAuditDeletionIntentBinding) throws -> NativeAuditDeletionRecoverySpoolLease {
        let rootFD = try openRoot(rootPath)
        let directoryFD = openat(rootFD, binding.spoolDirectoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directoryFD >= 0 else { close(rootFD); throw posixError() }
        do {
            try validatePrivateDirectory(directoryFD, label: "Audit deletion recovery spool")
            var info = stat(), pathInfo = stat()
            guard fstat(directoryFD, &info) == 0,
                  fstatat(rootFD, binding.spoolDirectoryName, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
                  UInt64(info.st_dev) == binding.spoolDevice, UInt64(info.st_ino) == binding.spoolInode,
                  pathInfo.st_dev == info.st_dev, pathInfo.st_ino == info.st_ino else {
                throw AgentPassNativeError.invalidSignature("Audit deletion spool path identity changed")
            }
            let manifestData = try readFile(directoryFD, manifestName, maximum: 64 * 1024)
            let manifest = try parseManifest(manifestData, binding: binding)
            let bundle = try readFile(directoryFD, bundleName, maximum: maximumBundleBytes)
            guard hash(bundle) == binding.bundleSHA256 else { throw AgentPassNativeError.invalidSignature("Audit deletion spooled bundle changed") }
            var descriptors: [Int32] = []
            do {
                for (index, name) in archiveNames.enumerated() {
                    let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                    guard fd >= 0 else { throw posixError() }
                    descriptors.append(fd)
                    let data = try readDescriptor(fd, maximum: NativeAuditRetentionArchiveObservation.maximumArchiveBytes)
                    let expected = manifest[index]
                    guard data.count == expected.size, hash(data) == expected.hash else { throw AgentPassNativeError.invalidSignature("Audit deletion spool archive changed") }
                }
            } catch { descriptors.forEach { close($0) }; throw error }
            return NativeAuditDeletionRecoverySpoolLease(rootPath: rootPath, rootFD: rootFD, directoryFD: directoryFD, fileFDs: descriptors, bundleData: bundle, binding: binding)
        } catch { close(directoryFD); close(rootFD); throw error }
    }

    fileprivate static func revalidate(_ lease: NativeAuditDeletionRecoverySpoolLease) throws {
        let reopened = try open(rootPath: lease.rootPath, binding: lease.binding)
        guard reopened.bundleData == lease.bundleData else { throw AgentPassNativeError.invalidSignature("Audit deletion spool rollback detected") }
    }

    private struct ManifestFile { let hash: String; let size: Int }
    private static func parseManifest(_ data: Data, binding: NativeAuditDeletionIntentBinding) throws -> [ManifestFile] {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["version", "bundle_sha256", "operation_id", "retained_segment_hash", "retained_identity_hash", "archive_path_chain_hash", "files", "manifest_hash"],
              try canonical(object) == data, object["version"] as? Int == 1,
              object["bundle_sha256"] as? String == binding.bundleSHA256,
              object["operation_id"] as? String == binding.operationID,
              object["retained_segment_hash"] as? String == binding.retainedSegmentHash,
              object["retained_identity_hash"] as? String == binding.retainedIdentityHash,
              object["archive_path_chain_hash"] as? String == binding.archivePathChainHash,
              object["manifest_hash"] as? String == binding.spoolManifestHash,
              let files = object["files"] as? [[String: Any]], files.count == 3 else { throw AgentPassNativeError.invalidSignature("Audit deletion spool manifest is invalid") }
        var unsigned = object; unsigned.removeValue(forKey: "manifest_hash")
        guard hash(try canonical(unsigned)) == binding.spoolManifestHash else { throw AgentPassNativeError.invalidSignature("Audit deletion spool manifest hash changed") }
        return try zip(archiveNames, files).map { name, file in
            guard Set(file.keys) == ["name", "sha256", "size"], file["name"] as? String == name,
                  let digest = file["sha256"] as? String, digest.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  let size = file["size"] as? Int, size > 0 else { throw AgentPassNativeError.invalidSignature("Audit deletion spool file manifest is invalid") }
            return ManifestFile(hash: digest, size: size)
        }
    }

    private static func openRoot(_ path: String) throws -> Int32 {
        let fd = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posixError() }; try validatePrivateDirectory(fd, label: "Audit deletion spool root"); return fd
    }
    private static func validatePrivateDirectory(_ fd: Int32, label: String) throws { var s = stat(); guard fstat(fd,&s)==0,(s.st_mode&S_IFMT)==S_IFDIR,s.st_uid==geteuid(),s.st_mode&0o077==0 else { throw AgentPassNativeError.invalidConfiguration("\(label) must be owner-private") } }
    private static func writeImmutable(_ dir:Int32,_ name:String,_ data:Data)throws{let fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o400);guard fd>=0 else{throw posixError()};defer{close(fd)};try data.withUnsafeBytes{p in var o=0;while o<data.count{let n=Darwin.write(fd,p.baseAddress!.advanced(by:o),data.count-o);guard n>0 else{throw posixError()};o+=n}};guard fsync(fd)==0 else{throw posixError()}}
    private static func readFile(_ dir:Int32,_ name:String,maximum:Int)throws->Data{let fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);guard fd>=0 else{throw posixError()};defer{close(fd)};return try readDescriptor(fd,maximum:maximum)}
    private static func readDescriptor(_ fd:Int32,maximum:Int)throws->Data{var before=stat();guard fstat(fd,&before)==0,(before.st_mode&S_IFMT)==S_IFREG,before.st_uid==geteuid(),before.st_mode&0o777==0o400,before.st_nlink==1,before.st_size>0,before.st_size<=maximum else{throw AgentPassNativeError.invalidSignature("Audit deletion spool file metadata is invalid")};guard lseek(fd,0,SEEK_SET)==0 else{throw posixError()};var d=Data(),b=[UInt8](repeating:0,count:65536);while true{let n=Darwin.read(fd,&b,b.count);guard n>=0 else{throw posixError()};if n==0{break};guard d.count<=maximum-n else{throw AgentPassNativeError.invalidSignature("Audit deletion spool file exceeds limit")};d.append(b,count:n)};var after=stat();guard fstat(fd,&after)==0,before.st_dev==after.st_dev,before.st_ino==after.st_ino,before.st_mode==after.st_mode,before.st_uid==after.st_uid,before.st_gid==after.st_gid,before.st_nlink==after.st_nlink,before.st_size==after.st_size,d.count==Int(before.st_size)else{throw AgentPassNativeError.invalidSignature("Audit deletion spool file changed while read")};return d}
    private static func bundleDocument(_ data:Data,key:String)throws->Data{guard let o=try JSONSerialization.jsonObject(with:data)as?[String:Any],let s=o[key]as?String,let d=Data(base64Encoded:s),d.base64EncodedString()==s else{throw AgentPassNativeError.invalidSignature("Audit deletion bundle document is invalid")};return d}
    private static func canonical(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys,.withoutEscapingSlashes])}
    private static func hash(_ data:Data)->String{SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
    private static func posixError()->POSIXError{POSIXError(POSIXErrorCode(rawValue:errno) ?? .EIO)}
}
