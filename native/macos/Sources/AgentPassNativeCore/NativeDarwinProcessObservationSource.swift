import CryptoKit
import Darwin
import Foundation
import Security

/// The bounded, machine-readable failure vocabulary used by the Darwin
/// observer.  These strings are intentionally not OS error descriptions: OS
/// descriptions can contain paths, process names, or other unstable data.
internal enum NativeDarwinProcessObservationReason: String, CaseIterable, Sendable {
    case currentProcessUnavailable = "darwin_current_process_unavailable"
    case effectiveUserUnavailable = "darwin_effective_user_unavailable"
    case bootIdentityUnavailable = "darwin_boot_identity_unavailable"
    case processUnavailable = "darwin_process_unavailable"
    case processSnapshotInvalid = "darwin_process_snapshot_invalid"
    case processChangedDuringObservation = "darwin_process_changed_during_observation"
    case processUserMismatch = "darwin_process_user_mismatch"
    case processAncestryCycle = "darwin_process_ancestry_cycle"
    case ancestorLimitExceeded = "darwin_ancestor_limit_exceeded"
    case executablePathUnavailable = "darwin_executable_path_unavailable"
    case executablePathInvalid = "darwin_executable_path_invalid"
    case executableFileUnavailable = "darwin_executable_file_unavailable"
    case executableFileInvalid = "darwin_executable_file_invalid"
    case executableChangedDuringObservation = "darwin_executable_changed_during_observation"
    case codeIdentityUnavailable = "darwin_code_identity_unavailable"
    case codeSignatureInvalid = "darwin_code_signature_invalid"
    case codeDirectoryHashUnavailable = "darwin_code_directory_hash_unavailable"
    case codeEntitlementsInvalid = "darwin_code_entitlements_invalid"
    case observationConstructionFailed = "darwin_observation_construction_failed"
}

private func nativeDarwinObservationFailure(_ reason: NativeDarwinProcessObservationReason) -> NativeProcessIdentityError {
    .invalidObservation(reason.rawValue)
}

/// A single kernel process snapshot.  `pidVersion` is derived by the real
/// adapter from `proc_bsdinfo.pbi_start_tvsec/usec`.  macOS does not expose a
/// stable PID-generation syscall through the public Swift API; this
/// start-time identity is therefore deliberately documented as a fallback,
/// not represented as a stronger kernel generation number.
internal struct NativeDarwinProcessSnapshot: Equatable, Sendable {
    let pid: Int32
    let parentPID: Int32
    let uid: UInt32
    let pidVersion: UInt64

    init(pid: Int32, parentPID: Int32, uid: UInt32, pidVersion: UInt64) {
        self.pid = pid
        self.parentPID = parentPID
        self.uid = uid
        self.pidVersion = pidVersion
    }
}

/// The Security.framework facts returned for one executable.  No executable
/// path, audit token, requirement blob, or certificate data crosses this
/// adapter boundary.
internal struct NativeDarwinCodeIdentity: Sendable {
    let codeDirectoryHash: String
    let bundleIdentifier: String?
    let teamIdentifier: String?
    let signatureKind: NativeCodeSignatureKind
    let entitlements: [String: NativeEntitlementValue]

    init(
        codeDirectoryHash: String,
        bundleIdentifier: String?,
        teamIdentifier: String?,
        signatureKind: NativeCodeSignatureKind,
        entitlements: [String: NativeEntitlementValue]
    ) {
        self.codeDirectoryHash = codeDirectoryHash
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.signatureKind = signatureKind
        self.entitlements = entitlements
    }
}

/// Injectable OS boundary for deterministic race and failure tests.  The
/// production implementation is `NativeDarwinSystemObservationAdapter`.
internal protocol NativeDarwinProcessObservationAdapter: Sendable {
    func currentProcessID() throws -> Int32
    func effectiveUserID() throws -> UInt32
    func bootIdentity() throws -> String
    func processSnapshot(pid: Int32) throws -> NativeDarwinProcessSnapshot
    func executablePath(pid: Int32) throws -> String
    func executableFileIdentity(path: String) throws -> NativeExecutableFileIdentity
    func codeIdentity(pid: Int32) throws -> NativeDarwinCodeIdentity
}

/// Darwin-backed implementation of `NativeProcessObservationSource`.
///
/// `observe()` retains its compatibility meaning of observing the current
/// process. `observe(pid:)` is the explicit peer-observation entry point: its
/// PID is authoritative and it never falls back to the current process. The
/// only path handled by the implementation is a transient kernel-provided
/// path used to query `stat` and Security.framework; it is never returned or
/// retained in the resulting model.
public struct NativeDarwinProcessObservationSource: NativeProcessObservationSource, Sendable {
    internal static let maximumAncestors = 16

    private let adapter: any NativeDarwinProcessObservationAdapter

    public init() {
        self.adapter = NativeDarwinSystemObservationAdapter()
    }

    internal init(adapter: any NativeDarwinProcessObservationAdapter) {
        self.adapter = adapter
    }

    public func observe() throws -> NativeProcessObservation {
        let pid = try readCurrentProcessID()
        return try observe(pid: pid)
    }

    /// Observes the explicitly supplied Darwin process ID.
    ///
    /// This method deliberately does not call `currentProcessID()`. A caller
    /// using an XPC audit-token PID must not be silently downgraded to
    /// observing the service itself when the peer PID is unavailable or
    /// invalid. The peer must also be owned by the service's effective user;
    /// cross-user observations fail closed.
    public func observe(pid: Int32) throws -> NativeProcessObservation {
        try observe(pid: pid, expectedUserID: readEffectiveUserID())
    }

    /// Observes a peer PID and binds it to an effective UID obtained from the
    /// connection's OS-owned metadata. Privileged services must use this
    /// overload: comparing a user peer to the daemon's own root EUID would
    /// reject every legitimate connection. The UID is an adapter input, never
    /// a request field controlled by the Agent protocol.
    public func observe(pid: Int32, expectedUserID uid: UInt32) throws -> NativeProcessObservation {
        guard pid > 0 else {
            throw nativeDarwinObservationFailure(.processSnapshotInvalid)
        }
        let bootIdentity = try readBootIdentity()

        let process = try observeFacts(
            pid: pid,
            expectedUID: uid,
            bootIdentity: bootIdentity
        )
        guard process.facts.uid == uid else {
            throw nativeDarwinObservationFailure(.processUserMismatch)
        }

        var ancestry: [NativeProcessAncestryEntry] = []
        var nextPID = process.parentPID
        var visited: Set<Int32> = [pid]

        // PID 1 is the system root and is intentionally the non-observed
        // boundary.  The useful ordered chain is the process's immediate
        // parent through the last user-visible ancestor.
        while nextPID > 1 {
            guard ancestry.count < Self.maximumAncestors else {
                throw nativeDarwinObservationFailure(.ancestorLimitExceeded)
            }
            guard visited.insert(nextPID).inserted else {
                throw nativeDarwinObservationFailure(.processAncestryCycle)
            }

            let ancestor = try observeFacts(
                pid: nextPID,
                expectedUID: uid,
                bootIdentity: bootIdentity
            )
            ancestry.append(.observed(ancestor.facts))
            nextPID = ancestor.parentPID
        }

        // The root peer is sampled again only after the complete ancestry
        // walk. This closes the window in which a peer can be replaced or
        // exec'd after its first fact collection but before the observation
        // is consumed by policy. observeFacts performs its own before/after
        // snapshot as well, so the second collection covers both PID-version
        // reuse and code/file identity substitution.
        let rootAfterAncestry = try observeFacts(
            pid: pid,
            expectedUID: uid,
            bootIdentity: bootIdentity
        )
        guard rootAfterAncestry.initialSnapshot == process.initialSnapshot,
              canonicalProcessFacts(rootAfterAncestry.facts) == canonicalProcessFacts(process.facts) else {
            throw nativeDarwinObservationFailure(.processChangedDuringObservation)
        }

        do {
            return try NativeProcessObservation(
                process: process.facts,
                ancestry: ancestry
            )
        } catch NativeProcessIdentityError.invalidObservation {
            throw nativeDarwinObservationFailure(.observationConstructionFailed)
        } catch {
            throw nativeDarwinObservationFailure(.observationConstructionFailed)
        }
    }

    private func readCurrentProcessID() throws -> Int32 {
        do {
            let pid = try adapter.currentProcessID()
            guard pid > 0 else {
                throw nativeDarwinObservationFailure(.currentProcessUnavailable)
            }
            return pid
        } catch {
            throw nativeDarwinObservationFailure(.currentProcessUnavailable)
        }
    }

    private func readEffectiveUserID() throws -> UInt32 {
        do {
            return try adapter.effectiveUserID()
        } catch {
            throw nativeDarwinObservationFailure(.effectiveUserUnavailable)
        }
    }

    private func readBootIdentity() throws -> String {
        do {
            let identity = try adapter.bootIdentity()
            guard !identity.isEmpty, identity.utf8.count <= 128 else {
                throw nativeDarwinObservationFailure(.bootIdentityUnavailable)
            }
            return identity
        } catch {
            throw nativeDarwinObservationFailure(.bootIdentityUnavailable)
        }
    }

    private func observeFacts(
        pid: Int32,
        expectedUID: UInt32,
        bootIdentity: String
    ) throws -> ObservedProcessFacts {
        let before = try snapshot(pid: pid)
        guard before.pid == pid, before.parentPID >= 0, before.uid == expectedUID,
              before.pidVersion > 0 else {
            throw nativeDarwinObservationFailure(.processSnapshotInvalid)
        }

        let path: String
        do {
            path = try adapter.executablePath(pid: pid)
        } catch {
            throw nativeDarwinObservationFailure(.executablePathUnavailable)
        }
        guard !path.isEmpty, path.utf8.count <= 4096, !path.utf8.contains(0) else {
            throw nativeDarwinObservationFailure(.executablePathInvalid)
        }

        let fileIdentity: NativeExecutableFileIdentity
        do {
            fileIdentity = try adapter.executableFileIdentity(path: path)
        } catch {
            throw nativeDarwinObservationFailure(.executableFileUnavailable)
        }

        let codeIdentity: NativeDarwinCodeIdentity
        do {
            codeIdentity = try adapter.codeIdentity(pid: pid)
        } catch {
            throw nativeDarwinObservationFailure(.codeIdentityUnavailable)
        }

        let fileIdentityAfterCodeObservation: NativeExecutableFileIdentity
        do {
            fileIdentityAfterCodeObservation = try adapter.executableFileIdentity(path: path)
        } catch {
            throw nativeDarwinObservationFailure(.executableFileUnavailable)
        }
        guard fileIdentity == fileIdentityAfterCodeObservation else {
            throw nativeDarwinObservationFailure(.executableChangedDuringObservation)
        }

        let after = try snapshot(pid: pid)
        guard before == after else {
            throw nativeDarwinObservationFailure(.processChangedDuringObservation)
        }

        do {
            let facts = try NativeObservedProcessFacts(
                uid: before.uid,
                pid: before.pid,
                pidVersion: before.pidVersion,
                bootIdentity: bootIdentity,
                executableFileIdentity: fileIdentity,
                codeDirectoryHash: codeIdentity.codeDirectoryHash,
                bundleIdentifier: codeIdentity.bundleIdentifier,
                teamIdentifier: codeIdentity.teamIdentifier,
                signatureKind: codeIdentity.signatureKind,
                entitlements: codeIdentity.entitlements
            )
            return ObservedProcessFacts(
                facts: facts,
                parentPID: before.parentPID,
                initialSnapshot: before
            )
        } catch NativeProcessIdentityError.invalidObservation {
            throw nativeDarwinObservationFailure(.observationConstructionFailed)
        } catch {
            throw nativeDarwinObservationFailure(.observationConstructionFailed)
        }
    }

    private func canonicalProcessFacts(_ facts: NativeObservedProcessFacts) -> String {
        guard let observation = try? NativeProcessObservation(process: facts, ancestry: []) else {
            return ""
        }
        return NativeProcessIdentity(observation: observation).canonicalRepresentation
    }

    private func snapshot(pid: Int32) throws -> NativeDarwinProcessSnapshot {
        do {
            let snapshot = try adapter.processSnapshot(pid: pid)
            guard snapshot.pid > 0, snapshot.parentPID >= 0, snapshot.pidVersion > 0 else {
                throw nativeDarwinObservationFailure(.processSnapshotInvalid)
            }
            return snapshot
        } catch {
            throw nativeDarwinObservationFailure(.processUnavailable)
        }
    }
}

private struct ObservedProcessFacts: Sendable {
    let facts: NativeObservedProcessFacts
    let parentPID: Int32
    let initialSnapshot: NativeDarwinProcessSnapshot
}

private struct NativeDarwinSystemObservationAdapter: NativeDarwinProcessObservationAdapter {
    private static let maximumPathBytes = 4096
    private static let maximumBootIdentityBytes = 128

    func currentProcessID() throws -> Int32 {
        let pid = getpid()
        guard pid > 0 else { throw nativeDarwinObservationFailure(.currentProcessUnavailable) }
        return pid
    }

    func effectiveUserID() throws -> UInt32 {
        UInt32(geteuid())
    }

    func bootIdentity() throws -> String {
        try readSysctlString(named: "kern.bootsessionuuid", maximumBytes: Self.maximumBootIdentityBytes)
    }

    func processSnapshot(pid: Int32) throws -> NativeDarwinProcessSnapshot {
        var information = proc_bsdinfo()
        let expectedSize = Int32(MemoryLayout<proc_bsdinfo>.size)
        let result = withUnsafeMutablePointer(to: &information) {
            proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, $0, expectedSize)
        }
        guard result == expectedSize else {
            throw nativeDarwinObservationFailure(.processUnavailable)
        }

        guard information.pbi_pid <= UInt32(Int32.max),
              information.pbi_ppid <= UInt32(Int32.max) else {
            throw nativeDarwinObservationFailure(.processSnapshotInvalid)
        }

        let startSeconds = information.pbi_start_tvsec
        let startMicroseconds = information.pbi_start_tvusec
        guard startSeconds > 0, startMicroseconds < 1_000_000,
              startSeconds <= (UInt64.max - startMicroseconds) / 1_000_000 else {
            throw nativeDarwinObservationFailure(.processSnapshotInvalid)
        }

        // This is the documented fallback described on
        // NativeDarwinProcessSnapshot: process start time in microseconds.
        let pidVersion = startSeconds * 1_000_000 + startMicroseconds
        return NativeDarwinProcessSnapshot(
            pid: Int32(information.pbi_pid),
            parentPID: Int32(information.pbi_ppid),
            uid: UInt32(information.pbi_uid),
            pidVersion: pidVersion
        )
    }

    func executablePath(pid: Int32) throws -> String {
        var buffer = [UInt8](repeating: 0, count: Self.maximumPathBytes)
        let length = buffer.withUnsafeMutableBytes { bytes in
            proc_pidpath(pid, bytes.baseAddress, UInt32(bytes.count))
        }
        guard length > 0, length < buffer.count else {
            throw nativeDarwinObservationFailure(.executablePathUnavailable)
        }
        let pathBytes = buffer.prefix(Int(length))
        guard let path = String(bytes: pathBytes, encoding: .utf8),
              !path.isEmpty, path.utf8.count <= Self.maximumPathBytes,
              !path.utf8.contains(0) else {
            throw nativeDarwinObservationFailure(.executablePathInvalid)
        }
        return path
    }

    func executableFileIdentity(path: String) throws -> NativeExecutableFileIdentity {
        let descriptor = path.withCString {
            open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw nativeDarwinObservationFailure(.executableFileUnavailable)
        }
        defer { _ = close(descriptor) }

        var information = stat()
        guard fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG,
              information.st_dev > 0, information.st_ino > 0,
              information.st_size > 0,
              information.st_mtimespec.tv_sec >= 0,
              information.st_mtimespec.tv_nsec >= 0,
              information.st_mtimespec.tv_nsec < 1_000_000_000 else {
            throw nativeDarwinObservationFailure(.executableFileInvalid)
        }

        let seconds = Int64(information.st_mtimespec.tv_sec)
        let nanoseconds = Int64(information.st_mtimespec.tv_nsec)
        guard seconds <= (Int64.max - nanoseconds) / 1_000_000_000 else {
            throw nativeDarwinObservationFailure(.executableFileInvalid)
        }

        do {
            return try NativeExecutableFileIdentity(
                deviceID: UInt64(information.st_dev),
                inode: UInt64(information.st_ino),
                fileSize: UInt64(information.st_size),
                modificationTimeNanoseconds: seconds * 1_000_000_000 + nanoseconds
            )
        } catch {
            throw nativeDarwinObservationFailure(.executableFileInvalid)
        }
    }

    func codeIdentity(pid: Int32) throws -> NativeDarwinCodeIdentity {
        let attributes: [String: Any] = [
            kSecGuestAttributePid as String: NSNumber(value: pid)
        ]
        var dynamicCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(
            nil,
            attributes as CFDictionary,
            [],
            &dynamicCode
        ) == errSecSuccess,
        let dynamicCode else {
            throw nativeDarwinObservationFailure(.codeIdentityUnavailable)
        }
        guard SecCodeCheckValidity(
            dynamicCode,
            SecCSFlags(rawValue: kSecCSStrictValidate),
            nil
        ) == errSecSuccess else {
            throw nativeDarwinObservationFailure(.codeSignatureInvalid)
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(dynamicCode, [], &staticCode) == errSecSuccess,
              let staticCode else {
            throw nativeDarwinObservationFailure(.codeIdentityUnavailable)
        }

        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
        let rawInformation,
        let information = rawInformation as? [String: Any] else {
            throw nativeDarwinObservationFailure(.codeIdentityUnavailable)
        }

        let codeDirectoryHash = try codeDirectoryHash(from: information)
        let bundleIdentifier = try boundedIdentifier(
            information[kSecCodeInfoIdentifier as String]
        )
        let teamIdentifier = try boundedIdentifier(
            information[kSecCodeInfoTeamIdentifier as String]
        )
        guard bundleIdentifier != nil else {
            throw nativeDarwinObservationFailure(.codeIdentityUnavailable)
        }
        let entitlements = try entitlements(from: information)
        let signatureKind = signatureKind(from: information)

        return NativeDarwinCodeIdentity(
            codeDirectoryHash: codeDirectoryHash,
            bundleIdentifier: bundleIdentifier,
            teamIdentifier: teamIdentifier,
            signatureKind: signatureKind,
            entitlements: entitlements
        )
    }

    private func codeDirectoryHash(from information: [String: Any]) throws -> String {
        let algorithms = (information[kSecCodeInfoDigestAlgorithms as String] as? [NSNumber]) ??
            ((information[kSecCodeInfoDigestAlgorithms as String] as? NSArray)?.compactMap { $0 as? NSNumber } ?? [])
        let hashes = (information[kSecCodeInfoCdHashes as String] as? [Data]) ??
            ((information[kSecCodeInfoCdHashes as String] as? NSArray)?.compactMap { $0 as? Data } ?? [])
        if let index = algorithms.firstIndex(where: { $0.intValue == Int(SecCSDigestAlgorithm.codeSignatureHashSHA256.rawValue) }),
           index < hashes.count, hashes[index].count == 32 {
            return hashes[index].map { String(format: "%02x", $0) }.joined()
        }

        // Some older Security.framework responses expose only `Unique`.  It
        // is accepted only when it is already the full SHA-256-sized value;
        // this avoids hashing a SHA-1 value and pretending it is a cdhash.
        if let unique = information[kSecCodeInfoUnique as String] as? Data,
           unique.count == 32 {
            return unique.map { String(format: "%02x", $0) }.joined()
        }
        throw nativeDarwinObservationFailure(.codeDirectoryHashUnavailable)
    }

    private func signatureKind(from information: [String: Any]) -> NativeCodeSignatureKind {
        let flags = (information[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        if flags & SecCodeSignatureFlags.adhoc.rawValue != 0 {
            return .adhoc
        }
        if let platform = information[kSecCodeInfoPlatformIdentifier as String] as? String,
           !platform.isEmpty {
            return .apple
        }
        if hasDeveloperIDCertificate(information[kSecCodeInfoCertificates as String]) {
            return .developerID
        }
        if information[kSecCodeInfoCertificates as String] != nil {
            return .other
        }
        return .unsigned
    }

    private func hasDeveloperIDCertificate(_ raw: Any?) -> Bool {
        let certificates: [SecCertificate]
        if let values = raw as? [SecCertificate] {
            certificates = values
        } else if let values = raw as? NSArray {
            certificates = values.compactMap { value in
                guard CFGetTypeID(value as CFTypeRef) == SecCertificateGetTypeID() else { return nil }
                return unsafeBitCast(value as CFTypeRef, to: SecCertificate.self)
            }
        } else {
            certificates = []
        }
        guard let leaf = certificates.first else { return false }

        // Developer ID Application certificates carry this Apple extension.
        // Only the presence of the OID is used; certificate contents never
        // leave this function.
        let developerIDExtension = "1.2.840.113635.100.6.1.13" as CFString
        guard let values = SecCertificateCopyValues(
            leaf,
            [developerIDExtension] as CFArray,
            nil
        ) as? [String: Any] else {
            return false
        }
        return values[developerIDExtension as String] != nil
    }

    private func entitlements(from information: [String: Any]) throws -> [String: NativeEntitlementValue] {
        guard let raw = information[kSecCodeInfoEntitlementsDict as String] else {
            return [:]
        }
        guard let dictionary = raw as? [String: Any] else {
            throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
        }
        guard dictionary.count <= 32 else {
            throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
        }
        var result: [String: NativeEntitlementValue] = [:]
        result.reserveCapacity(dictionary.count)
        for (key, value) in dictionary {
            guard isBoundedIdentifier(key) else {
                throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
            }
            result[key] = try entitlementValue(value, depth: 0)
        }
        return result
    }

    private func entitlementValue(_ value: Any, depth: Int) throws -> NativeEntitlementValue {
        guard depth <= 8 else {
            throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
        }
        if let string = value as? String {
            guard string.utf8.count <= 4096 else {
                throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
            }
            return .string(string)
        }

        let typeID = CFGetTypeID(value as CFTypeRef)
        if typeID == CFBooleanGetTypeID(), let number = value as? NSNumber {
            return .boolean(number.boolValue)
        }
        if typeID == CFNumberGetTypeID(), let number = value as? NSNumber {
            let type = String(cString: number.objCType)
            switch type {
            case "C", "S", "I", "L", "Q":
                return .unsignedInteger(number.uint64Value)
            case "c", "s", "i", "l", "q":
                return .integer(number.int64Value)
            default:
                throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
            }
        }
        if let array = value as? [Any] {
            guard array.count <= 64 else {
                throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
            }
            return .array(try array.map { try entitlementValue($0, depth: depth + 1) })
        }
        if let dictionary = value as? [String: Any] {
            guard dictionary.count <= 64 else {
                throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
            }
            var result: [String: NativeEntitlementValue] = [:]
            result.reserveCapacity(dictionary.count)
            for (key, nestedValue) in dictionary {
                guard isBoundedIdentifier(key) else {
                    throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
                }
                result[key] = try entitlementValue(nestedValue, depth: depth + 1)
            }
            return .object(result)
        }
        throw nativeDarwinObservationFailure(.codeEntitlementsInvalid)
    }

    private func boundedIdentifier(_ rawValue: Any?) throws -> String? {
        guard let rawValue else { return nil }
        guard let value = rawValue as? String, isBoundedIdentifier(value) else {
            throw nativeDarwinObservationFailure(.codeIdentityUnavailable)
        }
        return value
    }

    private func isBoundedIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 256 &&
            !value.unicodeScalars.contains { scalar in
                scalar.value < 0x20 || scalar.value == 0x7f
            }
    }

    private func readSysctlString(named name: String, maximumBytes: Int) throws -> String {
        var length = 0
        guard sysctlbyname(name, nil, &length, nil, 0) == 0,
              length > 0, length <= maximumBytes + 1 else {
            throw nativeDarwinObservationFailure(.bootIdentityUnavailable)
        }
        var bytes = [UInt8](repeating: 0, count: length)
        let result = bytes.withUnsafeMutableBytes { buffer in
            sysctlbyname(name, buffer.baseAddress, &length, nil, 0)
        }
        guard result == 0, length > 0 else {
            throw nativeDarwinObservationFailure(.bootIdentityUnavailable)
        }
        if bytes.last == 0 { bytes.removeLast() }
        guard let value = String(bytes: bytes.prefix(length), encoding: .utf8),
              !value.isEmpty, value.utf8.count <= maximumBytes else {
            throw nativeDarwinObservationFailure(.bootIdentityUnavailable)
        }
        return value
    }
}
