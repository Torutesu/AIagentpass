import Darwin
import Foundation

private let protocolName = "agentpass.atomic-rename.v1"

private enum ExitCode: Int32 {
    case success = 0
    case destinationExists = 17
    case usage = 64
    case internalFailure = 70
    case unsafeInput = 77
    case unsupportedFilesystem = 78
}

private enum ResultCode {
    static let complete = "ATOMIC_RENAME_COMPLETE"
    static let destinationExists = "ATOMIC_RENAME_DESTINATION_EXISTS"
    static let invalidInput = "ATOMIC_RENAME_INVALID_INPUT"
    static let helperFailure = "ATOMIC_RENAME_HELPER_FAILED"
    static let unsupportedFilesystem = "ATOMIC_RENAME_UNSUPPORTED_FILESYSTEM"
}

private struct Failure: Error {
    let code: String
    let exitCode: ExitCode
    let stage: String?

    init(code: String, exitCode: ExitCode, stage: String? = nil) {
        self.code = code
        self.exitCode = exitCode
        self.stage = stage
    }
}

private struct Arguments {
    let sourceParent: String
    let sourceName: String
    let destinationParent: String
    let destinationName: String
    let boundary: String
    let owner: uid_t
    let sourceDevice: UInt64
    let sourceInode: UInt64
    let sourceSize: UInt64
    let sourceMtimeNanoseconds: UInt64
}

private struct Output: Encodable {
    let code: String
    let ok: Bool
    let protocolVersion: String

    enum CodingKeys: String, CodingKey {
        case code, ok
        case protocolVersion = "protocol"
    }
}

@main
private enum AgentPassAtomicRenameMain {
    static func main() {
        do {
            let arguments = try parse(Array(CommandLine.arguments.dropFirst()))
            try execute(arguments)
            emit(Output(code: ResultCode.complete, ok: true, protocolVersion: protocolName), exitCode: .success)
        } catch let failure as Failure {
            emit(Output(code: failure.code, ok: false, protocolVersion: protocolName), exitCode: failure.exitCode)
        } catch {
            emit(Output(code: ResultCode.helperFailure, ok: false, protocolVersion: protocolName), exitCode: .internalFailure)
        }
    }

    private static func emit(_ output: Output, exitCode: ExitCode) -> Never {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(output)) ?? Data("{\"code\":\"ATOMIC_RENAME_HELPER_FAILED\",\"ok\":false,\"protocol\":\"agentpass.atomic-rename.v1\"}".utf8)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0a]))
        exit(exitCode.rawValue)
    }
}

private func parse(_ raw: [String]) throws -> Arguments {
    let allowed: Set<String> = [
        "--protocol", "--operation", "--source-parent", "--source-name",
        "--destination-parent", "--destination-name", "--boundary", "--owner",
        "--source-dev", "--source-ino", "--source-size", "--source-mtime-ns"
    ]
    var values: [String: String] = [:]
    var index = 0
    while index < raw.count {
        let key = raw[index]
        guard allowed.contains(key), index + 1 < raw.count else { throw Failure(code: ResultCode.invalidInput, exitCode: .usage) }
        guard values[key] == nil else { throw Failure(code: ResultCode.invalidInput, exitCode: .usage) }
        let value = raw[index + 1]
        guard !value.isEmpty, !value.contains("\0"), value.utf8.count <= 4096, !value.hasPrefix("--") else {
            throw Failure(code: ResultCode.invalidInput, exitCode: .usage)
        }
        values[key] = value
        index += 2
    }
    let required = allowed
    guard Set(values.keys) == required,
          values["--protocol"] == protocolName,
          values["--operation"] == "rename-no-replace" else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .usage)
    }
    guard let sourceParent = values["--source-parent"], let sourceName = values["--source-name"],
          let destinationParent = values["--destination-parent"], let destinationName = values["--destination-name"],
          let boundary = values["--boundary"], let ownerText = values["--owner"],
          let sourceDeviceText = values["--source-dev"], let sourceInodeText = values["--source-ino"],
          let sourceSizeText = values["--source-size"], let sourceMtimeText = values["--source-mtime-ns"],
          let ownerValue = UInt32(ownerText), let sourceDevice = UInt64(sourceDeviceText),
          let sourceInode = UInt64(sourceInodeText), let sourceSize = UInt64(sourceSizeText),
          let sourceMtimeNanoseconds = UInt64(sourceMtimeText) else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .usage)
    }
    guard ownerValue <= UInt32(uid_t.max) else { throw Failure(code: ResultCode.invalidInput, exitCode: .usage) }
    let boundaryParts = try canonicalAbsoluteComponents(boundary, label: "boundary", rejectRoot: true)
    let sourceParentParts = try canonicalAbsoluteComponents(sourceParent, label: "source parent", rejectRoot: false)
    let destinationParentParts = try canonicalAbsoluteComponents(destinationParent, label: "destination parent", rejectRoot: false)
    guard sourceParent == destinationParent,
          sourceParentParts == destinationParentParts,
          sourceParentParts.count >= boundaryParts.count,
          Array(sourceParentParts.prefix(boundaryParts.count)) == boundaryParts,
          isSingleComponent(sourceName), isSingleComponent(destinationName) else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    }
    return Arguments(
        sourceParent: sourceParent, sourceName: sourceName,
        destinationParent: destinationParent, destinationName: destinationName,
        boundary: boundary, owner: uid_t(ownerValue), sourceDevice: sourceDevice,
        sourceInode: sourceInode, sourceSize: sourceSize,
        sourceMtimeNanoseconds: sourceMtimeNanoseconds
    )
}

private func canonicalAbsoluteComponents(_ value: String, label: String, rejectRoot: Bool) throws -> [String] {
    guard value.hasPrefix("/"), value.utf8.count <= 4096, !value.contains("\0"),
          !value.contains("//"), !value.hasSuffix("/") || value == "/" else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    }
    let parts = value.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    guard !rejectRoot || !parts.isEmpty else { throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput) }
    guard parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("\0") }) else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    }
    _ = label
    return parts
}

private func isSingleComponent(_ value: String) -> Bool {
    !value.isEmpty && value != "." && value != ".." && !value.contains("/") && !value.contains("\0") && value.utf8.count <= 255
}

private func execute(_ arguments: Arguments) throws {
    guard getuid() == arguments.owner, geteuid() == arguments.owner else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    }
    let boundaryParts = try canonicalAbsoluteComponents(arguments.boundary, label: "boundary", rejectRoot: true)
    let parentParts = try canonicalAbsoluteComponents(arguments.sourceParent, label: "parent", rejectRoot: false)
    let suffix = Array(parentParts.dropFirst(boundaryParts.count))
    let directory = try withStage("open-directory") { try openDirectory(boundaryParts: boundaryParts, parentSuffix: suffix, owner: arguments.owner) }
    defer { close(directory.parentFD); close(directory.boundaryFD) }
    try validateDirectory(directory.boundaryFD, owner: arguments.owner, requireOwner: true)
    let parentStat = try validateDirectory(directory.parentFD, owner: arguments.owner, requireOwner: true)
    guard unsigned(parentStat.st_dev) == unsigned(directory.boundaryStat.st_dev) else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    }

    let sourceFD = openat(directory.parentFD, arguments.sourceName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard sourceFD >= 0 else { throw errnoFailure() }
    defer { close(sourceFD) }
    let sourceStat = try withStage("validate-source") { try validateSource(sourceFD, arguments: arguments, boundaryDevice: unsigned(directory.boundaryStat.st_dev)) }
    _ = try validateSource(sourceFD, arguments: arguments, boundaryDevice: unsigned(directory.boundaryStat.st_dev))
    try withStage("destination-absent") { try ensureDestinationAbsent(directory.parentFD, name: arguments.destinationName) }
    try withStage("fsync-source") { guard fsync(sourceFD) == 0 else { throw errnoFailure() } }
    try validateDirectory(directory.parentFD, owner: arguments.owner, requireOwner: true)

    try withStage("rename") {
        guard renameatx_np(directory.parentFD, arguments.sourceName, directory.parentFD, arguments.destinationName, UInt32(RENAME_EXCL)) == 0 else {
            throw errnoFailure()
        }
    }

    let destinationFD = openat(directory.parentFD, arguments.destinationName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard destinationFD >= 0 else { throw errnoFailure() }
    defer { close(destinationFD) }
    let destinationStat = try withStage("validate-destination") { try validateDestination(destinationFD, expected: sourceStat, owner: arguments.owner) }
    guard unsigned(destinationStat.st_dev) == arguments.sourceDevice,
          unsigned(destinationStat.st_ino) == arguments.sourceInode else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    }
    try withStage("fsync-destination") { guard fsync(destinationFD) == 0, fsync(directory.parentFD) == 0 else { throw errnoFailure() } }
}

private func withStage<T>(_ stage: String, _ operation: () throws -> T) throws -> T {
    do { return try operation() }
    catch let failure as Failure { throw Failure(code: failure.code, exitCode: failure.exitCode, stage: stage) }
    catch { throw Failure(code: ResultCode.helperFailure, exitCode: .internalFailure, stage: stage) }
}

private struct OpenDirectoryResult {
    let boundaryFD: Int32
    let parentFD: Int32
    let boundaryStat: stat
}

private func openDirectory(boundaryParts: [String], parentSuffix: [String], owner: uid_t) throws -> OpenDirectoryResult {
    let rootFD = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard rootFD >= 0 else { throw errnoFailure() }
    var current = rootFD
    var boundaryFD: Int32 = -1
    do {
        for part in boundaryParts {
            let next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw errnoFailure() }
            _ = try validateDirectory(next, owner: owner, requireOwner: false)
            close(current)
            current = next
        }
        boundaryFD = dup(current)
        guard boundaryFD >= 0 else { throw errnoFailure() }
        let boundaryStat = try validateDirectory(boundaryFD, owner: owner, requireOwner: true)
        for part in parentSuffix {
            let next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw errnoFailure() }
            _ = try validateDirectory(next, owner: owner, requireOwner: true)
            close(current)
            current = next
        }
        return OpenDirectoryResult(boundaryFD: boundaryFD, parentFD: current, boundaryStat: boundaryStat)
    } catch {
        close(current)
        if boundaryFD >= 0 { close(boundaryFD) }
        throw error
    }
}

@discardableResult
private func validateDirectory(_ descriptor: Int32, owner: uid_t, requireOwner: Bool) throws -> stat {
    var info = stat()
    guard fstat(descriptor, &info) == 0 else { throw errnoFailure() }
    guard (info.st_mode & S_IFMT) == S_IFDIR,
          info.st_mode & 0o022 == 0,
          !hasSetId(info.st_mode),
          !requireOwner || info.st_uid == owner else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    }
    return info
}

private func validateSource(_ descriptor: Int32, arguments: Arguments, boundaryDevice: UInt64) throws -> stat {
    var info = stat()
    guard fstat(descriptor, &info) == 0 else { throw errnoFailure() }
    guard (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == arguments.owner,
          info.st_nlink == 1,
          info.st_mode & 0o022 == 0,
          !hasSetId(info.st_mode),
          unsigned(info.st_dev) == boundaryDevice,
          unsigned(info.st_dev) == arguments.sourceDevice,
          unsigned(info.st_ino) == arguments.sourceInode,
          UInt64(info.st_size) == arguments.sourceSize,
          mtimeNanoseconds(info) == arguments.sourceMtimeNanoseconds else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    }
    return info
}

private func validateDestination(_ descriptor: Int32, expected: stat, owner: uid_t) throws -> stat {
    var info = stat()
    guard fstat(descriptor, &info) == 0 else { throw errnoFailure() }
    guard (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == owner,
          info.st_nlink == 1,
          info.st_mode & 0o022 == 0,
          !hasSetId(info.st_mode),
          unsigned(info.st_dev) == unsigned(expected.st_dev),
          unsigned(info.st_ino) == unsigned(expected.st_ino),
          UInt64(info.st_size) == UInt64(expected.st_size),
          mtimeNanoseconds(info) == mtimeNanoseconds(expected) else {
        throw Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    }
    return info
}

private func ensureDestinationAbsent(_ descriptor: Int32, name: String) throws {
    var info = stat()
    if fstatat(descriptor, name, &info, AT_SYMLINK_NOFOLLOW) == 0 {
        throw Failure(code: ResultCode.destinationExists, exitCode: .destinationExists)
    }
    let errorNumber = errno
    guard errorNumber == ENOENT else { throw errnoFailure(errorNumber) }
}

private func hasSetId(_ mode: mode_t) -> Bool {
    mode & 0o6000 != 0
}

private func unsigned<T: BinaryInteger>(_ value: T) -> UInt64 {
    UInt64(value)
}

private func mtimeNanoseconds(_ info: stat) -> UInt64 {
    UInt64(info.st_mtimespec.tv_sec) * 1_000_000_000 + UInt64(info.st_mtimespec.tv_nsec)
}

private func errnoFailure(_ errorNumber: Int32 = errno) -> Failure {
    switch errorNumber {
    case EEXIST:
        return Failure(code: ResultCode.destinationExists, exitCode: .destinationExists)
    case EINVAL, ENOTSUP, EOPNOTSUPP:
        return Failure(code: ResultCode.unsupportedFilesystem, exitCode: .unsupportedFilesystem)
    case EACCES, EPERM, ELOOP, ENOENT, ENOTDIR:
        return Failure(code: ResultCode.invalidInput, exitCode: .unsafeInput)
    default:
        return Failure(code: ResultCode.helperFailure, exitCode: .internalFailure)
    }
}
