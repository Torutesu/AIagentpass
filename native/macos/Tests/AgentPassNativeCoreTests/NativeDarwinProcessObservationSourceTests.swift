import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private let darwinTestHash = String(repeating: "d", count: 64)

private enum FixtureFailure: Error {
    case unavailable
}

private final class FixtureDarwinAdapter: NativeDarwinProcessObservationAdapter, @unchecked Sendable {
    let currentPID: Int32
    let uid: UInt32
    let boot: String
    let fileIdentity: NativeExecutableFileIdentity
    var fileIdentities: [NativeExecutableFileIdentity]
    var fileIdentityIndex = 0
    var identity: NativeDarwinCodeIdentity
    var snapshots: [Int32: [NativeDarwinProcessSnapshot]]
    var snapshotIndexes: [Int32: Int] = [:]
    var pathFailure = false
    var fileFailure = false
    var codeFailure = false
    var snapshotFailures: Set<Int32> = []
    var pathValue = "/private/var/empty/agent"

    init(
        currentPID: Int32 = 900,
        uid: UInt32 = 501,
        boot: String = "boot-fixture",
        fileIdentity: NativeExecutableFileIdentity,
        identity: NativeDarwinCodeIdentity,
        snapshots: [Int32: [NativeDarwinProcessSnapshot]]
    ) {
        self.currentPID = currentPID
        self.uid = uid
        self.boot = boot
        self.fileIdentity = fileIdentity
        self.fileIdentities = [fileIdentity]
        self.identity = identity
        self.snapshots = snapshots
    }

    func currentProcessID() throws -> Int32 { currentPID }
    func effectiveUserID() throws -> UInt32 { uid }
    func bootIdentity() throws -> String { boot }

    func processSnapshot(pid: Int32) throws -> NativeDarwinProcessSnapshot {
        if snapshotFailures.contains(pid) { throw FixtureFailure.unavailable }
        guard let values = snapshots[pid], !values.isEmpty else {
            throw FixtureFailure.unavailable
        }
        let index = snapshotIndexes[pid, default: 0]
        snapshotIndexes[pid] = index + 1
        return values[min(index, values.count - 1)]
    }

    func executablePath(pid: Int32) throws -> String {
        if pathFailure { throw FixtureFailure.unavailable }
        return pathValue
    }

    func executableFileIdentity(path: String) throws -> NativeExecutableFileIdentity {
        if fileFailure { throw FixtureFailure.unavailable }
        let index = fileIdentityIndex
        fileIdentityIndex += 1
        return fileIdentities[min(index, fileIdentities.count - 1)]
    }

    func codeIdentity(pid: Int32) throws -> NativeDarwinCodeIdentity {
        if codeFailure { throw FixtureFailure.unavailable }
        return identity
    }
}

private func fixtureFileIdentity() throws -> NativeExecutableFileIdentity {
    try NativeExecutableFileIdentity(
        deviceID: 7,
        inode: 8,
        fileSize: 9,
        modificationTimeNanoseconds: 10
    )
}

private func fixtureCodeIdentity() -> NativeDarwinCodeIdentity {
    NativeDarwinCodeIdentity(
        codeDirectoryHash: darwinTestHash,
        bundleIdentifier: "dev.agentpass.fixture",
        teamIdentifier: "FIXTURETEAM",
        signatureKind: .developerID,
        entitlements: ["dev.agentpass.fixture": .boolean(true)]
    )
}

private func snapshots(for pid: Int32, parentPID: Int32, uid: UInt32 = 501) -> [NativeDarwinProcessSnapshot] {
    [
        NativeDarwinProcessSnapshot(pid: pid, parentPID: parentPID, uid: uid, pidVersion: UInt64(pid) + 1000),
        NativeDarwinProcessSnapshot(pid: pid, parentPID: parentPID, uid: uid, pidVersion: UInt64(pid) + 1000)
    ]
}

private func fixtureAdapter(ancestorCount: Int = 0) throws -> FixtureDarwinAdapter {
    var processSnapshots: [Int32: [NativeDarwinProcessSnapshot]] = [
        900: snapshots(for: 900, parentPID: ancestorCount == 0 ? 1 : 100)
    ]
    if ancestorCount > 0 {
        for offset in 0..<ancestorCount {
            let pid = Int32(100 + offset)
            let parent = offset + 1 == ancestorCount ? 1 : Int32(100 + offset + 1)
            processSnapshots[pid] = snapshots(for: pid, parentPID: parent)
        }
    }
    return FixtureDarwinAdapter(
        fileIdentity: try fixtureFileIdentity(),
        identity: fixtureCodeIdentity(),
        snapshots: processSnapshots
    )
}

private func reason(from operation: () throws -> Void) -> String? {
    do {
        try operation()
        return nil
    } catch let NativeProcessIdentityError.invalidObservation(value) {
        return value
    } catch {
        return "unexpected"
    }
}

@Test func nativeDarwinSourceObservesLiveSelfWhenSecurityIdentityIsAvailable() throws {
    let result = Result { try NativeDarwinProcessObservationSource().observe() }
    switch result {
    case let .success(observation):
        let identity = NativeProcessIdentity(observation: observation)
        #expect(observation.process.pid == getpid())
        #expect(observation.process.uid == UInt32(geteuid()))
        #expect(observation.process.pidVersion > 0)
        #expect(!observation.process.bootIdentity.isEmpty)
        #expect(observation.ancestry.count <= NativeDarwinProcessObservationSource.maximumAncestors)
        #expect(!identity.canonicalRepresentation.contains("/"))
    case let .failure(error):
        // SwiftPM test binaries can be unsigned or lack a SHA-256 code
        // directory on developer machines.  That is an expected fail-closed
        // result; it must still be one of the stable observer reasons.
        guard case let NativeProcessIdentityError.invalidObservation(value) = error else {
            Issue.record("live Darwin observation returned an unstable error")
            return
        }
        #expect(NativeDarwinProcessObservationReason.allCases.map(\.rawValue).contains(value))
    }
}

@Test func nativeDarwinSourceCapturesFactsAndOrderedAncestryWithoutPath() throws {
    let adapter = try fixtureAdapter(ancestorCount: 2)
    let observation = try NativeDarwinProcessObservationSource(adapter: adapter).observe()
    let identity = NativeProcessIdentity(observation: observation)

    #expect(observation.process.pid == 900)
    #expect(observation.process.uid == 501)
    #expect(observation.process.codeDirectoryHash == darwinTestHash)
    #expect(observation.process.bundleIdentifier == "dev.agentpass.fixture")
    #expect(observation.process.teamIdentifier == "FIXTURETEAM")
    #expect(observation.ancestry.count == 2)
    if case let .observed(first) = observation.ancestry[0] {
        #expect(first.pid == 100)
    } else {
        Issue.record("immediate parent was not observed")
    }
    if case let .observed(second) = observation.ancestry[1] {
        #expect(second.pid == 101)
    } else {
        Issue.record("grandparent was not observed")
    }
    #expect(!identity.canonicalRepresentation.contains("/private/var/empty"))
    #expect(!identity.canonicalRepresentation.localizedCaseInsensitiveContains("audit"))
    #expect(!identity.canonicalRepresentation.localizedCaseInsensitiveContains("argv"))
    #expect(!identity.canonicalRepresentation.localizedCaseInsensitiveContains("environment"))
}

@Test func nativeDarwinSourceRejectsPIDReuseDuringObservationWithStableReason() throws {
    let adapter = try fixtureAdapter()
    adapter.snapshots[900] = [
        NativeDarwinProcessSnapshot(pid: 900, parentPID: 1, uid: 501, pidVersion: 10),
        NativeDarwinProcessSnapshot(pid: 900, parentPID: 1, uid: 501, pidVersion: 11)
    ]

    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: adapter).observe() } == NativeDarwinProcessObservationReason.processChangedDuringObservation.rawValue)
}

@Test func nativeDarwinSourceRejectsPathAndCodeIdentityFailures() throws {
    let pathFailure = try fixtureAdapter()
    pathFailure.pathFailure = true
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: pathFailure).observe() } == NativeDarwinProcessObservationReason.executablePathUnavailable.rawValue)

    let invalidPath = try fixtureAdapter()
    invalidPath.pathValue = "invalid\0path"
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: invalidPath).observe() } == NativeDarwinProcessObservationReason.executablePathInvalid.rawValue)

    let fileFailure = try fixtureAdapter()
    fileFailure.fileFailure = true
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: fileFailure).observe() } == NativeDarwinProcessObservationReason.executableFileUnavailable.rawValue)

    let fileRace = try fixtureAdapter()
    fileRace.fileIdentities = [try fixtureFileIdentity(), try NativeExecutableFileIdentity(deviceID: 7, inode: 99, fileSize: 9, modificationTimeNanoseconds: 10)]
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: fileRace).observe() } == NativeDarwinProcessObservationReason.executableChangedDuringObservation.rawValue)

    let codeFailure = try fixtureAdapter()
    codeFailure.codeFailure = true
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: codeFailure).observe() } == NativeDarwinProcessObservationReason.codeIdentityUnavailable.rawValue)
}

@Test func nativeDarwinSourceRejectsAncestorFailuresAndBounds() throws {
    let missingAncestor = try fixtureAdapter(ancestorCount: 1)
    missingAncestor.snapshotFailures.insert(100)
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: missingAncestor).observe() } == NativeDarwinProcessObservationReason.processUnavailable.rawValue)

    let racingAncestor = try fixtureAdapter(ancestorCount: 1)
    racingAncestor.snapshots[100] = [
        NativeDarwinProcessSnapshot(pid: 100, parentPID: 1, uid: 501, pidVersion: 20),
        NativeDarwinProcessSnapshot(pid: 100, parentPID: 1, uid: 501, pidVersion: 21)
    ]
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: racingAncestor).observe() } == NativeDarwinProcessObservationReason.processChangedDuringObservation.rawValue)

    let tooDeep = try fixtureAdapter(ancestorCount: NativeDarwinProcessObservationSource.maximumAncestors + 1)
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: tooDeep).observe() } == NativeDarwinProcessObservationReason.ancestorLimitExceeded.rawValue)
}

@Test func nativeDarwinSourceRejectsCrossUserAndInvalidCodeFacts() throws {
    let wrongUser = try fixtureAdapter()
    wrongUser.snapshots[900] = snapshots(for: 900, parentPID: 1, uid: 502)
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: wrongUser).observe() } == NativeDarwinProcessObservationReason.processSnapshotInvalid.rawValue)

    let invalidCode = try fixtureAdapter()
    invalidCode.identity = NativeDarwinCodeIdentity(
        codeDirectoryHash: "not-a-sha256",
        bundleIdentifier: "dev.agentpass.fixture",
        teamIdentifier: "FIXTURETEAM",
        signatureKind: .developerID,
        entitlements: [:]
    )
    #expect(reason { _ = try NativeDarwinProcessObservationSource(adapter: invalidCode).observe() } == NativeDarwinProcessObservationReason.observationConstructionFailed.rawValue)
}
