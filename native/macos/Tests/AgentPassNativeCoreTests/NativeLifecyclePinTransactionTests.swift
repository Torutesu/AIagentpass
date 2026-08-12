import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private let pinOld = String(repeating: "1", count: 64)
private let pinMiddle = String(repeating: "2", count: 64)
private let pinNew = String(repeating: "3", count: 64)
private let pinTime1 = "2027-04-05T06:07:08.000Z"
private let pinTime2 = "2027-04-05T06:07:09.000Z"

private func pinRoot() throws -> URL {
    let testParent = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    guard let canonicalParent = Darwin.realpath(testParent.path, nil) else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { free(canonicalParent) }
    let root = URL(fileURLWithPath: String(cString: canonicalParent)).appendingPathComponent("agentpass-pin-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return root
}

@Test func lifecyclePinPendingSurvivesRestartUntilExactResolution() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let expected = pinPreparation()
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path)
    #expect(try transaction.pending() == nil)
    _ = try prepare(transaction, expected)
    #expect(try transaction.pending() == expected)

    let restarted = try NativeLifecyclePinTransaction(rootPath: root.path)
    #expect(try restarted.pending() == expected)
    #expect(try restarted.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinOld) == .prepared(expected))
    #expect(try restarted.pending() == expected)
    _ = try restarted.commit(expected, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle)
    #expect(try restarted.pending() == nil)
}

private func pinPreparation(sequence: Int = 1, operationID: UUID = UUID(), old: String = pinOld, new: String = pinMiddle, preparedAt: String = pinTime1) -> NativeLifecyclePinPreparation {
    NativeLifecyclePinPreparation(operationID: operationID, sequence: sequence, role: .gitSigning, action: .activated, oldLifecycleHead: old, newLifecycleHead: new, preparedAt: preparedAt)
}

private func prepare(_ transaction: NativeLifecyclePinTransaction, _ value: NativeLifecyclePinPreparation) throws -> NativeLifecyclePinPreparation {
    try transaction.prepare(operationID: value.operationID, sequence: value.sequence, role: value.role, action: value.action, oldLifecycleHead: value.oldLifecycleHead, newLifecycleHead: value.newLifecycleHead, preparedAt: value.preparedAt)
}

private func pinFiles(_ root: URL) throws -> [URL] {
    try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil).sorted { $0.lastPathComponent < $1.lastPathComponent }
}

private final class PinFault: @unchecked Sendable {
    private let lock = NSLock()
    private let target: NativeLifecyclePinCrashPoint
    private var fired = false

    init(_ target: NativeLifecyclePinCrashPoint) { self.target = target }

    func inject(_ point: NativeLifecyclePinCrashPoint) throws {
        lock.lock()
        defer { lock.unlock() }
        if !fired, point == target {
            fired = true
            throw AgentPassNativeError.invalidConfiguration("injected crash")
        }
    }
}

@Test func lifecyclePinActionSchemaCoversEveryLifecycleMutationKind() throws {
    #expect(NativeLifecyclePinAction.allCases.map(\.rawValue) == [
        "staged", "abort_intent", "aborted", "activated", "recovered_activation",
        "deletion_intent", "deleted"
    ])
    for action in NativeLifecyclePinAction.allCases {
        let root = try pinRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let transaction = try NativeLifecyclePinTransaction(rootPath: root.path)
        let expected = NativeLifecyclePinPreparation(operationID: UUID(), sequence: 1, role: .auditCheckpoint, action: action, oldLifecycleHead: pinOld, newLifecycleHead: pinMiddle, preparedAt: pinTime1)
        _ = try prepare(transaction, expected)
        _ = try transaction.commit(expected, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle)
        #expect(try NativeLifecyclePinTransaction(rootPath: root.path).current() == expected)
    }
}

@Test func lifecyclePinPrepareCommitRestartAndCanonicalPersistence() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path)
    let expected = pinPreparation()

    #expect(try prepare(transaction, expected) == expected)
    #expect(try prepare(transaction, expected) == expected)
    #expect(try transaction.current() == nil)
    #expect(try transaction.commit(expected, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle) == expected)
    #expect(try transaction.commit(expected, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle) == expected)
    #expect(try transaction.current() == expected)

    let files = try pinFiles(root)
    #expect(files.map(\.lastPathComponent) == [
        String(format: "pin-%020d.json", 1),
        String(format: "prepare-%020d-%@.json", 1, expected.operationID.uuidString)
    ])
    for file in files {
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o400)
        #expect((attributes[.referenceCount] as? NSNumber)?.intValue == 1)
        let data = try Data(contentsOf: file)
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) == data)
    }
    #expect(try NativeLifecyclePinTransaction(rootPath: root.path).current() == expected)
}

@Test func lifecyclePinRecoveryDistinguishesOldNewAndUnknownHeads() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path)
    let expected = pinPreparation()
    _ = try prepare(transaction, expected)

    #expect(try transaction.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinOld) == .prepared(expected))
    #expect(throws: AgentPassNativeError.self) {
        try transaction.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinNew)
    }
    #expect(try transaction.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinMiddle) == .committed(expected))
    #expect(try transaction.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinMiddle) == .committed(expected))
    #expect(throws: AgentPassNativeError.self) {
        try transaction.recover(expected, observedOldLifecycleHead: pinMiddle, observedCurrentLifecycleHead: pinMiddle)
    }
    #expect(throws: AgentPassNativeError.self) {
        try transaction.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinOld)
    }
}

@Test func lifecyclePinRejectsEquivocationStaleGapAndWrongObservations() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path)
    let first = pinPreparation()
    _ = try prepare(transaction, first)

    #expect(throws: AgentPassNativeError.self) { try prepare(transaction, pinPreparation(operationID: UUID(), new: pinNew)) }
    #expect(throws: AgentPassNativeError.self) { try prepare(transaction, pinPreparation(sequence: 2, old: pinMiddle, new: pinNew, preparedAt: pinTime2)) }
    #expect(throws: AgentPassNativeError.self) {
        try transaction.commit(first, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinNew)
    }
    try transaction.commit(first, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle)

    #expect(throws: AgentPassNativeError.self) { try prepare(transaction, pinPreparation(sequence: 1, operationID: UUID(), new: pinNew)) }
    #expect(throws: AgentPassNativeError.self) { try prepare(transaction, pinPreparation(sequence: 2, old: pinOld, new: pinNew, preparedAt: pinTime2)) }
    let second = pinPreparation(sequence: 2, old: pinMiddle, new: pinNew, preparedAt: pinTime2)
    _ = try prepare(transaction, second)
    #expect(try transaction.commit(first, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle) == first)
    #expect(try transaction.current() == first)
}

@Test func lifecyclePinRejectsReusedOperationAndBackwardPreparationTime() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path)
    let operationID = UUID()
    let first = pinPreparation(operationID: operationID)
    _ = try prepare(transaction, first)
    _ = try transaction.commit(first, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle)

    #expect(throws: AgentPassNativeError.self) {
        try prepare(transaction, pinPreparation(sequence: 2, operationID: operationID, old: pinMiddle, new: pinNew, preparedAt: pinTime2))
    }
    #expect(throws: AgentPassNativeError.self) {
        try prepare(transaction, pinPreparation(sequence: 2, old: pinMiddle, new: pinNew, preparedAt: "2027-04-05T06:07:07.000Z"))
    }
}

@Test func lifecyclePinRejectsInvalidFieldsAndNonCanonicalJournal() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path)
    #expect(throws: AgentPassNativeError.self) { try prepare(transaction, pinPreparation(old: "BAD")) }
    #expect(throws: AgentPassNativeError.self) { try prepare(transaction, pinPreparation(new: pinOld)) }
    #expect(throws: AgentPassNativeError.self) { try prepare(transaction, pinPreparation(preparedAt: "2027-04-05T06:07:08Z")) }

    let expected = pinPreparation()
    _ = try prepare(transaction, expected)
    let journal = try #require(try pinFiles(root).first { $0.lastPathComponent.hasPrefix("prepare-") })
    var object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: journal)) as? [String: Any])
    object["unexpected"] = true
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journal.path)
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: journal)
    try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: journal.path)
    #expect(throws: AgentPassNativeError.self) { try NativeLifecyclePinTransaction(rootPath: root.path) }
}

@Test func lifecyclePinRejectsSymlinkHardlinkAndPrivatePathViolations() throws {
    let insecure = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-pin-insecure-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: insecure, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
    defer { try? FileManager.default.removeItem(at: insecure) }
    #expect(throws: AgentPassNativeError.self) { try NativeLifecyclePinTransaction(rootPath: insecure.path) }
    #expect(throws: AgentPassNativeError.self) { try NativeLifecyclePinTransaction(rootPath: "relative") }

    for hardlink in [false, true] {
        let root = try pinRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let transaction = try NativeLifecyclePinTransaction(rootPath: root.path)
        let expected = pinPreparation()
        _ = try prepare(transaction, expected)
        let journal = try #require(try pinFiles(root).first { $0.lastPathComponent.hasPrefix("prepare-") })
        let saved = root.appendingPathComponent("saved")
        if hardlink {
            try FileManager.default.linkItem(at: journal, to: saved)
        } else {
            try FileManager.default.moveItem(at: journal, to: saved)
            try FileManager.default.createSymbolicLink(at: journal, withDestinationURL: saved)
        }
        #expect(throws: Error.self) { try NativeLifecyclePinTransaction(rootPath: root.path) }
    }
}

@Test func lifecyclePinRejectsAncestorSymlinkAndPermissiveParent() throws {
    let container = try pinRoot()
    defer { try? FileManager.default.removeItem(at: container) }

    let realParent = container.appendingPathComponent("real-parent")
    let realRoot = realParent.appendingPathComponent("pin-root")
    try FileManager.default.createDirectory(at: realRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: realParent.path)
    let linkedParent = container.appendingPathComponent("linked-parent")
    try FileManager.default.createSymbolicLink(at: linkedParent, withDestinationURL: realParent)
    let throughSymlink = linkedParent.appendingPathComponent("pin-root")
    #expect(throws: AgentPassNativeError.self) { try NativeLifecyclePinTransaction(rootPath: throughSymlink.path) }

    let permissiveParent = container.appendingPathComponent("permissive-parent")
    let protectedChild = permissiveParent.appendingPathComponent("pin-root")
    try FileManager.default.createDirectory(at: protectedChild, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: permissiveParent.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: protectedChild.path)
    #expect(throws: AgentPassNativeError.self) { try NativeLifecyclePinTransaction(rootPath: protectedChild.path) }
}

@Test func lifecyclePinRecoversCrashBeforePreparationRename() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let crash = PinFault(.afterPreparationTemporaryFileSync)
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path, faultInjector: crash.inject)
    let expected = pinPreparation()
    #expect(throws: AgentPassNativeError.self) { try prepare(transaction, expected) }
    #expect(try pinFiles(root).contains { $0.lastPathComponent.hasPrefix(".lifecycle-pin-") })

    let restarted = try NativeLifecyclePinTransaction(rootPath: root.path)
    #expect(try pinFiles(root).isEmpty)
    _ = try prepare(restarted, expected)
    #expect(try restarted.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinMiddle) == .committed(expected))
}

@Test func lifecyclePinRecoversLostCommitResponseAfterDurableRename() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let crash = PinFault(.afterPinRename)
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path, faultInjector: crash.inject)
    let expected = pinPreparation()
    _ = try prepare(transaction, expected)
    #expect(throws: AgentPassNativeError.self) {
        try transaction.commit(expected, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle)
    }

    let restarted = try NativeLifecyclePinTransaction(rootPath: root.path)
    #expect(try restarted.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinMiddle) == .committed(expected))
    #expect(try restarted.current() == expected)
}

@Test func lifecyclePinRecoversCrashBeforePinRenameAndCommitsFromJournal() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let crash = PinFault(.afterPinTemporaryFileSync)
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path, faultInjector: crash.inject)
    let expected = pinPreparation()
    _ = try prepare(transaction, expected)
    #expect(throws: AgentPassNativeError.self) {
        try transaction.commit(expected, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle)
    }
    #expect(try pinFiles(root).contains { $0.lastPathComponent.hasPrefix(".lifecycle-pin-") })

    let restarted = try NativeLifecyclePinTransaction(rootPath: root.path)
    #expect(try restarted.current() == nil)
    #expect(try restarted.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinMiddle) == .committed(expected))
}

@Test func lifecyclePinRepairsMissingTailPinOnlyForExactNewLedgerHead() throws {
    let root = try pinRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path)
    let expected = pinPreparation()
    _ = try prepare(transaction, expected)
    try transaction.commit(expected, observedOldLifecycleHead: pinOld, observedNewLifecycleHead: pinMiddle)
    let pin = try #require(try pinFiles(root).first { $0.lastPathComponent.hasPrefix("pin-") })
    try FileManager.default.removeItem(at: pin)

    let restarted = try NativeLifecyclePinTransaction(rootPath: root.path)
    #expect(throws: AgentPassNativeError.self) {
        try restarted.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinNew)
    }
    #expect(try restarted.recover(expected, observedOldLifecycleHead: pinOld, observedCurrentLifecycleHead: pinMiddle) == .committed(expected))
}

@Test func lifecyclePinRejectsRootPathSwapWithoutWritingReplacement() throws {
    let root = try pinRoot()
    let moved = root.deletingLastPathComponent().appendingPathComponent(root.lastPathComponent + "-moved")
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: moved)
    }
    let expected = pinPreparation()
    let transaction = try NativeLifecyclePinTransaction(rootPath: root.path) { point in
        if point == .afterPreparationTemporaryFileSync {
            try FileManager.default.moveItem(at: root, to: moved)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
    }
    #expect(throws: AgentPassNativeError.self) { try prepare(transaction, expected) }
    #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
}
