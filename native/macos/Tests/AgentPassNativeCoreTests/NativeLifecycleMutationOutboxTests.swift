import Darwin
import Foundation
import Testing
@testable import AgentPassNativeCore

private let outboxHeadA = String(repeating: "a", count: 64)
private let outboxHeadB = String(repeating: "b", count: 64)
private let outboxHeadC = String(repeating: "c", count: 64)
private let outboxTime1 = "2027-05-06T07:08:09.000Z"
private let outboxTime2 = "2027-05-06T07:08:10.000Z"

private func outboxRoot() throws -> URL {
    let build = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".build")
    guard let resolved = Darwin.realpath(build.path, nil) else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { free(resolved) }
    let root = URL(fileURLWithPath: String(cString: resolved)).appendingPathComponent("agentpass-outbox-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return root
}

private func outboxPreparation(
    operationID: UUID = UUID(),
    pinSequence: Int = 1,
    lifecycleSequence: Int = 40,
    old: String = outboxHeadA,
    new: String = outboxHeadB,
    createdAt: String = outboxTime1,
    kind: NativeLifecycleMutationKind = .activated,
    payload: Data = Data(#"{"action":"activated","public_key":"AQID","signature":"BAUG"}"#.utf8)
) -> NativeLifecycleMutationPreparation {
    NativeLifecycleMutationPreparation(
        operationID: operationID,
        pinSequence: pinSequence,
        role: .gitSigning,
        kind: kind,
        lifecycleSequence: lifecycleSequence,
        oldLifecycleHead: old,
        newLifecycleHead: new,
        createdAt: createdAt,
        payload: payload
    )
}

private func outboxPrepare(_ outbox: NativeLifecycleMutationOutbox, _ value: NativeLifecycleMutationPreparation) throws -> NativeLifecycleMutationPreparation {
    try outbox.prepare(
        operationID: value.operationID,
        pinSequence: value.pinSequence,
        role: value.role,
        kind: value.kind,
        lifecycleSequence: value.lifecycleSequence,
        oldLifecycleHead: value.oldLifecycleHead,
        newLifecycleHead: value.newLifecycleHead,
        createdAt: value.createdAt,
        payload: value.payload
    )
}

private func outboxFiles(_ root: URL) throws -> [URL] {
    try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil).sorted { $0.lastPathComponent < $1.lastPathComponent }
}

private final class OutboxFault: @unchecked Sendable {
    private let lock = NSLock()
    private let target: NativeLifecycleMutationOutboxCrashPoint
    private var fired = false

    init(_ target: NativeLifecycleMutationOutboxCrashPoint) { self.target = target }

    func inject(_ point: NativeLifecycleMutationOutboxCrashPoint) throws {
        lock.lock()
        defer { lock.unlock() }
        if !fired, String(describing: point) == String(describing: target) {
            fired = true
            throw AgentPassNativeError.invalidConfiguration("injected outbox crash")
        }
    }
}

@Test func lifecycleMutationOutboxRetainsExactPayloadAcrossRestartAndCompletesIdempotently() throws {
    let root = try outboxRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let payload = Data((0..<4096).map { UInt8($0 % 251) })
    let expected = outboxPreparation(payload: payload)
    let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path)

    #expect(try outboxPrepare(outbox, expected) == expected)
    #expect(try outboxPrepare(outbox, expected) == expected)
    #expect(try outbox.pending()?.payload == payload)

    let restarted = try NativeLifecycleMutationOutbox(rootPath: root.path)
    #expect(try restarted.pending() == expected)
    #expect(try restarted.complete(expected, observedNewLifecycleHead: outboxHeadB) == expected)
    #expect(try restarted.complete(expected, observedNewLifecycleHead: outboxHeadB) == expected)
    #expect(try restarted.pending() == nil)
    #expect(try restarted.current() == expected)

    let files = try outboxFiles(root)
    #expect(files.map(\.lastPathComponent) == [
        String(format: "completed-%020d.json", 1),
        String(format: "prepare-%020d-%@.json", 1, expected.operationID.uuidString)
    ])
    for file in files {
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o400)
        #expect((attributes[.referenceCount] as? NSNumber)?.intValue == 1)
        let data = try Data(contentsOf: file)
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) == data)
        #expect(object["payload_hash"] as? String == expected.payloadHash)
        #expect(object["payload_bytes"] as? Int == payload.count)
    }
}

@Test func lifecycleMutationOutboxSchemaCoversAllKinds() throws {
    #expect(NativeLifecycleMutationKind.allCases.map(\.rawValue) == [
        "staged", "activated", "recovered_activation", "abort_intent", "aborted", "deletion_intent", "deleted"
    ])
    for kind in NativeLifecycleMutationKind.allCases {
        let root = try outboxRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path)
        let expected = outboxPreparation(kind: kind)
        _ = try outboxPrepare(outbox, expected)
        _ = try outbox.complete(expected, observedNewLifecycleHead: expected.newLifecycleHead)
        #expect(try NativeLifecycleMutationOutbox(rootPath: root.path).current() == expected)
    }
}

@Test func lifecycleMutationOutboxCanJoinAnExistingExternalPinSequence() throws {
    let root = try outboxRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path)
    let first = outboxPreparation(pinSequence: 7, lifecycleSequence: 7)
    _ = try outboxPrepare(outbox, first)
    _ = try outbox.complete(first, observedNewLifecycleHead: first.newLifecycleHead)
    let second = outboxPreparation(pinSequence: 8, lifecycleSequence: 8, old: outboxHeadB, new: outboxHeadC, createdAt: outboxTime2)
    _ = try outboxPrepare(outbox, second)
    #expect(try outbox.pending() == second)
}

@Test func lifecycleMutationOutboxRejectsEquivocationGapsRollbackAndWrongHead() throws {
    let root = try outboxRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path)
    let operationID = UUID()
    let first = outboxPreparation(operationID: operationID)
    _ = try outboxPrepare(outbox, first)

    #expect(throws: AgentPassNativeError.self) { try outboxPrepare(outbox, outboxPreparation(payload: Data("different".utf8))) }
    #expect(throws: AgentPassNativeError.self) {
        try outboxPrepare(outbox, outboxPreparation(pinSequence: 2, lifecycleSequence: 41, old: outboxHeadB, new: outboxHeadC, createdAt: outboxTime2))
    }
    #expect(throws: AgentPassNativeError.self) { try outbox.complete(first, observedNewLifecycleHead: outboxHeadC) }
    _ = try outbox.complete(first, observedNewLifecycleHead: outboxHeadB)

    #expect(throws: AgentPassNativeError.self) {
        try outboxPrepare(outbox, outboxPreparation(operationID: operationID, pinSequence: 2, lifecycleSequence: 41, old: outboxHeadB, new: outboxHeadC, createdAt: outboxTime2))
    }
    #expect(throws: AgentPassNativeError.self) {
        try outboxPrepare(outbox, outboxPreparation(pinSequence: 2, lifecycleSequence: 40, old: outboxHeadB, new: outboxHeadC, createdAt: outboxTime2))
    }
    #expect(throws: AgentPassNativeError.self) {
        try outboxPrepare(outbox, outboxPreparation(pinSequence: 2, lifecycleSequence: 42, old: outboxHeadB, new: outboxHeadC, createdAt: outboxTime2))
    }
    #expect(throws: AgentPassNativeError.self) {
        try outboxPrepare(outbox, outboxPreparation(pinSequence: 2, lifecycleSequence: 41, old: outboxHeadA, new: outboxHeadC, createdAt: outboxTime2))
    }
    #expect(throws: AgentPassNativeError.self) {
        try outboxPrepare(outbox, outboxPreparation(pinSequence: 2, lifecycleSequence: 41, old: outboxHeadB, new: outboxHeadC, createdAt: "2027-05-06T07:08:08.000Z"))
    }
}

@Test func lifecycleMutationOutboxEnforcesPayloadBoundsAndRejectsPrivateKeyMaterial() throws {
    let root = try outboxRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path)

    #expect(throws: AgentPassNativeError.self) { try outboxPrepare(outbox, outboxPreparation(payload: Data())) }
    #expect(throws: AgentPassNativeError.self) {
        try outboxPrepare(outbox, outboxPreparation(payload: Data(repeating: 7, count: NativeLifecycleMutationOutbox.maximumPayloadBytes + 1)))
    }
    #expect(throws: AgentPassNativeError.self) {
        try outboxPrepare(outbox, outboxPreparation(payload: Data("-----BEGIN PRIVATE KEY-----\nsecret".utf8)))
    }
    #expect(throws: AgentPassNativeError.self) {
        try outboxPrepare(outbox, outboxPreparation(payload: Data(#"{"private_key":"secret"}"#.utf8)))
    }

    let maximum = Data(repeating: 9, count: NativeLifecycleMutationOutbox.maximumPayloadBytes)
    let accepted = outboxPreparation(payload: maximum)
    #expect(try outboxPrepare(outbox, accepted).payload == maximum)
}

@Test func lifecycleMutationOutboxRejectsTamperUnknownFieldsAndNonCanonicalData() throws {
    for mutation in ["payload", "unknown", "noncanonical"] {
        let root = try outboxRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path)
        _ = try outboxPrepare(outbox, outboxPreparation())
        let file = try #require(try outboxFiles(root).first)
        var object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        let bytes: Data
        switch mutation {
        case "payload":
            object["payload"] = Data("substituted".utf8).base64EncodedString()
            bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        case "unknown":
            object["extra"] = true
            bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        default:
            bytes = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        try bytes.write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: file.path)
        #expect(throws: AgentPassNativeError.self) { try NativeLifecycleMutationOutbox(rootPath: root.path) }
    }
}

@Test func lifecycleMutationOutboxRejectsSymlinkHardlinkAndInsecureAncestors() throws {
    let insecure = FileManager.default.temporaryDirectory.appendingPathComponent("agentpass-outbox-insecure-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: insecure, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
    defer { try? FileManager.default.removeItem(at: insecure) }
    #expect(throws: AgentPassNativeError.self) { try NativeLifecycleMutationOutbox(rootPath: insecure.path) }
    #expect(throws: AgentPassNativeError.self) { try NativeLifecycleMutationOutbox(rootPath: "relative") }

    for hardlink in [false, true] {
        let root = try outboxRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path)
        _ = try outboxPrepare(outbox, outboxPreparation())
        let record = try #require(try outboxFiles(root).first)
        let saved = root.appendingPathComponent("saved")
        if hardlink {
            try FileManager.default.linkItem(at: record, to: saved)
        } else {
            try FileManager.default.moveItem(at: record, to: saved)
            try FileManager.default.createSymbolicLink(at: record, withDestinationURL: saved)
        }
        #expect(throws: Error.self) { try NativeLifecycleMutationOutbox(rootPath: root.path) }
    }

    let container = try outboxRoot()
    defer { try? FileManager.default.removeItem(at: container) }
    let parent = container.appendingPathComponent("parent")
    let child = parent.appendingPathComponent("outbox")
    try FileManager.default.createDirectory(at: child, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: parent.path)
    #expect(throws: AgentPassNativeError.self) { try NativeLifecycleMutationOutbox(rootPath: child.path) }
}

@Test func lifecycleMutationOutboxRecoversPrepareCrashesWithoutInventingCompletion() throws {
    for point in [NativeLifecycleMutationOutboxCrashPoint.afterPrepareTemporaryFileSync, .afterPrepareRename] {
        let root = try outboxRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let expected = outboxPreparation()
        let fault = OutboxFault(point)
        let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path, faultInjector: fault.inject)
        #expect(throws: AgentPassNativeError.self) { try outboxPrepare(outbox, expected) }

        let restarted = try NativeLifecycleMutationOutbox(rootPath: root.path)
        if String(describing: point).contains("Temporary") {
            #expect(try restarted.pending() == nil)
            _ = try outboxPrepare(restarted, expected)
        } else {
            #expect(try restarted.pending() == expected)
        }
        #expect(try restarted.pending()?.payload == expected.payload)
    }
}

@Test func lifecycleMutationOutboxRecoversCompletionCrashesByExactRetry() throws {
    for point in [NativeLifecycleMutationOutboxCrashPoint.afterCompletedTemporaryFileSync, .afterCompletedRename] {
        let root = try outboxRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let expected = outboxPreparation()
        let fault = OutboxFault(point)
        let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path, faultInjector: fault.inject)
        _ = try outboxPrepare(outbox, expected)
        #expect(throws: AgentPassNativeError.self) { try outbox.complete(expected, observedNewLifecycleHead: outboxHeadB) }

        let restarted = try NativeLifecycleMutationOutbox(rootPath: root.path)
        if String(describing: point).contains("Temporary") {
            #expect(try restarted.pending() == expected)
            _ = try restarted.complete(expected, observedNewLifecycleHead: outboxHeadB)
        }
        #expect(try restarted.pending() == nil)
        #expect(try restarted.current() == expected)
    }
}

@Test func lifecycleMutationOutboxRejectsRootPathSwapWithoutWritingReplacement() throws {
    let root = try outboxRoot()
    let moved = root.deletingLastPathComponent().appendingPathComponent(root.lastPathComponent + "-moved")
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: moved)
    }
    let outbox = try NativeLifecycleMutationOutbox(rootPath: root.path) { point in
        if point == .afterPrepareTemporaryFileSync {
            try FileManager.default.moveItem(at: root, to: moved)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
    }
    #expect(throws: Error.self) { try outboxPrepare(outbox, outboxPreparation()) }
    #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
}
