import AgentPassNativeCore
import Darwin
import Foundation
import Testing

private final class HelperErrorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Error?

    func set(_ error: Error?) {
        lock.lock()
        value = error
        lock.unlock()
    }

    func get() -> Error? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private final class FixedGitSigner: NativeAgentGitCommitSigning, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var calls = 0
    private(set) var payload: Data?

    func signGitCommitPayload(_ payload: Data) throws -> Data {
        lock.lock()
        calls += 1
        self.payload = payload
        lock.unlock()
        return Data("-----BEGIN SSH SIGNATURE-----\nfixed\n-----END SSH SIGNATURE-----\n".utf8)
    }
}

private func withTemporaryPayload<T>(
    _ payload: Data,
    _ body: (String) throws -> T
) throws -> T {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-git-helper-" + UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("commit-payload").path
    // The helper contract under test is the fd3 bridge and payload binding.
    // Complete-file-protection is an entitlement/device policy concern and
    // is unavailable in the hosted Swift runner; retain the explicit 0600
    // boundary without making this fixture depend on that external gate.
    try payload.write(to: URL(fileURLWithPath: path), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    return try body(path)
}

private func makeSocketPair() throws -> (Int32, Int32) {
    var descriptors: [Int32] = [-1, -1]
    let result = descriptors.withUnsafeMutableBufferPointer { buffer in
        socketpair(AF_UNIX, SOCK_STREAM, 0, buffer.baseAddress!)
    }
    guard result == 0 else { throw POSIXError(.init(rawValue: errno)!) }
    return (descriptors[0], descriptors[1])
}

@Test func fixedInvocationAcceptsOnlyTheGitNamespaceAndOpaqueSignerReference() throws {
    let invocation = try NativeAgentGitSigningInvocation(arguments: [
        "-Y", "sign", "-n", "git", "-f",
        NativeAgentGitSigningInvocation.fixedSignerReference,
        "/tmp/git-payload"
    ])
    #expect(invocation.payloadPath == "/tmp/git-payload")
    #expect(invocation.signaturePath == "/tmp/git-payload.sig")

    #expect(throws: NativeAgentGitSigningHelperError.unsupportedNamespace) {
        _ = try NativeAgentGitSigningInvocation(arguments: [
            "-Y", "sign", "-n", "ssh", "-f",
            NativeAgentGitSigningInvocation.fixedSignerReference,
            "/tmp/git-payload"
        ])
    }
    #expect(throws: NativeAgentGitSigningHelperError.unsupportedSignerReference) {
        _ = try NativeAgentGitSigningInvocation(arguments: [
            "-Y", "sign", "-n", "git", "-f", "/tmp/attacker-key",
            "/tmp/git-payload"
        ])
    }
    #expect(throws: NativeAgentGitSigningHelperError.invalidPayloadPath) {
        _ = try NativeAgentGitSigningInvocation(arguments: [
            "-Y", "sign", "-n", "git", "-f",
            NativeAgentGitSigningInvocation.fixedSignerReference,
            "--payload-selector"
        ])
    }
}

@Test func versionedSessionInvocationIsExplicitAndNeverAcceptsNormalGitArguments() throws {
    let invocation = try NativeAgentGitSessionSigningInvocation(arguments: [
        "--protocol", "versioned_session_v1", "--payload", "/tmp/one", "--payload", "/tmp/two"
    ])
    #expect(invocation.payloadPaths == ["/tmp/one", "/tmp/two"])

    #expect(throws: NativeAgentGitSigningHelperError.invalidInvocation) {
        _ = try NativeAgentGitSessionSigningInvocation(arguments: [
            "-Y", "sign", "-n", "git", "-f", "agentpass-managed", "/tmp/one"
        ])
    }
    #expect(throws: NativeAgentGitSigningHelperError.invalidInvocation) {
        _ = try NativeAgentGitSessionSigningInvocation(arguments: [
            "--protocol", "legacy_fd3", "--payload", "/tmp/one", "--payload", "/tmp/two"
        ])
    }
    #expect(throws: NativeAgentGitSigningHelperError.invalidInvocation) {
        _ = try NativeAgentGitSessionSigningInvocation(arguments: [
            "--protocol", "versioned_session_v1", "--payload", "/tmp/one", "--payload", "/tmp/one"
        ])
    }
}

@Test func hostVersionedSessionCommandFixesExecutableProtocolAndPayloadShape() throws {
    let command = try NativeAgentHostVersionedSessionCommand(
        payloadPaths: ["/tmp/one", "/tmp/two"])
    #expect(command.executablePath == NativeAgentHostGitConfiguration.versionedSessionHelperExecutablePath)
    #expect(command.arguments == [
        "--protocol", "versioned_session_v1", "--payload", "/tmp/one", "--payload", "/tmp/two"
    ])
    #expect(throws: NativeAgentHostVersionedSessionCommandError.invalidPayloads) {
        _ = try NativeAgentHostVersionedSessionCommand(payloadPaths: ["relative", "/tmp/two"])
    }
    #expect(throws: NativeAgentHostVersionedSessionCommandError.invalidPayloads) {
        _ = try NativeAgentHostVersionedSessionCommand(payloadPaths: ["/tmp/one", "/tmp/one"])
    }
}

@Test func helperConsumesFd3EquivalentSocketOnceAndWritesGitSignature() throws {
    try withTemporaryPayload(Data("tree abc\n\nmessage\n".utf8)) { payloadPath in
        let (serverDescriptor, helperDescriptor) = try makeSocketPair()
        let serverTransport = try NativeAgentPrivateFDTransport(
            fd: serverDescriptor,
            ownership: .owned
        )
        let server = NativeAgentPrivateGitBridgeServer(
            transport: serverTransport,
            signer: { payload in
                #expect(payload == Data("tree abc\n\nmessage\n".utf8))
                return Data("-----BEGIN SSH SIGNATURE-----\nfixed\n-----END SSH SIGNATURE-----\n".utf8)
            }
        )
        let serverError = HelperErrorBox()
        let serverFinished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            do { try server.serve() }
            catch { serverError.set(error) }
            serverFinished.signal()
        }

        try NativeAgentGitSigningHelper.run(
            arguments: [
                "-Y", "sign", "-n", "git", "-f",
                NativeAgentGitSigningInvocation.fixedSignerReference,
                payloadPath
            ],
            bridgeFileDescriptor: helperDescriptor
        )

        #expect(serverFinished.wait(timeout: .now() + .seconds(2)) == .success)
        #expect(serverError.get() == nil)
        let signature = try Data(contentsOf: URL(fileURLWithPath: payloadPath + ".sig"))
        #expect(String(data: signature, encoding: .utf8)?.contains("BEGIN SSH SIGNATURE") == true)
    }
}

@Test func explicitVersionedSessionHelperPerformsTwoSignsBeforeWritingOutputs() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-git-session-" + UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let firstPath = directory.appendingPathComponent("first").path
    let secondPath = directory.appendingPathComponent("second").path
    try Data("first payload\n".utf8).write(to: URL(fileURLWithPath: firstPath), options: .atomic)
    try Data("second payload\n".utf8).write(to: URL(fileURLWithPath: secondPath), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: firstPath)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secondPath)

    let (serverDescriptor, helperDescriptor) = try makeSocketPair()
    let serverTransport = try NativeAgentPrivateGitSessionTransport(
        fd: serverDescriptor,
        ownership: .owned)
    let calls = HelperErrorBox()
    let finished = DispatchSemaphore(value: 0)
    let server = NativeAgentPrivateGitBridgeSessionServer(
        transport: serverTransport,
        signer: { payload in
            if payload == Data("first payload\n".utf8) {
                return Data("-----BEGIN SSH SIGNATURE-----\nfirst\n-----END SSH SIGNATURE-----\n".utf8)
            }
            guard payload == Data("second payload\n".utf8) else {
                throw NativeAgentGitSigningHelperError.payloadChanged
            }
            return Data("-----BEGIN SSH SIGNATURE-----\nsecond\n-----END SSH SIGNATURE-----\n".utf8)
        })
    DispatchQueue.global().async {
        do { try server.serveTwoCommits() }
        catch { calls.set(error) }
        finished.signal()
    }

    try NativeAgentGitSigningHelper.runVersionedSession(
        payloadPaths: [firstPath, secondPath],
        bridgeFileDescriptor: helperDescriptor)

    #expect(finished.wait(timeout: .now() + .seconds(2)) == .success)
    #expect(calls.get() == nil)
    #expect(String(data: try Data(contentsOf: URL(fileURLWithPath: firstPath + ".sig")), encoding: .utf8)?.contains("first") == true)
    #expect(String(data: try Data(contentsOf: URL(fileURLWithPath: secondPath + ".sig")), encoding: .utf8)?.contains("second") == true)
}

@Test func helperRejectsMissingOrWrongBridgeBeforeAnySignatureOutput() throws {
    try withTemporaryPayload(Data("payload\n".utf8)) { payloadPath in
        #expect(throws: NativeAgentGitSigningHelperError.bridgeUnavailable) {
            try NativeAgentGitSigningHelper.run(
                arguments: [
                    "-Y", "sign", "-n", "git", "-f",
                    NativeAgentGitSigningInvocation.fixedSignerReference,
                    payloadPath
                ],
                bridgeFileDescriptor: -1
            )
        }
        #expect(!FileManager.default.fileExists(atPath: payloadPath + ".sig"))

        try Data("existing\n".utf8).write(to: URL(fileURLWithPath: payloadPath + ".sig"))
        #expect(throws: NativeAgentGitSigningHelperError.signatureAlreadyExists) {
            try NativeAgentGitSigningHelper.run(
                arguments: [
                    "-Y", "sign", "-n", "git", "-f",
                    NativeAgentGitSigningInvocation.fixedSignerReference,
                    payloadPath
                ],
                bridgeFileDescriptor: -1
            )
        }
    }
}

@Test func helperRejectsSymlinkPayloadAndDoesNotFollowIt() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("agentpass-git-helper-link-" + UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let target = directory.appendingPathComponent("target").path
    let link = directory.appendingPathComponent("payload").path
    try Data("payload\n".utf8).write(to: URL(fileURLWithPath: target))
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target)
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)

    #expect(throws: NativeAgentGitSigningHelperError.payloadUnavailable) {
        try NativeAgentGitSigningHelper.run(
            arguments: [
                "-Y", "sign", "-n", "git", "-f",
                NativeAgentGitSigningInvocation.fixedSignerReference,
                link
            ],
            bridgeFileDescriptor: -1
        )
    }
}
