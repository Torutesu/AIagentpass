import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private struct SoftwareSigner: P256MessageSigner {
    let privateKey = P256.Signing.PrivateKey()
    var publicKeyX963: Data { privateKey.publicKey.x963Representation }

    func sign(message: Data) throws -> Data {
        try privateKey.signature(for: message).rawRepresentation
    }
}

@Test func sshsigIsAcceptedByOpenSSH() throws {
    let signer = SoftwareSigner()
    let payload = Data("native AgentPass interoperability\n".utf8)
    let signature = try SSHSIG.sign(payload: payload, signer: signer)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let signatureURL = root.appendingPathComponent("payload.sig")
    let allowedURL = root.appendingPathComponent("allowed_signers")
    try Data(signature.utf8).write(to: signatureURL)
    try Data("agentpass \(try SSHSIG.authorizedKey(publicKeyX963: signer.publicKeyX963))\n".utf8).write(to: allowedURL)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = ["-Y", "verify", "-f", allowedURL.path, "-I", "agentpass", "-n", "git", "-s", signatureURL.path]
    let input = Pipe()
    let errors = Pipe()
    process.standardInput = input
    process.standardError = errors
    try process.run()
    input.fileHandleForWriting.write(payload)
    try input.fileHandleForWriting.close()
    process.waitUntilExit()
    let errorText = String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    #expect(process.terminationStatus == 0, Comment(rawValue: errorText))
}

@Test func malformedPublicKeysAndNamespacesFailClosed() throws {
    let signer = SoftwareSigner()
    #expect(throws: AgentPassNativeError.self) {
        try SSHSIG.sign(payload: Data("x".utf8), namespace: "", signer: signer)
    }
    #expect(throws: AgentPassNativeError.self) {
        try SSHSIG.authorizedKey(publicKeyX963: Data(repeating: 0, count: 65))
    }
}

@Test func derECDSASignatureIsNormalizedToRawRS() throws {
    let signer = SoftwareSigner()
    let signature = try signer.privateKey.signature(for: Data("der".utf8))
    let raw = try SecureEnclaveKeyStore.rawSignature(fromDER: signature.derRepresentation)
    #expect(raw == signature.rawRepresentation)
    #expect(throws: AgentPassNativeError.self) {
        try SecureEnclaveKeyStore.rawSignature(fromDER: Data([0x30, 0x01, 0x00]))
    }
}
