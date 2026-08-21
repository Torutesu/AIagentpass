import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

final class AgentCountingP256Signer: P256MessageSigner, @unchecked Sendable {
    private let key = P256.Signing.PrivateKey()
    private let lock = NSLock()
    private(set) var messages: [Data] = []
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(message: Data) throws -> Data {
        lock.withLock { messages.append(message) }
        return try key.signature(for: message).rawRepresentation
    }
}

@Test func fixedGitSignerProducesOnlyGitSSHSIGAndTouchesKeyOnce() throws {
    let primitive = AgentCountingP256Signer()
    let signer = try NativeAgentGitCommitSigner(signer: primitive)
    let payload = Data("tree abc\n\nmessage\n".utf8)
    let output = try signer.signGitCommitPayload(payload)
    let text = String(decoding: output, as: UTF8.self)
    #expect(text.hasPrefix("-----BEGIN SSH SIGNATURE-----\n"))
    #expect(text.hasSuffix("-----END SSH SIGNATURE-----\n"))
    #expect(primitive.messages.count == 1)
    let signedMessage = try #require(primitive.messages.first)
    #expect(signedMessage.starts(with: Data("SSHSIG".utf8)))
    #expect(signedMessage.range(of: Data("git".utf8)) != nil)
    #expect(try signer.verifyGitCommitSignature(payload: payload, signature: output))
    #expect(!(try signer.verifyGitCommitSignature(payload: Data("different".utf8), signature: output)))
}

@Test func fixedGitSignerRejectsEmptyAndOversizedPayloadBeforeKeyUse() throws {
    let primitive = AgentCountingP256Signer()
    let signer = try NativeAgentGitCommitSigner(signer: primitive)
    #expect(throws: NativeAgentGitCommitSignerError.invalidPayload) { _ = try signer.signGitCommitPayload(Data()) }
    #expect(throws: NativeAgentGitCommitSignerError.invalidPayload) { _ = try signer.signGitCommitPayload(Data(repeating: 1, count: NativeAgentGitCommitSigner.maximumPayloadBytes + 1)) }
    #expect(primitive.messages.isEmpty)
}

@Test func fixedGitSignerRejectsInvalidPrimitiveAtConstruction() {
    struct Invalid: P256MessageSigner {
        let publicKeyX963 = Data()
        func sign(message: Data) throws -> Data { Data() }
    }
    #expect(throws: NativeAgentGitCommitSignerError.invalidSigner) { _ = try NativeAgentGitCommitSigner(signer: Invalid()) }
}
