import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

private final class FakeEnrollmentKeyStore: NativeEnrollmentKeyStore, @unchecked Sendable {
    private let signingKey: P256.Signing.PrivateKey
    private let generatedPublicKey: Data
    var storedPublicKey: Data?
    var loadCount = 0
    var createCount = 0
    var signCount = 0
    var signedPreimages = [Data]()
    var throwAfterCreate = false
    var publicKeyX963ForTesting: Data { generatedPublicKey }

    init(publicKeyX963: Data? = nil) {
        let key = P256.Signing.PrivateKey()
        signingKey = key
        generatedPublicKey = publicKeyX963 ?? key.publicKey.x963Representation
    }

    func loadExistingPublicKeyX963() throws -> Data? {
        loadCount += 1
        return storedPublicKey
    }

    func createPublicKeyX963() throws -> Data {
        createCount += 1
        if storedPublicKey != nil {
            throw AgentPassNativeError.invalidKey("fake duplicate fixed enrollment binding")
        }
        storedPublicKey = generatedPublicKey
        if throwAfterCreate {
            throw AgentPassNativeError.invalidKey("fake create acknowledgement lost")
        }
        return generatedPublicKey
    }

    func signEnrollmentProof(preimage: Data) throws -> Data {
        signCount += 1
        signedPreimages.append(preimage)
        return try signingKey.signature(for: preimage).rawRepresentation
    }
}

private func p256SPKIDER(_ x963: Data) -> Data {
    Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
    ]) + x963
}

private func enrollmentProofPreimage(bodyDigest: String = String(repeating: "a", count: 64)) -> Data {
    Data([
        NativeEnrollmentProof.protocolIdentifier,
        "POST",
        "/v1/enrollments/11111111-1111-4111-8111-111111111111",
        bodyDigest,
        String(repeating: "b", count: 64)
    ].joined(separator: "\n").utf8)
}

private func enrollmentProofPreimageV2(nonce: String = String(repeating: "N", count: 43)) -> Data {
    Data("\(NativeEnrollmentProof.protocolIdentifierV2)\0POST\n/v1/enrollments/11111111-1111-4111-8111-111111111111\n\(String(repeating: "a", count: 64))\n\(String(repeating: "b", count: 64))\n\(nonce)\n\(String(repeating: "c", count: 64))".utf8)
}

@Test func enrollmentKeyPrimitiveCreatesOnlyFixedVersionedBindingAndIsIdempotent() throws {
    let store = FakeEnrollmentKeyStore()
    let primitive = NativeEnrollmentKeyPrimitive(store: store)

    let first = try primitive.loadOrCreate()
    let second = try primitive.loadOrCreate()

    #expect(first == second)
    #expect(store.createCount == 1)
    #expect(store.loadCount == 2)
    #expect(NativeEnrollmentKeyMaterial.fixedApplicationTag == "dev.agentpass.device-auth.v1")
    let expectedPEM = try p256SubjectPublicKeyInfoPEM(x963: store.storedPublicKey!)
    #expect(first.publicKeyPEM == expectedPEM)
    #expect(first.fingerprint == NativeEnrollmentKeyMaterial.fingerprint(p256SPKIDER(store.storedPublicKey!)))
    #expect(first.fingerprint.range(of: "^SHA256:[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil)
}

@Test func enrollmentKeyPrimitiveReconcilesCreateRaceWithoutReplacingWinner() throws {
    let store = FakeEnrollmentKeyStore()
    store.throwAfterCreate = true
    let primitive = NativeEnrollmentKeyPrimitive(store: store)

    let material = try primitive.loadOrCreate()

    #expect(store.createCount == 1)
    #expect(store.loadCount == 2)
    let expectedPEM = try p256SubjectPublicKeyInfoPEM(x963: store.storedPublicKey!)
    #expect(material.publicKeyPEM == expectedPEM)
}

@Test func enrollmentKeyPrimitiveSignsExactProofWithRawP1363AndNoPrivateMaterial() throws {
    let store = FakeEnrollmentKeyStore()
    let primitive = NativeEnrollmentKeyPrimitive(store: store)
    let preimage = enrollmentProofPreimage()

    let signature = try primitive.signEnrollmentProof(preimage: preimage)
    let publicKey = try P256.Signing.PublicKey(x963Representation: store.publicKeyX963ForTesting)
    let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: signature)

    #expect(signature.count == 64)
    #expect(publicKey.isValidSignature(ecdsa, for: preimage))
    #expect(store.signCount == 1)
    #expect(store.signedPreimages == [preimage])
}

@Test func enrollmentKeyPrimitiveSignsCandidateBoundV2ProofWithoutNormalizingBytes() throws {
    let store = FakeEnrollmentKeyStore()
    let primitive = NativeEnrollmentKeyPrimitive(store: store)
    let preimage = enrollmentProofPreimageV2()

    let signature = try primitive.signEnrollmentProof(preimage: preimage)
    let publicKey = try P256.Signing.PublicKey(x963Representation: store.publicKeyX963ForTesting)
    let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: signature)

    #expect(publicKey.isValidSignature(ecdsa, for: preimage))
    #expect(store.signedPreimages == [preimage])
}

@Test func enrollmentKeyPrimitiveRejectsV2DomainAndBindingSubstitution() throws {
    let store = FakeEnrollmentKeyStore()
    let primitive = NativeEnrollmentKeyPrimitive(store: store)

    #expect(throws: AgentPassNativeError.self) {
        _ = try primitive.signEnrollmentProof(preimage: Data(enrollmentProofPreimageV2().dropFirst()))
    }
    #expect(throws: AgentPassNativeError.self) {
        _ = try primitive.signEnrollmentProof(preimage: enrollmentProofPreimageV2(nonce: String(repeating: "N", count: 42)))
    }
    var nonCanonical = enrollmentProofPreimageV2()
    nonCanonical.append(0x0a)
    #expect(throws: AgentPassNativeError.self) {
        _ = try primitive.signEnrollmentProof(preimage: nonCanonical)
    }
    #expect(store.signCount == 0)
}

@Test func enrollmentKeyPrimitiveRejectsNonCanonicalOrOversizedProofBeforeSigning() throws {
    let store = FakeEnrollmentKeyStore()
    let primitive = NativeEnrollmentKeyPrimitive(store: store)

    let malformed = enrollmentProofPreimage() + Data([0x0a])
    #expect(throws: AgentPassNativeError.self) {
        _ = try primitive.signEnrollmentProof(preimage: malformed)
    }
    #expect(throws: AgentPassNativeError.self) {
        _ = try primitive.signEnrollmentProof(preimage: Data(repeating: 0x41, count: NativeEnrollmentProof.maximumPreimageBytes + 1))
    }
    #expect(store.signCount == 0)
}

@Test func enrollmentKeyPrimitiveRejectsMalformedProviderOutput() throws {
    let store = FakeEnrollmentKeyStore(publicKeyX963: Data(repeating: 0, count: 65))
    let primitive = NativeEnrollmentKeyPrimitive(store: store)

    #expect(throws: AgentPassNativeError.self) {
        _ = try primitive.loadOrCreate()
    }
}

@Test func enrollmentKeyMaterialContainsNoPrivateMaterialAndUsesCanonicalSPKI() throws {
    let publicKey = P256.Signing.PrivateKey().publicKey.x963Representation
    let material = try NativeEnrollmentKeyMaterial(publicKeyX963: publicKey)

    #expect(material.publicKeyPEM.hasPrefix("-----BEGIN PUBLIC KEY-----\n"))
    #expect(material.publicKeyPEM.hasSuffix("\n-----END PUBLIC KEY-----\n"))
    #expect(!material.publicKeyPEM.contains("PRIVATE"))
    #expect(material.fingerprint.hasPrefix("SHA256:"))
}

@Test func qualificationSnapshotSchemaHasNoPrivateKeyMaterialOrMutableClaims() throws {
    let source = try String(contentsOf: URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentPassNativeCore/NativeEnrollmentKey.swift"), encoding: .utf8)
    #expect(source.contains("public struct NativeSecureEnclaveQualificationSnapshot"))
    #expect(source.contains("fileprivate init(accessGroup: String, publicKeyFingerprint: String)"))
    #expect(source.contains("public func qualificationSnapshot() throws -> NativeSecureEnclaveQualificationSnapshot"))
    #expect(source.contains("SecKeyCopyExternalRepresentation(key, nil) == nil"))
    #expect(!source.contains("private_key_base64"))
    #expect(!source.contains("privateKeyData"))
}
