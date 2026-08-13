import CryptoKit
import Foundation
import Testing
@testable import AgentPassNativeCore

@Suite("Agent qualification controller manifest")
struct NativeAgentQualificationControllerManifestTests {
  private let now = Date(timeIntervalSince1970: 2_000_000_000)

  @Test("the controller accepts exactly arm, status, and disarm")
  func commandVocabularyIsClosed() throws {
    #expect(NativeAgentQualificationControllerCommand.allCases.map(\.rawValue) == [
      "arm", "status", "disarm",
    ])

    for command in NativeAgentQualificationControllerCommand.allCases {
      #expect(
        try NativeAgentQualificationControllerCommand.parse(arguments: [command.rawValue])
          == command)
    }

    for arguments in [
      [], ["arm", "status"], ["arm", "--scenario", "pre-cloud-kill"],
      ["--help"], ["status", "--json"], ["disarm", "receipt"], ["ARM"],
    ] {
      #expect(
        throws: NativeAgentQualificationControllerManifestError.invalidCommand
      ) {
        _ = try NativeAgentQualificationControllerCommand.parse(arguments: arguments)
      }
    }
  }

  @Test("a canonical Ed25519-signed manifest binds to the service and all six pairs")
  func verifiesCanonicalManifestAndAllScenarioPhasePairs() throws {
    for scenario in NativeAgentQualificationFaultScenario.allCases {
      let fixture = try Fixture(scenario: scenario, now: now)
      let context = try verify(fixture)

      #expect(context.candidateDigest == fixture.candidateDigest)
      #expect(context.sourceCommitDigest == fixture.sourceCommitDigest)
      #expect(context.codeIdentityDigest == fixture.codeIdentityDigest)
      #expect(context.runIDDigest == fixture.runIDDigest)
      #expect(context.expiresAtEpochSeconds == fixture.expiry)
      #expect(context.scenario == scenario)
      #expect(context.phase == scenario.phase)
    }
  }

  @Test("arm, status, and disarm requests contain only their digest bindings")
  func constructsDigestOnlyRequests() throws {
    let fixture = try Fixture(scenario: .postAuditPreReplyLoss, now: now)
    let context = try verify(fixture)

    let arm = try context.makeArmRequest()
    #expect(arm.protocolVersion == AgentPassQualificationXPCContract.protocolVersion)
    #expect(arm.faultPhase == NativeAgentQualificationFaultPhase.postAuditPreReply.rawValue)
    #expect(arm.candidateDigest == fixture.candidateDigest)
    #expect(arm.sourceCommitDigest == fixture.sourceCommitDigest)
    #expect(arm.codeIdentityDigest == fixture.codeIdentityDigest)
    #expect(arm.runIDDigest == fixture.runIDDigest)

    let status = try context.makeStatusRequest()
    #expect(status.protocolVersion == AgentPassQualificationXPCContract.protocolVersion)
    #expect(status.candidateDigest == fixture.candidateDigest)
    #expect(status.runIDDigest == fixture.runIDDigest)

    let receiptDigest = Data(repeating: 0x55, count: AgentPassQualificationXPCContract.digestBytes)
    let disarm = try context.makeDisarmRequest(receiptDigest: receiptDigest)
    #expect(disarm.protocolVersion == AgentPassQualificationXPCContract.protocolVersion)
    #expect(disarm.candidateDigest == fixture.candidateDigest)
    #expect(disarm.runIDDigest == fixture.runIDDigest)
    #expect(disarm.receiptDigest == receiptDigest)
  }

  @Test("manifest shape, schema, and canonical encoding are strict")
  func rejectsShapeAndCanonicalSubstitutions() throws {
    let fixture = try Fixture(scenario: .preCloudKill, now: now)

    let nonCanonical = fixture.manifestData + Data([0x0a])
    #expect(throws: NativeAgentQualificationControllerManifestError.nonCanonicalManifest) {
      _ = try verify(fixture, manifestData: nonCanonical)
    }

    var unknown = fixture.manifestObject
    unknown["unexpected"] = "not permitted"
    let unknownData = try NativeStrictJSON.data(unknown)
    #expect(throws: NativeAgentQualificationControllerManifestError.unknownField) {
      _ = try verify(fixture, manifestData: unknownData)
    }

    var wrongSchema = fixture.manifestObject
    wrongSchema["schema_version"] = 2
    let wrongSchemaData = try NativeStrictJSON.data(wrongSchema)
    #expect(throws: NativeAgentQualificationControllerManifestError.invalidSchema) {
      _ = try verify(fixture, manifestData: wrongSchemaData)
    }

    var wrongKind = fixture.manifestObject
    wrongKind["kind"] = "agentpass-n3e-other-candidate"
    let wrongKindData = try NativeStrictJSON.data(wrongKind)
    #expect(throws: NativeAgentQualificationControllerManifestError.invalidSchema) {
      _ = try verify(fixture, manifestData: wrongKindData)
    }
  }

  @Test("Ed25519 signature and public-key encodings are verified before use")
  func rejectsSignatureAndPublicKeySubstitutions() throws {
    let fixture = try Fixture(scenario: .preCloudKill, now: now)

    #expect(throws: NativeAgentQualificationControllerManifestError.invalidSignatureEncoding) {
      _ = try verify(fixture, signatureData: Data("not-base64\n".utf8))
    }

    #expect(throws: NativeAgentQualificationControllerManifestError.invalidPublicKey) {
      _ = try verify(fixture, publicKeyPEM: Data("not-a-public-key\n".utf8))
    }

    let otherKey = Curve25519.Signing.PrivateKey()
    let wrongSignature = try otherKey.signature(for: fixture.manifestData)
    let wrongSignatureData = Data(wrongSignature.base64EncodedString().utf8) + Data([0x0a])
    #expect(throws: NativeAgentQualificationControllerManifestError.invalidSignature) {
      _ = try verify(fixture, signatureData: wrongSignatureData)
    }

    var tampered = fixture.manifestObject
    tampered["candidate_sha256"] = hex(Data(repeating: 0x99, count: 32))
    let tamperedData = try NativeStrictJSON.data(tampered)
    #expect(throws: NativeAgentQualificationControllerManifestError.invalidSignature) {
      _ = try verify(fixture, manifestData: tamperedData)
    }
  }

  @Test("candidate, source, code-identity, and run digests are canonical non-zero hex")
  func rejectsInvalidIdentityDigests() throws {
    let fixture = try Fixture(scenario: .preCloudKill, now: now)
    let substitutions: [(String, String)] = [
      ("candidate_sha256", String(repeating: "A", count: 64)),
      ("source_commit_sha256", String(repeating: "b", count: 63)),
      ("code_identities_sha256", String(repeating: "g", count: 64)),
      ("run_id_sha256", String(repeating: "0", count: 64)),
    ]

    for (field, value) in substitutions {
      var object = fixture.manifestObject
      object[field] = value
      let data = try NativeStrictJSON.data(object)
      #expect(
        throws: NativeAgentQualificationControllerManifestError.invalidValue(field: field)
      ) {
        _ = try verify(fixture, manifestData: data)
      }
    }
  }

  @Test("expiry is live, bounded, and bound to the signed service configuration")
  func rejectsExpiredAndOverlongExpiry() throws {
    let expired = try Fixture(scenario: .preCloudKill, now: now, expiryOffset: 0)
    #expect(throws: NativeAgentQualificationControllerManifestError.expired) {
      _ = try verify(expired)
    }

    let tooFar = try Fixture(
      scenario: .preCloudKill,
      now: now,
      expiryOffset: NativeAgentQualificationConfiguration.maximumLifetimeSeconds + 1)
    #expect(throws: NativeAgentQualificationControllerManifestError.expiryTooFarInFuture) {
      _ = try verify(tooFar)
    }
  }

  @Test("every service binding field rejects substitution")
  func rejectsServiceBindingSubstitutions() throws {
    let fixture = try Fixture(scenario: .postCloudPreLocalKill, now: now)
    let substitutions: [(String, Any)] = [
      ("qualification_mode", "not-qualification"),
      ("qualification_mach_service_name", "dev.agentpass.other-service"),
      ("qualification_candidate_sha256", hex(Data(repeating: 0x91, count: 32))),
      ("qualification_source_commit_sha256", hex(Data(repeating: 0x92, count: 32))),
      ("qualification_code_identities_sha256", hex(Data(repeating: 0x93, count: 32))),
      ("qualification_run_id_sha256", hex(Data(repeating: 0x94, count: 32))),
      ("qualification_scenario", NativeAgentQualificationFaultScenario.preCloudKill.rawValue),
      ("qualification_phase", NativeAgentQualificationFaultPhase.preCloud.rawValue),
      (
        "qualification_expires_at_epoch_seconds",
        NSNumber(value: fixture.expiry + 1)
      ),
    ]

    for (field, value) in substitutions {
      var service = fixture.serviceObject
      service[field] = value
      let serviceData = try NativeStrictJSON.data(service)
      #expect(
        throws: NativeAgentQualificationControllerManifestError.serviceBindingMismatch(field: field)
      ) {
        _ = try verify(fixture, serviceConfigurationData: serviceData)
      }
    }
  }

  private func verify(
    _ fixture: Fixture,
    manifestData: Data? = nil,
    signatureData: Data? = nil,
    publicKeyPEM: Data? = nil,
    serviceConfigurationData: Data? = nil
  ) throws -> NativeAgentQualificationControllerContext {
    try NativeAgentQualificationControllerContext.verify(
      manifestData: manifestData ?? fixture.manifestData,
      signatureData: signatureData ?? fixture.signatureData,
      publicKeyPEM: publicKeyPEM ?? fixture.publicKeyPEM,
      serviceConfigurationData: serviceConfigurationData ?? fixture.serviceConfigurationData,
      wallTime: fixture.now)
  }

  private struct Fixture {
    let now: Date
    let signingKey: Curve25519.Signing.PrivateKey
    let candidateDigest: Data
    let sourceCommitDigest: Data
    let codeIdentityDigest: Data
    let runIDDigest: Data
    let expiry: UInt64
    let manifestObject: [String: Any]
    let manifestData: Data
    let signatureData: Data
    let publicKeyPEM: Data
    let serviceObject: [String: Any]
    let serviceConfigurationData: Data

    init(
      scenario: NativeAgentQualificationFaultScenario,
      now: Date,
      expiryOffset: UInt64 = 60
    ) throws {
      self.now = now
      signingKey = Curve25519.Signing.PrivateKey()
      candidateDigest = Data(repeating: 0x11, count: AgentPassQualificationXPCContract.digestBytes)
      sourceCommitDigest = Data(repeating: 0x22, count: AgentPassQualificationXPCContract.digestBytes)
      codeIdentityDigest = Data(repeating: 0x33, count: AgentPassQualificationXPCContract.digestBytes)
      runIDDigest = Data(repeating: 0x44, count: AgentPassQualificationXPCContract.digestBytes)
      expiry = UInt64(now.timeIntervalSince1970) + expiryOffset
      manifestObject = [
        "schema_version": NativeAgentQualificationControllerContext.manifestSchemaVersion,
        "kind": NativeAgentQualificationControllerContext.manifestKind,
        "candidate_sha256": hex(candidateDigest),
        "source_commit_sha256": hex(sourceCommitDigest),
        "code_identities_sha256": hex(codeIdentityDigest),
        "run_id_sha256": hex(runIDDigest),
        "expires_at_epoch_seconds": NSNumber(value: expiry),
        "scenario": scenario.rawValue,
        "phase": scenario.phase.rawValue,
      ]
      manifestData = try NativeStrictJSON.data(manifestObject)
      let rawSignature = try signingKey.signature(for: manifestData)
      signatureData = Data(rawSignature.base64EncodedString().utf8) + Data([0x0a])

      let publicKeyDER = Data([
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
      ]) + signingKey.publicKey.rawRepresentation
      publicKeyPEM = Data(
        "-----BEGIN PUBLIC KEY-----\n\(publicKeyDER.base64EncodedString())\n-----END PUBLIC KEY-----\n".utf8)

      serviceObject = [
        "qualification_mode": NativeAgentQualificationConfiguration.modeMarker,
        "qualification_mach_service_name": AgentPassQualificationXPCContract.machServiceName,
        "qualification_candidate_sha256": hex(candidateDigest),
        "qualification_source_commit_sha256": hex(sourceCommitDigest),
        "qualification_code_identities_sha256": hex(codeIdentityDigest),
        "qualification_run_id_sha256": hex(runIDDigest),
        "qualification_expires_at_epoch_seconds": NSNumber(value: expiry),
        "qualification_scenario": scenario.rawValue,
        "qualification_phase": scenario.phase.rawValue,
      ]
      serviceConfigurationData = try NativeStrictJSON.data(serviceObject)
    }
  }
}

private func hex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}
