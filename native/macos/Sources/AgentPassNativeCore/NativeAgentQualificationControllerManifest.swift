import CryptoKit
import Foundation

/// The only command vocabulary accepted by the external N3-E qualification
/// controller. Paths, Mach services, phases, selectors, and release identity
/// are deliberately not command-line inputs.
public enum NativeAgentQualificationControllerCommand: String, CaseIterable, Sendable {
  case arm
  case status
  case disarm

  public static func parse(arguments: [String]) throws -> Self {
    guard arguments.count == 1, let command = Self(rawValue: arguments[0]) else {
      throw NativeAgentQualificationControllerManifestError.invalidCommand
    }
    return command
  }
}

public enum NativeAgentQualificationControllerManifestError: Error, Equatable, Sendable {
  case invalidCommand
  case invalidJSON
  case nonCanonicalManifest
  case unknownField
  case invalidSchema
  case invalidValue(field: String)
  case invalidSignatureEncoding
  case invalidPublicKey
  case invalidSignature
  case serviceBindingMismatch(field: String)
  case expired
  case expiryTooFarInFuture
  case requestConstructionFailed
}

/// Verified, immutable controller input derived from two protected sources:
/// the installed service configuration and a detached-signed candidate/run
/// manifest. Only the run digest is present; the raw run ID is never persisted,
/// loaded by this process, emitted, or returned by the service.
public struct NativeAgentQualificationControllerContext: Sendable {
  public static let manifestSchemaVersion = 1
  public static let manifestKind = "agentpass-n3e-controller-candidate"
  public static let maximumManifestBytes = 16 * 1024
  public static let maximumServiceConfigurationBytes = 1 * 1024 * 1024

  public let candidateDigest: Data
  public let sourceCommitDigest: Data
  public let codeIdentityDigest: Data
  public let runIDDigest: Data
  public let expiresAtEpochSeconds: UInt64
  public let scenario: NativeAgentQualificationFaultScenario
  public let phase: NativeAgentQualificationFaultPhase

  private init(
    candidateDigest: Data,
    sourceCommitDigest: Data,
    codeIdentityDigest: Data,
    runIDDigest: Data,
    expiresAtEpochSeconds: UInt64,
    scenario: NativeAgentQualificationFaultScenario,
    phase: NativeAgentQualificationFaultPhase
  ) {
    self.candidateDigest = candidateDigest
    self.sourceCommitDigest = sourceCommitDigest
    self.codeIdentityDigest = codeIdentityDigest
    self.runIDDigest = runIDDigest
    self.expiresAtEpochSeconds = expiresAtEpochSeconds
    self.scenario = scenario
    self.phase = phase
  }

  public static func verify(
    manifestData: Data,
    signatureData: Data,
    publicKeyPEM: Data,
    serviceConfigurationData: Data,
    wallTime: Date = Date()
  ) throws -> Self {
    guard !manifestData.isEmpty, manifestData.count <= maximumManifestBytes,
      !serviceConfigurationData.isEmpty,
      serviceConfigurationData.count <= maximumServiceConfigurationBytes
    else {
      throw NativeAgentQualificationControllerManifestError.invalidJSON
    }

    let manifest: [String: Any]
    let service: [String: Any]
    do {
      manifest = try NativeStrictJSON.object(from: manifestData, maxBytes: maximumManifestBytes, maxDepth: 4)
      service = try NativeStrictJSON.object(
        from: serviceConfigurationData,
        maxBytes: maximumServiceConfigurationBytes,
        maxDepth: 16)
    } catch {
      throw NativeAgentQualificationControllerManifestError.invalidJSON
    }

    let fields: Set<String> = [
      "schema_version", "kind", "candidate_sha256", "source_commit_sha256",
      "code_identities_sha256", "run_id_sha256", "expires_at_epoch_seconds",
      "scenario", "phase",
    ]
    guard Set(manifest.keys) == fields else {
      throw NativeAgentQualificationControllerManifestError.unknownField
    }
    let canonical: Data
    do {
      canonical = try NativeStrictJSON.data(manifest)
    } catch {
      throw NativeAgentQualificationControllerManifestError.invalidJSON
    }
    guard canonical == manifestData else {
      throw NativeAgentQualificationControllerManifestError.nonCanonicalManifest
    }

    guard Self.integer(manifest["schema_version"]) == UInt64(manifestSchemaVersion),
      manifest["kind"] as? String == manifestKind
    else {
      throw NativeAgentQualificationControllerManifestError.invalidSchema
    }

    let candidate = try digest(manifest["candidate_sha256"], field: "candidate_sha256")
    let source = try digest(manifest["source_commit_sha256"], field: "source_commit_sha256")
    let identities = try digest(manifest["code_identities_sha256"], field: "code_identities_sha256")
    let runDigest = try digest(manifest["run_id_sha256"], field: "run_id_sha256")
    guard let expiry = integer(manifest["expires_at_epoch_seconds"]),
      let scenarioText = manifest["scenario"] as? String,
      let scenario = NativeAgentQualificationFaultScenario(rawValue: scenarioText),
      let phaseText = manifest["phase"] as? String,
      let phase = NativeAgentQualificationFaultPhase(rawValue: phaseText),
      scenario.phase == phase
    else {
      throw NativeAgentQualificationControllerManifestError.invalidValue(field: "scenario_phase")
    }

    let signature = try detachedSignature(signatureData)
    let key = try publicKey(publicKeyPEM)
    guard key.isValidSignature(signature, for: manifestData) else {
      throw NativeAgentQualificationControllerManifestError.invalidSignature
    }

    try match(service, key: "qualification_mode", string: NativeAgentQualificationConfiguration.modeMarker)
    try match(service, key: "qualification_mach_service_name", string: AgentPassQualificationXPCContract.machServiceName)
    try match(service, key: "qualification_candidate_sha256", string: hex(candidate))
    try match(service, key: "qualification_source_commit_sha256", string: hex(source))
    try match(service, key: "qualification_code_identities_sha256", string: hex(identities))
    try match(service, key: "qualification_run_id_sha256", string: hex(runDigest))
    try match(service, key: "qualification_scenario", string: scenario.rawValue)
    try match(service, key: "qualification_phase", string: phase.rawValue)
    guard integer(service["qualification_expires_at_epoch_seconds"]) == expiry else {
      throw NativeAgentQualificationControllerManifestError.serviceBindingMismatch(
        field: "qualification_expires_at_epoch_seconds")
    }

    let now = wallTime.timeIntervalSince1970
    guard now.isFinite, now >= 0, Double(expiry).isFinite else {
      throw NativeAgentQualificationControllerManifestError.invalidValue(field: "wall_time")
    }
    guard Double(expiry) > now else {
      throw NativeAgentQualificationControllerManifestError.expired
    }
    guard Double(expiry) - now <= Double(NativeAgentQualificationConfiguration.maximumLifetimeSeconds) else {
      throw NativeAgentQualificationControllerManifestError.expiryTooFarInFuture
    }

    return Self(
      candidateDigest: candidate,
      sourceCommitDigest: source,
      codeIdentityDigest: identities,
      runIDDigest: runDigest,
      expiresAtEpochSeconds: expiry,
      scenario: scenario,
      phase: phase)
  }

  public func makeArmRequest() throws -> AgentPassQualificationArmFaultRequest {
    guard let wirePhase = AgentPassQualificationXPCContract.FaultPhase(rawValue: phase.rawValue),
      let request = AgentPassQualificationArmFaultRequest(
        faultPhase: wirePhase,
        candidateDigest: candidateDigest,
        sourceCommitDigest: sourceCommitDigest,
        codeIdentityDigest: codeIdentityDigest,
        runIDDigest: runIDDigest)
    else {
      throw NativeAgentQualificationControllerManifestError.requestConstructionFailed
    }
    return request
  }

  public func makeStatusRequest() throws -> AgentPassQualificationStatusRequest {
    guard let request = AgentPassQualificationStatusRequest(
      candidateDigest: candidateDigest, runIDDigest: runIDDigest)
    else {
      throw NativeAgentQualificationControllerManifestError.requestConstructionFailed
    }
    return request
  }

  public func makeDisarmRequest(receiptDigest: Data) throws -> AgentPassQualificationDisarmRequest {
    guard let request = AgentPassQualificationDisarmRequest(
      candidateDigest: candidateDigest,
      runIDDigest: runIDDigest,
      receiptDigest: receiptDigest)
    else {
      throw NativeAgentQualificationControllerManifestError.requestConstructionFailed
    }
    return request
  }

  private static func digest(_ value: Any?, field: String) throws -> Data {
    guard let text = value as? String, text.utf8.count == 64,
      text.utf8.allSatisfy({ byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
      }),
      text.utf8.contains(where: { $0 != 48 })
    else {
      throw NativeAgentQualificationControllerManifestError.invalidValue(field: field)
    }
    var result = Data()
    result.reserveCapacity(32)
    var index = text.startIndex
    for _ in 0..<32 {
      let next = text.index(index, offsetBy: 2)
      guard let byte = UInt8(text[index..<next], radix: 16) else {
        throw NativeAgentQualificationControllerManifestError.invalidValue(field: field)
      }
      result.append(byte)
      index = next
    }
    return result
  }

  private static func integer(_ value: Any?) -> UInt64? {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID()
    else { return nil }
    let numeric = number.doubleValue
    guard numeric.isFinite, numeric >= 0, numeric <= 9_007_199_254_740_991,
      numeric.rounded(.towardZero) == numeric
    else { return nil }
    return number.uint64Value
  }

  private static func match(_ service: [String: Any], key: String, string: String) throws {
    guard service[key] as? String == string else {
      throw NativeAgentQualificationControllerManifestError.serviceBindingMismatch(field: key)
    }
  }

  private static func detachedSignature(_ data: Data) throws -> Data {
    guard data.count <= 256, let text = String(data: data, encoding: .utf8),
      text.hasSuffix("\n"), text.filter({ $0 == "\n" }).count == 1
    else {
      throw NativeAgentQualificationControllerManifestError.invalidSignatureEncoding
    }
    let encoded = String(text.dropLast())
    guard let signature = Data(base64Encoded: encoded), signature.count == 64,
      signature.base64EncodedString() == encoded
    else {
      throw NativeAgentQualificationControllerManifestError.invalidSignatureEncoding
    }
    return signature
  }

  private static func publicKey(_ data: Data) throws -> Curve25519.Signing.PublicKey {
    guard data.count <= 4 * 1024, let pem = String(data: data, encoding: .utf8),
      pem.hasSuffix("\n")
    else {
      throw NativeAgentQualificationControllerManifestError.invalidPublicKey
    }
    let lines = pem.split(whereSeparator: \.isNewline).map(String.init)
    let prefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    guard lines.count == 3, lines[0] == "-----BEGIN PUBLIC KEY-----",
      lines[2] == "-----END PUBLIC KEY-----",
      let der = Data(base64Encoded: lines[1]), der.count == 44, der.prefix(12) == prefix
    else {
      throw NativeAgentQualificationControllerManifestError.invalidPublicKey
    }
    do {
      return try Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32))
    } catch {
      throw NativeAgentQualificationControllerManifestError.invalidPublicKey
    }
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }
}
