import Foundation
import Testing

private struct DeviceEnrollmentContract: Decodable {
    struct DeviceKey: Decodable {
        let algorithm: String
        let spkiPEM: String

        enum CodingKeys: String, CodingKey {
            case algorithm
            case spkiPEM = "spki_pem"
        }
    }

    let version: Int
    let enrollmentID: UUID
    let organizationID: UUID
    let deviceID: UUID
    let label: String
    let platform: String
    let deviceKey: DeviceKey

    enum CodingKeys: String, CodingKey {
        case version
        case enrollmentID = "enrollment_id"
        case organizationID = "organization_id"
        case deviceID = "device_id"
        case label
        case platform
        case deviceKey = "device_key"
    }
}

private struct BundleAcknowledgementContract: Decodable {
    let version: Int
    let organizationID: UUID
    let deviceID: UUID
    let formatEpoch: Int
    let sequence: Int64
    let statementHash: String
    let appliedAt: String
    let status: String
    let reason: String?

    enum CodingKeys: String, CodingKey {
        case version
        case organizationID = "organization_id"
        case deviceID = "device_id"
        case formatEpoch = "format_epoch"
        case sequence
        case statementHash = "statement_hash"
        case appliedAt = "applied_at"
        case status
        case reason
    }
}

private func platformContractFixture(_ name: String) throws -> Data {
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let fixture = testDirectory
        .appendingPathComponent("../../../../contracts/fixtures", isDirectory: true)
        .appendingPathComponent(name)
        .standardizedFileURL
    return try Data(contentsOf: fixture)
}

private func exactKeys(in data: Data, expected: Set<String>) throws {
    let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    #expect(Set(object.keys) == expected)
}

@Test func macOSDecodesTheCanonicalDeviceEnrollmentContract() throws {
    let data = try platformContractFixture("device-enrollment.valid.json")
    try exactKeys(
        in: data,
        expected: ["version", "enrollment_id", "organization_id", "device_id", "label", "platform", "device_key"]
    )

    let enrollment = try JSONDecoder().decode(DeviceEnrollmentContract.self, from: data)
    #expect(enrollment.version == 1)
    #expect(enrollment.platform == "macos")
    #expect(enrollment.deviceKey.algorithm == "p256-sha256")
    #expect(enrollment.deviceKey.spkiPEM.hasPrefix("-----BEGIN PUBLIC KEY-----"))
    #expect(enrollment.enrollmentID != enrollment.organizationID)
    #expect(enrollment.organizationID != enrollment.deviceID)
}

@Test func macOSDecodesTheCanonicalBundleAcknowledgementContract() throws {
    let data = try platformContractFixture("bundle-ack.valid.json")
    try exactKeys(
        in: data,
        expected: ["version", "organization_id", "device_id", "format_epoch", "sequence", "statement_hash", "applied_at", "status"]
    )

    let acknowledgement = try JSONDecoder().decode(BundleAcknowledgementContract.self, from: data)
    #expect(acknowledgement.version == 1)
    #expect(acknowledgement.formatEpoch == 2)
    #expect(acknowledgement.sequence == 7)
    #expect(acknowledgement.statementHash.count == 64)
    #expect(acknowledgement.status == "applied")
    #expect(acknowledgement.reason == nil)
}
