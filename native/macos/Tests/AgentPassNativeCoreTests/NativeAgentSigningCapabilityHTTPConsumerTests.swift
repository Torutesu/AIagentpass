import Foundation
import Testing

@testable import AgentPassNativeCore

private struct CapabilityTestSigner: P256MessageSigner {
    let publicKeyX963 = Data([0x04] + Array(repeating: 0x01, count: 64))
    func sign(message: Data) throws -> Data { Data(repeating: 0x02, count: 64) }
}

private struct CapabilityTestRandom: NativeAgentRandomBytesGenerating {
    func randomBytes(count: Int) throws -> Data { Data(repeating: 0x03, count: count) }
}

private struct CapabilityTestClock: NativeAgentWallClock {
    func sample() throws -> NativeAgentWallClockValue {
        NativeAgentWallClockValue(millisecondsSinceUnixEpoch: 1_786_615_200_000)
    }
}

private final class CapabilityTransport: NativeAgentHTTPTransporting, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var lastURL: URL?
    private(set) var lastHeaders: [String: String] = [:]
    private(set) var lastBody = Data()
    var statusCode = 200
    var responseBody = Data("{}".utf8)

    func send(url: URL, method: String, headers: [String: String], body: Data, timeoutSeconds: Int) throws -> NativeAgentHTTPResponse {
        lock.withLock {
            lastURL = url
            lastHeaders = headers
            lastBody = body
        }
        return NativeAgentHTTPResponse(statusCode: statusCode, body: responseBody)
    }
}

private let capabilityOrganization = "11111111-1111-4111-8111-111111111111"
private let capabilityDevice = "22222222-2222-4222-8222-222222222222"
private let capabilitySession = "33333333-3333-4333-8333-333333333333"
private let capabilityRequest = "44444444-4444-4444-8444-444444444444"

@Test func capabilityHTTPConsumerAuthenticatesCanonicalDeviceRequest() throws {
    let transport = CapabilityTransport()
    let consumer = try NativeAgentSigningCapabilityHTTPConsumer(
        baseURL: URL(string: "https://api.agentpass.test")!,
        organizationID: capabilityOrganization,
        deviceID: capabilityDevice,
        sessionID: capabilitySession,
        transport: transport,
        signer: CapabilityTestSigner(),
        random: CapabilityTestRandom(),
        wallClock: CapabilityTestClock())
    let request = try NativeAgentSigningCapabilityRequest(requestID: capabilityRequest)

    #expect(throws: NativeAgentSigningCapabilityHTTPError.invalidResponse) {
        _ = try consumer.issue(request)
    }
    #expect(transport.lastURL?.path == "/v1/organizations/\(capabilityOrganization)/devices/\(capabilityDevice)/agent-sessions/\(capabilitySession)/signing-capabilities")
    #expect(transport.lastHeaders["AgentPass-Device"] == capabilityDevice)
    #expect(transport.lastHeaders["AgentPass-Timestamp"] == "1786615200000")
    #expect(transport.lastHeaders["AgentPass-Content-SHA256"]?.count == 64)
    #expect(String(data: transport.lastBody, encoding: .utf8) == "{\"request_id\":\"\(capabilityRequest)\"}")
}

@Test func capabilityHTTPConsumerRejectsInsecureOrMalformedConfiguration() throws {
    #expect(throws: NativeAgentSigningCapabilityHTTPError.invalidConfiguration) {
        _ = try NativeAgentSigningCapabilityHTTPConsumer(
            baseURL: URL(string: "http://api.agentpass.test")!,
            organizationID: capabilityOrganization,
            deviceID: capabilityDevice,
            sessionID: capabilitySession,
            transport: CapabilityTransport(),
            signer: CapabilityTestSigner())
    }
}

@Test func capabilityHTTPConsumerMapsServerReplayAndRateLimitFailures() throws {
    let transport = CapabilityTransport()
    let consumer = try NativeAgentSigningCapabilityHTTPConsumer(
        baseURL: URL(string: "https://api.agentpass.test")!,
        organizationID: capabilityOrganization,
        deviceID: capabilityDevice,
        sessionID: capabilitySession,
        transport: transport,
        signer: CapabilityTestSigner())
    let request = try NativeAgentSigningCapabilityRequest(requestID: capabilityRequest)
    transport.statusCode = 409
    #expect(throws: NativeAgentSigningCapabilityHTTPError.conflict) { _ = try consumer.issue(request) }
    transport.statusCode = 429
    #expect(throws: NativeAgentSigningCapabilityHTTPError.rateLimited) { _ = try consumer.issue(request) }
}
