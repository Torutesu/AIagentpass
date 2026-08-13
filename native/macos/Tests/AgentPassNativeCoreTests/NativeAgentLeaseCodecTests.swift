import Foundation
import Testing
@testable import AgentPassNativeCore

private let leaseOrganizationID = "11111111-1111-4111-8111-111111111111"
private let leaseDeviceID = "22222222-2222-4222-8222-222222222222"
private let leaseAgentID = "33333333-3333-4333-8333-333333333333"
private let leaseAdapterID = "44444444-4444-4444-8444-444444444444"
private let leaseGrantID = "55555555-5555-4555-8555-555555555555"
private let leaseSessionID = "66666666-6666-4666-8666-666666666666"

private func expectedLeaseBinding() throws -> NativeAgentSessionBinding {
    try NativeAgentSessionBinding(
        agentID: leaseAgentID,
        deviceID: leaseDeviceID,
        processBindingDigest: Data(repeating: 0xbb, count: 32),
        ancestryBindingDigest: Data(repeating: 0xcc, count: 32),
        worktreeBindingDigest: Data(repeating: 0xaa, count: 32),
        controlSequence: 12,
        authorityGeneration: 7,
        keyGeneration: 99
    )
}

private func leaseObject() -> [String: Any] {
    [
        "version": 1,
        "type": "agentpass.agent-session-lease",
        "session_id": leaseSessionID,
        "grant_id": leaseGrantID,
        "organization_id": leaseOrganizationID,
        "device_id": leaseDeviceID,
        "agent_id": leaseAgentID,
        "agent_kind": "claude-code",
        "adapter_id": leaseAdapterID,
        "adapter_version": "1.0.0",
        "process_binding_sha256": String(repeating: "b", count: 64),
        "ancestry_binding_sha256": String(repeating: "c", count: 64),
        "worktree_binding_sha256": String(repeating: "a", count: 64),
        "max_signatures": 2,
        "used_signatures": 0,
        "not_before": "2026-08-13T10:00:00.000Z",
        "expires_at": "2026-08-13T10:15:00.000Z",
        "control_sequence": 12,
        "authority_generation": 7
    ]
}

private func leaseData(_ mutate: ((inout [String: Any]) -> Void)? = nil) throws -> Data {
    var object = leaseObject()
    mutate?(&object)
    return try NativeStrictJSON.data(object)
}

@Test func cloudLeaseCodecRetainsEveryCloudFieldAndBindsAllRepresentableAuthority() throws {
    let data = try leaseData()
    let expectedBinding = try expectedLeaseBinding()
    let lease = try NativeAgentLeaseCodec.decode(data, expectedBinding: expectedBinding)

    #expect(lease.version == 1)
    #expect(lease.type == "agentpass.agent-session-lease")
    #expect(lease.sessionID == leaseSessionID)
    #expect(lease.grantID == leaseGrantID)
    #expect(lease.organizationID == leaseOrganizationID)
    #expect(lease.deviceID == leaseDeviceID)
    #expect(lease.agentID == leaseAgentID)
    #expect(lease.agentKind == "claude-code")
    #expect(lease.adapterID == leaseAdapterID)
    #expect(lease.adapterVersion == "1.0.0")
    #expect(lease.processBindingSHA256 == String(repeating: "b", count: 64))
    #expect(lease.ancestryBindingSHA256 == String(repeating: "c", count: 64))
    #expect(lease.worktreeBindingSHA256 == String(repeating: "a", count: 64))
    #expect(lease.maxSignatures == 2)
    #expect(lease.usedSignatures == 0)
    #expect(lease.notBefore == "2026-08-13T10:00:00.000Z")
    #expect(lease.expiresAt == "2026-08-13T10:15:00.000Z")
    #expect(lease.controlSequence == 12)
    #expect(lease.authorityGeneration == 7)
    #expect(lease.binding == expectedBinding)
    #expect(try NativeAgentLeaseCodec.canonicalJSON(lease) == data)
    #expect(try NativeAgentLeaseCodec.canonicalJSON(data, expectedBinding: expectedLeaseBinding()) == data)
}

@Test func cloudLeaseCodecRejectsDuplicateUnknownAndNonCanonicalJSON() throws {
    let duplicate = Data(#"{"version":1,"version":1}"#.utf8)
    #expect(throws: NativeAgentLeaseCodecError.duplicateField) {
        _ = try NativeAgentLeaseCodec.decode(duplicate, expectedBinding: expectedLeaseBinding())
    }

    let unknown = try leaseData { $0["unexpected"] = true }
    #expect(throws: NativeAgentLeaseCodecError.invalidShape) {
        _ = try NativeAgentLeaseCodec.decode(unknown, expectedBinding: expectedLeaseBinding())
    }

    let canonical = try leaseData()
    let nonCanonical = Data((" " + String(decoding: canonical, as: UTF8.self)).utf8)
    #expect(throws: NativeAgentLeaseCodecError.nonCanonicalJSON) {
        _ = try NativeAgentLeaseCodec.decode(nonCanonical, expectedBinding: expectedLeaseBinding())
    }
}

@Test func cloudLeaseCodecRejectsVersionTypeIdentifiersAndDigestSubstitutions() throws {
    #expect(throws: NativeAgentLeaseCodecError.unsupportedVersion) {
        _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["version"] = 2 }, expectedBinding: expectedLeaseBinding())
    }
    #expect(throws: NativeAgentLeaseCodecError.invalidType) {
        _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["type"] = "agentpass.other" }, expectedBinding: expectedLeaseBinding())
    }

    for key in ["session_id", "grant_id", "organization_id", "device_id", "agent_id", "adapter_id"] {
        #expect(throws: NativeAgentLeaseCodecError.invalidIdentifier) {
            _ = try NativeAgentLeaseCodec.decode(try leaseData { $0[key] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" }, expectedBinding: expectedLeaseBinding())
        }
    }
    #expect(throws: NativeAgentLeaseCodecError.invalidIdentifier) {
        _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["agent_id"] = "33333333-3333-4333-8333-33333333333" }, expectedBinding: expectedLeaseBinding())
    }
    for key in ["process_binding_sha256", "ancestry_binding_sha256", "worktree_binding_sha256"] {
        #expect(throws: NativeAgentLeaseCodecError.invalidDigest) {
            _ = try NativeAgentLeaseCodec.decode(try leaseData { $0[key] = String(repeating: "A", count: 64) }, expectedBinding: expectedLeaseBinding())
        }
    }
}

@Test func cloudLeaseCodecRejectsBudgetTimestampAndGenerationSubstitutions() throws {
    for value in [0, 65] {
        #expect(throws: NativeAgentLeaseCodecError.invalidBudget) {
            _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["max_signatures"] = value }, expectedBinding: expectedLeaseBinding())
        }
    }
    for value in [-1, 65] {
        #expect(throws: NativeAgentLeaseCodecError.invalidBudget) {
            _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["used_signatures"] = value }, expectedBinding: expectedLeaseBinding())
        }
    }
    #expect(throws: NativeAgentLeaseCodecError.invalidBudget) {
        _ = try NativeAgentLeaseCodec.decode(try leaseData {
            $0["max_signatures"] = 1
            $0["used_signatures"] = 2
        }, expectedBinding: expectedLeaseBinding())
    }
    #expect(throws: NativeAgentLeaseCodecError.invalidTimestamp) {
        _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["expires_at"] = $0["not_before"] }, expectedBinding: expectedLeaseBinding())
    }
    #expect(throws: NativeAgentLeaseCodecError.invalidTimestamp) {
        _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["not_before"] = "2026-02-30T10:00:00.000Z" }, expectedBinding: expectedLeaseBinding())
    }
    #expect(throws: NativeAgentLeaseCodecError.invalidGeneration) {
        _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["control_sequence"] = 0 }, expectedBinding: expectedLeaseBinding())
    }
    #expect(throws: NativeAgentLeaseCodecError.invalidGeneration) {
        _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["authority_generation"] = 9_007_199_254_740_992 }, expectedBinding: expectedLeaseBinding())
    }
    #expect(throws: NativeAgentLeaseCodecError.invalidGeneration) {
        _ = try NativeAgentLeaseCodec.decode(try leaseData { $0["authority_generation"] = 1.5 }, expectedBinding: expectedLeaseBinding())
    }
}

@Test func cloudLeaseCodecRejectsEveryBindingSubstitutionAndDoesNotInventLeaseID() throws {
    for key in [
        "agent_id", "device_id", "process_binding_sha256", "ancestry_binding_sha256",
        "worktree_binding_sha256", "control_sequence", "authority_generation"
    ] {
        #expect(throws: NativeAgentLeaseCodecError.bindingMismatch) {
            _ = try NativeAgentLeaseCodec.decode(try leaseData { object in
                switch key {
                case "agent_id": object[key] = "99999999-9999-4999-8999-999999999999"
                case "device_id": object[key] = "99999999-9999-4999-8999-999999999999"
                case "process_binding_sha256": object[key] = String(repeating: "d", count: 64)
                case "ancestry_binding_sha256": object[key] = String(repeating: "d", count: 64)
                case "worktree_binding_sha256": object[key] = String(repeating: "d", count: 64)
                case "control_sequence": object[key] = 13
                case "authority_generation": object[key] = 8
                default: break
                }
            }, expectedBinding: expectedLeaseBinding())
        }
    }

    let lease = try NativeAgentLeaseCodec.decode(try leaseData(), expectedBinding: expectedLeaseBinding())
    #expect(lease.sessionID != lease.grantID)
    // The Cloud schema has no lease_id.  The wrapper intentionally exposes no
    // synthetic lease ID and cannot be converted to the legacy dependency type.
}
