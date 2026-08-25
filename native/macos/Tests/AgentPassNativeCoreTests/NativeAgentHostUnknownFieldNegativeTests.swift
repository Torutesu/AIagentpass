import AgentPassNativeCore
import Foundation
import Testing

private func archiveHostFields(_ fields: [(String, Any)]) -> Data {
    let archiver = NSKeyedArchiver(requiringSecureCoding: true)
    for (key, value) in fields {
        switch value {
        case let value as NSNumber:
            archiver.encode(value, forKey: key)
        case let value as NSData:
            archiver.encode(value, forKey: key)
        case let value as NSString:
            archiver.encode(value, forKey: key)
        default:
            preconditionFailure("test fixture contains an unsupported archive value")
        }
    }
    archiver.finishEncoding()
    return archiver.encodedData
}

@Test func hostRequestDecodersRejectAnUnrecognisedKeyedField() throws {
    let digest = Data(repeating: 0x11, count: AgentPassHostXPCContract.digestBytes)
    let nonce = Data(repeating: 0x22, count: AgentPassHostXPCContract.minimumNonceBytes)
    let unknown = ("future_" + "authority") as NSString

    let prepareData = archiveHostFields([
        ("protocol_version", NSNumber(value: AgentPassHostXPCContract.protocolVersion)),
        ("launch_nonce", nonce as NSData),
        ("future_authority", unknown),
    ])
    let attachData = archiveHostFields([
        ("protocol_version", NSNumber(value: AgentPassXPCProtocolVersion.host)),
        ("child_pid", NSNumber(value: 42)),
        ("child_pid_version", NSNumber(value: 9)),
        ("executable_identity_digest", digest as NSData),
        ("ancestry_binding_digest", digest as NSData),
        ("worktree_binding_digest", digest as NSData),
        ("future_authority", unknown),
    ])
    let signData = archiveHostFields([
        ("request_sequence", NSNumber(value: 1)),
        ("commit_payload", Data([1]) as NSData),
        ("future_authority", unknown),
    ])
    let statusData = archiveHostFields([
        ("protocol_version", NSNumber(value: AgentPassHostXPCContract.protocolVersion)),
        ("future_authority", unknown),
    ])
    let closeData = archiveHostFields([
        ("reason", AgentPassHostXPCContract.CloseReason.completed.rawValue as NSString),
        ("future_authority", unknown),
    ])
    let controlCloseData = archiveHostFields([
        ("protocol_version", NSNumber(value: AgentPassHostControlXPCContract.protocolVersion)),
        ("session_id", "22222222-2222-4222-8222-222222222222" as NSString),
        ("operation_id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" as NSString),
        ("reason", AgentPassHostXPCContract.CloseReason.completed.rawValue as NSString),
        ("future_authority", unknown),
    ])

    // This is an intentionally strict schema test. A future field must not
    // be silently ignored on an authority boundary; it needs an explicit
    // contract/version change and a new decoder allow-list.
    #expect((try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassHostPrepareRequest.self, from: prepareData)) == nil)
    #expect((try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassHostAttachChildRequest.self, from: attachData)) == nil)
    #expect((try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassHostSignRequest.self, from: signData)) == nil)
    #expect((try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassHostStatusRequest.self, from: statusData)) == nil)
    #expect((try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassHostCloseRequest.self, from: closeData)) == nil)
    #expect((try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassHostControlCloseRequest.self, from: controlCloseData)) == nil)
}

@Test func childGitRequestDecoderRejectsAnUnrecognisedKeyedField() throws {
    let archiver = NSKeyedArchiver(requiringSecureCoding: true)
    archiver.encode(NSNumber(value: AgentPassChildGitXPCContract.protocolVersion), forKey: "protocol_version")
    archiver.encode(NSNumber(value: 1), forKey: "request_sequence")
    archiver.encode(Data([1, 2, 3]) as NSData, forKey: "commit_payload")
    archiver.encode("future_authority" as NSString, forKey: "future_authority")
    archiver.finishEncoding()

    #expect((try? NSKeyedUnarchiver.unarchivedObject(ofClass: AgentPassChildGitSignRequest.self, from: archiver.encodedData)) == nil)
}

private enum AgentPassXPCProtocolVersion {
    static let host = AgentPassHostXPCContract.protocolVersion
}
