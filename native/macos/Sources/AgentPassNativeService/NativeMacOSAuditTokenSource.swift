import Darwin
import Foundation

/// The live complete-token source for NSXPC listeners on macOS.
///
/// Foundation intentionally exposes only a projection of the peer's security
/// attributes on `NSXPCConnection`. The incoming connection nevertheless owns
/// the kernel-supplied `auditToken` selector. This adapter keeps that runtime
/// boundary in one place, decodes the returned `NSValue` as the Darwin
/// `audit_token_t`, and uses the BSM accessors rather than relying on the
/// token's opaque storage layout.
///
/// The selector is not part of the public Foundation header. If a future OS
/// removes or changes it, this source throws and every listener using it
/// rejects the connection. It never falls back to the public projection.
public struct NativeMacOSAuditTokenSource: NativeAgentAuthenticatedHostAuditTokenSource {
    typealias RawAuditTokenReader = @Sendable (NSXPCConnection) throws -> audit_token_t

    private let readRawToken: RawAuditTokenReader

    /// Creates the production source backed by the live NSXPC connection.
    public init() {
        self.readRawToken = Self.readRawAuditToken
    }

    /// Injectable raw-token boundary for tests. The closure is intentionally
    /// internal so callers cannot provide a caller-controlled token in the
    /// production API surface.
    init(readRawToken: @escaping RawAuditTokenReader) {
        self.readRawToken = readRawToken
    }

    public func completeAuditToken(for connection: NSXPCConnection) throws -> NativeAgentAuthenticatedHostCompleteAuditToken {
        let rawToken: audit_token_t
        do {
            rawToken = try readRawToken(connection)
        } catch {
            throw NativeAgentAuthenticatedHostAuditTokenError.auditTokenUnavailable
        }

        do {
            return try NativeAgentAuthenticatedHostCompleteAuditToken(words: Self.validatedWords(from: rawToken))
        } catch let error as NativeAgentAuthenticatedHostAuditTokenError {
            throw error
        } catch {
            throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
        }
    }

    private static func readRawAuditToken(from connection: NSXPCConnection) throws -> audit_token_t {
        let selector = NSSelectorFromString("auditToken")
        guard connection.responds(to: selector),
              let value = connection.value(forKey: "auditToken") as? NSValue,
              let token = value.value(of: audit_token_t.self) else {
            throw NativeAgentAuthenticatedHostAuditTokenError.auditTokenUnavailable
        }
        return token
    }

    /// Extracts all eight Darwin fields through the documented BSM conversion
    /// routines. The resulting order is the `audit_token_t.val` order used by
    /// the complete-token boundary: auid, euid, egid, ruid, rgid, pid, asid,
    /// pidversion.
    private static func validatedWords(from token: audit_token_t) throws -> [UInt32] {
        guard let accessors = NativeMacOSAuditTokenBSMAccessors.shared() else {
            throw NativeAgentAuthenticatedHostAuditTokenError.auditTokenUnavailable
        }
        let auditUserID = accessors.auditUserID(token)
        let effectiveUserID = accessors.effectiveUserID(token)
        let effectiveGroupID = accessors.effectiveGroupID(token)
        let realUserID = accessors.realUserID(token)
        let realGroupID = accessors.realGroupID(token)
        let pid = accessors.pid(token)
        let auditSessionID = accessors.auditSessionID(token)
        let pidVersion = accessors.pidVersion(token)

        // AU_DEFAUDITID is the valid "no audit user" sentinel for auid. The
        // remaining credential fields use UINT32_MAX as an invalid value.
        guard effectiveUserID < UInt32.max,
              effectiveGroupID < UInt32.max,
              realUserID < UInt32.max,
              realGroupID < UInt32.max,
              pid > 0,
              auditSessionID > 0,
              pidVersion > 0 else {
            throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
        }

        let words = [
            auditUserID,
            effectiveUserID,
            effectiveGroupID,
            realUserID,
            realGroupID,
            UInt32(pid),
            UInt32(auditSessionID),
            UInt32(pidVersion)
        ]
        guard words.count == 8, words.contains(where: { $0 != 0 }) else {
            throw NativeAgentAuthenticatedHostAuditTokenError.invalidAuditToken
        }
        return words
    }
}

/// BSM is an Apple system library, but SwiftPM does not link it for this
/// service target transitively. Resolve only the documented field-conversion
/// entry points and fail closed if the system library or any entry point is
/// unavailable. The raw token never leaves this process-local adapter.
private struct NativeMacOSAuditTokenBSMAccessors: @unchecked Sendable {
    typealias UInt32Accessor = @convention(c) (audit_token_t) -> UInt32
    typealias Int32Accessor = @convention(c) (audit_token_t) -> Int32

    let auditUserID: UInt32Accessor
    let effectiveUserID: UInt32Accessor
    let effectiveGroupID: UInt32Accessor
    let realUserID: UInt32Accessor
    let realGroupID: UInt32Accessor
    let pid: Int32Accessor
    let auditSessionID: Int32Accessor
    let pidVersion: Int32Accessor

    private static let cached: NativeMacOSAuditTokenBSMAccessors? = load()

    static func shared() -> NativeMacOSAuditTokenBSMAccessors? {
        cached
    }

    static func load() -> NativeMacOSAuditTokenBSMAccessors? {
        guard let handle = dlopen("/usr/lib/libbsm.0.dylib", RTLD_LAZY | RTLD_LOCAL) else {
            return nil
        }
        guard let auditUserID: UInt32Accessor = symbol("audit_token_to_auid", from: handle),
              let effectiveUserID: UInt32Accessor = symbol("audit_token_to_euid", from: handle),
              let effectiveGroupID: UInt32Accessor = symbol("audit_token_to_egid", from: handle),
              let realUserID: UInt32Accessor = symbol("audit_token_to_ruid", from: handle),
              let realGroupID: UInt32Accessor = symbol("audit_token_to_rgid", from: handle),
              let pid: Int32Accessor = symbol("audit_token_to_pid", from: handle),
              let auditSessionID: Int32Accessor = symbol("audit_token_to_asid", from: handle),
              let pidVersion: Int32Accessor = symbol("audit_token_to_pidversion", from: handle) else {
            return nil
        }
        return Self(
            auditUserID: auditUserID,
            effectiveUserID: effectiveUserID,
            effectiveGroupID: effectiveGroupID,
            realUserID: realUserID,
            realGroupID: realGroupID,
            pid: pid,
            auditSessionID: auditSessionID,
            pidVersion: pidVersion
        )
    }

    private static func symbol<T>(_ name: String, from handle: UnsafeMutableRawPointer) -> T? {
        name.withCString { namePointer in
            guard let address = dlsym(handle, namePointer) else { return nil }
            return unsafeBitCast(address, to: T.self)
        }
    }
}
