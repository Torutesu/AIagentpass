import Foundation

@objc public protocol AgentPassNativeServiceProtocol {
    func health(withReply reply: @escaping (NSDictionary) -> Void)
    func publicKey(withReply reply: @escaping (NSString?, NSError?) -> Void)
    func sign(request: NSData, withReply reply: @escaping (NSString?, NSError?) -> Void)
    func auditStatus(withReply reply: @escaping (NSData?, NSError?) -> Void)
    func auditPublicKey(withReply reply: @escaping (NSString?, NSError?) -> Void)
    func createAuditCheckpoint(withReply reply: @escaping (NSData?, NSError?) -> Void)
    func auditAnchorStatus(withReply reply: @escaping (NSData?, NSError?) -> Void)
    func pushAuditAnchor(withReply reply: @escaping (NSData?, NSError?) -> Void)
    func beginSession(agentID: NSString, ttlSeconds: Int, withReply reply: @escaping (NSData?, NSError?) -> Void)
    func completeSession(challenge: NSData, signature: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void)
    func revokeSessions(withReply reply: @escaping (NSData?, NSError?) -> Void)
    func validateSession(token: NSString?, agentID: NSString, withReply reply: @escaping (Bool, NSError?) -> Void)
    func applyControlBundle(bundle: NSData, withReply reply: @escaping (NSData?, NSError?) -> Void)
    func controlStatus(withReply reply: @escaping (NSData?, NSError?) -> Void)
    func validateControl(agentID: NSString, withReply reply: @escaping (Bool, NSError?) -> Void)
}
