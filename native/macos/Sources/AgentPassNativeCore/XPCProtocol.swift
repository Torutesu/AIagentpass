import Foundation

@objc public protocol AgentPassNativeServiceProtocol {
    func health(withReply reply: @escaping (NSDictionary) -> Void)
    func publicKey(withReply reply: @escaping (NSString?, NSError?) -> Void)
    func sign(request: NSData, withReply reply: @escaping (NSString?, NSError?) -> Void)
    func auditStatus(withReply reply: @escaping (NSData?, NSError?) -> Void)
    func auditPublicKey(withReply reply: @escaping (NSString?, NSError?) -> Void)
    func createAuditCheckpoint(withReply reply: @escaping (NSData?, NSError?) -> Void)
}
