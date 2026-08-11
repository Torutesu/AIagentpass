import Foundation

@objc public protocol AgentPassNativeServiceProtocol {
    func health(withReply reply: @escaping (NSDictionary) -> Void)
    func publicKey(withReply reply: @escaping (NSString?, NSError?) -> Void)
    func sign(request: NSData, withReply reply: @escaping (NSString?, NSError?) -> Void)
}
