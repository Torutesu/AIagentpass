import AgentPassNativeCore
import Darwin
import Foundation

// No command, endpoint, path, key, credential, or output destination is
// accepted from argv or the environment. Any extra argument is a fixed
// invocation failure and is never echoed.
guard CommandLine.arguments.count == 1 else {
  emitFailure(.invalidInvocation)
}
do {
  _ = try FixedQualificationGrantClient.runProduction()
  exit(0)
} catch let error as QualificationGrantClientError {
  emitFailure(error)
} catch {
  emitFailure(.claimFailed)
}

private func emitFailure(_ error: QualificationGrantClientError) -> Never {
  // This is deliberately a bounded, non-sensitive class. In particular,
  // never print localized NSError text or HTTP response bytes.
  let data = Data("AGENTPASS_QUALIFICATION_GRANT_CLIENT_\(error.rawValue)\n".utf8)
  FileHandle.standardError.write(data)
  exit(1)
}
