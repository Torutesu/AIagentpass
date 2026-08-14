import { handleOwnerRecoveryRequest } from "../../../../../../../../lib/owner-recovery-api.mjs";

export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  return handleOwnerRecoveryRequest(request);
}
