import { handleOwnerRecoveryRequest } from "../../../../../../../lib/owner-recovery-api.mjs";

export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  return handleOwnerRecoveryRequest(request);
}
