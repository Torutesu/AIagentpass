import { handleHumanAuthRequest } from "../../../../../lib/human-auth-api.mjs";

export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  return handleHumanAuthRequest(request);
}
