import { getChatGPTUser } from "../../../chatgpt-auth";
import { handleHumanAuthRequest } from "../../../../lib/human-auth-api.mjs";

export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return handleHumanAuthRequest(request, { getSiwcUser: getChatGPTUser });
}
