import { getChatGPTUser } from "../../../../chatgpt-auth";
import { handleHumanAuthRequest } from "../../../../../lib/human-auth-api.mjs";

export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  return handleHumanAuthRequest(request, { getSiwcUser: getChatGPTUser });
}

export async function POST(request: Request): Promise<Response> {
  return handleHumanAuthRequest(request, { getSiwcUser: getChatGPTUser });
}

export async function PATCH(request: Request): Promise<Response> {
  return handleHumanAuthRequest(request, { getSiwcUser: getChatGPTUser });
}
