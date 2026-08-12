import { getChatGPTUser } from "../../chatgpt-auth";
import { handleConsoleRequest } from "../../../lib/console-api.mjs";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  return handleConsoleRequest(request, { getSiwcUser: getChatGPTUser });
}

export async function POST(request: Request) {
  return handleConsoleRequest(request, { getSiwcUser: getChatGPTUser });
}
