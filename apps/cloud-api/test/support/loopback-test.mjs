import net from "node:net";

const LOOPBACK_FAILURE_CODES = new Set(["EACCES", "EADDRNOTAVAIL", "EPERM"]);
const REQUIRE_LOOPBACK = "AGENTPASS_REQUIRE_LOOPBACK_TESTS";

export const LOOPBACK_UNAVAILABLE_MESSAGE = "loopback listener is unavailable in this sandbox; external Cloud API HTTP E2E remains not_proven";

export function isLoopbackListenerUnavailable(error) {
  if (!LOOPBACK_FAILURE_CODES.has(error?.code)) return false;
  const address = typeof error?.address === "string" ? error.address : "";
  const message = typeof error?.message === "string" ? error.message : "";
  return address === "127.0.0.1" || /(?:^|\s|\/)(?:127\.0\.0\.1|::1)(?::|\s|\/|$)/u.test(message);
}

export function loopbackTestsAreRequired(env = process.env) {
  return env[REQUIRE_LOOPBACK] === "1";
}

export function createLoopbackAwareTest(nodeTest, { env = process.env } = {}) {
  let unavailable = false;
  let availabilityPromise;

  async function probe() {
    if (loopbackTestsAreRequired(env)) return true;
    availabilityPromise ??= new Promise((resolve, reject) => {
      const server = net.createServer();
      server.once("error", (error) => {
        if (isLoopbackListenerUnavailable(error)) {
          unavailable = true;
          resolve(false);
          return;
        }
        reject(error);
      });
      server.listen(0, "127.0.0.1", () => {
        server.close((error) => error ? reject(error) : resolve(true));
      });
    });
    return availabilityPromise;
  }

  return function loopbackAwareTest(name, handler) {
    return nodeTest(name, async (t) => {
      const available = await probe();
      if (!available && !loopbackTestsAreRequired(env)) {
        t.skip(LOOPBACK_UNAVAILABLE_MESSAGE);
        return;
      }
      if (unavailable && !loopbackTestsAreRequired(env)) {
        t.skip(LOOPBACK_UNAVAILABLE_MESSAGE);
        return;
      }
      try {
        return await handler(t);
      } catch (error) {
        if (!loopbackTestsAreRequired(env) && isLoopbackListenerUnavailable(error)) {
          unavailable = true;
          t.skip(LOOPBACK_UNAVAILABLE_MESSAGE);
          return;
        }
        throw error;
      }
    });
  };
}
