const PROBE_GENERATION = "1";
const PROBE_BASE64 = "__PROBE_BASE64__";

function decodeBase64(value) {
  const raw = atob(value);
  return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}

function requestIsExactProbe(request) {
  if (request.method !== "GET") return false;
  const url = new URL(request.url);
  if (url.pathname !== "/v1/credentials") return false;
  const keys = [...url.searchParams.keys()];
  return (
    keys.length === 1 &&
    keys[0] === "generation" &&
    url.searchParams.get("generation") === PROBE_GENERATION
  );
}

const PROBE_BYTES = decodeBase64(PROBE_BASE64);

export default {
  async fetch(request) {
    if (!requestIsExactProbe(request)) {
      return new Response("bounded credential probe only", {
        status: 404,
        headers: { "cache-control": "no-store" },
      });
    }

    return new Response(PROBE_BYTES, {
      status: 200,
      headers: {
        "cache-control": "no-store",
        "content-type": "application/x-protobuf",
      },
    });
  },
};
